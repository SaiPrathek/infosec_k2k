from serpapi import GoogleSearch
import subprocess
from database import SessionLocal, engine, Base
import requests
import re
from bs4 import BeautifulSoup
from sqlalchemy.orm import Session
from models import User, SessionModel, ScanMetadata, Entity, Edge

Base.metadata.create_all(bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def start_osint_service(username: str):
    osint_data = {
        "username": username,
        "google_results": [],
        "document_links": [],
        "emails": [],
        "social_media_accounts": {}
    }

    serp_api_key = '3249e7e616c64b3bedc3ca68e0bf42c370ecb8f3eade304d5abc435e16ad0305'

    # Google Search using SERP API
    try:
        search_params = {
            "engine": "google",
            "q": username,
            "api_key": serp_api_key,
            "num": 5
        }
        search = GoogleSearch(search_params)
        results = search.get_dict()

        # Extract URLs from search results
        for result in results.get("organic_results", []):
            osint_data["google_results"].append(result.get("link"))

    except Exception as e:
        osint_data["google_results"].append(f"Error during Google search: {str(e)}")

    # Google Dorks Search for documents
    try:
        dork_params = {
            "engine": "google",
            "q": f'"{username}" filetype:pdf OR filetype:doc OR filetype:docx OR filetype:ppt OR filetype:pptx',
            "api_key": serp_api_key,
            "num": 5
        }
        dork_search = GoogleSearch(dork_params)
        dork_results = dork_search.get_dict()

        for result in dork_results.get("organic_results", []):
            osint_data["document_links"].append(result.get("link"))

    except Exception as e:
        osint_data["document_links"].append(f"Error during Google Dorks search: {str(e)}")

    # Social Media Search
    try:
        social_sites = [
            "twitter.com",
            "facebook.com",
            "instagram.com",
            "linkedin.com",
            "tiktok.com",
            "github.com",
        ]

        for site in social_sites:
            social_params = {
                "engine": "google",
                "q": f'"{username}" site:{site}',
                "api_key": serp_api_key,
                "num": 5
            }
            social_search = GoogleSearch(social_params)
            social_results = social_search.get_dict()

            site_links = []
            for result in social_results.get("organic_results", []):
                site_links.append(result.get("link"))
            osint_data["social_media_accounts"][site] = site_links

    except Exception as e:
        osint_data["social_media_accounts"]["error"] = f"Error during social media search: {str(e)}"

    return osint_data

def run_subprocess_realtime(command):
    """
    Run a subprocess, print its logs in real time, and store the output in a variable.

    Args:
        command (list): List of strings representing the command and its arguments.

    Returns:
        str: The full output (logs) of the subprocess.
    """
    output_lines = []  # To store the output lines

    # Start the subprocess with unbuffered output
    with subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,  # Combine stderr with stdout
        bufsize=1,                 # Line-buffered
        universal_newlines=True    # Decode output as text
    ) as process:
        
        # Print and collect output line by line
        for line in process.stdout:
            print(line, end='')    # Print each line in real-time
            output_lines.append(line)  # Store the line in the list

        # Wait for the process to finish
        process.wait()

    full_output = ''.join(output_lines)  # Combine all lines into a single string
    print(f"\nSubprocess exited with return code: {process.returncode}")
    return full_output

def start_org_osint_service(db: Session, goal:str, identifier: str, searchQuery: str, graphId: str):
    # sfcli_path = r'C:\Users\SaiPrathekKotha\Projects\osint_sas\spiderfoot\sf.py'  # Replace with the actual path

    # # Define the target and modules
    # target = searchQuery  # Replace with your target
    # modules = 'sfp_securitytrails'  # Replace with desired modules
    # use_case = 'passive'
    # output_csv = 'json'
    # # Construct the command
    # command = [
    #     'python',  # Ensure 'python' is in your system's PATH
    #     sfcli_path,
    #     '-s', target,
    #     '-m', modules,
    #     "-o", output_csv
    # ]

    # try:
    #     # Execute the command
    #     result = run_subprocess_realtime(command)

    #     # Print the output
    #     print('Scan Output:')
    #     print(result)

    #     # Add result to the database
    #     new_scan = ScanMetadata(
    #         session_id=graphId,  # Assuming identifier is the session_id
    #         scan_name=f"OSINT Scan for {searchQuery}",
    #         scan_type="org_osint",
    #         scan_result={"output": result}  # Store the result as JSON
    #     )
    #     db.add(new_scan)
    #     db.commit()
    #     db.refresh(new_scan)

    # except subprocess.CalledProcessError as e:
    #     result = []
    #     print(f'An error occurred: {e}')
    #     print(f'Stderr: {e.stderr}')

    # return result

    dummy_data = {
        "graphId": graphId,
        "entities": [
            {
                "id": "sclowy_root",
                "label": "sclowy.com",
                "type": "domain",
                "metadata": [
                    {
                        "title": "Domain",
                        "url": "https://sclowy.com"
                    }
                ]
            },
            {
                "id": "blacklisted_names_bucket",
                "label": "Blacklisted Names",
                "type": "bucket",
                "metadata": [
                    {
                        "title": "Type",
                        "url": "Blacklisted Names"
                    }
                ],
                "childCount": 3,
            },
            {
                "id": "dns_records_bucket",
                "label": "DNS Records",
                "type": "bucket",
                "metadata": [
                    {
                        "title": "Type",
                        "url": "DNS Records"
                    }
                ]
            },
            {
                "id": "emails_bucket",
                "label": "Emails",
                "type": "bucket",
                "metadata": [
                    {
                        "title": "Type",
                        "url": "Emails"
                    }
                ]
            },
            {
                "id": "malicious_names_bucket",
                "label": "Malicious Names",
                "type": "bucket",
                "metadata": [
                    {
                        "title": "Type",
                        "url": "Malicious Names"
                    }
                ]
            },
            {
                "id": "ssl_certificates_bucket",
                "label": "SSL Certificates",
                "type": "bucket",
                "metadata": [
                    {
                        "title": "Type",
                        "url": "SSL Certificates"
                    }
                ]
            },
            {
                "id": "social_media_bucket",
                "label": "Social Media",
                "type": "bucket",
                "metadata": [
                    {
                        "title": "Type",
                        "url": "Social Media"
                    }
                ]
            }
        ],
        "edges": [
            {
                "id": "edge_sclowy_root_blacklisted_names_bucket",
                "sourceId": "sclowy_root",
                "targetId": "blacklisted_names_bucket"
            },
            {
                "id": "edge_sclowy_root_dns_records_bucket",
                "sourceId": "sclowy_root",
                "targetId": "dns_records_bucket"
            },
            {
                "id": "edge_sclowy_root_emails_bucket",
                "sourceId": "sclowy_root",
                "targetId": "emails_bucket"
            },
            {
                "id": "edge_sclowy_root_malicious_names_bucket",
                "sourceId": "sclowy_root",
                "targetId": "malicious_names_bucket"
            },
            {
                "id": "edge_sclowy_root_ssl_certificates_bucket",
                "sourceId": "sclowy_root",
                "targetId": "ssl_certificates_bucket"
            },
            {
                "id": "edge_sclowy_root_social_media_bucket",
                "sourceId": "sclowy_root",
                "targetId": "social_media_bucket"
            }
        ]
    }
    dummy_data = {
    "graphId": graphId,
    "entities": [
        {
            "id": "sclowy_root",
            "label": "sclowy.com",
            "type": "root",
            "metadata": [
                {
                    "title": "Domain",
                    "url": "https://sclowy.com"
                }
            ]
        },
        {
            "id": "blacklisted_names_bucket",
            "label": "Blacklisted Names",
            "type": "bucket",
            "metadata": [
                {
                    "title": "Type",
                    "url": "Blacklisted Names"
                }
            ],
            "childCount": 3,
        },
        {
            "id": "dns_records_bucket",
            "label": "DNS Records",
            "type": "bucket",
            "metadata": [
                {
                    "title": "Type",
                    "url": "DNS Records"
                }
            ]
        },
        {
            "id": "emails_bucket",
            "label": "Emails",
            "type": "bucket",
            "metadata": [
                {
                    "title": "Type",
                    "url": "Emails"
                }
            ]
        },
        {
            "id": "malicious_names_bucket",
            "label": "Malicious Names",
            "type": "bucket",
            "metadata": [
                {
                    "title": "Type",
                    "url": "Malicious Names"
                }
            ]
        },
        {
            "id": "ssl_certificates_bucket",
            "label": "SSL Certificates",
            "type": "bucket",
            "metadata": [
                {
                    "title": "Type",
                    "url": "SSL Certificates"
                }
            ]
        },
        {
            "id": "social_media_bucket",
            "label": "Social Media",
            "type": "bucket",
            "metadata": [
                {
                    "title": "Type",
                    "url": "Social Media"
                }
            ],
            "childCount": 3
        },
        {
            "id": "linkedin_node",
            "label": "LinkedIn",
            "type": "platform",
            "metadata": [
                {
                    "title": "Type",
                    "url": "Social Media Platform"
                }
            ],
            "childCount": 2
        },
        {
            "id": "linkedin_user_profiles",
            "label": "User Profiles",
            "type": "subcategory",
            "metadata": [
                {
                    "title": "Category",
                    "url": "Profiles"
                }
            ]
        },
        {
            "id": "linkedin_company_profiles",
            "label": "Company Profiles",
            "type": "subcategory",
            "metadata": [
                {
                    "title": "Category",
                    "url": "Companies"
                }
            ]
        },
        {
            "id": "instagram_node",
            "label": "Instagram",
            "type": "platform",
            "metadata": [
                {
                    "title": "Type",
                    "url": "Social Media Platform"
                }
            ],
            "childCount": 1
        },
        {
            "id": "instagram_posts",
            "label": "Posts",
            "type": "subcategory",
            "metadata": [
                {
                    "title": "Category",
                    "url": "Posts"
                }
            ]
        },
        {
            "id": "twitter_node",
            "label": "Twitter",
            "type": "platform",
            "metadata": [
                {
                    "title": "Type",
                    "url": "Social Media Platform"
                }
            ],
            "childCount": 1
        },
        {
            "id": "twitter_tweets",
            "label": "Tweets",
            "type": "subcategory",
            "metadata": [
                {
                    "title": "Category",
                    "url": "Tweets"
                }
            ]
        }
    ],
    "edges": [
        {
            "id": "edge_sclowy_root_blacklisted_names_bucket",
            "sourceId": "sclowy_root",
            "targetId": "blacklisted_names_bucket"
        },
        {
            "id": "edge_sclowy_root_dns_records_bucket",
            "sourceId": "sclowy_root",
            "targetId": "dns_records_bucket"
        },
        {
            "id": "edge_sclowy_root_emails_bucket",
            "sourceId": "sclowy_root",
            "targetId": "emails_bucket"
        },
        {
            "id": "edge_sclowy_root_malicious_names_bucket",
            "sourceId": "sclowy_root",
            "targetId": "malicious_names_bucket"
        },
        {
            "id": "edge_sclowy_root_ssl_certificates_bucket",
            "sourceId": "sclowy_root",
            "targetId": "ssl_certificates_bucket"
        },
        {
            "id": "edge_sclowy_root_social_media_bucket",
            "sourceId": "sclowy_root",
            "targetId": "social_media_bucket"
        },
        {
            "id": "edge_social_media_linkedin",
            "sourceId": "social_media_bucket",
            "targetId": "linkedin_node"
        },
        {
            "id": "edge_social_media_instagram",
            "sourceId": "social_media_bucket",
            "targetId": "instagram_node"
        },
        {
            "id": "edge_social_media_twitter",
            "sourceId": "social_media_bucket",
            "targetId": "twitter_node"
        },
        {
            "id": "edge_linkedin_profiles",
            "sourceId": "linkedin_node",
            "targetId": "linkedin_user_profiles"
        },
        {
            "id": "edge_linkedin_companies",
            "sourceId": "linkedin_node",
            "targetId": "linkedin_company_profiles"
        },
        {
            "id": "edge_instagram_posts",
            "sourceId": "instagram_node",
            "targetId": "instagram_posts"
        },
        {
            "id": "edge_twitter_tweets",
            "sourceId": "twitter_node",
            "targetId": "twitter_tweets"
        }
    ]
}

    # Existing graph JSON
    graph_data = {
        "graphId": "exampleGraph",
        "entities": [
            {
                "id": "sclowy_root",
                "label": "sclowy.com",
                "type": "domain",
                "metadata": [
                    {
                        "title": "Domain",
                        "url": "https://sclowy.com"
                    }
                ]
            }
        ],
        "edges": []
    }

    # New node to add
    new_node = {
        "id": "new_node",
        "label": "New Node",
        "type": "bucket",
        "metadata": [
            {
                "title": "Type",
                "url": "New Node Type"
            }
        ]
    }

    # Add the new node under the parent with ID "sclowy_root"
    parent_id = "sclowy_root"
    updated_graph = add_node_to_parent(graph_data, new_node, parent_id)

    print(updated_graph)

    insert_graph_data(db, dummy_data, graphId)
    
def insert_graph_data(session: Session, graph_data: dict, graph_id: str):


    for entity in graph_data['entities']:
        entity_record = Entity(
            id=entity['id'],
            label=entity['label'],
            type=entity['type'],
            graph_id = graph_id,
            metadata=entity.get('metadata'),
            child_count=entity.get('childCount')
        )
        session.add(entity_record)

    # Insert edges
    for edge in graph_data['edges']:
        edge_record = Edge(
            id=edge['id'],
            graph_id = graph_id,
            source_id=edge['sourceId'],
            target_id=edge['targetId']
        )
        session.add(edge_record)

    session.commit()

def add_node_to_parent(graph_data, new_node, parent_id):
    """
    Adds a new node to the graph and connects it to a specified parent.

    Args:
        graph_data (dict): The existing graph JSON.
        new_node (dict): The new node to add (in the same format as entities in the graph).
        parent_id (str): The ID of the parent node to connect the new node to.

    Returns:
        dict: The updated graph JSON.
    """
    # Validate parent ID exists
    parent_exists = any(entity['id'] == parent_id for entity in graph_data['entities'])
    if not parent_exists:
        raise ValueError(f"Parent node with ID '{parent_id}' does not exist.")

    # Add the new node
    graph_data['entities'].append(new_node)

    # Create an edge from the parent to the new node
    new_edge = {
        "id": f"edge_{parent_id}_{new_node['id']}",
        "sourceId": parent_id,
        "targetId": new_node['id']
    }
    graph_data['edges'].append(new_edge)

    return graph_data

def generate_graph_json(session: Session, graph_id, source_id, action):
    """
    Reads entities and edges from the database and generates a graph JSON.
    Optionally filters edges by source_id and entities by target nodes.

    Args:
        session (Session): SQLAlchemy session.
        graph_id (str): The graph ID to filter by.
        source_id (str, optional): The source ID to filter edges by.

    Returns:
        dict: The graph JSON.
    """
    dummy_response = {
        "graphId": graph_id,
        "entities": [
            {
                "id": "sclowy_root",
                "label": "sclowy.com",
                "type": "root",
                "metadata": [
                    {
                        "title": "Domain",
                        "url": "https://sclowy.com"
                    }
                ]
            },
            {
                "id": "blacklisted_names_bucket",
                "label": "Blacklisted Names",
                "type": "bucket",
                "metadata": [
                    {
                        "title": "Type",
                        "url": "Blacklisted Names"
                    }
                ],
                "childCount": 0,
            },
            {
                "id": "dns_records_bucket",
                "label": "DNS Records",
                "type": "bucket",
                "metadata": [
                    {
                        "title": "Type",
                        "url": "DNS Records"
                    }
                ]
            },
            {
                "id": "emails_bucket",
                "label": "Emails",
                "type": "bucket",
                "metadata": [
                    {
                        "title": "Type",
                        "url": "Emails"
                    }
                ]
            },
            {
                "id": "malicious_names_bucket",
                "label": "Malicious Names",
                "type": "bucket",
                "metadata": [
                    {
                        "title": "Type",
                        "url": "Malicious Names"
                    }
                ]
            },
            {
                "id": "ssl_certificates_bucket",
                "label": "SSL Certificates",
                "type": "bucket",
                "metadata": [
                    {
                        "title": "Type",
                        "url": "SSL Certificates"
                    }
                ]
            },
            {
                "id": "social_media_bucket",
                "label": "Social Media",
                "type": "bucket",
                "metadata": [
                    {
                        "title": "Type",
                        "url": "Social Media"
                    }
                ],
                "childCount": 4,
            }
        ],
        "edges": [
            {
                "id": "edge_sclowy_root_blacklisted_names_bucket",
                "sourceId": "sclowy_root",
                "targetId": "blacklisted_names_bucket"
            },
            {
                "id": "edge_sclowy_root_dns_records_bucket",
                "sourceId": "sclowy_root",
                "targetId": "dns_records_bucket"
            },
            {
                "id": "edge_sclowy_root_emails_bucket",
                "sourceId": "sclowy_root",
                "targetId": "emails_bucket"
            },
            {
                "id": "edge_sclowy_root_malicious_names_bucket",
                "sourceId": "sclowy_root",
                "targetId": "malicious_names_bucket"
            },
            {
                "id": "edge_sclowy_root_ssl_certificates_bucket",
                "sourceId": "sclowy_root",
                "targetId": "ssl_certificates_bucket"
            },
            {
                "id": "edge_sclowy_root_social_media_bucket",
                "sourceId": "sclowy_root",
                "targetId": "social_media_bucket"
            }
        ]
    }
    dummy_data = {
    "graphId": graph_id,
    "entities": [
        {
            "id": "social_media_root",
            "label": "Social Media",
            "type": "root",
            "metadata": [
                {
                    "title": "Type",
                    "url": "Social Media"
                }
            ]
        },
        {
            "id": "linkedin_bucket",
            "label": "LinkedIn",
            "type": "bucket",
            "metadata": [
                {
                    "title": "Type",
                    "url": "LinkedIn Profiles"
                }
            ],
            "childCount": 5
        },
        {
            "id": "instagram_bucket",
            "label": "Instagram",
            "type": "bucket",
            "metadata": [
                {
                    "title": "Type",
                    "url": "Instagram Profiles"
                }
            ],
            "childCount": 8
        },
        {
            "id": "facebook_bucket",
            "label": "Facebook",
            "type": "bucket",
            "metadata": [
                {
                    "title": "Type",
                    "url": "Facebook Profiles"
                }
            ],
            "childCount": 3
        },
        {
            "id": "twitter_bucket",
            "label": "Twitter",
            "type": "bucket",
            "metadata": [
                {
                    "title": "Type",
                    "url": "Twitter Profiles"
                }
            ],
            "childCount": 6
        }
    ],
    "edges": [
        {
            "id": "edge_social_media_linkedin_bucket",
            "sourceId": "social_media_root",
            "targetId": "linkedin_bucket"
        },
        {
            "id": "edge_social_media_instagram_bucket",
            "sourceId": "social_media_root",
            "targetId": "instagram_bucket"
        },
        {
            "id": "edge_social_media_facebook_bucket",
            "sourceId": "social_media_root",
            "targetId": "facebook_bucket"
        },
        {
            "id": "edge_social_media_twitter_bucket",
            "sourceId": "social_media_root",
            "targetId": "twitter_bucket"
        }
    ]
}

    # Query edges from the database, optionally filtering by source_id
    if action == 'root':
        return dummy_response
    elif action == 'expand':
        return dummy_data
        if source_id:
            edges = session.query(Edge).filter(Edge.graph_id == graph_id, Edge.source_id == source_id).all()
        else:
            edges = session.query(Edge).filter(Edge.graph_id == graph_id).all()

    elif action == 'collapse':
        return dummy_response
        pass


    # Extract target node IDs from the filtered edges
    target_node_ids = {edge.target_id for edge in edges}

    # Query entities from the database, filtering by target node IDs
    entities = session.query(Entity).filter(Entity.graph_id == graph_id, Entity.id.in_(target_node_ids)).all()

    # Construct the graph JSON
    graph_json = {
        "graphId": graph_id,
        "entities": [
            {
                "id": entity.id,
                "graph_id": entity.graph_id,
                "label": entity.label,
                "type": entity.type,
                "metadata": entity.scan_metadata,
                "childCount": entity.child_count
            }
            for entity in entities
        ],
        "edges": [
            {
                "id": edge.id,
                "graph_id": edge.graph_id,
                "sourceId": edge.source_id,
                "targetId": edge.target_id
            }
            for edge in edges
        ]
    }

    return graph_json












def start_ind_osint_service(identifier: str, searchQuery: str):
     return []

def scrape_linkedin_profiles(url):
	headers = {
		"User-Agent": "Guest", # Access as Guest
	}

	response = requests.get(url, headers=headers)

	if response.status_code == 200: # if request granted
		soup = BeautifulSoup(response.content, 'html.parser')

		# Extract profile information
		title_tag = soup.find('title')
		designation_tag = soup.find('h2')
		followers_tag = soup.find('meta', {"property": "og:description"})
		description_tag = soup.find('p', class_='break-words')

		# Check if the tags are found before calling get_text()
		name = title_tag.get_text(strip=True).split("|")[0].strip() if title_tag else "Profile Name not found"
		designation = designation_tag.get_text(strip=True) if designation_tag else "Designation not found"

		# Use regular expression to extract followers and description count
		followers_match = re.search(r'\b(\d[\d,.]*)\s+followers\b', followers_tag["content"]) if followers_tag else None
		followers_count = followers_match.group(1) if followers_match else "Followers count not found"

		description = description_tag.get_text(strip=True) if description_tag else "Description not found"

		print(f"Profile Name: {name}")
		print(f"Designation: {designation}")
		print(f"Followers Count: {followers_count}")
		print(f"Description: {description}")
	else:
		print(f"Error: Unable to retrieve the LinkedIn company profile. Status code: {response.status_code}")

def create_user(db: Session, email: str, password_hash: str, name: str = None):
    new_user = User(email=email, password_hash=password_hash, name=name)
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return new_user

def get_user(db: Session, user_id: int):
    return db.query(User).filter(User.user_id == user_id).first()

def update_user(db: Session, user_id: int, email: str = None, name: str = None):
    user = get_user(db, user_id)
    if user:
        if email:
            user.email = email
        if name:
            user.name = name
        db.commit()
        db.refresh(user)
    return user

def delete_user(db: Session, user_id: int):
    user = get_user(db, user_id)
    if user:
        db.delete(user)
        db.commit()
    return user

def create_session(db: Session, user_id: int, device_info: str = None, ip_address: str = None):
    new_session = SessionModel(user_id=user_id, device_info=device_info, ip_address=ip_address)
    db.add(new_session)
    db.commit()
    db.refresh(new_session)
    return new_session

def get_session(db: Session, session_id: int):
    return db.query(SessionModel).filter(SessionModel.session_id == session_id).first()

def delete_session(db: Session, session_id: int):
    session = get_session(db, session_id)
    if session:
        db.delete(session)
        db.commit()
    return session

def create_scan_metadata(db: Session, session_id: int, scan_name: str, scan_type: str = None, scan_result: dict = None):
    new_scan = ScanMetadata(session_id=session_id, scan_name=scan_name, scan_type=scan_type, scan_result=scan_result)
    db.add(new_scan)
    db.commit()
    db.refresh(new_scan)
    return new_scan

def get_scan_metadata(db: Session, scan_id: int):
    return db.query(ScanMetadata).filter(ScanMetadata.scan_id == scan_id).first()

def delete_scan_metadata(db: Session, scan_id: int):
    scan = get_scan_metadata(db, scan_id)
    if scan:
        db.delete(scan)
        db.commit()
    return scan