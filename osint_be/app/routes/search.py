# app/routes/items.py
from fastapi import APIRouter, Depends, HTTPException, Body, BackgroundTasks, Query
from sqlalchemy.orm import Session
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from osint_service import *
from database import *

router = APIRouter()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Define a Pydantic model for the payload
class OSINTPayload(BaseModel):
    goal: str
    graphId: str
    identifier: str
    searchQuery: str

# Define a Pydantic model for the payload
class GraphPayload(BaseModel):
    graphId: str
    action: str
    entityId: str


@router.post("/startSearch")
async def start_osint(background_tasks: BackgroundTasks, payload: OSINTPayload = Body(...), db: Session = Depends(get_db)):
    
    background_tasks.add_task(start_org_osint_service, db, payload.goal, payload.identifier, payload.searchQuery, payload.graphId)

    return JSONResponse(content={"message": "OSINT search started successfully", "graphId": payload.graphId})

@router.post("/fetchGraph")
async def fetch_graph(payload: GraphPayload = Body(...), db: Session = Depends(get_db)):
    # Simulate fetching the graph with the given graphId
    # dummy_response = {
    #     "graphId": graph_id,
    #     "entities": [
    #         {
    #             "id": "sclowy_root",
    #             "label": "sclowy.com",
    #             "type": "domain",
    #             "metadata": [
    #                 {
    #                     "title": "Domain",
    #                     "url": "https://sclowy.com"
    #                 }
    #             ]
    #         },
    #         {
    #             "id": "blacklisted_names_bucket",
    #             "label": "Blacklisted Names",
    #             "type": "bucket",
    #             "metadata": [
    #                 {
    #                     "title": "Type",
    #                     "url": "Blacklisted Names"
    #                 }
    #             ],
    #             "childCount": 3,
    #         },
    #         {
    #             "id": "dns_records_bucket",
    #             "label": "DNS Records",
    #             "type": "bucket",
    #             "metadata": [
    #                 {
    #                     "title": "Type",
    #                     "url": "DNS Records"
    #                 }
    #             ]
    #         },
    #         {
    #             "id": "emails_bucket",
    #             "label": "Emails",
    #             "type": "bucket",
    #             "metadata": [
    #                 {
    #                     "title": "Type",
    #                     "url": "Emails"
    #                 }
    #             ]
    #         },
    #         {
    #             "id": "malicious_names_bucket",
    #             "label": "Malicious Names",
    #             "type": "bucket",
    #             "metadata": [
    #                 {
    #                     "title": "Type",
    #                     "url": "Malicious Names"
    #                 }
    #             ]
    #         },
    #         {
    #             "id": "ssl_certificates_bucket",
    #             "label": "SSL Certificates",
    #             "type": "bucket",
    #             "metadata": [
    #                 {
    #                     "title": "Type",
    #                     "url": "SSL Certificates"
    #                 }
    #             ]
    #         },
    #         {
    #             "id": "social_media_bucket",
    #             "label": "Social Media",
    #             "type": "bucket",
    #             "metadata": [
    #                 {
    #                     "title": "Type",
    #                     "url": "Social Media"
    #                 }
    #             ]
    #         }
    #     ],
    #     "edges": [
    #         {
    #             "id": "edge_sclowy_root_blacklisted_names_bucket",
    #             "sourceId": "sclowy_root",
    #             "targetId": "blacklisted_names_bucket"
    #         },
    #         {
    #             "id": "edge_sclowy_root_dns_records_bucket",
    #             "sourceId": "sclowy_root",
    #             "targetId": "dns_records_bucket"
    #         },
    #         {
    #             "id": "edge_sclowy_root_emails_bucket",
    #             "sourceId": "sclowy_root",
    #             "targetId": "emails_bucket"
    #         },
    #         {
    #             "id": "edge_sclowy_root_malicious_names_bucket",
    #             "sourceId": "sclowy_root",
    #             "targetId": "malicious_names_bucket"
    #         },
    #         {
    #             "id": "edge_sclowy_root_ssl_certificates_bucket",
    #             "sourceId": "sclowy_root",
    #             "targetId": "ssl_certificates_bucket"
    #         },
    #         {
    #             "id": "edge_sclowy_root_social_media_bucket",
    #             "sourceId": "sclowy_root",
    #             "targetId": "social_media_bucket"
    #         }
    #     ]
    # }
    
    graph_id = payload.graphId
    entity_id = payload.entityId
    action = payload.action
    return JSONResponse(content=generate_graph_json(db, graph_id, entity_id, action))


@router.get("/expandEntity")
async def expand_entity( entityId: str = Query(...), db: Session= Depends(get_db)):
    # Simulate expanding the entity with the given entityId
    dummy_response = {
        "entityId": entityId,
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
        "edges": [
            
        ]
    }

    graph_id = '1'

    return JSONResponse(content=generate_graph_json(db, graph_id, entityId))


