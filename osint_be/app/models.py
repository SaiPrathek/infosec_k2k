# app/models.py
from sqlalchemy import Column, String, Integer, ForeignKey, TIMESTAMP, JSON, func
from sqlalchemy.orm import declarative_base, relationship, Session, sessionmaker
from database import Base


class User(Base):
    __tablename__ = "users"

    user_id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    email = Column(String, unique=True, index=True, nullable=False)
    password_hash = Column(String, nullable=False)
    name = Column(String, nullable=True)
    created_at = Column(TIMESTAMP, server_default=func.now())

    sessions = relationship("SessionModel", back_populates="user")

class SessionModel(Base):
    __tablename__ = "sessions"

    session_id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey("users.user_id"), nullable=False)
    device_info = Column(String, nullable=True)
    ip_address = Column(String, nullable=True)
    started_at = Column(TIMESTAMP, server_default=func.now())

    user = relationship("User", back_populates="sessions")
    scans = relationship("ScanMetadata", back_populates="session")

class ScanMetadata(Base):
    __tablename__ = "scan_metadata"

    scan_id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    session_id = Column(Integer, ForeignKey("sessions.session_id"), nullable=False)
    scan_name = Column(String, nullable=False)
    scan_type = Column(String, nullable=True)
    scan_result = Column(JSON, nullable=True)
    created_at = Column(TIMESTAMP, server_default=func.now())

    session = relationship("SessionModel", back_populates="scans")

# New Entity model
class Entity(Base):
    __tablename__ = "entities"

    id = Column(String, primary_key=True, index=True)
    graph_id = Column(String, nullable=False)
    label = Column(String, nullable=False)
    type = Column(String, nullable=False)
    scan_metadata = Column(JSON, nullable=True)
    child_count = Column(Integer, nullable=True)

    # Relationships
    outgoing_edges = relationship("Edge", back_populates="source", foreign_keys="Edge.source_id")
    incoming_edges = relationship("Edge", back_populates="target", foreign_keys="Edge.target_id")


# New Edge model
class Edge(Base):
    __tablename__ = "edges"

    id = Column(String, primary_key=True, index=True)
    graph_id = Column(String, nullable=False)

    source_id = Column(String, ForeignKey("entities.id"), nullable=False)
    target_id = Column(String, ForeignKey("entities.id"), nullable=False)

    # Relationships
    source = relationship("Entity", back_populates="outgoing_edges", foreign_keys=[source_id])
    target = relationship("Entity", back_populates="incoming_edges", foreign_keys=[target_id])