from pydantic import BaseModel

# User Schema
class UserCreate(BaseModel):
    email: str
    password_hash: str
    name: str | None = None

# Session Schema
class SessionCreate(BaseModel):
    user_id: int
    device_info: str | None = None
    ip_address: str | None = None

# Scan Schema
class ScanCreate(BaseModel):
    session_id: int
    scan_name: str
    scan_type: str | None = None
    scan_result: dict | None = None
