# app/models.py
from pydantic import BaseModel
from typing import Optional

# Pydantic model for JWT token response
class Token(BaseModel):
    access_token: str
    token_type: str

# Pydantic model for data contained within a JWT token
class TokenData(BaseModel): # <--- THIS CLASS DEFINITION IS CRUCIAL
    username: Optional[str] = None
    role: Optional[str] = None

# Pydantic model for creating new shipment data
class ShipmentCreateData(BaseModel):
    shipment_id: str
    po_number: str
    route_details: str
    device: str
    ndc_number: str
    serial_number: str
    container_number: str
    goods_type: str
    expected_delivery_date: str # Consider validating as a proper date format if needed
    delivery_number: str
    batch_id: str
    origin: str
    destination: str
    shipment_description: str

