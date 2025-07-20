# app/schemas/auth.py

from pydantic import BaseModel, EmailStr, Field
from typing import Optional, Any, Dict, Union

class UserLogin(BaseModel):
    email: EmailStr = Field(..., description="User's email address")
    password: str = Field(..., min_length=1, description="User's password")

class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"

class TokenData(BaseModel):
    user_id: Optional[int] = None

class GenericResponse(BaseModel):
    """
    Generic response structure for all API endpoints
    """
    success: bool = Field(..., description="Indicates if the operation was successful")
    message: str = Field(..., description="Human-readable message about the operation")
    data: Optional[Union[Dict[str, Any], list, str, int, float]] = Field(
        None, 
        description="Response data, can be any type or None"
    )
    
    class Config:
        json_encoders = {
            # Handle datetime serialization if needed
            # datetime: lambda v: v.isoformat() if v else None
        }

class WalletRequest(BaseModel):
    amount: float = Field(..., gt=0, description="Amount to add to wallet (must be positive)")

class TransferRequest(BaseModel):
    recipient_email: EmailStr = Field(..., description="Email of the recipient")
    amount: float = Field(..., gt=0, description="Amount to transfer (must be positive)")
    description: Optional[str] = Field(None, max_length=255, description="Optional transfer description")