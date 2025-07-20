# app/schemas/user.py

from pydantic import BaseModel, EmailStr, Field
from typing import Optional
from datetime import datetime
from enum import Enum

class UserRole(str, Enum):
    USER = "user"
    MERCHANT = "merchant"
    ADMIN = "admin"

class UserBase(BaseModel):
    full_name: str = Field(..., min_length=2, max_length=100, description="User's full name")
    email: EmailStr = Field(..., description="User's email address")
    role: UserRole = Field(default=UserRole.USER, description="User role in the system")

class UserCreate(UserBase):
    password: str = Field(..., min_length=8, max_length=100, description="User's password (min 8 characters)")

class UserUpdate(BaseModel):
    full_name: Optional[str] = Field(None, min_length=2, max_length=100, description="User's full name")
    email: Optional[EmailStr] = Field(None, description="User's email address")
    password: Optional[str] = Field(None, min_length=8, max_length=100, description="User's new password")
    role: Optional[UserRole] = Field(None, description="User role in the system")
    wallet_balance: Optional[float] = Field(None, ge=0, description="Wallet balance (non-negative)")
    is_active: Optional[bool] = Field(None, description="User active status")

class User(UserBase):
    id: int
    wallet_balance: float = Field(default=0.0, ge=0, description="Current wallet balance")
    is_active: bool = Field(default=True, description="User active status")
    created_at: Optional[datetime] = Field(None, description="Account creation timestamp")
    updated_at: Optional[datetime] = Field(None, description="Last update timestamp")

    class Config:
        from_attributes = True

class UserResponse(BaseModel):
    id: int
    full_name: str
    email: str
    role: UserRole
    wallet_balance: float
    is_active: bool
    created_at: Optional[str] = None

    class Config:
        from_attributes = True