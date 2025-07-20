# app/models/user.py

from sqlalchemy import Column, Integer, String, Float, Boolean, DateTime, Enum as SqlEnum
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.sql import func
import enum
from app.schemas.user import UserRole

Base = declarative_base()

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    full_name = Column(String(100), index=True, nullable=False)
    email = Column(String(100), unique=True, index=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    role = Column(
        SqlEnum(UserRole, values_callable=lambda x: [e.value for e in x], native_enum=False),
        default=UserRole.USER.value,
        nullable=False
    )
    wallet_balance = Column(Float, default=0.0, nullable=False)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

    def __repr__(self):
        return f"<User(id={self.id}, email='{self.email}', role='{self.role.value}', balance=${self.wallet_balance})>"