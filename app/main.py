# app/main.py
# IMPORTANT: This file should now be located inside the 'app' folder.
# The command to run the server from your project's root directory is:
# uvicorn app.main:app --reload

from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session
from typing import List, Optional
from datetime import datetime, timedelta
import jwt
from passlib.context import CryptContext
from app.models.user import Base, User

# Use relative imports because main.py is now inside the 'app' package.
from .db.session import engine, get_db
from .models import user as user_model
from .schemas import user as user_schema, auth as auth_schema
from .schemas.user import UserRole

# JWT Configuration
SECRET_KEY = "your-secret-key-change-this-in-production"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
security = HTTPBearer()

# Password utility functions
def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    try:
        payload = jwt.decode(credentials.credentials, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: int = payload.get("sub")
        if user_id is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid authentication credentials",
                headers={"WWW-Authenticate": "Bearer"},
            )
        return user_id
    except jwt.PyJWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

def get_current_user(user_id: int = Depends(verify_token), db: Session = Depends(get_db)):
    user = db.query(user_model.User).filter(user_model.User.id == user_id).first()
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found"
        )
    return user

# Create the database tables.
user_model.Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="Digital Wallet API",
    description="A digital wallet system with merchant and user roles",
    version="1.0.0"
)

# --- AUTHENTICATION ENDPOINTS ---
@app.post("/auth/register", response_model=auth_schema.GenericResponse, tags=["Authentication"])
def register_user(user: user_schema.UserCreate, db: Session = Depends(get_db)):
    """
    Register a new user in the digital wallet system.
    """
    try:
        # Check if user already exists
        db_user = db.query(user_model.User).filter(user_model.User.email == user.email).first()
        if db_user:
            return auth_schema.GenericResponse(
                success=False,
                message="Email already registered",
                data=None
            )

        # Create new user
        hashed_password = get_password_hash(user.password)
        new_user = user_model.User(
            full_name=user.full_name,
            email=user.email,
            hashed_password=hashed_password,
            role=user.role,
            wallet_balance=0.0  # Initialize with zero balance
        )
        db.add(new_user)
        db.commit()
        db.refresh(new_user)

        # Create access token
        access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = create_access_token(
            data={"sub": str(new_user.id)}, expires_delta=access_token_expires
        )

        return auth_schema.GenericResponse(
            success=True,
            message="User registered successfully",
            data={
                "user": {
                    "id": new_user.id,
                    "full_name": new_user.full_name,
                    "email": new_user.email,
                    "role": new_user.role,
                    "wallet_balance": new_user.wallet_balance
                },
                "access_token": access_token,
                "token_type": "bearer"
            }
        )
    except Exception as e:
        return auth_schema.GenericResponse(
            success=False,
            message=f"Registration failed: {str(e)}",
            data=None
        )

@app.post("/auth/login", response_model=auth_schema.GenericResponse, tags=["Authentication"])
def login_user(login_data: auth_schema.UserLogin, db: Session = Depends(get_db)):
    """
    Login user and return JWT token.
    """
    try:
        # Find user by email
        user = db.query(user_model.User).filter(user_model.User.email == login_data.email).first()
        if not user or not verify_password(login_data.password, user.hashed_password):
            return auth_schema.GenericResponse(
                success=False,
                message="Incorrect email or password",
                data=None
            )

        # Create access token
        access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = create_access_token(
            data={"sub": str(user.id)}, expires_delta=access_token_expires
        )

        return auth_schema.GenericResponse(
            success=True,
            message="Login successful",
            data={
                "user": {
                    "id": user.id,
                    "full_name": user.full_name,
                    "email": user.email,
                    "role": user.role,
                    "wallet_balance": user.wallet_balance
                },
                "access_token": access_token,
                "token_type": "bearer"
            }
        )
    except Exception as e:
        return auth_schema.GenericResponse(
            success=False,
            message=f"Login failed: {str(e)}",
            data=None
        )

# --- USER CRUD ENDPOINTS ---
@app.get("/users/profile", response_model=auth_schema.GenericResponse, tags=["Users"])
def get_user_profile(current_user: user_model.User = Depends(get_current_user)):
    """
    Get current user's profile.
    """
    return auth_schema.GenericResponse(
        success=True,
        message="Profile retrieved successfully",
        data={
            "id": current_user.id,
            "full_name": current_user.full_name,
            "email": current_user.email,
            "role": current_user.role,
            "wallet_balance": current_user.wallet_balance,
            "is_active": current_user.is_active,
            "created_at": current_user.created_at.isoformat() if current_user.created_at else None
        }
    )

@app.get("/users/", response_model=auth_schema.GenericResponse, tags=["Users"])
def get_all_users(skip: int = 0, limit: int = 100, current_user: user_model.User = Depends(get_current_user), db: Session = Depends(get_db)):
    """
    Get all users (Admin/Merchant access).
    """
    # Only merchants can view all users
    if current_user.role not in ["merchant", "admin"]:
        return auth_schema.GenericResponse(
            success=False,
            message="Access denied. Only merchants and admins can view all users.",
            data=None
        )

    try:
        users = db.query(user_model.User).offset(skip).limit(limit).all()
        users_data = []
        for user in users:
            users_data.append({
                "id": user.id,
                "full_name": user.full_name,
                "email": user.email,
                "role": user.role,
                "wallet_balance": user.wallet_balance,
                "is_active": user.is_active,
                "created_at": user.created_at.isoformat() if user.created_at else None
            })

        return auth_schema.GenericResponse(
            success=True,
            message="Users retrieved successfully",
            data={
                "users": users_data,
                "total": len(users_data),
                "skip": skip,
                "limit": limit
            }
        )
    except Exception as e:
        return auth_schema.GenericResponse(
            success=False,
            message=f"Failed to retrieve users: {str(e)}",
            data=None
        )

@app.get("/users/{user_id}", response_model=auth_schema.GenericResponse, tags=["Users"])
def get_user_by_id(user_id: int, current_user: user_model.User = Depends(get_current_user), db: Session = Depends(get_db)):
    """
    Get user by ID (Own profile or merchant access).
    """
    try:
        # Users can only view their own profile unless they're merchants
        if current_user.role not in ["merchant", "admin"] and current_user.id != user_id:
            return auth_schema.GenericResponse(
                success=False,
                message="Access denied. You can only view your own profile.",
                data=None
            )

        user = db.query(user_model.User).filter(user_model.User.id == user_id).first()
        if not user:
            return auth_schema.GenericResponse(
                success=False,
                message="User not found",
                data=None
            )

        return auth_schema.GenericResponse(
            success=True,
            message="User retrieved successfully",
            data={
                "id": user.id,
                "full_name": user.full_name,
                "email": user.email,
                "role": user.role,
                "wallet_balance": user.wallet_balance,
                "is_active": user.is_active,
                "created_at": user.created_at.isoformat() if user.created_at else None
            }
        )
    except Exception as e:
        return auth_schema.GenericResponse(
            success=False,
            message=f"Failed to retrieve user: {str(e)}",
            data=None
        )

@app.put("/users/{user_id}", response_model=auth_schema.GenericResponse, tags=["Users"])
def update_user(user_id: int, user_update: user_schema.UserUpdate, current_user: user_model.User = Depends(get_current_user), db: Session = Depends(get_db)):
    """
    Update user information.
    """
    try:
        # Users can only update their own profile unless they're merchants
        if current_user.role not in ["merchant", "admin"] and current_user.id != user_id:
            return auth_schema.GenericResponse(
                success=False,
                message="Access denied. You can only update your own profile.",
                data=None
            )

        user = db.query(user_model.User).filter(user_model.User.id == user_id).first()
        if not user:
            return auth_schema.GenericResponse(
                success=False,
                message="User not found",
                data=None
            )

        # Get the update data, excluding unset fields
        update_data = user_update.model_dump(exclude_unset=True)

        # Hash password if provided
        if "password" in update_data:
            update_data["hashed_password"] = get_password_hash(update_data.pop("password"))

        # Update user fields
        for key, value in update_data.items():
            setattr(user, key, value)

        db.add(user)
        db.commit()
        db.refresh(user)

        return auth_schema.GenericResponse(
            success=True,
            message="User updated successfully",
            data={
                "id": user.id,
                "full_name": user.full_name,
                "email": user.email,
                "role": user.role,
                "wallet_balance": user.wallet_balance,
                "is_active": user.is_active
            }
        )
    except Exception as e:
        return auth_schema.GenericResponse(
            success=False,
            message=f"Failed to update user: {str(e)}",
            data=None
        )

@app.delete("/users/{user_id}", response_model=auth_schema.GenericResponse, tags=["Users"])
def delete_user(user_id: int, current_user: user_model.User = Depends(get_current_user), db: Session = Depends(get_db)):
    """
    Delete user (Admin/Merchant access only).
    """
    try:
        # Only merchants and admins can delete users
        if current_user.role not in ["merchant", "admin"]:
            return auth_schema.GenericResponse(
                success=False,
                message="Access denied. Only merchants and admins can delete users.",
                data=None
            )

        user = db.query(user_model.User).filter(user_model.User.id == user_id).first()
        if not user:
            return auth_schema.GenericResponse(
                success=False,
                message="User not found",
                data=None
            )

        # Don't allow deleting yourself
        if user.id == current_user.id:
            return auth_schema.GenericResponse(
                success=False,
                message="You cannot delete your own account.",
                data=None
            )

        deleted_user_data = {
            "id": user.id,
            "full_name": user.full_name,
            "email": user.email,
            "role": user.role
        }

        db.delete(user)
        db.commit()

        return auth_schema.GenericResponse(
            success=True,
            message="User deleted successfully",
            data=deleted_user_data
        )
    except Exception as e:
        return auth_schema.GenericResponse(
            success=False,
            message=f"Failed to delete user: {str(e)}",
            data=None
        )

# --- WALLET ENDPOINTS ---
@app.post("/wallet/add-funds", response_model=auth_schema.GenericResponse, tags=["Wallet"])
def add_funds(amount: float, current_user: user_model.User = Depends(get_current_user), db: Session = Depends(get_db)):
    """
    Add funds to user's wallet.
    """
    try:
        if amount <= 0:
            return auth_schema.GenericResponse(
                success=False,
                message="Amount must be greater than zero",
                data=None
            )

        current_user.wallet_balance += amount
        db.add(current_user)
        db.commit()
        db.refresh(current_user)

        return auth_schema.GenericResponse(
            success=True,
            message=f"Successfully added ${amount} to wallet",
            data={
                "new_balance": current_user.wallet_balance,
                "amount_added": amount
            }
        )
    except Exception as e:
        return auth_schema.GenericResponse(
            success=False,
            message=f"Failed to add funds: {str(e)}",
            data=None
        )

@app.get("/wallet/balance", response_model=auth_schema.GenericResponse, tags=["Wallet"])
def get_wallet_balance(current_user: user_model.User = Depends(get_current_user)):
    """
    Get current wallet balance.
    """
    return auth_schema.GenericResponse(
        success=True,
        message="Wallet balance retrieved successfully",
        data={
            "balance": current_user.wallet_balance,
            "user_id": current_user.id,
            "user_name": current_user.full_name
        }
    )

@app.get("/", response_model=auth_schema.GenericResponse, tags=["Root"])
def read_root():
    """
    Root endpoint with API information.
    """
    return auth_schema.GenericResponse(
        success=True,
        message="Welcome to the Digital Wallet API",
        data={
            "api_name": "Digital Wallet API",
            "version": "1.0.0",
            "documentation": "/docs",
            "features": [
                "User Registration & Authentication",
                "JWT Token-based Security",
                "Role-based Access Control (User/Merchant)",
                "Wallet Management",
                "User CRUD Operations"
            ]
        }
    )