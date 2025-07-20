# app/db/session.py

from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
import os

# Database URL - you can change this to your preferred database
# For development, using SQLite
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./digital_wallet.db")

print(f"🔗 Using database: {DATABASE_URL}")

# Create SQLAlchemy engine
try:
    if DATABASE_URL.startswith("sqlite"):
        # SQLite specific configuration
        engine = create_engine(
            DATABASE_URL, 
            connect_args={"check_same_thread": False},
            echo=False,  # Changed to False to reduce noise
            pool_timeout=20,
            pool_recycle=-1
        )
    else:
        # For other databases like PostgreSQL, MySQL
        engine = create_engine(
            DATABASE_URL, 
            echo=False,
            pool_timeout=20,
            pool_recycle=3600
        )
    
    print("✅ Database engine created successfully")
    
except Exception as e:
    print(f"❌ Failed to create database engine: {e}")
    raise

# Create SessionLocal class
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Create Base class for models
Base = declarative_base()

# Dependency to get database session
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Test database connection
def test_db_connection():
    try:
        # Test the connection
        with engine.connect() as connection:
            print("✅ Database connection test successful")
            return True
    except Exception as e:
        print(f"❌ Database connection test failed: {e}")
        return False