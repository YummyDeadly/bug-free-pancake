from sqlalchemy import Column, String, Boolean
from .database import Base

class User(Base):
    __tablename__ = "users"

    username = Column(String, primary_key=True, index=True)
    email = Column(String, unique=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    is_verified = Column(Boolean, default=False)

class Password(Base):
    __tablename__ = "passwords"

    id = Column(String, primary_key=True, index=True)
    username = Column(String, index=True)
    site = Column(String, nullable=False)
    encrypted_password = Column(String, nullable=False)