from pydantic import BaseModel, EmailStr, constr, validator
from datetime import datetime
from sqlalchemy import Column, String, Boolean, DateTime, ForeignKey, Integer, Text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship

Base = declarative_base()


# SQLAlchemy Models
class User(Base):
    __tablename__ = "users"

    username = Column(String(32), primary_key=True)
    email = Column(String(255), unique=True, nullable=False)
    password = Column(String(128), nullable=False)
    full_name = Column(String(64), nullable=False)
    created_at = Column(DateTime, default=datetime.now)
    is_active = Column(Boolean, default=True)

    cookies = relationship("AuthCookie", back_populates="user")


class AuthCookie(Base):
    __tablename__ = "auth_cookies"

    value = Column(String(44), primary_key=True)  # 32 bytes base64 encoded
    user_id = Column(String(32), ForeignKey("users.username"), nullable=False)
    expire_date = Column(DateTime, nullable=False)
    created_at = Column(DateTime, default=datetime.now)

    user = relationship("User", back_populates="cookies")


# Pydantic Models
class LoginInfo(BaseModel):
    username: constr(min_length=3, max_length=32)
    password: constr(min_length=8, max_length=128)


class SignUp(BaseModel):
    username: constr(min_length=3, max_length=32)
    password: constr(min_length=8, max_length=128)
    full_name: constr(min_length=2, max_length=64)
    email: EmailStr

    @validator('password')
    def password_complexity(cls, v):
        if len(v) < 8:
            raise ValueError("Password must be at least 8 characters long")
        if not any(c.isupper() for c in v):
            raise ValueError("Password must contain at least one uppercase letter")
        if not any(c.islower() for c in v):
            raise ValueError("Password must contain at least one lowercase letter")
        if not any(c.isdigit() for c in v):
            raise ValueError("Password must contain at least one digit")
        return v


class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str


class UserProfileResponse(BaseModel):
    username: str
    email: str
    full_name: str
    created_at: datetime
    is_active: bool


class Standard(Base):
    __tablename__ = "standards"

    id = Column(Integer, primary_key=True, index=True)
    code = Column(String(50), nullable=False)
    desc = Column(String(255), nullable=False)
    category = Column(String(50), nullable=False)
    details = Column(Text, nullable=False)
    link = Column(String(255), nullable=False)
    created_at = Column(DateTime, default=datetime.now)
    is_active = Column(Boolean, default=True)
    status = Column(String(20), default='normal')  # افزودن فیلد جدید