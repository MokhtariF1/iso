from pydantic import BaseModel, EmailStr, constr, validator
from datetime import datetime
from sqlalchemy import Column, String, Boolean, DateTime, ForeignKey, Integer, Text, ARRAY
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
    cookies = relationship("AuthCookie", back_populates="user_rel")
    inventory = Column(Integer, default=0)
    charge_wallet_count = Column(Integer, default=0)
    wallet_all_charge = Column(Integer, default=0)
    is_premium = Column(Boolean, default=False)
    newNotification = Column(Boolean, default=False)
class AuthCookie(Base):
    __tablename__ = "auth_cookies"

    value = Column(String(44), primary_key=True)  # 32 bytes base64 encoded
    user = Column(String(32), ForeignKey("users.username"), nullable=False)
    expire_date = Column(DateTime, nullable=False)
    created_at = Column(DateTime, default=datetime.now)

    user_rel = relationship("User", back_populates="cookies")  # renamed to avoid conflict


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


class PaymentRequest(BaseModel):
    amount: int
    description: str

class PaymentSuccessRequest(BaseModel):
    success: str
    status: str
    trackId: str
    orderId: str


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


class Payment(Base):
    __tablename__ = 'pay'
    authority = Column(String, primary_key=True)
    user = Column(String)  # Foreign key if needed later
    amount = Column(Integer)
    description = Column(Text)
    status = Column(String(20), nullable=False)

class Notification(Base):
    __tablename__ = 'notifications'
    id = Column(Integer, primary_key=True, index=True)
    title = Column(String(255), nullable=False)
    content = Column(Text, nullable=False)
    visited_count = Column(Integer, default=0)
    created_at = Column(DateTime, default=datetime.now)
    users_visited = Column(ARRAY(item_type=String()), default=[])
class NotificationRequest(BaseModel):
    title: str
    content: str