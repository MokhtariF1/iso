from pydantic import BaseModel, EmailStr, constr, validator
from datetime import datetime


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
