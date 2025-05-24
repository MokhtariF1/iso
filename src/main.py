from fastapi import FastAPI, Request, HTTPException, Depends
from fastapi.responses import Response, RedirectResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer
from pymongo import MongoClient
import secrets
from passlib.context import CryptContext
from datetime import datetime, timedelta
import models
from config import settings
from fastapi import status
from typing import Dict, Any

# Security configurations
security = HTTPBearer()
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

app = FastAPI()

# CORS configuration should be more restrictive in production
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

# Static files
app.mount("/static", StaticFiles(directory="static"), name="static")

templates = Jinja2Templates(directory="templates")


# Database connection
def get_db():
    client = MongoClient(settings.MONGO_URI)
    try:
        db = client[settings.DB_NAME]
        yield db
    finally:
        client.close()


# Security utilities
def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)


def generate_auth_cookie() -> str:
    return secrets.token_urlsafe(32)


# Authentication dependencies
async def get_current_user(request: Request, db=Depends(get_db)):
    auth_key = request.cookies.get("auth_key")
    if not auth_key:
        raise HTTPException(status_code=401, detail="Not authenticated")

    cookie_collection = db["cookie"]
    user_cookie = cookie_collection.find_one({"value": auth_key})

    if not user_cookie:
        raise HTTPException(status_code=401, detail="Invalid authentication cookie")

    if datetime.now() > user_cookie["expire_date"]:
        cookie_collection.delete_one({"value": auth_key})
        raise HTTPException(status_code=401, detail="Cookie expired")

    users_collection = db["users"]
    user = users_collection.find_one({"username": user_cookie["user"]})

    if not user:
        raise HTTPException(status_code=401, detail="User not found")

    return user


@app.post("/sign_up/")
async def sign_up(info: models.SignUp, request: Request, response: Response, db=Depends(get_db)):
    # Check if user is already logged in
    if request.cookies.get("auth_key"):
        raise HTTPException(status_code=400, detail="Already logged in. Please logout first.")

    users_collection = db["users"]

    # Check if username already exists
    if users_collection.find_one({"username": info.username}):
        raise HTTPException(status_code=400, detail="Username already exists")

    # Check if email already exists
    if users_collection.find_one({"email": info.email}):
        raise HTTPException(status_code=400, detail="Email already registered")

    # Create new user
    hashed_password = get_password_hash(info.password)
    user_data = {
        "username": info.username,
        "password": hashed_password,
        "email": info.email,
        "full_name": info.full_name,
        "created_at": datetime.now(),
        "is_active": True
    }

    users_collection.insert_one(user_data)

    # Generate auth cookie
    auth_cookie = generate_auth_cookie()
    expire_time = datetime.now() + timedelta(seconds=settings.COOKIE_EXPIRE_TIME)

    cookie_collection = db["cookie"]
    cookie_collection.insert_one({
        "value": auth_cookie,
        "expire_date": expire_time,
        "user": info.username,
        "created_at": datetime.now()
    })

    # Set secure cookie
    response.set_cookie(
        key="auth_key",
        value=auth_cookie,
        max_age=settings.COOKIE_EXPIRE_TIME,
        httponly=True,
        secure=settings.SECURE_COOKIES,
        samesite="lax"
    )

    return {"message": "Account created successfully"}


@app.post("/login/")
async def login(info: models.LoginInfo, request: Request, response: Response, db=Depends(get_db)):
    # Check if user is already logged in
    if request.cookies.get("auth_key"):
        raise HTTPException(status_code=400, detail="Already logged in")

    users_collection = db["users"]
    user = users_collection.find_one({"username": info.username})

    if not user or not verify_password(info.password, user["password"]):
        raise HTTPException(status_code=401, detail="Invalid username or password")

    if not user.get("is_active", True):
        raise HTTPException(status_code=403, detail="Account is disabled")

    # Generate auth cookie
    auth_cookie = generate_auth_cookie()
    expire_time = datetime.now() + timedelta(seconds=settings.COOKIE_EXPIRE_TIME)

    cookie_collection = db["cookie"]
    cookie_collection.insert_one({
        "value": auth_cookie,
        "expire_date": expire_time,
        "user": info.username,
        "created_at": datetime.now()
    })

    # Set secure cookie
    response.set_cookie(
        key="auth_key",
        value=auth_cookie,
        max_age=settings.COOKIE_EXPIRE_TIME,
        httponly=True,
        secure=settings.SECURE_COOKIES,
        samesite="lax"
    )

    return {"message": "Logged in successfully"}


@app.get("/login/")
async def login_page(request: Request):
    if request.cookies.get("auth_key"):
        return RedirectResponse("/")
    else:
        return templates.TemplateResponse("login.html", {"request": request})


@app.post("/logout/")
async def logout(request: Request, response: Response, db=Depends(get_db)):
    auth_key = request.cookies.get("auth_key")
    if not auth_key:
        raise HTTPException(status_code=401, detail="Not authenticated")

    cookie_collection = db["cookie"]
    cookie_collection.delete_one({"value": auth_key})

    response.delete_cookie("auth_key")
    return {"message": "Logged out successfully"}


@app.get("/")
async def main(request: Request, db=Depends(get_db)):
    # Check if user is authenticated
    try:
        current_user = await get_current_user(request, db)
        return templates.TemplateResponse(
            request=request,
            name="main.html",
            context={"user": current_user}
        )
    except HTTPException:
        return RedirectResponse("/login/")


@app.get("/api/user/profile", response_model=models.UserProfileResponse)
async def get_user_profile(user: Dict[str, Any] = Depends(get_current_user)):
    return user


@app.post("/api/user/change-password")
async def change_password(
        request: models.ChangePasswordRequest,
        user: Dict[str, Any] = Depends(get_current_user),
        db=Depends(get_db)
):
    users_collection = db["users"]

    # Verify current password
    if not verify_password(request.current_password, user["password"]):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Current password is incorrect"
        )

    # Validate new password
    if len(request.new_password) < 8:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Password must be at least 8 characters long"
        )

    # Update password
    hashed_password = get_password_hash(request.new_password)
    users_collection.update_one(
        {"username": user["username"]},
        {"$set": {"password": hashed_password}}
    )

    return {"message": "Password changed successfully"}
