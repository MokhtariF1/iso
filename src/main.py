from fastapi import FastAPI, Request, HTTPException, Depends, status
from fastapi.responses import Response, RedirectResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session
from passlib.context import CryptContext
import secrets
from datetime import datetime, timedelta
from typing import Dict, Any
from models import Base, User, AuthCookie, ChangePasswordRequest, UserProfileResponse, LoginInfo, SignUp
from config import settings

from models import Standard
from fastapi import Query

# Database setup
engine = create_engine(settings.DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base.metadata.create_all(bind=engine)

# Security configurations
security = HTTPBearer()
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

app = FastAPI()

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)


# Database dependency
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# Static files and templates
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")


# Security utilities
def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)


def generate_auth_cookie() -> str:
    return secrets.token_urlsafe(32)


# Authentication dependency
async def get_current_user(request: Request, db: Session = Depends(get_db)):
    auth_key = request.cookies.get("auth_key")
    if not auth_key:
        raise HTTPException(status_code=401, detail="Not authenticated")

    cookie = db.query(AuthCookie).filter(AuthCookie.value == auth_key).first()
    if not cookie:
        raise HTTPException(status_code=401, detail="Invalid authentication cookie")

    if datetime.now() > cookie.expire_date:
        db.delete(cookie)
        db.commit()
        raise HTTPException(status_code=401, detail="Cookie expired")

    user = db.query(User).filter(User.username == cookie.user_id).first()
    if not user:
        raise HTTPException(status_code=401, detail="User not found")

    return user


@app.post("/sign_up/")
async def sign_up(info: SignUp, request: Request, db: Session = Depends(get_db)):
    if request.cookies.get("auth_key"):
        raise HTTPException(status_code=400, detail="Already logged in")

    # Check existing user
    if db.query(User).filter(User.username == info.username).first():
        raise HTTPException(status_code=400, detail="Username already exists")

    if db.query(User).filter(User.email == info.email).first():
        raise HTTPException(status_code=400, detail="Email already registered")

    # Create user
    hashed_password = get_password_hash(info.password)
    user = User(
        username=info.username,
        password=hashed_password,
        email=info.email,
        full_name=info.full_name
    )

    # Create cookie
    auth_cookie = generate_auth_cookie()
    expire_time = datetime.now() + timedelta(seconds=settings.COOKIE_EXPIRE_TIME)
    cookie = AuthCookie(
        value=auth_cookie,
        user_id=info.username,
        expire_date=expire_time
    )

    db.add(user)
    db.add(cookie)
    db.commit()
    response = JSONResponse(content={"message": "Account created successfully"})
    response.set_cookie(
        key="auth_key",
        value=auth_cookie,
        max_age=settings.COOKIE_EXPIRE_TIME,
        httponly=True,
        secure=settings.SECURE_COOKIES,
        samesite="lax"
    )

    return response


@app.post("/login/")
async def login(info: LoginInfo, request: Request, db: Session = Depends(get_db)):
    if request.cookies.get("auth_key"):
        raise HTTPException(status_code=400, detail="Already logged in")

    user = db.query(User).filter(User.username == info.username).first()
    if not user or not verify_password(info.password, user.password):
        raise HTTPException(status_code=401, detail="Invalid username or password")

    if not user.is_active:
        raise HTTPException(status_code=403, detail="Account is disabled")

    # Create new cookie
    auth_cookie = generate_auth_cookie()
    expire_time = datetime.now() + timedelta(seconds=settings.COOKIE_EXPIRE_TIME)
    cookie = AuthCookie(
        value=auth_cookie,
        user_id=user.username,
        expire_date=expire_time
    )

    db.add(cookie)
    db.commit()
    response = JSONResponse(content={"message": "Logged in successfully"})
    response.set_cookie(
        key="auth_key",
        value=auth_cookie,
        max_age=settings.COOKIE_EXPIRE_TIME,
        secure=settings.SECURE_COOKIES,
        samesite="lax",
        httponly=True
    )

    return response


@app.get("/login/")
async def login_page(request: Request):
    if request.cookies.get("auth_key"):
        return RedirectResponse("/")
    return templates.TemplateResponse("login.html", {"request": request})


@app.post("/logout/")
async def logout(request: Request, response: Response, db: Session = Depends(get_db)):
    auth_key = request.cookies.get("auth_key")
    if not auth_key:
        raise HTTPException(status_code=401, detail="Not authenticated")

    cookie = db.query(AuthCookie).filter(AuthCookie.value == auth_key).first()
    if cookie:
        db.delete(cookie)
        db.commit()

    response.delete_cookie("auth_key")
    return {"message": "Logged out successfully"}


@app.get("/")
async def main(request: Request, db: Session = Depends(get_db)):
    try:
        current_user = await get_current_user(request, db)
        return templates.TemplateResponse(
            "main.html",
            {"request": request, "user": current_user}
        )
    except HTTPException:
        return RedirectResponse("/login/")


@app.get("/api/user/profile", response_model=UserProfileResponse)
async def get_user_profile(user: Dict[str, Any] = Depends(get_current_user)):
    return JSONResponse(content={
        "username": user.username,
        "email": user.email,
        "full_name": user.full_name,
        "created_at": user.created_at.isoformat(),
        "is_admin": user.username == "admin"  # یا از سیستم نقش‌ها استفاده کنید
    })


@app.post("/api/user/change-password")
async def change_password(
        request: ChangePasswordRequest,
        user: User = Depends(get_current_user),
        db: Session = Depends(get_db)
):
    # Verify current password
    if not verify_password(request.current_password, user.password):
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
    user.password = get_password_hash(request.new_password)
    db.commit()

    return {"message": "Password changed successfully"}


@app.get("/api/standards/")
async def get_standards(
        search: str = Query(None, description="Search term"),
        category: str = Query(None, description="Filter by category"),
        db: Session = Depends(get_db)
):
    query = db.query(Standard)

    if search:
        query = query.filter(
            (Standard.code.ilike(f"%{search}%")) |
            (Standard.desc.ilike(f"%{search}%"))
        )

    if category and category != "all":
        query = query.filter(Standard.category == category)

    standards = query.all()
    return standards


@app.post("/api/standards/")
async def create_standard(
        standard_data: dict,
        db: Session = Depends(get_db),
        user: User = Depends(get_current_user)
):
    try:
        standard = Standard(**standard_data)
        db.add(standard)
        db.commit()
        db.refresh(standard)
        return standard
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=400, detail=str(e))


@app.get("/api/categories/")
async def get_categories(db: Session = Depends(get_db)):
    categories = db.query(Standard.category).distinct().all()
    return [category[0] for category in categories]


@app.delete("/api/standards/{standard_id}")
async def delete_standard(
        standard_id: int,
        db: Session = Depends(get_db),
        user: User = Depends(get_current_user)
):
    standard = db.query(Standard).filter(Standard.id == standard_id).first()
    if not standard:
        raise HTTPException(status_code=404, detail="Standard not found")

    db.delete(standard)
    db.commit()
    return {"message": "Standard deleted successfully"}


@app.get("/api/standards/{standard_id}")
async def get_standard(
        standard_id: int,
        db: Session = Depends(get_db),
        user: User = Depends(get_current_user)
):
    standard = db.query(Standard).filter(Standard.id == standard_id).first()
    if not standard:
        raise HTTPException(status_code=404, detail="Standard not found")

    return standard


@app.put("/api/standards/{standard_id}")
async def update_standard(
        standard_id: int,
        standard_data: dict,
        db: Session = Depends(get_db),
        user: User = Depends(get_current_user)
):
    standard = db.query(Standard).filter(Standard.id == standard_id).first()
    if not standard:
        raise HTTPException(status_code=404, detail="Standard not found")

    allowed_fields = ['code', 'desc', 'category', 'details', 'link', 'status']
    for key, value in standard_data.items():
        if key in allowed_fields:
            setattr(standard, key, value)

    db.commit()
    db.refresh(standard)
    return standard


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
