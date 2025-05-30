import json
import random
import requests
from fastapi import FastAPI, Request, HTTPException, Depends, status, Query
from fastapi.responses import Response, RedirectResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer
from rfc3986.parseresult import authority_from
from sqlalchemy import desc
from sqlalchemy.orm import sessionmaker, Session
from passlib.context import CryptContext
import secrets
from datetime import datetime, timedelta
from typing import Dict, Any

from yaml import AnchorToken

from models import Base, User, AuthCookie, ChangePasswordRequest, UserProfileResponse, LoginInfo, SignUp, Standard, \
    Payment, PaymentRequest, PaymentSuccessRequest, NotificationRequest, Notification
from config import settings
from database import get_db
from zarinpal_core import *

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

# Static files and templates
app.mount("/static", StaticFiles(directory="src/static"), name="static")
templates = Jinja2Templates(directory="src/templates")


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

    user = db.query(User).filter(User.username == cookie.user).first()
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
        user=info.username,
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
        user=user.username,
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
async def get_user_profile(user: User = Depends(get_current_user)):
    return JSONResponse(content={
        "username": user.username,
        "email": user.email,
        "full_name": user.full_name,
        "created_at": user.created_at.isoformat(),
        "is_admin": user.username == "admin",
        "is_premium": user.is_premium,
        "has_notification": user.newNotification,
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


@app.get("/api/payments/success")
async def pay_success(request: Request, Authority: str, Status: str,
                      db: Session = Depends(get_db), find_user: User = Depends(get_current_user)):
    if find_user.is_premium:
        return HTTPException(400, detail="You are alerdy premium user!")
    pay = db.query(Payment).filter(Payment.authority == Authority).first()
    if pay:
        pay_status = pay.status
        if pay_status != "CREATED":
            return HTTPException(400, detail="Payment has already been closed!")
        else:
            if Status == "OK":
                pay.status = "PAID"
                db.commit()
            else:
                pay.status = "Failure"
                db.commit()
                return templates.TemplateResponse("pay_not_success.html", {"request": request})
            response = verify_payment(authority=Authority, status=Status)
            if response:
                find_user.inventory += pay.amount
                find_user.charge_wallet_count += 1
                find_user.wallet_all_charge += pay.amount
                pay.status = "Success"
                find_user.is_premium = True
                db.commit()
                return templates.TemplateResponse("pay_success.html", {"request": request})
            else:
                return templates.TemplateResponse("pay_not_success.html", {"request": request})
    else:
        return templates.TemplateResponse("pay_not_success.html", {"request": request})


@app.post("/api/payments/create-pay/")
async def create_pay(pay: PaymentRequest, db: Session = Depends(get_db),
                     user: User = Depends(get_current_user)):
    if user.is_premium:
        return HTTPException(400, detail="You are alerdy premium user!")
    request_pay = initiate_payment(amount=pay.amount, description=pay.description)
    print("________", request_pay)
    if request_pay is not None and request_pay["authority"] is not None:
        # Create new payment record
        new_payment = Payment(
            authority=request_pay["authority"],
            user=user.username,
            amount=pay.amount,
            status="CREATED",
        )

        try:
            db.add(new_payment)
            db.commit()
            db.refresh(new_payment)
        except Exception as e:
            db.rollback()
            return Response(json.dumps({"status": 500, "message": "Database error", "error": str(e)}), status_code=500)

        return Response(json.dumps(
            {"authority": request_pay["authority"], "amount": pay.amount, "payment_url": request_pay["payment_url"]}),
            status_code=200)
    else:
        return HTTPException(500, detail="Cant create payment!")


@app.post("/api/notifications/add/")
async def admin_add_notification(notification: NotificationRequest, db: Session = Depends(get_db),
                                 user: User = Depends(get_current_user)):
    if user.username != "admin":
        return HTTPException(403, "Access denide")
    try:
        add_notification = Notification(title=notification.title, content=notification.content)
        db.add(add_notification)
        db.commit()
        db.refresh(add_notification)
        db.query(User).update({"newNotification": True})
        db.commit()
        return Response(json.dumps({"status": 200, "message": "notification added!"}))
    except Exception as e:
        db.rollback()
        return Response(json.dumps({"status": 500, "message": "Database error", "error": e}), status_code=500)


@app.get("/api/notifications/user/")
async def notifications(db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    find_notifications = db.query(Notification).count()
    if find_notifications <= 0:
        return Response(json.dumps({"status": 404, "message": "Notification not found"}), status_code=404)
    find_notifications = db.query(Notification).order_by(desc(Notification.created_at)).limit(5).all()
    notifications = []
    for notification in find_notifications:
        notification = {
            "id": notification.id,
            "title": notification.title,
            "content": notification.content,
            "visited_count": notification.visited_count,
            "created_at": notification.created_at,
        }
        notifications.append(notification)
    user.newNotification = False
    db.commit()
    # notifications = notifications[::-1]
    return Response(json.dumps({"notifications": notifications}, indent=4, default=str))
#
# main.py

# API برای دریافت همه اعلان‌ها (برای ادمین)
@app.get("/api/notifications/")
async def notifications(
        db: Session = Depends(get_db),
        user: User = Depends(get_current_user)
):
    if user.username != "admin":
        raise HTTPException(status_code=403, detail="Access denied")

    notifications = db.query(Notification).all()
    return {"notifications": notifications}


# API برای ویرایش اعلان
@app.put("/api/notifications/{notification_id}/")
async def update_notification(
        notification_id: int,
        notification_data: NotificationRequest,
        db: Session = Depends(get_db),
        user: User = Depends(get_current_user)
):
    if user.username != "admin":
        raise HTTPException(status_code=403, detail="Access denied")

    notification = db.query(Notification).filter(Notification.id == notification_id).first()
    if not notification:
        raise HTTPException(status_code=404, detail="Notification not found")

    notification.title = notification_data.title
    notification.content = notification_data.content
    db.commit()
    db.refresh(notification)
    return notification


# API برای حذف اعلان
@app.delete("/api/notifications/{notification_id}/")
async def delete_notification(
        notification_id: int,
        db: Session = Depends(get_db),
        user: User = Depends(get_current_user)
):
    if user.username != "admin":
        raise HTTPException(status_code=403, detail="Access denied")

    notification = db.query(Notification).filter(Notification.id == notification_id).first()
    if not notification:
        raise HTTPException(status_code=404, detail="Notification not found")

    db.delete(notification)
    db.commit()
    return {"message": "Notification deleted successfully"}


# API برای دریافت یک اعلان خاص
@app.get("/api/notifications/{notification_id}/")
async def get_notification(
        notification_id: int,
        db: Session = Depends(get_db),
        user: User = Depends(get_current_user)
):
    notification = db.query(Notification).filter(Notification.id == notification_id).first()
    if not notification:
        raise HTTPException(status_code=404, detail="Notification not found")
    data = {
        "id": notification.id,
        "title": notification.title,
        "content": notification.content,
        "created_at": notification.created_at,
        "visited_count": notification.visited_count
    }
    return data


@app.post("/api/notifications/mark-as-seen/")
async def mark_notifications_as_seen(
        db: Session = Depends(get_db),
        user: User = Depends(get_current_user)
):
    user.newNotification = False
    db.commit()
    return {"message": "Notifications marked as seen"}


@app.post("/api/notifications/{notification_id}/increment-views/")
async def increment_notification_views(
        notification_id: int,
        db: Session = Depends(get_db),
        user: User = Depends(get_current_user)
):
    notification = db.query(Notification).filter(Notification.id == notification_id)
    f_notification = notification.first()
    if not f_notification:
        raise HTTPException(status_code=404, detail="Notification not found")
    if user.username not in f_notification.users_visited:
        f_notification.visited_count += 1
        notification.update(values={"users_visited": Notification.users_visited + [user.username]})
        db.commit()
    return {"message": "View count incremented"}


# @app.get("/api/notifications/user/")
# async def get_user_notifications(
#         db: Session = Depends(get_db),
#         user: User = Depends(get_current_user)
# ):
#     # دریافت 5 اعلان آخر
#     notifications = db.query(Notification).order_by(Notification.created_at.desc()).limit(5).all()
#
#     # به‌روزرسانی وضعیت کاربر (اگر اعلان جدیدی وجود دارد)
#     if notifications and user.newNotification:
#         user.newNotification = False
#         db.commit()
#
#     return {"notifications": notifications}
#
if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
