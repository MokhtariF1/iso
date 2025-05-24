from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    MONGO_URI: str = "mongodb://localhost:27017"
    DB_NAME: str = "iso"
    SECRET_KEY: str = "your-secret-key-here"  # Change this in production
    COOKIE_EXPIRE_TIME: int = 86400  # 1 day in seconds
    SECURE_COOKIES: bool = True  # Should be True in production
    ALLOWED_ORIGINS: list = [
        "http://localhost",
        "http://localhost:8000",
        "http://127.0.0.1:8000"
    ]

    class Config:
        env_file = ".env"


settings = Settings()