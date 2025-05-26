from pydantic_settings import BaseSettings
from pydantic import PostgresDsn


class Settings(BaseSettings):
    POSTGRES_USER: str = "postgres"
    POSTGRES_PASSWORD: str = "1234"
    POSTGRES_DB: str = "iso"
    POSTGRES_HOST: str = "localhost"
    POSTGRES_PORT: int = 5432

    @property
    def DATABASE_URL(self):
        return 'postgresql://postgres:1234@localhost:5432/iso'

    SECRET_KEY: str = "your-secret-key-here"
    COOKIE_EXPIRE_TIME: int = 86400
    SECURE_COOKIES: bool = True
    ALLOWED_ORIGINS: list = [
        # "http://localhost",
        # "http://localhost:8000",
        # "http://127.0.0.1:8000"
        "*"
    ]

    class Config:
        env_file = ".env"


settings = Settings()
