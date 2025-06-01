# config.py
from pydantic_settings import BaseSettings
from pydantic import PostgresDsn
from utils.Config import Config


class Settings(BaseSettings):
    POSTGRES_USER: str = "standards_postgres"
    POSTGRES_PASSWORD: str = "Hossein_90"
    POSTGRES_DB: str = "standards_iso"
    POSTGRES_HOST: str = "localhost"
    POSTGRES_PORT: int = 5432

    @property
    def DATABASE_URL(self):
        return f'postgresql://standard_postgres:Hossein_90@localhost:5432/standard_iso'

    SECRET_KEY: str = "your-secret-key-here"
    COOKIE_EXPIRE_TIME: int = 86400
    SECURE_COOKIES: bool = False
    ALLOWED_ORIGINS: list = ["*"]
    merchant: str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    domain: str = "https://standards.ncp3.xyz/standards"
    callback_url: str = "https://standards.ncp3.xyz/api/payments/success"
    zarinpal: str = "https://sandbox.zarinpal.com/"
    config: Config = Config(merchant_id=merchant, sandbox=True)


settings = Settings()
