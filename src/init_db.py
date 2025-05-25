# init_db.py
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from models import Base, Standard
from standards import data as standards_data
from config import settings

engine = create_engine(settings.DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def init_standards():
    db = SessionLocal()
    try:
        # Create tables if they don't exist
        Base.metadata.create_all(bind=engine)

        # Check if standards already exist
        if db.query(Standard).count() == 0:
            for standard in standards_data:
                db_standard = Standard(**standard)
                db.add(db_standard)
            db.commit()
            print("Standards initialized successfully")
        else:
            print("Standards already exist in database")
    except Exception as e:
        print(f"Error initializing standards: {e}")
    finally:
        db.close()


if __name__ == "__main__":
    init_standards()