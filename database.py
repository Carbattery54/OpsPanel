import os
from sqlmodel import create_engine, Session, SQLModel
from sqlalchemy import event
from config import settings

# Construct the SQLite database URL
db_file = os.path.join(settings.PROJECT_ROOT, "opspanel.db")
db_url = f"sqlite:///{db_file}"

engine = create_engine(
    db_url,
    connect_args={"check_same_thread": False},
    echo=False
)

# Enable WAL mode and foreign key constraints on connection startup
@event.listens_for(engine, "connect")
def set_sqlite_pragma(dbapi_connection, connection_record):
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA journal_mode=WAL;")
    cursor.execute("PRAGMA foreign_keys=ON;")
    cursor.close()

def get_session():
    """FastAPI dependency to yield database sessions."""
    with Session(engine) as session:
        yield session

def init_db():
    """Ensure database tables exist."""
    # Ensure the scratch directory exists
    os.makedirs(settings.PROJECT_ROOT, exist_ok=True)
    SQLModel.metadata.create_all(engine)
