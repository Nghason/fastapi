from os import environ
from dotenv import load_dotenv
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

load_dotenv()

db_name = environ.get('DB_NAME', 'default.db')

connection_string = f"sqlite:///./{db_name}"

engine = create_engine(connection_string, connect_args={"check_same_thread": False})

SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False)
db = SessionLocal()
Base = declarative_base()

Base.metadata.create_all(bind=engine)
