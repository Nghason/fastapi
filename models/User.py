from sqlalchemy import TIMESTAMP, Column, Integer, SmallInteger, String, text, func
from database import Base

class User(Base):
    __tablename__ = 'user'
    id = Column(Integer, primary_key=True, autoincrement=True)
    email = Column(String(50), unique=True, nullable=False)
    password = Column(String(255), nullable=True)
    created_at = Column(TIMESTAMP, nullable=False, server_default=func.now())
    updated_at = Column(
        TIMESTAMP,
        nullable=True,
        default=None,
        onupdate=func.now(),
        server_onupdate=func.now()
    )
    deleted_at = Column(TIMESTAMP, nullable=True, default=None)

    def serialize(self):
        return {
            'id': self.id,
            'email': self.email
        }