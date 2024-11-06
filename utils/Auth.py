from datetime import datetime, timedelta
from os import environ

from dotenv import load_dotenv
from fastapi import HTTPException, status
from jose import jwt
from jose.exceptions import JWTError
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import secrets
from models import User
from sqlalchemy.orm import Session
from database import SessionLocal

load_dotenv()


def create_access_token(data: dict):
    to_encode = data.copy()

    expires_delta = timedelta(
        minutes=float(environ.get("ACCESS_TOKEN_EXPIRE_MINUTES","15"))
    )
    expire = datetime.utcnow() + expires_delta if expires_delta else datetime.utcnow()

    to_encode.update({'exp': expire})
    encoded_jwt = jwt.encode(
        to_encode,
        environ.get("ACCESS_TOKEN_SECRET","mysecretkey123"),
        algorithm=environ.get("ALGORITHM","HS256")
    )
    return encoded_jwt


def create_refresh_token(data: dict):
    to_encode = data.copy()

    expires_delta = timedelta(
        minutes=float(environ.get("REFRESH_TOKEN_EXPIRE_MINUTES", "1500"))
    )
    expire = datetime.utcnow() + expires_delta if expires_delta else datetime.utcnow()

    to_encode.update({'exp': expire})
    encoded_jwt = jwt.encode(
        to_encode,
        environ.get("REFRESH_TOKEN_SECRET", "mysecretkey234"),
        algorithm=environ.get("ALGORITHM", "HS256")
    )
    return encoded_jwt


def decode_access_token(token):
    try:
        payload = jwt.decode(
            token.replace('Bearer ', ''),
            environ.get("ACCESS_TOKEN_SECRET","mysecretkey123"),
            algorithms=[environ.get("ALGORITHM","HS256")]
        )
        return payload
    except JWTError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(e),
            headers={"WWW-Authenticate": "Bearer"}
        )


def decode_refresh_token(token):
    try:
        payload = jwt.decode(
            token.replace('Bearer ', ''),
            environ.get("REFRESH_TOKEN_SECRET", "mysecretkey234"),
            algorithms=[environ.get("ALGORITHM", "HS256")]
        )
        return payload
    except JWTError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(e),
            headers={"WWW-Authenticate": "Bearer"}
        )

# def send_reset_password(email: str, reset_token: str):
#     msg = MIMEMultipart()
#     msg['From'] = 'your-email@example.com'
#     msg['To'] = email
#     msg['Subject'] = 'Password Reset Request'

#     body = f"Click on the following link to reset your password: http://local:8181/users/auth/reset_password?token={reset_token}"
#     msg.attach(MIMEText(body, 'plain'))

#     try:
#         with smtplib.SMTP('smtp.example.com', 587) as server:
#             server.starttls()  
#             server.login("your-email@example.com", "your-email-password")
#             server.sendmail(msg['From'], msg['To'], msg.as_string())
#     except Exception as e:
#         raise HTTPException(
#             status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
#             detail=f"Failed to send email: {str(e)}"
#         )
def generate_reset_token() -> str:
    return secrets.token_urlsafe(32)  # Tạo token dài 32 ký tự

# Cập nhật reset token cho người dùng (lưu vào cơ sở dữ liệu)
def save_reset_token(user: User, token: str):
    db: Session = SessionLocal()
    try: 
        user = db.merge(user)
        user.reset_token = token
        user.reset_token_expiry = datetime.utcnow() + timedelta(hours=1)  # Token có hiệu lực trong 1 giờ
        db.commit()
        db.refresh(user)
    except Exception as e:
        db.rollback()  # Nếu có lỗi, rollback các thay đổi
        raise e
    finally:
        db.close()