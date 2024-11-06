from fastapi import HTTPException, status
from database import db
from models.User import User
from schemas.UserSchema import createUserSchema
from pydantic import EmailStr

def check_existing_user(user: createUserSchema):
    existing_email = db.query(User).filter(User.email == user.email).first()
    if existing_email:
        raise HTTPException(
            status_code=422,
            detail= "Email already registered"
        )
    return user

def check_exiting_email_for_reset_password(email:EmailStr):
    existing_email_for_reset_password = db.query(User).filter(User.email == email).first()
    if not existing_email_for_reset_password:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail= "Email didn't exits",
        )
    return existing_email_for_reset_password