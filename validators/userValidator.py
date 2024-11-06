from fastapi import HTTPException, status
from database import db
from models.User import User
from schemas.UserSchema import createUserSchema

def check_existing_user(user: createUserSchema):
    existing_email = db.query(User).filter(User.email == user.email).first()
    if existing_email:
        raise HTTPException(
            status_code=422,
            detail= "Email already registered"
        )
    return user
