from typing import Annotated

from dotenv import load_dotenv
from fastapi import Depends, HTTPException, Request, status

from database import db
from models.User import User
from utils import Auth

load_dotenv()


async def get_current_user(request: Request):
    token_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail='Unauthorized',
        headers={'WWW-Authenticate': 'Bearer'},
    )

    token = request.headers.get('Authorization')
    if token is None or not token.startswith('Bearer '):
        raise token_exception

    token = token.replace('Bearer ', '')

    try:
        payload = Auth.decode_access_token(token)
        email = payload.get('sub')
        if not email:
            raise token_exception

    except Exception as e:
        raise token_exception

    user = db.query(User).filter(User.email == email).first()
    if not user:
        raise token_exception

    user = {
        'id': user.id,
        'email': user.email
    }

    return user

async def get_current_user_for_reset_password(request: Request):
    token_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail='Unauthorized',
        headers={'WWW-Authenticate': 'Bearer'},
    )

    token = request.headers.get('Authorization')
    if token is None or not token.startswith('Bearer '):
        raise token_exception

    token = token.replace('Bearer ', '')

    try:
        payload = Auth.decode_access_token(token)
        email = payload.get('sub')
        if not email:
            raise token_exception

    except Exception as e:
        raise token_exception

    user = db.query(User).filter(User.email == email).first()
    if not user:
        raise token_exception
    return user

async def get_current_user2(request: Request):
    token = request.headers.get('Authorization')
    
    if token is None or not token.startswith('Bearer '):
        return None

    token = token.replace('Bearer ', '')

    try:
        payload = Auth.decode_access_token(token)
        email = payload.get('sub')
        if not email:
            return None

    except Exception as e:
        return None

    _user = db.query(User).filter(User.email == email).first()
    if not _user:
        return None

    user = {
        'id': _user.id,
        'email': _user.email
    }

    return user
