from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import JSONResponse, RedirectResponse
from typing import Annotated
from schemas.UserSchema import (
    createUserSchema,
    loginFormSchema 
)
from models.User import User
from utils import Auth
from utils.Hash import Hash  
from validators.userValidator import check_existing_user
from database import db
from passlib.exc import UnknownHashError

from os import environ
from middlewares import get_current_user
from dotenv import load_dotenv

load_dotenv()
router = APIRouter()

@router.post('/user/auth/register')
def register(
    user: Annotated[createUserSchema, Depends(check_existing_user)]
):
    try:
        new_user = User(
            email=user.email,
            password=Hash.make(user.password)
        )
        db.add(new_user)
        db.commit()
        db.refresh(new_user)
        _new_user = new_user.serialize()
        resp = {
            'detail': 'done',
            'data': _new_user
        }
        return JSONResponse(status_code=201, content=resp)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        db.close()
@router.post('/users/auth/login')
def login(form_data: loginFormSchema):
    try:
        user = db.query(User).filter(User.email == form_data.email).first()
        if not user or not Hash.verify(form_data.password, user.password):
            return JSONResponse(
                status_code=status.HTTP_401_UNAUTHORIZED
            )
        
        access_token = Auth.create_access_token(data={'sub': user.email})
        # print(access_token)
        refresh_token = Auth.create_refresh_token(data={'sub': user.email})
        response = JSONResponse(
            status_code=status.HTTP_200_OK,
            content={
                'detail': 'Login successful',
                'data': {
                    'access_token': access_token
                }
            },
            headers={'WWW-Authenticate': 'Bearer'},
        )
        response.set_cookie(
            key='refresh_token',
            value=refresh_token,
            max_age=environ.get('REFRESH_TOKEN_EXPIRE_MINUTES'),
            expires=environ.get('REFRESH_TOKEN_EXPIRE_MINUTES'),
                # path='/api/v1/users/auth/refreshtoken',
            path='/',
            secure=False,
            httponly=True,
            samesite="strict",
        )
        return response

    except UnknownHashError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)+' xx',
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e) + ' x2x',
        )
    finally:
        db.close()
@router.post('/users/auth/refreshtoken')
def refresh_token(request: Request):
    token_exception = JSONResponse(
        status_code=status.HTTP_400_BAD_REQUEST,
        content={'detail': 'Unauthorized'},
        headers={'WWW-Authenticate': 'Bearer'},
    )

    token = request.cookies.get('refresh_token')

    if not token:
        return token_exception

    try:
        payload = Auth.decode_refresh_token(token)
        email = payload.get('sub')
        if not email:
            raise token_exception
        user = db.query(User).filter(User.email == email).first()
        if not user:
            raise token_exception

    except Exception:
        return token_exception

    try:
        access_token = Auth.create_access_token(data={'sub': user.email})
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content={
                'detail': 'Authentication successful',
                'data': {
                    'access_token': access_token,
                }
            },
            headers={'WWW-Authenticate': 'Bearer'},
        )

    except UnknownHashError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e),
        )
    

@router.get('/users/profile')
def profile(request: Request, user=Depends(get_current_user)):
    try:
        return JSONResponse(
            status_code=200,
            content={
                'detail': 'User fetched successfully',
                'data': {
                    'user': {
                        'id': user.get('id'),
                        'email': user.get('email')
                    }
                }
            }
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# Logout
@router.post('/users/auth/logout')
def logout(request: Request):
    response = JSONResponse(
        status_code=status.HTTP_200_OK,
        content={
            'detail': 'Logout successful',
        }
    )
    response.delete_cookie('refresh_token')
    return response