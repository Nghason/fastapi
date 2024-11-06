from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import JSONResponse, RedirectResponse
from typing import Annotated
from schemas.UserSchema import (
    createUserSchema,
    loginFormSchema,
    forgotFormSchema,
    AcceptTokenPasswordRequest,
    ResetPasswordRequest
)
from models.User import User
from utils import Auth
from utils.Hash import Hash  
from validators.userValidator import check_existing_user, check_exiting_email_for_reset_password
from database import db
from passlib.exc import UnknownHashError

from os import environ
from middlewares import get_current_user
from dotenv import load_dotenv
from datetime import datetime

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

# @router.post('/users/auth/forgot_password')
# def forgot_password(
#     form_data: forgotFormSchema,
# ):
#     try:
#         check_exiting_email_for_reset_password(form_data.email)
#         reset_token = Auth.generate_reset_token()
#         Auth.send_reset_password(form_data.email, reset_token)
#         return {"message": "Password reset link has been sent to your email."}
#     except Exception as e:
#         raise HTTPException(
#             status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
#             detail=str(e) ,
#         )

@router.post('/users/auth/forgot_password')
def forgot_password(
    form_data: forgotFormSchema
):
    try:

        user = check_exiting_email_for_reset_password(form_data.email)

        reset_token = Auth.generate_reset_token()

        Auth.save_reset_token(user, reset_token)

        reset_link = f"http://localhost:8181/user/auth/reset_password"

        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content={
                "message": "Password reset link has been sent to your email.",
                "reset_link": reset_link,
                "reset_token": reset_token  
            }
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e),
        )

@router.post('/users/auth/reset_password')
def reset_password_with_reset_token(
    form_data: ResetPasswordRequest
):
    try:
        user = db.query(User).filter(User.reset_token == form_data.reset_token).first()
        if not user:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid or expired reset token"
            )
        if user.reset_token_expiry < datetime.utcnow():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Reset token has expired"
            )
        password = Hash.make(form_data.new_password)
        user.password = password
        user.reset_token = None
        user.reset_token_expỉry = None
        db.commit()
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content="password had success change"
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e),
        )


@router.post('/users/auth/reset_token_with_accept_token')
def reset_password_with_accept_token(
    form_data = AcceptTokenPasswordRequest,
    user=Depends(get_current_user)
):
    try:
        password = Hash.make(form_data.new_password)
        user.password = password
        db.commit()
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content="password had success change"
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e),
        )

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

