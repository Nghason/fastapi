from pydantic import BaseModel, EmailStr, field_validator


class createUserSchema(BaseModel):
    email: EmailStr
    password: str

    @field_validator('password')
    def validate_password(cls, value):
        value = value.strip()
        if ' ' in value:
            raise ValueError('Password does not contain spaces')
        if len(value) < 6:
            raise ValueError('Password must longer')
        return value
    
class loginFormSchema(BaseModel):
    email:EmailStr
    password: str
    @field_validator('password')
    def validate_password(cls, value):
        value = value.strip()
        if ' ' in value:
            raise ValueError('Password does not contain spaces')
        if len(value) < 6:
            raise ValueError('Password must longer')
        return value
    
class forgotFormSchema(BaseModel):
    email:EmailStr

class ResetPasswordRequest(BaseModel):
    reset_token: str
    new_password: str
    for_sure: bool

class ResetPasswordWithAcceptToken(BaseModel):
    password: str
