from fastapi import FastAPI
import models.User
from routers import users
from database import Base,engine

Base.metadata.create_all(engine)
app = FastAPI()

@app.get("/")
async def root():
    return {"message": "Hello World"}
app.include_router(users.router, prefix="/api")
