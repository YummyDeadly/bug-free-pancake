from fastapi import FastAPI
from .routes import auth, passwords
from .database import engine, Base

app = FastAPI(title="Password Manager API")

Base.metadata.create_all(bind=engine)

app.include_router(auth.router)
app.include_router(passwords.router)