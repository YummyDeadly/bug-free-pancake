from fastapi import APIRouter, HTTPException, Depends
from sqlalchemy.orm import Session
from pydantic import BaseModel
from ..database import SessionLocal
from ..models import Password
from .auth import get_current_user
import uuid
from cryptography.fernet import Fernet
from ..database import get_db

SECRET_KEY = Fernet.generate_key()
fernet = Fernet(SECRET_KEY)

router = APIRouter(prefix="/passwords", tags=["Passwords"])

class PasswordCreate(BaseModel):
    site: str
    password: str

class PasswordUpdate(BaseModel):
    site: str
    new_password: str

@router.post("/add")
async def add_password(data: PasswordCreate, db: Session = Depends(get_db), current_user: dict = Depends(get_current_user)):
    encrypted_password = fernet.encrypt(data.password.encode()).decode()
    new_password = Password(id=str(uuid.uuid4()), username=current_user.username, site=data.site, encrypted_password=encrypted_password)
    db.add(new_password)
    db.commit()
    return {"message": "Пароль добавлен!"}

@router.put("/update")
async def update_password(data: PasswordUpdate, db: Session = Depends(get_db), current_user: dict = Depends(get_current_user)):
    password_entry = db.query(Password).filter(Password.site == data.site, Password.username == current_user.username).first()
    if not password_entry:
        raise HTTPException(status_code=404, detail="Пароль не найден")

    password_entry.encrypted_password = fernet.encrypt(data.new_password.encode()).decode()
    db.commit()
    return {"message": "Пароль успешно обновлён!"}

@router.delete("/delete/{site}")
async def delete_password(site: str, db: Session = Depends(get_db), current_user: dict = Depends(get_current_user)):
    password_entry = db.query(Password).filter(Password.site == site, Password.username == current_user.username).first()
    if not password_entry:
        raise HTTPException(status_code=404, detail="Пароль не найден")

    db.delete(password_entry)
    db.commit()
    return {"message": "Пароль успешно удалён!"}