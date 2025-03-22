from fastapi import APIRouter, HTTPException, Depends
from sqlalchemy.orm import Session
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel, EmailStr
from passlib.context import CryptContext
from jose import JWTError, jwt
from smtplib import SMTP
from email.message import EmailMessage
from datetime import datetime, timedelta
from ..database import SessionLocal, get_db
from ..models import User
from ..utils.utilservice import LogService as logSer

SECRET_KEY = "supersecretkey"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")

router = APIRouter(prefix="/auth", tags=["Auth"])

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

EMAIL_HOST = "smtp.gmail.com"
EMAIL_PORT = 587
EMAIL_USER = "vagabondchannel033@gmail.com"
EMAIL_PASS = "ehpmdpjkxexejdfa"

logSer.setup_logging()


def send_verification_email(email: str, token: str):
    msg = EmailMessage()
    msg["Subject"] = "Подтверждение вашей учетной записи"
    msg["From"] = EMAIL_USER
    msg["To"] = email
    verification_link = f"http://localhost:8000/auth/verify-email?token={token}"
    msg.set_content(f"Пожалуйста, подтвердите вашу учетную запись по ссылке: {verification_link}")

    try:
        with SMTP(EMAIL_HOST, EMAIL_PORT) as server:
            server.starttls()
            server.login(EMAIL_USER, EMAIL_PASS)
            server.send_message(msg)
            logSer.create_action_log(f"Письмо успешно отправлено на {email}")
    except Exception as e:
        logSer.create_error_log(f"Ошибка при отправке письма на {email}: {e}")

class UserRegister(BaseModel):
    username: str
    password: str
    email: EmailStr

class UserLogin(BaseModel):
    username: str
    password: str

def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=15))
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=401, detail="Не удалось проверить учетные данные")
        user = db.query(User).filter(User.username == username).first()
        if not user:
            raise HTTPException(status_code=404, detail="Пользователь не найден")
        return user
    except JWTError as e:
        logSer.create_error_log(f"Ошибка при декодировании токена: {e}")
        raise HTTPException(status_code=401, detail="Неверный токен")

@router.post("/register")
async def register(user: UserRegister, db: Session = Depends(get_db)):
    if db.query(User).filter(User.username == user.username).first():
        raise HTTPException(status_code=400, detail="Пользователь уже существует")
    if db.query(User).filter(User.email == user.email).first():
        raise HTTPException(status_code=400, detail="Почта уже используется")

    hashed_password = pwd_context.hash(user.password)
    db_user = User(username=user.username, email=user.email, hashed_password=hashed_password, is_verified=False)
    db.add(db_user)
    db.commit()

    token = jwt.encode({"sub": user.username, "exp": datetime.utcnow() + timedelta(hours=1)}, SECRET_KEY, algorithm=ALGORITHM)
    send_verification_email(user.email, token)

    logSer.create_action_log(f"Пользователь {user.username} успешно зарегистрирован")

    return {"message": "Регистрация успешна! Проверьте вашу почту для подтверждения аккаунта."}

@router.get("/verify-email")
async def verify_email(token: str, db: Session = Depends(get_db)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        user = db.query(User).filter(User.username == username).first()
        if not user:
            raise HTTPException(status_code=404, detail="Пользователь не найден")
        if user.is_verified:
            return {"message": "Аккаунт уже подтвержден."}

        user.is_verified = True
        db.commit()
        logSer.create_action_log(f"Аккаунт {user.username} успешно подтвержден")
        return {"message": "Аккаунт успешно подтвержден!"}
    except JWTError:
        logSer.create_error_log("Ошибка при верификации email - Неверный или истекший токен")
        raise HTTPException(status_code=400, detail="Неверный или истекший токен")

@router.post("/login")
async def login(user: UserLogin, db: Session = Depends(get_db)):
    db_user = db.query(User).filter(User.username == user.username).first()
    if not db_user or not pwd_context.verify(user.password, db_user.hashed_password):
        logSer.create_error_log(f"Неверное имя пользователя или пароль: {user.username}")
        raise HTTPException(status_code=400, detail="Неверное имя пользователя или пароль")

    if not db_user.is_verified:
        logSer.create_error_log(f"Аккаунт не подтвержден для пользователя: {user.username}")
        raise HTTPException(status_code=403, detail="Аккаунт не подтвержден. Пожалуйста, подтвердите вашу почту.")

    access_token = jwt.encode({"sub": user.username}, SECRET_KEY, algorithm=ALGORITHM)
    logSer.create_action_log(f"Пользователь {user.username} успешно авторизован")
    return {"access_token": access_token, "token_type": "bearer"}