import os
import jwt
from fastapi import FastAPI, HTTPException, Depends
from sqlalchemy import create_engine, Boolean, Column, Integer, String, Date, ForeignKey, PrimaryKeyConstraint
from sqlalchemy.orm import sessionmaker, relationship, Session, mapper
from sqlalchemy.ext.declarative import declarative_base
from pydantic import BaseModel
from typing import Optional, List
from datetime import datetime, timedelta, date
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from passlib.context import CryptContext
from fastapi.middleware.cors import CORSMiddleware

SECRET_KEY = os.environ.get("SECRET_KEY")
DEBUG_MODE = os.environ.get("DEBUG_MODE")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")
SQLALCHEMY_DATABASE_URL = "sqlite:///./tmpDataBase.db"
engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

class User(Base):
    __tablename__ = 'user'
    loginId = Column(Integer, autoincrement=True, primary_key=True, index=True)
    loginUsername = Column(String(50), unique=True, index=True)
    password = Column(String(100), nullable=False)
    
class UserModel(BaseModel):
    loginId: int
    loginUsername: str
    password: str
    class Config:
        orm_mode = True 

class Token(BaseModel):
    access_token: str
    token_type: str


app = FastAPI(
    title="app", 
    version="0.0.1",
    )


origins = ["*"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

def create_tables():
    Base.metadata.create_all(bind=engine)

def check_tables():
    from sqlalchemy import inspect
    insp = inspect(engine)
    table_names = insp.get_table_names()
    required_tables = ['user']
    return all(table in table_names for table in required_tables)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
        
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def authenticate_user(username: str, password: str, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.loginUsername == username).first()
    if not user:
        return False
    if not verify_password(password, user.password):
        return False
    return user

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=22)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

import socket
def isConnected() -> bool:
    IPaddress=socket.gethostbyname(socket.gethostname())
    return not IPaddress=="127.0.0.1"

@app.on_event("startup")
def startup_event():
    if not check_tables():
        create_tables()
    try:
        db = SessionLocal()
        db.execute("SELECT 1")
    except:
        raise HTTPException(status_code=500, detail="Impossibile connettersi al database")
    finally:
        db.close()
    if not isConnected():
        print("\n")
        print("\nWARNING:    No internet Connection [Connessione Assente]")
        print("\nINFO:       Only Localhost connection \n")
        print("\n")
        if not DEBUG_MODE:
            raise SystemExit

@app.on_event("shutdown")
async def shutdown(db: Session = Depends(get_db)):
    db.close_all()


@app.post("/token", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = authenticate_user(form_data.username, form_data.password, db)
    if not user:
        raise HTTPException(status_code=401, detail="Nome utente o password non validi")        
    
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.loginUsername}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}


import re
@app.post("/register", response_model=UserModel)
async def register(user: UserModel, db: Session = Depends(get_db)):
    if len(user.password) < 6 or not re.search(r'\d', user.password) or \
                    not re.search(r'[!@#$%^&*(),.?":{}|<>]', user.password):
        raise HTTPException(status_code=400, detail="Errore: La password deve avere almeno 6 caratteri, \
                            almeno un simbolo e almeno un numero.")
    if db.query(User).filter(User.loginUsername == user.loginUsername).first():
        raise HTTPException(status_code=400, detail="Errore Username non valido")
    if db.query(User).filter_by(loginId=user.loginId).first():
        raise HTTPException(status_code=400, detail="Errore: Id non valido")
    
    hashed_password = pwd_context.hash(user.password)
    db_user = User(loginUsername=user.loginUsername, password=hashed_password)
    try:
        db.add(db_user)
        db.commit()
    except:
        db.rollback()
        raise HTTPException(status_code=400, detail="Errore Inserimento Dati")
    db.refresh(db_user)
    return db_user


#Generic free route
@app.get("/free", response_model=None)
def free(aParam: str, db: Session = Depends(get_db)):
    #do something with aParam...
    return None

#Generic Protectec Route
@app.post("/protected", response_model=None)
async def protect(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    try:
        jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except jwt.JWTError:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    #do something...
    return None
    
