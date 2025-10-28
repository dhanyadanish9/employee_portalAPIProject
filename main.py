# main.py
from fastapi import FastAPI, HTTPException, Query, Depends, Form
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import create_engine, Column, Integer, String
from sqlalchemy.orm import sessionmaker, declarative_base, Session
from passlib.context import CryptContext
from pydantic import BaseModel
from typing import Optional
import os
from dotenv import load_dotenv
load_dotenv()

# ------------------------------------------------------------
# DATABASE CONFIGURATION
# ------------------------------------------------------------
DATABASE_URL = os.getenv("DATABASE_URL")

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# ------------------------------------------------------------
# FASTAPI APP
# ------------------------------------------------------------
app = FastAPI(title="User Management API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
    allow_credentials=True,
)

# ------------------------------------------------------------
# DATABASE MODELS
# ------------------------------------------------------------
class UserModel(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False)
    age = Column(Integer, nullable=False)
    job = Column(String, nullable=True)
    city = Column(String, nullable=True)
    mailid = Column(String, nullable=True)
    phone = Column(String(20), nullable=True)


class AdminModel(Base):
    __tablename__ = "admins"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, nullable=False)
    password_hash = Column(String, nullable=False)


Base.metadata.create_all(bind=engine)

# ------------------------------------------------------------
# SCHEMAS
# ------------------------------------------------------------
class User(BaseModel):
    name: str
    age: int
    job: Optional[str] = None
    city: Optional[str] = None
    mailid: Optional[str] = None
    phone: Optional[str] = None

    class Config:
        orm_mode = True


class AdminLogin(BaseModel):
    username: str
    password: str


# ------------------------------------------------------------
# DEPENDENCIES
# ------------------------------------------------------------
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# ------------------------------------------------------------
# HELPERS
# ------------------------------------------------------------
# def get_password_hash(password: str) -> str:
#     return pwd_context.hash(password)

# def get_password_hash(password: str) -> str:
#     # bcrypt supports up to 72 bytes only
#     if len(password.encode("utf-8")) > 72:
#         password = password[:72]
#     return pwd_context.hash(password)


# def verify_password(plain: str, hashed: str) -> bool:

#     if len(plain.encode("utf-8")) > 72:
#         plain = plain[:72]
#     return pwd_context.verify(plain, hashed)


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def get_password_hash(password: str) -> str:
    # bcrypt supports only up to 72 bytes
    password_bytes = password.encode("utf-8")
    if len(password_bytes) > 72:
        password = password_bytes[:72].decode("utf-8", errors="ignore")
    return pwd_context.hash(password)

def verify_password(plain: str, hashed: str) -> bool:
    plain_bytes = plain.encode("utf-8")
    if len(plain_bytes) > 72:
        plain = plain_bytes[:72].decode("utf-8", errors="ignore")
    return pwd_context.verify(plain, hashed)


# ------------------------------------------------------------
# SETUP ADMIN
# ------------------------------------------------------------
@app.post("/setup_admin/")
def setup_admin(username: str = Form(...), password: str = Form(...), db: Session = Depends(get_db)):
    existing = db.query(AdminModel).filter(AdminModel.username == username).first()
    if existing:
        raise HTTPException(status_code=400, detail="Admin already exists")
    admin = AdminModel(username=username, password_hash=get_password_hash(password))
    db.add(admin)
    db.commit()
    return {"message": "Admin created successfully"}


# ------------------------------------------------------------
# ADMIN LOGIN
# ------------------------------------------------------------
@app.post("/login")
def login(admin: AdminLogin, db: Session = Depends(get_db)):
    user = db.query(AdminModel).filter(AdminModel.username == admin.username).first()
    if not user or not verify_password(admin.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid username or password")
    return {"message": "Login successful"}


# ------------------------------------------------------------
# CRUD OPERATIONS
# ------------------------------------------------------------
@app.post("/users/")
def create_user(
    name: str = Form(...),
    age: int = Form(...),
    job: Optional[str] = Form(None),
    city: Optional[str] = Form(None),
    mailid: Optional[str] = Form(None),
    phone: Optional[str] = Form(None),
    db: Session = Depends(get_db),
):
    """Add a new user (Form-based for frontend compatibility)"""
    new_user = UserModel(name=name, age=age, job=job, city=city, mailid=mailid, phone=phone)
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return {"message": "User added successfully", "user_id": new_user.id}


@app.get("/users/")
def get_users(
    name: Optional[str] = Query(None),
    job: Optional[str] = Query(None),
    city: Optional[str] = Query(None),
    mailid: Optional[str] = Query(None),
    phone: Optional[str] = Query(None),
    db: Session = Depends(get_db),
):
    query = db.query(UserModel)
    if name:
        query = query.filter(UserModel.name.ilike(f"%{name}%"))
    if job:
        query = query.filter(UserModel.job.ilike(f"%{job}%"))
    if city:
        query = query.filter(UserModel.city.ilike(f"%{city}%"))
    if mailid:
        query = query.filter(UserModel.mailid.ilike(f"%{mailid}%"))
    if phone:
        query = query.filter(UserModel.phone.ilike(f"%{phone}%"))
    users = query.all()

    return {"users": [
        {
            "id": u.id,
            "name": u.name,
            "age": u.age,
            "job": u.job,
            "city": u.city,
            "mailid": u.mailid,
            "phone": u.phone,
        }
        for u in users
    ]}


@app.put("/users/{user_id}")
def update_user(
    user_id: int,
    name: str = Form(...),
    age: int = Form(...),
    job: Optional[str] = Form(None),
    city: Optional[str] = Form(None),
    mailid: Optional[str] = Form(None),
    phone: Optional[str] = Form(None),
    password: str = Form(...),
    db: Session = Depends(get_db),
):
    admin = db.query(AdminModel).first()
    if not admin or not verify_password(password, admin.password_hash):
        raise HTTPException(status_code=401, detail="Invalid admin password")

    user = db.query(UserModel).filter(UserModel.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    user.name = name
    user.age = age
    user.job = job
    user.city = city
    user.mailid = mailid
    user.phone = phone
    db.commit()
    db.refresh(user)
    return {"message": "User updated successfully"}


@app.delete("/users/{user_id}")
def delete_user(user_id: int, password: str = Query(...), db: Session = Depends(get_db)):
    admin = db.query(AdminModel).first()
    if not admin or not verify_password(password, admin.password_hash):
        raise HTTPException(status_code=401, detail="Invalid admin password")

    user = db.query(UserModel).filter(UserModel.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    db.delete(user)
    db.commit()
    return {"message": "User deleted successfully"}
