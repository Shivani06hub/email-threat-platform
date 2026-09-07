"""
Authentication routes: register a new analyst account, and login
to receive a JWT access token.
"""

from fastapi import APIRouter, Depends, HTTPException
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.database.session import get_db
from app.models.models import User
from app.core.security import hash_password, verify_password, create_access_token

router = APIRouter(prefix="/api/auth", tags=["auth"])


class RegisterRequest(BaseModel):
    username: str
    password: str


@router.post("/register")
def register(payload: RegisterRequest, db: Session = Depends(get_db)):
    existing = db.query(User).filter(User.username == payload.username).first()
    if existing:
        raise HTTPException(status_code=400, detail="Username already taken")

    new_user = User(
        username=payload.username,
        password_hash=hash_password(payload.password),
        role="analyst",
    )
    db.add(new_user)
    db.commit()
    return {"message": "Account created successfully. Please log in."}


@router.post("/login")
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == form_data.username).first()
    if not user or not verify_password(form_data.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Incorrect username or password")

    token = create_access_token(username=user.username)
    return {"access_token": token, "token_type": "bearer"}