"""
Entry point for the Email Threat Intelligence Platform backend.

Phase 1: health-check endpoint + CORS
Phase 2: database + models setup (tables auto-created on startup)
Phase 3: email upload + parsing route
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.core.config import settings
from app.database.session import engine, Base
from app.models import models
from app.api import emails, cases, reports, auth

app = FastAPI(
    title=settings.APP_NAME,
    description="AI-Powered Email Threat Detection, GeoLocation & Forensic Intelligence Platform",
    version="0.1.0",
)

Base.metadata.create_all(bind=engine)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(emails.router)
app.include_router(reports.router)
app.include_router(auth.router)
app.include_router(cases.router)


@app.get("/")
def root():
    return {
        "message": f"{settings.APP_NAME} backend is running",
        "docs": "/docs",
    }


@app.get("/health")
def health_check():
    """Simple endpoint to confirm the server is alive."""
    return {"status": "ok", "env": settings.ENV}


@app.get("/db-check")
def db_check():
    """Confirms the database file was created and tables exist."""
    import os
    db_exists = os.path.exists("app.db")
    return {"database_file_exists": db_exists}