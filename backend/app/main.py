"""
ProvGuard - main FastAPI application.

Run locally:
    cd backend && uvicorn app.main:app --reload

Production (Render):
    uvicorn app.main:app --host 0.0.0.0 --port $PORT
"""
from pathlib import Path
from fastapi import FastAPI, Request, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session

from app.config import settings
from app.models.database import engine, get_db
from app.models.schemas import Base
from app.routes.api import router as api_router
from app.provenance.signing import ensure_keys_exist


# Create database tables on startup
Base.metadata.create_all(bind=engine)
# Ensure the system signing keys exist
ensure_keys_exist()

app = FastAPI(
    title=settings.APP_NAME,
    description=settings.APP_TAGLINE,
    version=settings.VERSION,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(api_router)

# Static files and templates for the frontend
FRONTEND_DIR = Path(__file__).resolve().parent.parent.parent / "frontend"
STATIC_DIR = FRONTEND_DIR / "static"
STATIC_DIR.mkdir(parents=True, exist_ok=True)
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
templates = Jinja2Templates(directory=str(FRONTEND_DIR / "templates"))


@app.get("/", response_class=HTMLResponse)
def index(request: Request, db: Session = Depends(get_db)):
    from app.models.schemas import File
    recent = db.query(File).order_by(File.uploaded_at.desc()).limit(10).all()
    return templates.TemplateResponse("index.html", {
        "request": request,
        "recent_files": recent,
        "app_name": settings.APP_NAME,
        "tagline": settings.APP_TAGLINE
    })


@app.get("/file/{file_id}", response_class=HTMLResponse)
def file_view(file_id: str, request: Request, db: Session = Depends(get_db)):
    from app.models.schemas import File, ProvenanceBlock
    file_record = db.query(File).filter(File.file_id == file_id).first()
    if not file_record:
        return HTMLResponse("<h1>File not found</h1>", status_code=404)
    blocks = db.query(ProvenanceBlock).filter(
        ProvenanceBlock.file_id == file_id
    ).order_by(ProvenanceBlock.block_index.asc()).all()
    return templates.TemplateResponse("file.html", {
        "request": request,
        "file": file_record,
        "blocks": blocks,
        "app_name": settings.APP_NAME
    })


@app.get("/chain", response_class=HTMLResponse)
def chain_view(request: Request, db: Session = Depends(get_db)):
    from app.models.schemas import ProvenanceBlock
    blocks = db.query(ProvenanceBlock).order_by(
        ProvenanceBlock.block_index.desc()
    ).limit(100).all()
    return templates.TemplateResponse("chain.html", {
        "request": request,
        "blocks": list(reversed(blocks)),
        "app_name": settings.APP_NAME
    })


@app.get("/health")
def health():
    return {"status": "ok", "app": settings.APP_NAME, "version": settings.VERSION}
