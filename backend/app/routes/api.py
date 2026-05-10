"""
FastAPI routes.

Endpoints:
  POST /api/upload              - upload a file and run verification
  GET  /api/file/{file_id}      - get verification details for a file
  GET  /api/file/{file_id}/certificate  - download PDF certificate
  GET  /api/files               - list all verified files (audit dashboard)
  GET  /api/chain/verify        - verify the integrity of the entire ledger
  GET  /api/chain               - return the full provenance chain
  GET  /api/stats               - dashboard statistics
"""
import json
import shutil
import uuid
from pathlib import Path
from fastapi import APIRouter, Depends, UploadFile, File as FastAPIFile, HTTPException
from fastapi.responses import Response
from sqlalchemy.orm import Session

from app.config import settings
from app.models.database import get_db
from app.models.schemas import File, ProvenanceBlock, AuditLog
from app.provenance.chain import verify_chain
from app.utils.orchestrator import verify_file
from app.utils.certificate import generate_certificate

router = APIRouter(prefix="/api", tags=["provguard"])


@router.post("/upload")
async def upload_file(
    file: UploadFile = FastAPIFile(...),
    uploader: str = "anonymous",
    db: Session = Depends(get_db)
):
    """Upload a file and run the full verification pipeline."""
    if not file.filename:
        raise HTTPException(status_code=400, detail="No filename provided.")

    # Save uploaded file to disk
    temp_name = f"{uuid.uuid4()}_{Path(file.filename).name}"
    save_path = settings.UPLOAD_DIR / temp_name

    with open(save_path, "wb") as out:
        shutil.copyfileobj(file.file, out)

    if save_path.stat().st_size > settings.MAX_UPLOAD_SIZE:
        save_path.unlink(missing_ok=True)
        raise HTTPException(status_code=413, detail="File too large.")

    file_record = await verify_file(
        db=db,
        file_path=str(save_path),
        original_filename=file.filename,
        uploader=uploader
    )

    return _serialize_file(file_record, db)


@router.get("/file/{file_id}")
def get_file(file_id: str, db: Session = Depends(get_db)):
    file_record = db.query(File).filter(File.file_id == file_id).first()
    if not file_record:
        raise HTTPException(status_code=404, detail="File not found.")
    return _serialize_file(file_record, db)


@router.get("/file/{file_id}/certificate")
def download_certificate(file_id: str, db: Session = Depends(get_db)):
    file_record = db.query(File).filter(File.file_id == file_id).first()
    if not file_record:
        raise HTTPException(status_code=404, detail="File not found.")
    blocks = db.query(ProvenanceBlock).filter(
        ProvenanceBlock.file_id == file_id
    ).order_by(ProvenanceBlock.block_index.asc()).all()

    pdf_bytes = generate_certificate(file_record, blocks)
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="provguard-{file_id[:8]}.pdf"'
        }
    )


@router.get("/files")
def list_files(limit: int = 50, db: Session = Depends(get_db)):
    files = db.query(File).order_by(File.uploaded_at.desc()).limit(limit).all()
    return [{
        "file_id": f.file_id,
        "filename": f.original_filename,
        "sha256": f.sha256,
        "size_bytes": f.size_bytes,
        "decision": f.decision,
        "final_score": round(f.final_score, 1),
        "uploaded_at": f.uploaded_at.isoformat()
    } for f in files]


@router.get("/chain/verify")
def verify_ledger(db: Session = Depends(get_db)):
    """Verify the integrity of the entire hash-chained ledger."""
    return verify_chain(db)


@router.get("/chain")
def get_chain(limit: int = 100, db: Session = Depends(get_db)):
    blocks = db.query(ProvenanceBlock).order_by(
        ProvenanceBlock.block_index.desc()
    ).limit(limit).all()
    return [{
        "block_index": b.block_index,
        "file_id": b.file_id,
        "timestamp": b.timestamp.isoformat(),
        "event_type": b.event_type,
        "previous_hash": b.previous_hash,
        "block_hash": b.block_hash,
        "signature_preview": b.signature[:32] + "..."
    } for b in reversed(blocks)]


@router.get("/stats")
def get_stats(db: Session = Depends(get_db)):
    """Dashboard statistics."""
    total = db.query(File).count()
    trusted = db.query(File).filter(File.decision == "TRUSTED").count()
    suspicious = db.query(File).filter(File.decision == "SUSPICIOUS").count()
    malicious = db.query(File).filter(File.decision == "MALICIOUS").count()
    blocks = db.query(ProvenanceBlock).count()
    return {
        "total_files": total,
        "trusted": trusted,
        "suspicious": suspicious,
        "malicious": malicious,
        "blocks_in_chain": blocks
    }


def _serialize_file(file_record: File, db: Session) -> dict:
    """Convert a File record (and its chain entries) into a JSON response."""
    blocks = db.query(ProvenanceBlock).filter(
        ProvenanceBlock.file_id == file_record.file_id
    ).order_by(ProvenanceBlock.block_index.asc()).all()

    return {
        "file_id": file_record.file_id,
        "filename": file_record.original_filename,
        "sha256": file_record.sha256,
        "size_bytes": file_record.size_bytes,
        "mime_type": file_record.mime_type,
        "uploader": file_record.uploader,
        "uploaded_at": file_record.uploaded_at.isoformat(),
        "scores": {
            "provenance": round(file_record.provenance_score, 1),
            "threat": round(file_record.threat_score, 1),
            "behavioral": round(file_record.behavioral_score, 1),
            "final": round(file_record.final_score, 1)
        },
        "decision": file_record.decision,
        "provenance_details": json.loads(file_record.provenance_details or "{}"),
        "threat_details": json.loads(file_record.threat_details or "{}"),
        "behavioral_details": json.loads(file_record.behavioral_details or "{}"),
        "chain": [{
            "block_index": b.block_index,
            "event_type": b.event_type,
            "timestamp": b.timestamp.isoformat(),
            "block_hash": b.block_hash,
            "previous_hash": b.previous_hash,
            "signature_preview": b.signature[:32] + "..."
        } for b in blocks]
    }
