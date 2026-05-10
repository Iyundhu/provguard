"""
Verification orchestrator.

This is the main pipeline. Given a saved file, it:
  1. Computes the SHA-256 hash
  2. Detects MIME type
  3. Runs provenance extraction
  4. Queries threat intelligence
  5. Runs behavioral analysis
  6. Combines scores into a decision
  7. Appends provenance blocks to the chain
  8. Persists the File record
  9. Logs the audit event

Returns the saved File record.
"""
import json
import uuid
from pathlib import Path
from sqlalchemy.orm import Session

from app.models.schemas import File, AuditLog
from app.provenance.hashing import compute_sha256
from app.provenance.metadata import detect_mime_type, extract_provenance
from app.provenance.chain import append_block
from app.threat.virustotal import query_hash
from app.threat.behavioral import analyze_behavior
from app.threat.scoring import combine_scores, decide, explain_decision


async def verify_file(
    db: Session,
    file_path: str,
    original_filename: str,
    uploader: str = "anonymous"
) -> File:
    """Run the full verification pipeline on a saved file."""

    file_id = str(uuid.uuid4())
    size_bytes = Path(file_path).stat().st_size

    # Step 1: hash + MIME
    sha256 = compute_sha256(file_path)
    mime_type = detect_mime_type(file_path)

    # Step 2: provenance extraction
    provenance_result = extract_provenance(file_path, mime_type)

    # Step 3: threat intelligence (async)
    threat_result = await query_hash(sha256)

    # Step 4: behavioral analysis
    behavioral_result = analyze_behavior(file_path, mime_type)

    # Step 5: combine and decide
    final_score = combine_scores(
        provenance_score=provenance_result["score"],
        threat_score=threat_result["score"],
        behavioral_score=behavioral_result["score"]
    )
    decision = decide(
        final_score=final_score,
        threat_verdict=threat_result["verdict"],
        behavioral_flags=behavioral_result["flags"]
    )

    # Step 6: persist File record
    file_record = File(
        file_id=file_id,
        original_filename=original_filename,
        sha256=sha256,
        size_bytes=size_bytes,
        mime_type=mime_type,
        uploader=uploader,
        provenance_score=provenance_result["score"],
        threat_score=threat_result["score"],
        behavioral_score=behavioral_result["score"],
        final_score=final_score,
        decision=decision,
        provenance_details=json.dumps(provenance_result),
        threat_details=json.dumps(threat_result),
        behavioral_details=json.dumps(behavioral_result),
    )
    db.add(file_record)
    db.commit()
    db.refresh(file_record)

    # Step 7: append provenance blocks (UPLOAD, VERIFY, DECISION)
    append_block(db, file_id, "UPLOAD", {
        "filename": original_filename,
        "sha256": sha256,
        "size_bytes": size_bytes,
        "mime_type": mime_type,
        "uploader": uploader
    })
    append_block(db, file_id, "VERIFY", {
        "provenance": provenance_result,
        "threat": threat_result,
        "behavioral": behavioral_result
    })
    append_block(db, file_id, "DECISION", {
        "final_score": final_score,
        "decision": decision,
        "explanation": explain_decision(decision)
    })

    # Step 8: audit log
    db.add(AuditLog(
        actor=uploader,
        action="VERIFY_FILE",
        target=file_id,
        details=json.dumps({
            "filename": original_filename,
            "decision": decision,
            "final_score": final_score
        })
    ))
    db.commit()

    return file_record
