"""
Database models for ProvGuard.

Three tables:
- File: each uploaded file's metadata
- ProvenanceBlock: hash-chained ledger of verification events (mimics blockchain immutability)
- AuditLog: every action taken by the system, for transparency
"""
from datetime import datetime
from sqlalchemy import Column, Integer, String, Float, DateTime, Text, ForeignKey
from sqlalchemy.orm import relationship
from app.models.database import Base


class File(Base):
    __tablename__ = "files"

    id = Column(Integer, primary_key=True, index=True)
    file_id = Column(String, unique=True, index=True)  # public UUID
    original_filename = Column(String)
    sha256 = Column(String, index=True)
    size_bytes = Column(Integer)
    mime_type = Column(String)
    uploader = Column(String, default="anonymous")
    uploaded_at = Column(DateTime, default=datetime.utcnow)

    # Scores
    provenance_score = Column(Float, default=0.0)
    threat_score = Column(Float, default=0.0)
    behavioral_score = Column(Float, default=0.0)
    final_score = Column(Float, default=0.0)
    decision = Column(String)  # TRUSTED / SUSPICIOUS / MALICIOUS

    # Detail blobs (JSON-encoded strings)
    provenance_details = Column(Text)
    threat_details = Column(Text)
    behavioral_details = Column(Text)

    blocks = relationship("ProvenanceBlock", back_populates="file")


class ProvenanceBlock(Base):
    """
    Hash-chained ledger entry. Each block stores the hash of the previous block,
    so any tampering breaks the chain. This is how we get blockchain-style
    immutability without running an actual blockchain.
    """
    __tablename__ = "provenance_chain"

    id = Column(Integer, primary_key=True, index=True)
    block_index = Column(Integer, index=True)
    file_id = Column(String, ForeignKey("files.file_id"))
    timestamp = Column(DateTime, default=datetime.utcnow)
    event_type = Column(String)  # e.g. UPLOAD, VERIFY, DECISION
    payload = Column(Text)  # JSON string of event details
    previous_hash = Column(String)
    block_hash = Column(String, index=True)
    signature = Column(Text)  # digital signature of block_hash

    file = relationship("File", back_populates="blocks")


class AuditLog(Base):
    __tablename__ = "audit_log"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    actor = Column(String, default="system")
    action = Column(String)
    target = Column(String)
    details = Column(Text)
