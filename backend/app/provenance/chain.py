"""
Hash-chained provenance ledger.

Each block contains the hash of the previous block plus a digital signature.
Tampering with any historical block breaks the chain — the hashes no longer match.

This gives us blockchain-style tamper-evidence without the overhead of running
a distributed blockchain. Suitable for single-organization or consortium use.
"""
import json
from datetime import datetime
from sqlalchemy.orm import Session
from app.models.schemas import ProvenanceBlock
from app.provenance.hashing import compute_sha256_bytes
from app.provenance.signing import sign, verify

GENESIS_HASH = "0" * 64  # the "previous hash" for the very first block ever


def _serialize_block_for_hashing(
    block_index: int,
    file_id: str,
    timestamp: str,
    event_type: str,
    payload: dict,
    previous_hash: str
) -> str:
    """Deterministic JSON serialization so hashes are reproducible."""
    return json.dumps({
        "block_index": block_index,
        "file_id": file_id,
        "timestamp": timestamp,
        "event_type": event_type,
        "payload": payload,
        "previous_hash": previous_hash
    }, sort_keys=True, separators=(",", ":"))


def get_last_block(db: Session) -> ProvenanceBlock | None:
    return db.query(ProvenanceBlock).order_by(ProvenanceBlock.block_index.desc()).first()


def append_block(
    db: Session,
    file_id: str,
    event_type: str,
    payload: dict
) -> ProvenanceBlock:
    """
    Append a new block to the chain.
    Computes the block hash from its contents + previous block's hash,
    then signs it with the system private key.
    """
    last = get_last_block(db)
    next_index = (last.block_index + 1) if last else 0
    previous_hash = last.block_hash if last else GENESIS_HASH

    timestamp = datetime.utcnow().isoformat()

    serialized = _serialize_block_for_hashing(
        next_index, file_id, timestamp, event_type, payload, previous_hash
    )
    block_hash = compute_sha256_bytes(serialized.encode("utf-8"))
    signature = sign(block_hash)

    block = ProvenanceBlock(
        block_index=next_index,
        file_id=file_id,
        timestamp=datetime.fromisoformat(timestamp),
        event_type=event_type,
        payload=json.dumps(payload),
        previous_hash=previous_hash,
        block_hash=block_hash,
        signature=signature
    )
    db.add(block)
    db.commit()
    db.refresh(block)
    return block


def verify_chain(db: Session) -> dict:
    """
    Walk the entire chain and verify each block.
    Returns a report showing which blocks are valid and where (if anywhere)
    the chain is broken.
    """
    blocks = db.query(ProvenanceBlock).order_by(ProvenanceBlock.block_index.asc()).all()

    if not blocks:
        return {"valid": True, "total_blocks": 0, "broken_at": None, "details": []}

    details = []
    expected_previous_hash = GENESIS_HASH
    chain_valid = True
    broken_at = None

    for block in blocks:
        block_report = {
            "block_index": block.block_index,
            "file_id": block.file_id,
            "timestamp": block.timestamp.isoformat(),
            "event_type": block.event_type,
            "previous_hash_match": block.previous_hash == expected_previous_hash,
            "hash_recomputes_correctly": False,
            "signature_valid": False
        }

        # Recompute the hash from stored content
        try:
            payload_dict = json.loads(block.payload)
        except Exception:
            payload_dict = {}

        serialized = _serialize_block_for_hashing(
            block.block_index,
            block.file_id,
            block.timestamp.isoformat(),
            block.event_type,
            payload_dict,
            block.previous_hash
        )
        recomputed_hash = compute_sha256_bytes(serialized.encode("utf-8"))
        block_report["hash_recomputes_correctly"] = (recomputed_hash == block.block_hash)

        # Verify the signature
        block_report["signature_valid"] = verify(block.block_hash, block.signature)

        block_valid = (
            block_report["previous_hash_match"]
            and block_report["hash_recomputes_correctly"]
            and block_report["signature_valid"]
        )

        if not block_valid and chain_valid:
            chain_valid = False
            broken_at = block.block_index

        details.append(block_report)
        expected_previous_hash = block.block_hash

    return {
        "valid": chain_valid,
        "total_blocks": len(blocks),
        "broken_at": broken_at,
        "details": details
    }
