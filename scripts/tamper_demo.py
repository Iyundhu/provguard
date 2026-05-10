"""
Demo helper: tamper with the provenance chain to demonstrate detection.

Run AFTER you've uploaded a few demo files. This corrupts one block in the ledger
so the /chain page's "Verify chain" button reports the violation.

Usage:
    python scripts/tamper_demo.py
    python scripts/tamper_demo.py --restore   (undo)
"""
import sys
import sqlite3
from pathlib import Path

DB = Path(__file__).resolve().parent.parent / "data" / "provguard.db"
BACKUP = Path(__file__).resolve().parent.parent / "data" / "provguard.db.backup"


def tamper():
    if not DB.exists():
        print(f"Database not found at {DB}. Run the app and upload files first.")
        sys.exit(1)

    # Backup first
    BACKUP.write_bytes(DB.read_bytes())
    print(f"✓ Backup saved to {BACKUP}")

    conn = sqlite3.connect(DB)
    cur = conn.cursor()
    cur.execute("SELECT id, block_index FROM provenance_chain ORDER BY block_index ASC LIMIT 5")
    rows = cur.fetchall()
    if len(rows) < 2:
        print("Need at least 2 blocks in the chain. Upload more files first.")
        conn.close()
        return

    target_id = rows[1][0]
    target_index = rows[1][1]
    cur.execute(
        "UPDATE provenance_chain SET payload=? WHERE id=?",
        ('{"tampered": true, "note": "this block was modified after the fact"}', target_id)
    )
    conn.commit()
    conn.close()
    print(f"✓ Tampered with block #{target_index}")
    print("  Now visit /chain and click 'Verify chain' to see the violation.")


def restore():
    if not BACKUP.exists():
        print(f"No backup found at {BACKUP}.")
        sys.exit(1)
    DB.write_bytes(BACKUP.read_bytes())
    print(f"✓ Database restored from backup.")


if __name__ == "__main__":
    if "--restore" in sys.argv:
        restore()
    else:
        tamper()
