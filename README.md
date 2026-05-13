# ProvGuard

> Trust by Verification, Not Detection.

**ProvGuard** is a prototype implementation of the *Digital Provenance & Preemptive Cybersecurity* concept, built for the CSC3217 Emerging Trends in Computer Science course.

It demonstrates how cryptographic provenance and preemptive threat analysis can be fused into a single gateway: every file entering an organisation is hashed, signed, checked against threat intelligence, behaviourally analysed, and recorded on a tamper-evident ledger — *before* it is opened or executed.

---

## What it does

For every uploaded file, ProvGuard:

1. Computes a **SHA-256 fingerprint**.
2. Extracts **provenance signals** (C2PA Content Credentials, EXIF, PDF digital signatures).
3. Queries **VirusTotal** for known threat intelligence on the hash.
4. Runs **behavioural analysis** — Shannon entropy, magic-byte / extension mismatch, suspicious patterns (PE headers, PDF JavaScript, Office macros, EICAR signature).
5. Combines the three sub-scores into a final **risk score** and decision: `TRUSTED` / `SUSPICIOUS` / `MALICIOUS`.
6. Appends the verification event to a **hash-chained ledger**, with each block digitally signed using RSA-2048.
7. Issues a downloadable **PDF certificate** of verification.

The hash-chained ledger gives blockchain-style tamper-evidence without running an actual blockchain — any modification to a historical block breaks the chain on the next verification.

---

## Architecture

```
                       ┌────────────────────────────────────────┐
                       │       Frontend (HTML + Tailwind)       │
                       │   Upload • Result • Chain dashboard    │
                       └──────────────────┬─────────────────────┘
                                          │ REST
                       ┌──────────────────▼─────────────────────┐
                       │          FastAPI gateway               │
                       └──┬──────────────┬──────────────┬───────┘
                          │              │              │
              ┌───────────▼──┐   ┌───────▼─────┐   ┌────▼──────┐
              │  Provenance  │   │   Threat    │   │ Behavior  │
              │   engine     │   │ intelligence│   │  engine   │
              │ C2PA / EXIF  │   │ (VirusTotal)│   │ entropy / │
              │ hashing /    │   │             │   │ heuristics│
              │ signing      │   │             │   │           │
              └───────┬──────┘   └──────┬──────┘   └─────┬─────┘
                      │                 │                │
                      └─────────┬───────┴────────────────┘
                                │
                       ┌────────▼─────────┐
                       │ Risk scorer      │
                       │ + Decision logic │
                       └────────┬─────────┘
                                │
                       ┌────────▼─────────┐
                       │ Hash-chained     │
                       │ ledger (SQLite)  │
                       │ + RSA signatures │
                       └──────────────────┘
```

---

## Tech stack

| Layer | Technology |
|---|---|
| Backend | Python 3.11, FastAPI, SQLAlchemy |
| Database | SQLite (zero-config, single-file) |
| Cryptography | `cryptography` library (RSA-2048, SHA-256, PSS) |
| Threat intel | VirusTotal Public API |
| Frontend | Jinja2 templates + Tailwind CSS |
| PDF generation | ReportLab |
| Deployment | Render (free tier) |

---

## Quick start (local)

```bash
# 1. Clone and enter the repo
git clone <your-repo-url> provguard
cd provguard

# 2. Set up Python environment
cd backend
python -m venv venv
source venv/bin/activate         # Windows: venv\Scripts\activate
pip install -r requirements.txt

# 3. Configure environment
cd ..
cp .env.example .env
# Edit .env and add your VirusTotal API key (free at virustotal.com)

# 4. Run the server
cd backend
uvicorn app.main:app --reload

# 5. Open the dashboard
open http://localhost:8000
```

---

## Running the demo

```bash
# Generate a set of demo files (clean PDF, EICAR test, disguised PE, high-entropy)
python scripts/generate_demo_files.py
```

Then walk through this sequence in the UI:

1. **Upload `clean_document.pdf`** → expect `TRUSTED` or near-trusted (good provenance, no threats).
2. **Upload `eicar_test.txt`** → expect `MALICIOUS` (industry-standard safe malware test signature, detected by VT and behavioural engine).
3. **Upload `disguised.pdf`** → expect `MALICIOUS` (extension mismatch + embedded PE header).
4. **Upload `high_entropy.bin`** → expect `SUSPICIOUS` (no provenance, no threat intel match, high entropy).
5. **Visit `/chain`** and click **Verify chain** — the entire ledger validates.
6. **Run `python scripts/tamper_demo.py`** to corrupt one block in the database directly.
7. **Re-click Verify chain** — the integrity violation is detected and the broken block is identified.
8. **Run `python scripts/tamper_demo.py --restore`** to put the database back.

---

## Project structure

```
provguard/
├── backend/
│   ├── app/
│   │   ├── main.py                  # FastAPI entry point
│   │   ├── config.py                # Settings + env vars
│   │   ├── models/
│   │   │   ├── database.py          # SQLAlchemy session
│   │   │   └── schemas.py           # ORM models (File, ProvenanceBlock, AuditLog)
│   │   ├── provenance/
│   │   │   ├── hashing.py           # SHA-256
│   │   │   ├── signing.py           # RSA-2048 sign/verify
│   │   │   ├── chain.py             # Hash-chained ledger
│   │   │   └── metadata.py          # C2PA / EXIF / PDF metadata
│   │   ├── threat/
│   │   │   ├── virustotal.py        # VT API client
│   │   │   ├── behavioral.py        # Entropy + heuristics
│   │   │   └── scoring.py           # Score combination + decision
│   │   ├── utils/
│   │   │   ├── orchestrator.py      # Verification pipeline
│   │   │   └── certificate.py       # PDF certificate generator
│   │   └── routes/
│   │       └── api.py               # REST endpoints
│   ├── tests/
│   └── requirements.txt
├── frontend/
│   ├── templates/
│   │   ├── base.html
│   │   ├── index.html               # Upload + dashboard
│   │   ├── file.html                # Verification result
│   │   └── chain.html               # Provenance ledger
│   └── static/
├── scripts/
│   ├── generate_demo_files.py
│   └── tamper_demo.py
├── data/                            # SQLite DB, uploads, keys (gitignored)
├── docs/
├── .env.example
├── .gitignore
├── render.yaml
└── README.md
```

---

## API reference

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/api/upload` | Upload a file and run verification |
| `GET` | `/api/file/{file_id}` | Get verification details for a file |
| `GET` | `/api/file/{file_id}/certificate` | Download PDF certificate |
| `GET` | `/api/files` | List recently verified files |
| `GET` | `/api/chain` | Return the full provenance chain |
| `GET` | `/api/chain/verify` | Verify ledger integrity |
| `GET` | `/api/stats` | Dashboard statistics |
| `GET` | `/health` | Health check |

Full interactive docs at `/docs` (FastAPI auto-generated Swagger UI).

---

## Deployment to Render

1. Push the repo to GitHub.
2. In Render, create a new **Web Service** pointing at your repo. The included `render.yaml` configures everything.
3. Add `VIRUSTOTAL_API_KEY` as an environment variable in the Render dashboard.
4. Deploy. Render gives you a public URL like `https://provguard.onrender.com`.

> Render's free tier sleeps after inactivity — hit the URL once before the live demo to wake the instance.

---

## Mapping to course concepts

| Concept | Implementation |
|---|---|
| Cryptographic hashing | `provenance/hashing.py` (SHA-256) |
| Digital signatures | `provenance/signing.py` (RSA-2048 + PSS padding) |
| C2PA Content Credentials | `provenance/metadata.py` (marker detection) |
| Tamper-evident ledger | `provenance/chain.py` (hash-chained blocks + signatures) |
| Threat intelligence | `threat/virustotal.py` (VT API integration) |
| Preemptive behavioural analysis | `threat/behavioral.py` (entropy + pattern heuristics) |
| Risk scoring | `threat/scoring.py` (weighted combination + decision) |
| Audit trail | `models/schemas.py` (AuditLog table) |

---

## Limitations and future work

- **C2PA validation** is currently a marker scan. Production deployment would integrate the full `c2pa-rs` validation library.
- **Behavioural analysis** uses rule-based heuristics. A natural extension is an ML classifier trained on the EMBER or Microsoft Malware datasets.
- **Ledger** is single-organisation. A consortium deployment would replicate blocks across organisations or anchor to a public blockchain.
- **Post-quantum cryptography** is not yet implemented. RSA-2048 is sufficient for the demo but should migrate to lattice-based signatures (e.g. CRYSTALS-Dilithium) for long-term durability.

---

## Course context


Topic: **Digital Provenance & Preemptive Cybersecurity**.
Local relevance: positioned for Ugandan financial services (mobile money fraud preemption), media verification (election misinformation), and government software supply chain (NITA-U procurement).

---

## License

Educational / academic use.
