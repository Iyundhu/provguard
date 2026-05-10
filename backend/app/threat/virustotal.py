"""
VirusTotal threat intelligence client.

Queries VT's public API by SHA-256 hash. If the hash is known, returns the
detection statistics from 70+ antivirus engines. If unknown, returns a neutral
result (we don't auto-upload files to VT for privacy reasons).

Free tier: 4 requests/minute, 500/day. We cache results in-process to avoid
hammering the API during demos.
"""
import httpx
from app.config import settings


# Simple in-memory cache: sha256 -> result dict
_cache: dict[str, dict] = {}


async def query_hash(sha256: str) -> dict:
    """
    Look up a file hash on VirusTotal.

    Returns:
        {
            "available": bool,         # was VT reachable / API key present
            "known": bool,             # was the hash in VT's database
            "malicious": int,          # engines flagging as malicious
            "suspicious": int,
            "harmless": int,
            "undetected": int,
            "total_engines": int,
            "verdict": str,            # CLEAN / SUSPICIOUS / MALICIOUS / UNKNOWN
            "score": int,              # 0-100, higher = safer
            "details": str
        }
    """
    if sha256 in _cache:
        return _cache[sha256]

    if not settings.VIRUSTOTAL_API_KEY:
        result = {
            "available": False,
            "known": False,
            "malicious": 0, "suspicious": 0, "harmless": 0, "undetected": 0,
            "total_engines": 0,
            "verdict": "UNKNOWN",
            "score": 50,  # neutral score when intel is unavailable
            "details": "VirusTotal API key not configured. Threat intelligence skipped."
        }
        _cache[sha256] = result
        return result

    url = f"{settings.VIRUSTOTAL_URL}/{sha256}"
    headers = {"x-apikey": settings.VIRUSTOTAL_API_KEY}

    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            response = await client.get(url, headers=headers)

        if response.status_code == 404:
            # Hash not in VT database — file is unknown to threat intel
            result = {
                "available": True, "known": False,
                "malicious": 0, "suspicious": 0, "harmless": 0, "undetected": 0,
                "total_engines": 0,
                "verdict": "UNKNOWN",
                "score": 60,  # slight benefit of the doubt
                "details": "File hash not found in VirusTotal database (new or private file)."
            }
            _cache[sha256] = result
            return result

        if response.status_code != 200:
            result = {
                "available": False, "known": False,
                "malicious": 0, "suspicious": 0, "harmless": 0, "undetected": 0,
                "total_engines": 0,
                "verdict": "UNKNOWN",
                "score": 50,
                "details": f"VirusTotal API returned HTTP {response.status_code}."
            }
            return result

        data = response.json()
        stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        harmless = stats.get("harmless", 0)
        undetected = stats.get("undetected", 0)
        total = malicious + suspicious + harmless + undetected

        if malicious >= 3:
            verdict = "MALICIOUS"
            score = 0
        elif malicious >= 1 or suspicious >= 3:
            verdict = "SUSPICIOUS"
            score = 25
        elif total > 0:
            verdict = "CLEAN"
            score = 95
        else:
            verdict = "UNKNOWN"
            score = 50

        result = {
            "available": True, "known": True,
            "malicious": malicious, "suspicious": suspicious,
            "harmless": harmless, "undetected": undetected,
            "total_engines": total,
            "verdict": verdict,
            "score": score,
            "details": (
                f"VirusTotal: {malicious} malicious, {suspicious} suspicious, "
                f"{harmless} harmless, {undetected} undetected across {total} engines."
            )
        }
        _cache[sha256] = result
        return result

    except Exception as e:
        return {
            "available": False, "known": False,
            "malicious": 0, "suspicious": 0, "harmless": 0, "undetected": 0,
            "total_engines": 0,
            "verdict": "UNKNOWN",
            "score": 50,
            "details": f"VirusTotal request failed: {str(e)[:100]}"
        }
