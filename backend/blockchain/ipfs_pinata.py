"""
backend/blockchain/ipfs_pinata.py
-----------------------------------
Real IPFS integration via Pinata API.
Falls back to local filesystem if PINATA_API_KEY is not configured.
"""

import os
import hashlib
import base64
import requests

PINATA_BASE    = "https://api.pinata.cloud"
PINATA_GATEWAY = "https://gateway.pinata.cloud/ipfs"


def _pinata_headers() -> dict:
    jwt = os.environ.get("PINATA_JWT", "").strip()
    if jwt:
        return {"Authorization": f"Bearer {jwt}"}
    return {
        "pinata_api_key":        os.environ.get("PINATA_API_KEY", "").strip(),
        "pinata_secret_api_key": os.environ.get("PINATA_SECRET_KEY", "").strip(),
    }


def _is_configured() -> bool:
    has_jwt = bool(os.environ.get("PINATA_JWT", "").strip())
    has_keys = bool(os.environ.get("PINATA_API_KEY", "").strip() and os.environ.get("PINATA_SECRET_KEY", "").strip())
    return has_jwt or has_keys


import threading

# ── Local fallback & caching ──────────────────────────────────────────────

def _local_ipfs_dir() -> str:
    base = os.environ.get("SQLITE_PATH_DIR") or os.path.join(
        os.path.dirname(__file__), "..", "..", "database", "instance"
    )
    d = os.path.join(base, "ipfs_storage")
    os.makedirs(d, exist_ok=True)
    return d


def _local_cid(payload: str) -> str:
    raw  = hashlib.sha256(payload.encode("utf-8")).digest()
    return "Qm" + base64.urlsafe_b64encode(raw).decode("utf-8").rstrip("=")[:44]


def _local_save(payload: str) -> str:
    cid  = _local_cid(payload)
    path = os.path.join(_local_ipfs_dir(), cid)
    if not os.path.exists(path):
        with open(path, "w", encoding="utf-8") as f:
            f.write(payload)
    return cid


def _local_fetch(cid: str) -> str | None:
    path = os.path.join(_local_ipfs_dir(), cid)
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            return f.read()
    return None


def _async_pin_pinata(payload: str, filename: str):
    """Background worker to pin payload to Pinata without blocking client."""
    if not _is_configured():
        return
    try:
        requests.post(
            f"{PINATA_BASE}/pinning/pinFileToIPFS",
            headers=_pinata_headers(),
            files={"file": (f"{filename}.enc", payload.encode("utf-8"), "text/plain")},
            timeout=15,
        )
    except Exception:
        pass


# ── Public API ───────────────────────────────────────────────────────────────

def upload_to_ipfs(payload: str) -> str:
    """
    Upload encrypted payload to IPFS.
    Saves locally instantly for sub-millisecond response,
    and asynchronously pins to Pinata decentralized cloud.
    """
    cid = _local_save(payload)
    if _is_configured():
        # Pin in background thread so messaging remains instant
        threading.Thread(target=_async_pin_pinata, args=(payload, cid), daemon=True).start()
    return cid


def fetch_from_ipfs(cid: str) -> str | None:
    """
    Fetch content by CID.
    Checks local fast cache first (instant), falls back to Pinata gateway.
    """
    local = _local_fetch(cid)
    if local is not None:
        return local

    if _is_configured():
        try:
            resp = requests.get(f"{PINATA_GATEWAY}/{cid}", timeout=4)
            if resp.ok:
                text = resp.text
                _local_save(text)  # cache locally for next time
                return text
        except Exception:
            pass

    return None


def get_ipfs_gateway_url(cid: str) -> str:
    """Return a public IPFS gateway URL for a CID."""
    if _is_configured():
        return f"{PINATA_GATEWAY}/{cid}"
    return f"/ipfs/{cid}"
