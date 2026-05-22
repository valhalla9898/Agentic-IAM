"""Append-only tamper-evident audit ledger.
Writes JSON events to a ledger file and chains them by hashing previous entry.
"""

import hashlib
import json
import logging
from datetime import datetime
from pathlib import Path

LEDGER_PATH = Path("data") / "audit_ledger.log"
LEDGER_PATH.parent.mkdir(parents=True, exist_ok=True)


def _last_hash() -> str:
    try:
        if not LEDGER_PATH.exists():
            return ""
        with LEDGER_PATH.open("rb") as f:
            data = f.read()
            if not data:
                return ""
            last_line = data.strip().split(b"\n")[-1]
            try:
                entry = json.loads(last_line.decode("utf-8"))
                return entry.get("_hash", "")
            except (json.JSONDecodeError, UnicodeDecodeError) as e:
                logging.getLogger(__name__).debug("Failed to decode last audit ledger line: %s", e)
                return ""
    except OSError as e:
        logging.getLogger(__name__).debug("Failed to read audit ledger: %s", e)
        return ""


def append_audit_entry(event: dict) -> bool:
    try:
        prev = _last_hash()
        payload = dict(event)
        payload.setdefault("timestamp", datetime.utcnow().isoformat())
        payload["_prev"] = prev
        # compute hash
        h = hashlib.sha256(json.dumps(payload, sort_keys=True).encode("utf-8")).hexdigest()
        payload["_hash"] = h
        with LEDGER_PATH.open("a", encoding="utf-8") as f:
            f.write(json.dumps(payload, ensure_ascii=False) + "\n")
        return True
    except (OSError, TypeError, ValueError) as e:
        logging.getLogger(__name__).error("Failed to append audit entry: %s", e)
        return False
