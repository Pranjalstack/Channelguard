import hashlib
import json
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path


# ============================================================
# Audit log location
# ============================================================

BASE_DIR = Path(__file__).resolve().parent.parent

DATA_DIR = BASE_DIR / "data"

AUDIT_FILE = DATA_DIR / "audit.jsonl"


# Make sure the data directory exists
DATA_DIR.mkdir(
    parents=True,
    exist_ok=True
)


# Prevent simultaneous writes from corrupting the log
AUDIT_LOCK = threading.Lock()


# ============================================================
# Hashing
# ============================================================

def hash_sensitive_value(value: str):
    """
    Create a SHA-256 hash of a sensitive value.

    The raw sensitive value is never stored in the audit log.
    """

    return hashlib.sha256(
        value.encode("utf-8")
    ).hexdigest()


# ============================================================
# Create safe detection record
# ============================================================

def make_safe_detection(detection):
    """
    Convert a detector result into an audit-safe record.

    The raw 'value' field is intentionally removed.
    """

    safe_detection = {
        "category": detection["category"],
        "start": detection["start"],
        "end": detection["end"],
        "source": detection.get(
            "source",
            "unknown"
        )
    }

    if "normalization" in detection:
        safe_detection["normalization"] = (
            detection["normalization"]
        )

    if "confidence" in detection:
        safe_detection["confidence"] = (
            detection["confidence"]
        )

    if detection.get("value"):
        safe_detection["value_hash"] = (
            hash_sensitive_value(
                detection["value"]
            )
        )

    if detection.get("memory_hit"):
        safe_detection["memory_hit"] = True

    return safe_detection


# ============================================================
# Write audit event
# ============================================================

def write_audit_event(
    session_id,
    channel,
    status,
    categories,
    sanitized_content,
    detections
):
    """
    Write one safe audit event to JSONL.

    IMPORTANT:
    Raw event content and raw sensitive values are never stored.
    """

    audit_id = str(
        uuid.uuid4()
    )

    timestamp = datetime.now(
        timezone.utc
    ).isoformat()

    safe_detections = [
        make_safe_detection(
            detection
        )
        for detection in detections
    ]

    audit_event = {
        "audit_id": audit_id,

        "timestamp": timestamp,

        "session_id": session_id,

        "channel": channel,

        "status": status,

        "categories": categories,

        "sanitized_content": sanitized_content,

        "detections": safe_detections
    }

    with AUDIT_LOCK:

        with AUDIT_FILE.open(
            "a",
            encoding="utf-8"
        ) as file:

            file.write(
                json.dumps(
                    audit_event,
                    ensure_ascii=False
                )
                + "\n"
            )

    return audit_event


# ============================================================
# Read audit events
# ============================================================

def read_audit_events(limit=50):
    """
    Read recent audit events.

    Only the safe audit records are returned.
    """

    if not AUDIT_FILE.exists():
        return []

    with AUDIT_LOCK:

        lines = AUDIT_FILE.read_text(
            encoding="utf-8"
        ).splitlines()

    events = []

    for line in reversed(lines):

        if not line.strip():
            continue

        try:

            events.append(
                json.loads(line)
            )

        except json.JSONDecodeError:
            continue

        if len(events) >= limit:
            break

    return events