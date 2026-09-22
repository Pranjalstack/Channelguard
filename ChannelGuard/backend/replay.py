import json
from pathlib import Path

from backend.detectors.pii_detector import (
    detect_pii,
    redact_text
)

from backend.session_memory import (
    remember_detections,
    find_memory_matches,
    clear_session
)

from backend.audit_log import (
    write_audit_event
)


# ============================================================
# Channel mapping
# ============================================================

CHANNEL_MAP = {
    "tool_response": "tool_output",
    "tool_output": "tool_output",
    "tool_call": "tool_output",

    "inter_agent_message": "agent_message",
    "inter-agent-message": "agent_message",
    "agent_message": "agent_message",
    "inter_agent": "agent_message",

    "log": "runtime_log",
    "runtime_log": "runtime_log",
    "system_log": "runtime_log",

    "debug": "debug_event",
    "debug_event": "debug_event",
    "intermediate": "debug_event",
    "intermediate_execution": "debug_event",
}


CHANNEL_NAMES = {
    "agent_message": "Agent-to-Agent Message",
    "tool_output": "Tool Output",
    "runtime_log": "Runtime Log",
    "debug_event": "Debug Event"
}


CHANNEL_POLICIES = {
    "agent_message": "REDACT",
    "tool_output": "REDACT",
    "runtime_log": "ALERT",
    "debug_event": "ALERT"
}


# ============================================================
# Normalize channel names
# ============================================================

def normalize_channel(channel):
    """Convert an AgentLeak-style channel to ChannelGuard's channel."""

    if not channel:
        return None

    original = str(channel).strip().lower()

    normalized = (
        original
        .replace(" ", "_")
        .replace("-", "_")
    )

    if normalized in CHANNEL_MAP:
        return CHANNEL_MAP[normalized]

    # Flexible fallback matching
    if "tool" in normalized:
        return "tool_output"

    if (
        "inter" in normalized
        and "agent" in normalized
    ):
        return "agent_message"

    if "debug" in normalized:
        return "debug_event"

    if (
        "log" in normalized
        or "logging" in normalized
    ):
        return "runtime_log"

    if "intermediate" in normalized:
        return "debug_event"

    return None


# ============================================================
# Convert structured event content to text
# ============================================================

def content_to_text(value):
    """
    Convert strings, dictionaries and lists into searchable text.
    """

    if value is None:
        return ""

    if isinstance(value, str):
        return value

    if isinstance(value, dict):

        parts = []

        for key, child in value.items():

            child_text = content_to_text(child)

            if child_text:
                parts.append(
                    f"{key}: {child_text}"
                )

        return " | ".join(parts)

    if isinstance(value, list):

        parts = []

        for child in value:

            child_text = content_to_text(child)

            if child_text:
                parts.append(child_text)

        return " | ".join(parts)

    return str(value)


# ============================================================
# Decision
# ============================================================

def decide_action(channel, detections):
    """
    Decide the ChannelGuard action.
    """

    if not detections:
        return "ALLOW"

    # Cards are always high-risk
    has_card = any(
        detection["category"] == "CARD"
        for detection in detections
    )

    if has_card:
        return "ALERT"

    return CHANNEL_POLICIES.get(
        channel,
        "ALERT"
    )


# ============================================================
# Process one replay event
# ============================================================

def process_replay_event(
    event,
    session_id
):
    """
    Process one event through the same
    detection, memory, policy and audit pipeline.
    """

    raw_channel = event.get(
        "channel",
        ""
    )

    channel = normalize_channel(
        raw_channel
    )

    event_id = event.get(
        "event_id",
        event.get(
            "id",
            "unknown"
        )
    )

    content = content_to_text(
        event.get(
            "content",
            event.get(
                "message",
                event.get(
                    "data",
                    ""
                )
            )
        )
    )

    # Unsupported channel
    if not channel:

        return {
            "event_id": event_id,
            "source_channel": raw_channel,
            "status": "SKIPPED",
            "reason": "Unsupported channel",
            "categories": [],
            "original_content": content,
            "sanitized_content": content,
            "memory_hit": False
        }

    # --------------------------------------------------------
    # Detect
    # --------------------------------------------------------

    detections = detect_pii(
        content
    )

    # --------------------------------------------------------
    # Session memory
    # --------------------------------------------------------

    memory_detections = find_memory_matches(
        session_id,
        content
    )

    for memory_detection in memory_detections:

        duplicate = any(
            detection["category"]
            == memory_detection["category"]

            and detection["start"]
            == memory_detection["start"]

            and detection["end"]
            == memory_detection["end"]

            for detection in detections
        )

        if not duplicate:
            detections.append(
                memory_detection
            )

    detections.sort(
        key=lambda detection: (
            detection["start"],
            detection["end"]
        )
    )

    # --------------------------------------------------------
    # Remember values
    # --------------------------------------------------------

    remember_detections(
        session_id,
        detections
    )

    # --------------------------------------------------------
    # Decision
    # --------------------------------------------------------

    status = decide_action(
        channel,
        detections
    )

    # --------------------------------------------------------
    # Redaction
    # --------------------------------------------------------

    if detections:

        sanitized_content = redact_text(
            content,
            detections
        )

    else:

        sanitized_content = content

    # --------------------------------------------------------
    # Categories
    # --------------------------------------------------------

    categories = list(
        dict.fromkeys(
            detection["category"]
            for detection in detections
        )
    )

    # --------------------------------------------------------
    # Memory hits
    # --------------------------------------------------------

    memory_hits = [
        detection
        for detection in detections
        if detection.get("source")
        == "session_memory"
    ]

    # --------------------------------------------------------
    # Reason
    # --------------------------------------------------------

    if status == "ALLOW":

        reason = (
            "No sensitive information detected."
        )

    elif status == "REDACT":

        if memory_hits:

            reason = (
                "Sensitive information detected "
                "using session memory and redacted."
            )

        else:

            reason = (
                "Sensitive information detected "
                "and redacted according to the "
                "channel policy."
            )

    else:

        reason = (
            "Sensitive information detected in "
            "a high-risk channel or category. "
            "Event was sanitized and an alert "
            "was generated."
        )

    # --------------------------------------------------------
    # Audit
    # --------------------------------------------------------

    audit_event = write_audit_event(
        session_id=session_id,
        channel=channel,
        status=status,
        categories=categories,
        sanitized_content=sanitized_content,
        detections=detections
    )

    return {
        "event_id": event_id,

        "source_channel": raw_channel,

        "channel": channel,

        "channel_name": CHANNEL_NAMES[
            channel
        ],

        "status": status,

        "categories": categories,

        "reason": reason,

        "memory_hit": (
            len(memory_hits) > 0
        ),

        "memory_hit_count": len(
            memory_hits
        ),

        "audit_id": audit_event[
            "audit_id"
        ],

        "original_content": content,

        "sanitized_content": sanitized_content
    }


# ============================================================
# Replay trace object
# ============================================================

def replay_trace(
    trace,
    session_id="replay-session"
):
    """
    Replay an AgentLeak-style trace.

    Expected structure:

        {
            "run_id": "...",
            "events": [...]
        }
    """

    events = trace.get(
        "events",
        []
    )

    if not isinstance(events, list):

        raise ValueError(
            "Trace must contain an 'events' array."
        )

    # Start with a clean session for deterministic replay
    clear_session(
        session_id
    )

    results = []

    counts = {
        "ALLOW": 0,
        "REDACT": 0,
        "ALERT": 0,
        "SKIPPED": 0
    }

    for event in events:

        if not isinstance(event, dict):
            continue

        result = process_replay_event(
            event,
            session_id
        )

        results.append(
            result
        )

        status = result["status"]

        if status in counts:
            counts[status] += 1

    return {
        "run_id": trace.get(
            "run_id",
            "unknown"
        ),

        "session_id": session_id,

        "total_events": len(
            results
        ),

        "counts": counts,

        "events": results
    }


# ============================================================
# Replay a JSON trace file
# ============================================================

def replay_trace_file(
    trace_path,
    session_id="replay-session"
):
    """
    Load and replay a JSON trace.
    """

    path = Path(
        trace_path
    )

    if not path.exists():

        raise FileNotFoundError(
            f"Trace file not found: {path}"
        )

    with path.open(
        "r",
        encoding="utf-8"
    ) as file:

        trace = json.load(file)

    return replay_trace(
        trace,
        session_id
    )