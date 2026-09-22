import json
from pathlib import Path
from typing import Optional

from fastapi import (
    FastAPI,
    Header,
    HTTPException
)

from fastapi.staticfiles import (
    StaticFiles
)

from fastapi.responses import (
    FileResponse
)

from pydantic import BaseModel

from backend.detectors.pii_detector import (
    detect_pii,
    redact_text
)

from backend.session_memory import (
    remember_detections,
    find_memory_matches,
    get_session_summary,
    clear_session
)

from backend.audit_log import (
    write_audit_event,
    read_audit_events
)

from backend.replay import (
    replay_trace_file
)

from backend.evaluator import (
    evaluate_dataset
)

from backend.token_vault import (
    authenticate_agent,
    tokenize_text,
    resolve_token,
    get_vault_status,
    ACCESS_POLICIES
)


app = FastAPI(
    title="ChannelGuard"
)


# ============================================================
# Frontend
# ============================================================

app.mount(
    "/static",
    StaticFiles(
        directory="frontend"
    ),
    name="static"
)


# ============================================================
# Supported channels
# ============================================================

SUPPORTED_CHANNELS = {

    "agent_message":
        "Agent-to-Agent Message",

    "tool_output":
        "Tool Output",

    "runtime_log":
        "Runtime Log",

    "debug_event":
        "Debug Event"
}


# ============================================================
# Channel-specific policies
# ============================================================

CHANNEL_POLICIES = {

    "agent_message": {

        "action_with_pii":
            "REDACT",

        "description":
            (
                "Sensitive data is redacted "
                "before forwarding."
            )
    },

    "tool_output": {

        "action_with_pii":
            "REDACT",

        "description":
            (
                "Sensitive tool output "
                "is sanitized."
            )
    },

    "runtime_log": {

        "action_with_pii":
            "ALERT",

        "description":
            (
                "Sensitive runtime logs trigger "
                "an alert and are sanitized."
            )
    },

    "debug_event": {

        "action_with_pii":
            "ALERT",

        "description":
            (
                "Sensitive debug events trigger "
                "an alert and are sanitized."
            )
    }
}


# ============================================================
# Event model
# ============================================================

class Event(BaseModel):

    channel: str

    content: str

    session_id: str = "default"

    forwarding_mode: str = "redact"

    requester: str = "unknown"

    purpose: str = ""


# ============================================================
# Secure token request
# ============================================================

class TokenRequest(BaseModel):

    token: str

    purpose: str

    session_id: str


# ============================================================
# Home
# ============================================================

@app.get("/")
def home():

    return {

        "message":
            "ChannelGuard Privacy Proxy is running",

        "supported_channels":
            list(
                SUPPORTED_CHANNELS.keys()
            ),

        "channel_coverage":
            "4/4",

        "secure_token_vault":
            True,

        "agent_authentication":
            True
    }


# ============================================================
# Dashboard
# ============================================================

@app.get("/dashboard")
def dashboard():

    return FileResponse(
        "frontend/index.html"
    )


# ============================================================
# Channels
# ============================================================

@app.get("/channels")
def get_channels():

    return {

        "supported_channels":
            SUPPORTED_CHANNELS,

        "policies":
            CHANNEL_POLICIES,

        "coverage":
            "4/4"
    }


# ============================================================
# Audit
# ============================================================

@app.get("/audit")
def get_audit(
    limit: int = 50
):

    limit = max(
        1,
        min(
            limit,
            200
        )
    )

    events = read_audit_events(
        limit
    )

    return {

        "count":
            len(events),

        "events":
            events
    }


# ============================================================
# Session memory
# ============================================================

@app.get("/sessions/{session_id}")
def get_session(
    session_id: str
):

    return {

        "session_id":
            session_id,

        "remembered_values":
            get_session_summary(
                session_id
            )
    }


@app.delete("/sessions/{session_id}")
def delete_session(
    session_id: str
):

    clear_session(
        session_id
    )

    return {

        "message":
            "Session memory cleared",

        "session_id":
            session_id
    }


# ============================================================
# Vault status
# ============================================================

@app.get("/vault/status")
def vault_status():

    return get_vault_status()


# ============================================================
# Secure token resolution
#
# Identity comes from X-Agent-Key.
# The caller does NOT get to choose its identity.
# ============================================================

@app.post("/vault/resolve")
def vault_resolve(

    request: TokenRequest,

    x_agent_key:
        Optional[str] = Header(
            default=None,
            alias="X-Agent-Key"
        )
):

    # --------------------------------------------------------
    # Authenticate caller
    # --------------------------------------------------------

    requester = authenticate_agent(
        x_agent_key
    )

    if not requester:

        raise HTTPException(

            status_code=401,

            detail={

                "error":
                    "Authentication failed",

                "message":
                    (
                        "A valid Agent credential "
                        "is required."
                    )
            }
        )


    # --------------------------------------------------------
    # Resolve token
    # --------------------------------------------------------

    result = resolve_token(

        token=request.token,

        requester=requester,

        purpose=request.purpose,

        session_id=request.session_id
    )


    # --------------------------------------------------------
    # Authorization failed
    # --------------------------------------------------------

    if not result.get(
        "authorized",
        False
    ):

        raise HTTPException(

            status_code=403,

            detail=result
        )


    return result


# ============================================================
# Decision engine
# ============================================================

def decide_action(
    channel,
    detections
):

    if not detections:

        return "ALLOW"


    # Cards are always high-risk.

    has_card = any(

        detection["category"]
        == "CARD"

        for detection
        in detections
    )


    if has_card:

        return "ALERT"


    policy = CHANNEL_POLICIES.get(
        channel
    )


    if policy:

        return policy[
            "action_with_pii"
        ]


    return "ALERT"


# ============================================================
# Purpose validation
# ============================================================

def validate_token_purpose(
    categories,
    purpose
):
    """
    Make sure a selected tokenization purpose is
    actually compatible with every detected category.

    Example:

        EMAIL + email_delivery    -> valid
        EMAIL + payment_processing -> invalid
        CARD + payment_processing  -> valid
    """

    if not categories:

        return


    allowed_categories = (
        ACCESS_POLICIES.get(
            purpose,
            set()
        )
    )


    invalid_categories = [

        category

        for category
        in categories

        if category
        not in allowed_categories
    ]


    if invalid_categories:

        valid_purposes = []


        for category in invalid_categories:

            category_purposes = [

                name

                for name, allowed
                in ACCESS_POLICIES.items()

                if category in allowed
            ]


            valid_purposes.append({

                "category":
                    category,

                "allowed_purposes":
                    category_purposes
            })


        raise HTTPException(

            status_code=400,

            detail={

                "error":
                    "Invalid purpose for detected data",

                "detected_categories":
                    categories,

                "selected_purpose":
                    purpose,

                "required_purpose_options":
                    valid_purposes,

                "message":
                    (
                        "The selected purpose is not "
                        "authorized for one or more "
                        "detected sensitive categories."
                    )
            }
        )


# ============================================================
# Scan endpoint
# ============================================================

@app.post("/scan")
def scan_event(
    event: Event
):

    # --------------------------------------------------------
    # Validate channel
    # --------------------------------------------------------

    if event.channel not in SUPPORTED_CHANNELS:

        raise HTTPException(

            status_code=400,

            detail={

                "error":
                    "Unsupported channel",

                "supported_channels":
                    list(
                        SUPPORTED_CHANNELS.keys()
                    )
            }
        )


    # --------------------------------------------------------
    # Validate forwarding mode
    # --------------------------------------------------------

    allowed_forwarding_modes = {

        "redact",

        "tokenize"
    }


    if (
        event.forwarding_mode
        not in allowed_forwarding_modes
    ):

        raise HTTPException(

            status_code=400,

            detail={

                "error":
                    "Unsupported forwarding mode",

                "allowed_modes":
                    list(
                        allowed_forwarding_modes
                    )
            }
        )


    # --------------------------------------------------------
    # Tokenization needs a purpose
    # --------------------------------------------------------

    if (
        event.forwarding_mode
        == "tokenize"
    ):

        if not event.purpose.strip():

            raise HTTPException(

                status_code=400,

                detail={

                    "error":
                        "Purpose is required",

                    "message":
                        (
                            "Select a legitimate "
                            "purpose before using "
                            "secure tokenization."
                        )
                }
            )


    # --------------------------------------------------------
    # Detect
    # --------------------------------------------------------

    detections = detect_pii(
        event.content
    )


    # --------------------------------------------------------
    # Session memory
    # --------------------------------------------------------

    memory_detections = (

        find_memory_matches(

            event.session_id,

            event.content
        )
    )


    for memory_detection in (
        memory_detections
    ):

        duplicate = any(

            detection["category"]
            == memory_detection[
                "category"
            ]

            and detection["start"]
            == memory_detection[
                "start"
            ]

            and detection["end"]
            == memory_detection[
                "end"
            ]

            for detection
            in detections
        )


        if not duplicate:

            detections.append(
                memory_detection
            )


    # --------------------------------------------------------
    # Sort
    # --------------------------------------------------------

    detections.sort(

        key=lambda detection: (

            detection["start"],

            detection["end"]
        )
    )


    # --------------------------------------------------------
    # Categories
    # --------------------------------------------------------

    categories = list(

        dict.fromkeys(

            detection["category"]

            for detection
            in detections
        )
    )


    # --------------------------------------------------------
    # Validate token purpose BEFORE creating tokens
    # --------------------------------------------------------

    if (
        event.forwarding_mode
        == "tokenize"
    ):

        validate_token_purpose(

            categories,

            event.purpose
        )


    # --------------------------------------------------------
    # Remember
    # --------------------------------------------------------

    remember_detections(

        event.session_id,

        detections
    )


    # --------------------------------------------------------
    # Decision
    # --------------------------------------------------------

    status = decide_action(

        event.channel,

        detections
    )


    # --------------------------------------------------------
    # Memory hits
    # --------------------------------------------------------

    memory_hits = [

        detection

        for detection
        in detections

        if detection.get(
            "source"
        ) == "session_memory"
    ]


    # --------------------------------------------------------
    # Secure forwarding
    # --------------------------------------------------------

    token_records = []


    if not detections:

        sanitized_content = (
            event.content
        )


    elif (
        event.forwarding_mode
        == "tokenize"
    ):

        (
            sanitized_content,
            token_records
        ) = tokenize_text(

            event.content,

            detections,

            event.session_id
        )


    else:

        sanitized_content = redact_text(

            event.content,

            detections
        )


    # Policy

    policy = CHANNEL_POLICIES[
        event.channel
    ]

    # Reason
    
    if status == "ALLOW":

        reason = (
            "No sensitive information detected."
        )


    elif (
        event.forwarding_mode
        == "tokenize"
    ):

        if memory_hits:

            reason = (
                "Sensitive information detected "
                "using session memory. Values were "
                "stored in the secure token vault "
                "and replaced with secure references."
            )

        else:

            reason = (
                "Sensitive information detected. "
                "Values were replaced by secure "
                "references for authorized retrieval."
            )


    elif status == "REDACT":

        if memory_hits:

            reason = (
                "Sensitive information detected "
                "using session memory and redacted "
                "according to the channel policy."
            )

        else:

            reason = (
                "Sensitive information detected "
                "and redacted according to the "
                "channel policy."
            )


    else:

        reason = (
            "Sensitive information detected in a "
            "high-risk channel or category. "
            "Event was sanitized and an alert "
            "was generated."
        )


    
    # Audit

    audit_event = write_audit_event(

        session_id=
            event.session_id,

        channel=
            event.channel,

        status=
            status,

        categories=
            categories,

        sanitized_content=
            sanitized_content,

        detections=
            detections
    )


    # Response

    return {

        "audit_id":
            audit_event[
                "audit_id"
            ],

        "channel":
            event.channel,

        "channel_name":
            SUPPORTED_CHANNELS[
                event.channel
            ],

        "session_id":
            event.session_id,

        "policy_action":
            policy[
                "action_with_pii"
            ],

        "policy_description":
            policy[
                "description"
            ],

        "status":
            status,

        "categories":
            categories,

        "reason":
            reason,

        "memory_hit":
            (
                len(memory_hits)
                > 0
            ),

        "memory_hit_count":
            len(memory_hits),

        "forwarding_mode":
            event.forwarding_mode,

        "requester":
            event.requester,

        "purpose":
            event.purpose,

        "original_content":
            event.content,

        "sanitized_content":
            sanitized_content,

        "token_records":
            token_records,

        "detections":
            detections
    }


# Sample trace replay

@app.get("/replay/sample")
def replay_sample():

    try:

        result = replay_trace_file(

            "data/agentleak_sample.json",

            session_id="sample-replay"
        )


        return result


    except Exception as error:

        raise HTTPException(

            status_code=500,

            detail=str(error)
        )


# Evaluation

@app.get("/evaluate")
def evaluate():

    evaluation_file = (

        Path(__file__).resolve().parent.parent

        / "data"

        / "evaluation_cases.json"
    )


    if not evaluation_file.exists():

        raise HTTPException(

            status_code=404,

            detail=(

                "Evaluation dataset not found: "

                f"{evaluation_file}"
            )
        )


    try:

        with evaluation_file.open(

            "r",

            encoding="utf-8"

        ) as file:

            cases = json.load(
                file
            )


    except json.JSONDecodeError as error:

        raise HTTPException(

            status_code=500,

            detail=(

                "Invalid evaluation_cases.json: "

                f"{error}"
            )
        )


    try:

        report = evaluate_dataset(
            cases
        )


        return report


    except Exception as error:

        raise HTTPException(

            status_code=500,

            detail=(

                "Evaluation failed: "

                f"{error}"
            )
        )