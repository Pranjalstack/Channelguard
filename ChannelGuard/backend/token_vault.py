import hmac
import json
import os
import secrets
from datetime import datetime, timedelta, timezone
from pathlib import Path


# ============================================================
# Configuration
# ============================================================

TOKEN_TTL_SECONDS = 900

DEFAULT_TOKEN_TARGET = "Agent B"


# ============================================================
# Agent credentials
#
# The secret is supplied through an environment variable.
# It is NOT stored in source code.
# ============================================================

AGENT_KEYS = {
    "Agent B": os.environ.get(
        "CHANNELGUARD_AGENT_B_KEY",
        ""
    )
}


# ============================================================
# Purpose-based access policy
# ============================================================

ACCESS_POLICIES = {
    "email_delivery": {
        "EMAIL"
    },

    "phone_verification": {
        "PHONE"
    },

    "payment_processing": {
        "CARD"
    },

    "identity_verification": {
        "EMAIL",
        "PHONE",
        "PERSON",
        "LOCATION"
    }
}


# ============================================================
# In-memory secure token vault
# ============================================================

VAULT = {}


# ============================================================
# Access log
# ============================================================

ACCESS_LOG_FILE = (
    Path(__file__).resolve().parent.parent
    / "data"
    / "token_access.jsonl"
)


# ============================================================
# Time helper
# ============================================================

def utc_now():

    return datetime.now(
        timezone.utc
    )


# ============================================================
# Authenticate agent
# ============================================================

def authenticate_agent(
    provided_key
):

    if not provided_key:

        return None


    for agent_name, stored_key in (
        AGENT_KEYS.items()
    ):

        if not stored_key:

            continue


        if hmac.compare_digest(
            provided_key,
            stored_key
        ):

            return agent_name


    return None


# ============================================================
# Cleanup expired tokens
# ============================================================

def cleanup_expired_tokens():

    now = utc_now()

    expired_tokens = []


    for token, record in VAULT.items():

        if now >= record[
            "expires_at"
        ]:

            expired_tokens.append(
                token
            )


    for token in expired_tokens:

        del VAULT[token]


# ============================================================
# Access logging
# ============================================================

def write_access_log(
    token,
    requester,
    purpose,
    status,
    session_id,
    category=None
):

    ACCESS_LOG_FILE.parent.mkdir(
        parents=True,
        exist_ok=True
    )


    event = {

        "timestamp":
            utc_now().isoformat(),

        "token":
            token,

        "requester":
            requester,

        "purpose":
            purpose,

        "status":
            status,

        "session_id":
            session_id,

        "category":
            category
    }


    with ACCESS_LOG_FILE.open(
        "a",
        encoding="utf-8"
    ) as file:

        file.write(
            json.dumps(
                event
            ) + "\n"
        )


# ============================================================
# Create secure token
# ============================================================

def create_token(
    category,
    value,
    session_id,
    intended_requester=DEFAULT_TOKEN_TARGET
):

    cleanup_expired_tokens()


    random_part = secrets.token_urlsafe(
        8
    )


    token = (
        f"CG-{category}-"
        f"{random_part}"
    )


    now = utc_now()


    expires_at = (
        now
        + timedelta(
            seconds=TOKEN_TTL_SECONDS
        )
    )


    VAULT[token] = {

        "category":
            category,

        "value":
            value,

        "session_id":
            session_id,

        "intended_requester":
            intended_requester,

        "created_at":
            now,

        "expires_at":
            expires_at
    }


    return token


# ============================================================
# Tokenize message
# ============================================================

def tokenize_text(
    text,
    detections,
    session_id
):

    if not detections:

        return text, []


    filtered_detections = []


    candidates = sorted(

        detections,

        key=lambda item: (
            item["start"],
            -(item["end"] - item["start"])
        )
    )


    for detection in candidates:

        overlap = any(

            detection["start"]
            < existing["end"]

            and existing["start"]
            < detection["end"]

            for existing
            in filtered_detections
        )


        if not overlap:

            filtered_detections.append(
                detection
            )


    filtered_detections.sort(
        key=lambda detection:
            detection["start"],
        reverse=True
    )


    tokenized = text

    token_records = []


    for detection in filtered_detections:

        category = detection[
            "category"
        ]


        value = detection.get(
            "value",
            ""
        )


        token = create_token(

            category=category,

            value=value,

            session_id=session_id,

            intended_requester=
                DEFAULT_TOKEN_TARGET
        )


        tokenized = (

            tokenized[
                :detection["start"]
            ]

            + (
                f"[{category}_TOKEN:"
                f"{token}]"
            )

            + tokenized[
                detection["end"]:]
        )


        token_records.append({

            "token":
                token,

            "category":
                category,

            "session_id":
                session_id,

            "intended_requester":
                DEFAULT_TOKEN_TARGET,

            "expires_in_seconds":
                TOKEN_TTL_SECONDS
        })


    return (
        tokenized,
        token_records
    )


# ============================================================
# Resolve token with authentication +
# authorization + session binding
# ============================================================

def resolve_token(
    token,
    requester,
    purpose,
    session_id
):

    cleanup_expired_tokens()


    record = VAULT.get(
        token
    )


    # --------------------------------------------------------
    # Token exists?
    # --------------------------------------------------------

    if not record:

        write_access_log(

            token=token,

            requester=requester,

            purpose=purpose,

            status="NOT_FOUND",

            session_id=session_id
        )


        return {

            "authorized": False,

            "reason":
                "Token not found or expired."
        }


    category = record[
        "category"
    ]


    # --------------------------------------------------------
    # Agent identity check
    # --------------------------------------------------------

    intended_requester = record[
        "intended_requester"
    ]


    if requester != intended_requester:

        write_access_log(

            token=token,

            requester=requester,

            purpose=purpose,

            status="DENIED",

            session_id=session_id,

            category=category
        )


        return {

            "authorized": False,

            "reason":
                (
                    "Authenticated agent is not "
                    "the intended token recipient."
                ),

            "category":
                category
        }


    # --------------------------------------------------------
    # Session binding
    # --------------------------------------------------------

    if session_id != record[
        "session_id"
    ]:

        write_access_log(

            token=token,

            requester=requester,

            purpose=purpose,

            status="DENIED",

            session_id=session_id,

            category=category
        )


        return {

            "authorized": False,

            "reason":
                (
                    "Token does not belong to "
                    "this session."
                ),

            "category":
                category
        }


    # --------------------------------------------------------
    # Purpose check
    # --------------------------------------------------------

    allowed_categories = (
        ACCESS_POLICIES.get(
            purpose,
            set()
        )
    )


    if category not in allowed_categories:

        write_access_log(

            token=token,

            requester=requester,

            purpose=purpose,

            status="DENIED",

            session_id=session_id,

            category=category
        )


        return {

            "authorized": False,

            "reason":
                (
                    "Authenticated agent is not "
                    "authorized to access this "
                    "category for the requested purpose."
                ),

            "category":
                category
        }


    # --------------------------------------------------------
    # Authorized
    # --------------------------------------------------------

    write_access_log(

        token=token,

        requester=requester,

        purpose=purpose,

        status="AUTHORIZED",

        session_id=session_id,

        category=category
    )


    return {

        "authorized":
            True,

        "token":
            token,

        "category":
            category,

        "value":
            record["value"],

        "session_id":
            record["session_id"],

        "requester":
            requester,

        "purpose":
            purpose
    }


# ============================================================
# Vault statistics
# ============================================================

def get_vault_status():

    cleanup_expired_tokens()


    category_counts = {}


    for record in VAULT.values():

        category = record[
            "category"
        ]


        category_counts[
            category
        ] = (

            category_counts.get(
                category,
                0
            )

            + 1
        )


    return {

        "active_tokens":
            len(VAULT),

        "categories":
            category_counts,

        "token_ttl_seconds":
            TOKEN_TTL_SECONDS
    }