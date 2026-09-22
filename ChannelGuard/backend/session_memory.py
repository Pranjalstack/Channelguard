import re


# Stores remembered sensitive values for each session.
# Example:
#
# {
#     "default": [
#         {
#             "category": "EMAIL",
#             "canonical": "user@example.com"
#         }
#     ]
# }
#
SESSIONS = {}


def canonicalize(category: str, value: str):
    """
    Convert a sensitive value into a consistent form.

    This allows ChannelGuard to recognize the same value
    when it appears with different spacing or formatting.
    """

    if category == "EMAIL":
        return re.sub(
            r"\s+",
            "",
            value
        ).lower()

    if category in {"PHONE", "CARD"}:
        return re.sub(
            r"\D",
            "",
            value
        )

    return value.strip().lower()


def remember_detections(session_id: str, detections):
    """
    Remember detected sensitive values for a session.

    Only high-confidence structured values are stored:
    EMAIL, PHONE and CARD.

    Raw values are not needed for matching.
    """

    if session_id not in SESSIONS:
        SESSIONS[session_id] = []

    for detection in detections:

        category = detection["category"]

        if category not in {
            "EMAIL",
            "PHONE",
            "CARD"
        }:
            continue

        canonical = canonicalize(
            category,
            detection["value"]
        )

        if not canonical:
            continue

        already_exists = any(
            item["category"] == category
            and item["canonical"] == canonical
            for item in SESSIONS[session_id]
        )

        if not already_exists:

            SESSIONS[session_id].append({
                "category": category,
                "canonical": canonical
            })


def find_memory_matches(session_id: str, text: str):
    """
    Look for previously remembered sensitive values
    appearing in a reformatted form.
    """

    if session_id not in SESSIONS:
        return []

    detections = []

    # --------------------------------------------------------
    # Flexible email format
    #
    # Examples:
    # user@example.com
    # user @ example.com
    # user @ example . com
    # --------------------------------------------------------

    email_pattern = re.compile(
        r"[A-Za-z0-9._%+\-]+"
        r"\s*@\s*"
        r"[A-Za-z0-9.\-]+"
        r"\s*\.\s*"
        r"[A-Za-z]{2,}"
    )

    # --------------------------------------------------------
    # Flexible Indian phone format
    #
    # Examples:
    # 9876543210
    # 98765 43210
    # +91 98765 43210
    # --------------------------------------------------------

    phone_pattern = re.compile(
        r"(?:\+91[\s-]*)?"
        r"[6-9]"
        r"(?:[\s-]*\d){9}"
    )

    # --------------------------------------------------------
    # Flexible card format
    #
    # Examples:
    # 4111111111111111
    # 4111 1111 1111 1111
    # 4111-1111-1111-1111
    # --------------------------------------------------------

    card_pattern = re.compile(
        r"(?:\d[\s-]*){13,19}"
    )

    patterns = {
        "EMAIL": email_pattern,
        "PHONE": phone_pattern,
        "CARD": card_pattern
    }

    for memory_item in SESSIONS[session_id]:

        category = memory_item["category"]
        canonical_value = memory_item["canonical"]

        pattern = patterns.get(category)

        if not pattern:
            continue

        for match in pattern.finditer(text):

            candidate = match.group()

            candidate_canonical = canonicalize(
                category,
                candidate
            )

            if candidate_canonical == canonical_value:

                detections.append({
                    "category": category,
                    "value": candidate,
                    "start": match.start(),
                    "end": match.end(),
                    "source": "session_memory",
                    "memory_hit": True
                })

    return detections


def clear_session(session_id: str):
    """
    Clear remembered values for one session.
    """

    SESSIONS.pop(
        session_id,
        None
    )


def get_session_summary(session_id: str):
    """
    Return a safe summary of remembered values.

    Raw sensitive values are never returned.
    """

    if session_id not in SESSIONS:
        return []

    return [
        {
            "category": item["category"],
            "remembered": True
        }
        for item in SESSIONS[session_id]
    ]