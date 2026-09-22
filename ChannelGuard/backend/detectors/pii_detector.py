import base64
import json
import re
from urllib.parse import quote, quote_plus, unquote

from presidio_analyzer import AnalyzerEngine
from presidio_analyzer.nlp_engine import NlpEngineProvider


# ============================================================
# Presidio + spaCy setup
# ============================================================

nlp_configuration = {
    "nlp_engine_name": "spacy",
    "models": [
        {
            "lang_code": "en",
            "model_name": "en_core_web_sm"
        }
    ]
}


nlp_provider = NlpEngineProvider(
    nlp_configuration=nlp_configuration
)


nlp_engine = nlp_provider.create_engine()


analyzer = AnalyzerEngine(
    nlp_engine=nlp_engine,
    supported_languages=["en"]
)


# ============================================================
# Regex patterns
# ============================================================

EMAIL_PATTERN = re.compile(
    r"\b[A-Za-z0-9._%+-]+"
    r"@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"
)


PHONE_PATTERN = re.compile(
    r"\b(?:\+91[-\s]?)?[6-9]\d{9}\b"
)


CARD_PATTERN = re.compile(
    r"\b(?:\d[ -]*?){13,19}\b"
)


BASE64_PATTERN = re.compile(
    r"\b[A-Za-z0-9+/]{16,}={0,2}\b"
)


UNICODE_ESCAPE_PATTERN = re.compile(
    r"\\u([0-9a-fA-F]{4})"
)


# ============================================================
# Presidio entity mapping
# ============================================================

PRESIDIO_CATEGORY_MAP = {
    "EMAIL_ADDRESS": "EMAIL",
    "PHONE_NUMBER": "PHONE",
    "CREDIT_CARD": "CARD",
    "PERSON": "PERSON",
    "LOCATION": "LOCATION",
    "IP_ADDRESS": "IP_ADDRESS"
}


# ============================================================
# Utility
# ============================================================

def overlaps(
    start1,
    end1,
    start2,
    end2
):
    """Check whether two text spans overlap."""

    return (
        start1 < end2
        and start2 < end1
    )


# ============================================================
# Regex detection
# ============================================================

def detect_with_regex(text: str):

    detections = []


    # --------------------------------------------------------
    # Email
    # --------------------------------------------------------

    for match in EMAIL_PATTERN.finditer(text):

        detections.append({
            "category": "EMAIL",
            "value": match.group(),
            "start": match.start(),
            "end": match.end(),
            "source": "regex"
        })


    # --------------------------------------------------------
    # Phone
    # --------------------------------------------------------

    for match in PHONE_PATTERN.finditer(text):

        detections.append({
            "category": "PHONE",
            "value": match.group(),
            "start": match.start(),
            "end": match.end(),
            "source": "regex"
        })


    # --------------------------------------------------------
    # Card
    # --------------------------------------------------------

    for match in CARD_PATTERN.finditer(text):

        value = (
            match.group()
            .replace(" ", "")
            .replace("-", "")
        )


        if 13 <= len(value) <= 19:

            detections.append({
                "category": "CARD",
                "value": match.group(),
                "start": match.start(),
                "end": match.end(),
                "source": "regex"
            })


    return detections


# ============================================================
# Presidio detection
# ============================================================

def detect_with_presidio(text: str):

    entities = [
        "EMAIL_ADDRESS",
        "PHONE_NUMBER",
        "CREDIT_CARD",
        "PERSON",
        "LOCATION",
        "IP_ADDRESS"
    ]


    results = analyzer.analyze(
        text=text,
        entities=entities,
        language="en"
    )


    detections = []


    for result in results:

        entity_type = result.entity_type


        category = PRESIDIO_CATEGORY_MAP.get(
            entity_type
        )


        if not category:
            continue


        detections.append({
            "category": category,
            "value": text[
                result.start:result.end
            ],
            "start": result.start,
            "end": result.end,
            "source": "presidio",
            "confidence": round(
                result.score,
                3
            )
        })


    return detections


# ============================================================
# Plain text detection
# ============================================================

def detect_plain_text(text: str):

    detections = detect_with_regex(
        text
    )


    presidio_detections = (
        detect_with_presidio(
            text
        )
    )


    for detection in presidio_detections:

        duplicate = any(

            detection["category"]
            == existing["category"]

            and detection["start"]
            == existing["start"]

            and detection["end"]
            == existing["end"]

            for existing in detections
        )


        if not duplicate:

            detections.append(
                detection
            )


    detections.sort(
        key=lambda detection: (
            detection["start"],
            detection["end"]
        )
    )


    return detections


# ============================================================
# Unicode decoding
# ============================================================

def decode_unicode_with_mapping(text: str):

    decoded_chars = []

    mapping = []

    index = 0


    while index < len(text):

        if (

            index + 6 <= len(text)

            and text[index] == "\\"

            and text[index + 1] == "u"

            and re.fullmatch(
                r"[0-9a-fA-F]{4}",
                text[
                    index + 2:index + 6
                ]
            )

        ):

            code_point = int(
                text[
                    index + 2:index + 6
                ],
                16
            )


            decoded_chars.append(
                chr(code_point)
            )


            mapping.append(
                (
                    index,
                    index + 6
                )
            )


            index += 6


        else:

            decoded_chars.append(
                text[index]
            )


            mapping.append(
                (
                    index,
                    index + 1
                )
            )


            index += 1


    return (
        "".join(decoded_chars),
        mapping
    )


# ============================================================
# JSON extraction
# ============================================================

def extract_json_strings(value):

    strings = []


    if isinstance(value, str):

        strings.append(value)


    elif isinstance(value, dict):

        for child in value.values():

            strings.extend(
                extract_json_strings(
                    child
                )
            )


    elif isinstance(value, list):

        for child in value:

            strings.extend(
                extract_json_strings(
                    child
                )
            )


    return strings


# ============================================================
# Generate normalized variants
# ============================================================

def generate_variants(text: str):

    variants = []


    # --------------------------------------------------------
    # Original
    # --------------------------------------------------------

    variants.append({
        "normalization": "original",
        "text": text,
        "source_start": 0,
        "source_end": len(text)
    })


    # --------------------------------------------------------
    # URL decoding
    # --------------------------------------------------------

    url_decoded = unquote(
        text
    )


    if url_decoded != text:

        variants.append({
            "normalization": "url_decode",
            "text": url_decoded,
            "source_start": 0,
            "source_end": len(text)
        })


    # --------------------------------------------------------
    # Unicode decoding
    # --------------------------------------------------------

    if UNICODE_ESCAPE_PATTERN.search(
        text
    ):

        unicode_decoded, mapping = (
            decode_unicode_with_mapping(
                text
            )
        )


        if unicode_decoded != text:

            variants.append({
                "normalization": "unicode_decode",
                "text": unicode_decoded,
                "mapping": mapping,
                "source_start": 0,
                "source_end": len(text)
            })


    # --------------------------------------------------------
    # JSON extraction
    # --------------------------------------------------------

    try:

        json_value = json.loads(
            text
        )


        json_strings = (
            extract_json_strings(
                json_value
            )
        )


        for index, string_value in enumerate(
            json_strings
        ):

            if string_value:

                variants.append({
                    "normalization":
                        f"json_string_{index + 1}",

                    "text":
                        string_value,

                    "source_start":
                        0,

                    "source_end":
                        len(text)
                })


    except (
        json.JSONDecodeError,
        TypeError,
        ValueError
    ):

        pass


    # --------------------------------------------------------
    # Base64 decoding
    # --------------------------------------------------------

    for match in BASE64_PATTERN.finditer(
        text
    ):

        token = match.group()


        padded_token = token


        missing_padding = len(token) % 4


        if missing_padding:

            padded_token += "=" * (
                4 - missing_padding
            )


        try:

            decoded_bytes = (
                base64.b64decode(
                    padded_token,
                    validate=True
                )
            )


            decoded_text = (
                decoded_bytes.decode(
                    "utf-8"
                )
            )


            if (

                decoded_text

                and decoded_text != token

                and any(
                    character.isalnum()
                    for character
                    in decoded_text
                )

            ):

                variants.append({
                    "normalization":
                        "base64_decode",

                    "text":
                        decoded_text,

                    "source_start":
                        match.start(),

                    "source_end":
                        match.end()
                })


        except (
            ValueError,
            UnicodeDecodeError
        ):

            continue


    return variants


# ============================================================
# Map detection back to original text
# ============================================================

def map_detection_to_original(
    original_text,
    detection,
    variant
):

    normalization = (
        variant["normalization"]
    )


    start = detection["start"]

    end = detection["end"]

    value = detection["value"]


    # --------------------------------------------------------
    # Original
    # --------------------------------------------------------

    if normalization == "original":

        return {
            **detection,
            "normalization": "original"
        }


    # --------------------------------------------------------
    # Unicode
    # --------------------------------------------------------

    if normalization == "unicode_decode":

        mapping = variant["mapping"]


        if (

            start < len(mapping)

            and end > start

            and end - 1 < len(mapping)

        ):

            original_start = (
                mapping[start][0]
            )

            original_end = (
                mapping[end - 1][1]
            )


            return {
                **detection,
                "start": original_start,
                "end": original_end,
                "normalization":
                    "unicode_decode"
            }


        return {
            **detection,
            "start": 0,
            "end": len(original_text),
            "normalization":
                "unicode_decode"
        }


    # --------------------------------------------------------
    # Base64
    # --------------------------------------------------------

    if normalization == "base64_decode":

        encoded_value = (
            base64.b64encode(
                value.encode("utf-8")
            ).decode("ascii")
        )


        encoded_index = (
            original_text.find(
                encoded_value
            )
        )


        if encoded_index != -1:

            return {
                **detection,

                "start":
                    encoded_index,

                "end":
                    encoded_index
                    + len(encoded_value),

                "normalization":
                    "base64_decode"
            }


        return {
            **detection,

            "start":
                variant["source_start"],

            "end":
                variant["source_end"],

            "normalization":
                "base64_decode"
        }


    # --------------------------------------------------------
    # URL encoding
    # --------------------------------------------------------

    if normalization == "url_decode":

        encoded_candidates = [

            quote(
                value,
                safe=""
            ),

            quote_plus(
                value
            )
        ]


        for encoded_value in (
            encoded_candidates
        ):

            encoded_index = (
                original_text.find(
                    encoded_value
                )
            )


            if encoded_index != -1:

                return {
                    **detection,

                    "start":
                        encoded_index,

                    "end":
                        encoded_index
                        + len(encoded_value),

                    "normalization":
                        "url_decode"
                }


        direct_index = (
            original_text.find(
                value
            )
        )


        if direct_index != -1:

            return {
                **detection,

                "start":
                    direct_index,

                "end":
                    direct_index
                    + len(value),

                "normalization":
                    "url_decode"
            }


        return {
            **detection,

            "start":
                variant["source_start"],

            "end":
                variant["source_end"],

            "normalization":
                "url_decode"
        }


    # --------------------------------------------------------
    # JSON
    # --------------------------------------------------------

    if normalization.startswith(
        "json_string_"
    ):

        direct_index = (
            original_text.find(
                value
            )
        )


        if direct_index != -1:

            return {
                **detection,

                "start":
                    direct_index,

                "end":
                    direct_index
                    + len(value),

                "normalization":
                    normalization
            }


        json_escaped = (
            json.dumps(
                value
            )[1:-1]
        )


        escaped_index = (
            original_text.find(
                json_escaped
            )
        )


        if escaped_index != -1:

            return {
                **detection,

                "start":
                    escaped_index,

                "end":
                    escaped_index
                    + len(json_escaped),

                "normalization":
                    normalization
            }


        return {
            **detection,

            "start":
                variant["source_start"],

            "end":
                variant["source_end"],

            "normalization":
                normalization
        }


    # --------------------------------------------------------
    # Fallback
    # --------------------------------------------------------

    return {
        **detection,

        "start":
            variant["source_start"],

        "end":
            variant["source_end"],

        "normalization":
            normalization
    }


# ============================================================
# Main detection pipeline
# ============================================================

def detect_pii(text: str):

    all_detections = []


    variants = generate_variants(
        text
    )


    for variant in variants:

        normalized_text = (
            variant["text"]
        )


        detections = detect_plain_text(
            normalized_text
        )


        for detection in detections:

            mapped_detection = (
                map_detection_to_original(
                    text,
                    detection,
                    variant
                )
            )


            all_detections.append(
                mapped_detection
            )


    # --------------------------------------------------------
    # Remove duplicate detections
    # --------------------------------------------------------

    unique_detections = []


    for detection in all_detections:

        duplicate = any(

            detection["category"]
            == existing["category"]

            and detection["start"]
            == existing["start"]

            and detection["end"]
            == existing["end"]

            for existing
            in unique_detections
        )


        if not duplicate:

            unique_detections.append(
                detection
            )


    # --------------------------------------------------------
    # Remove overlapping duplicate detections
    #
    # Prefer structured sensitive categories
    # over broader detections.
    # --------------------------------------------------------

    priority = {
        "CARD": 5,
        "EMAIL": 5,
        "PHONE": 5,
        "PERSON": 4,
        "LOCATION": 4,
        "IP_ADDRESS": 4
    }


    unique_detections.sort(
        key=lambda detection: (
            detection["start"],
            -(priority.get(
                detection["category"],
                1
            )),
            -(detection["end"] - detection["start"])
        )
    )


    filtered_detections = []


    for detection in unique_detections:

        conflicting = False


        for existing in filtered_detections:

            if overlaps(
                detection["start"],
                detection["end"],
                existing["start"],
                existing["end"]
            ):

                # Prefer the higher-priority
                # structured PII detection.
                if (
                    priority.get(
                        existing["category"],
                        1
                    )
                    >= priority.get(
                        detection["category"],
                        1
                    )
                ):

                    conflicting = True
                    break


        if not conflicting:

            filtered_detections.append(
                detection
            )


    # --------------------------------------------------------
    # Final sort
    # --------------------------------------------------------

    filtered_detections.sort(
        key=lambda detection: (
            detection["start"],
            detection["end"]
        )
    )


    return filtered_detections


# ============================================================
# Redaction
# ============================================================

def redact_text(
    text: str,
    detections
):

    if not detections:

        return text


    filtered_detections = []


    candidates = sorted(
        detections,
        key=lambda item: (
            item["start"],
            -(item["end"] - item["start"])
        )
    )


    for detection in candidates:

        overlaps_existing = any(

            overlaps(
                detection["start"],
                detection["end"],
                existing["start"],
                existing["end"]
            )

            for existing
            in filtered_detections
        )


        if not overlaps_existing:

            filtered_detections.append(
                detection
            )


    # Replace right-to-left
    filtered_detections.sort(
        key=lambda detection: detection["start"],
        reverse=True
    )


    redacted = text


    for detection in filtered_detections:

        category = (
            detection["category"]
        )


        replacement = (
            f"[{category}]"
        )


        redacted = (

            redacted[
                :detection["start"]
            ]

            + replacement

            + redacted[
                detection["end"]:]
        )


    return redacted