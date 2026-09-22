from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import os
import re
import requests


# ============================================================
# Server configuration
# ============================================================

HOST = "127.0.0.1"
PORT = 8002


# ============================================================
# ChannelGuard configuration
# ============================================================

CHANNELGUARD_URL = "http://127.0.0.1:8000"

VAULT_RESOLVE_URL = (
    f"{CHANNELGUARD_URL}/vault/resolve"
)


# ============================================================
# Ollama configuration
# ============================================================

OLLAMA_URL = (
    "http://127.0.0.1:11434/api/generate"
)

OLLAMA_MODEL = "qwen3.5:0.8b"


# ============================================================
# Agent identity
# ============================================================

AGENT_NAME = "Agent B"


# ============================================================
# Agent authentication
# ============================================================

AGENT_KEY = os.environ.get(
    "CHANNELGUARD_AGENT_B_KEY",
    ""
)


# ============================================================
# Secure token pattern
# ============================================================

TOKEN_PATTERN = re.compile(
    r"\[(EMAIL|PHONE|CARD|PERSON|LOCATION|IP_ADDRESS)"
    r"_TOKEN:(CG-[A-Za-z0-9_-]+)\]"
)


# ============================================================
# Purpose detection
# ============================================================

def infer_purpose(message, categories):

    lower_message = message.lower()

    # --------------------------------------------------------
    # Email
    # --------------------------------------------------------

    if "EMAIL" in categories:

        email_keywords = [
            "send email",
            "send an email",
            "email",
            "e-mail",
            "mail",
            "follow-up",
            "follow up",
            "invoice"
        ]

        if any(
            keyword in lower_message
            for keyword in email_keywords
        ):
            return "email_delivery"

    # --------------------------------------------------------
    # Phone
    # --------------------------------------------------------

    if "PHONE" in categories:

        phone_keywords = [
            "verify phone",
            "phone verification",
            "verify the phone",
            "otp",
            "one-time password",
            "phone number"
        ]

        if any(
            keyword in lower_message
            for keyword in phone_keywords
        ):
            return "phone_verification"

    # --------------------------------------------------------
    # Card
    # --------------------------------------------------------

    if "CARD" in categories:

        card_keywords = [
            "payment",
            "pay",
            "charge",
            "transaction",
            "card payment",
            "process payment"
        ]

        if any(
            keyword in lower_message
            for keyword in card_keywords
        ):
            return "payment_processing"

    # --------------------------------------------------------
    # Identity
    # --------------------------------------------------------

    identity_keywords = [
        "verify identity",
        "identity verification",
        "kyc",
        "identity check"
    ]

    if any(
        keyword in lower_message
        for keyword in identity_keywords
    ):

        if any(
            category in categories
            for category in [
                "EMAIL",
                "PHONE",
                "PERSON",
                "LOCATION"
            ]
        ):
            return "identity_verification"

    return None


# ============================================================
# Find secure tokens
# ============================================================

def find_tokens(message):

    matches = TOKEN_PATTERN.findall(
        message
    )

    tokens = []

    for category, token in matches:

        tokens.append({
            "category": category,
            "token": token
        })

    return tokens


# ============================================================
# Resolve secure token
# ============================================================

def resolve_secure_token(
    token,
    purpose,
    session_id
):

    if not AGENT_KEY:

        return {
            "authorized": False,
            "error": (
                "CHANNELGUARD_AGENT_B_KEY "
                "is not configured."
            )
        }

    headers = {
        "X-Agent-Key": AGENT_KEY
    }

    payload = {
        "token": token,
        "session_id": session_id,
        "purpose": purpose
    }

    try:

        response = requests.post(
            VAULT_RESOLVE_URL,
            headers=headers,
            json=payload,
            timeout=10
        )

        if response.status_code == 200:

            return response.json()

        try:
            detail = response.json()

        except Exception:
            detail = response.text

        return {
            "authorized": False,
            "status_code": response.status_code,
            "error": detail
        }

    except requests.exceptions.ConnectionError:

        return {
            "authorized": False,
            "error": (
                "Could not connect to "
                "ChannelGuard."
            )
        }

    except requests.exceptions.Timeout:

        return {
            "authorized": False,
            "error": (
                "ChannelGuard token request "
                "timed out."
            )
        }

    except Exception as error:

        return {
            "authorized": False,
            "error": str(error)
        }


# ============================================================
# Secure operation
# ============================================================

def perform_secure_operation(
    category,
    secure_value,
    purpose
):
    """
    Demonstrates an authorized secure operation.

    The raw sensitive value is intentionally not printed
    and is never inserted into the LLM prompt.

    In a production system, this function could call a
    secure email, payment, verification, or identity service.
    """

    if purpose == "email_delivery":

        # The sensitive value exists only in this
        # local function scope.

        _recipient = secure_value

        return (
            True,
            "Secure email operation authorized."
        )

    if purpose == "phone_verification":

        _phone = secure_value

        return (
            True,
            "Secure phone verification authorized."
        )

    if purpose == "payment_processing":

        _card = secure_value

        return (
            True,
            "Secure payment operation authorized."
        )

    if purpose == "identity_verification":

        _identity_value = secure_value

        return (
            True,
            "Secure identity verification authorized."
        )

    return (
        False,
        "No secure operation is available "
        "for this purpose."
    )


# ============================================================
# AI
# ============================================================

def ask_ai(
    message,
    secure_operation_notes=None
):

    notes = secure_operation_notes or []

    note_text = ""

    if notes:

        note_text = (
            "\n\nSecurity operation status:\n"
            + "\n".join(
                f"- {note}"
                for note in notes
            )
        )

    # --------------------------------------------------------
    # Never expose the actual secure token to the LLM.
    # --------------------------------------------------------

    safe_message = TOKEN_PATTERN.sub(
        "[PROTECTED_TOKEN]",
        message
    )

    payload = {

        "model": OLLAMA_MODEL,

        "prompt": (

            "You are Agent B in a multi-agent system.\n"
            "You receive messages from Agent A "
            "through ChannelGuard.\n\n"

            "Process the message and provide a "
            "useful, concise response.\n\n"

            "SECURITY RULES:\n"

            "1. Never reconstruct or guess "
            "redacted sensitive information.\n"

            "2. Never output, repeat, expose, "
            "or transform a secure token.\n"

            "3. Never create URLs, links, APIs, "
            "or endpoints for secure tokens.\n"

            "4. Never claim that you personally "
            "verified a sensitive value.\n"

            "5. If a secure operation was authorized, "
            "simply state that the operation was "
            "authorized and completed.\n"

            "6. Do not ask the user to provide a "
            "sensitive value again when the secure "
            "operation has already been authorized.\n\n"

            "Message from Agent A:\n"

            + safe_message

            + note_text
        ),

        "stream": False,

        "think": False
    }

    try:

        response = requests.post(
            OLLAMA_URL,
            json=payload,
            timeout=120
        )

        response.raise_for_status()

        data = response.json()

        return data.get(
            "response",
            ""
        ).strip()

    except requests.exceptions.ConnectionError:

        raise RuntimeError(
            "Could not connect to Ollama. "
            "Make sure Ollama is running."
        )

    except requests.exceptions.Timeout:

        raise RuntimeError(
            "Ollama request timed out."
        )


# ============================================================
# HTTP Handler
# ============================================================

class AgentBHandler(
    BaseHTTPRequestHandler
):

    def send_json(
        self,
        data,
        status=200
    ):

        response = json.dumps(
            data
        ).encode("utf-8")

        self.send_response(
            status
        )

        self.send_header(
            "Content-Type",
            "application/json"
        )

        self.send_header(
            "Content-Length",
            str(len(response))
        )

        self.end_headers()

        self.wfile.write(
            response
        )


    # ========================================================
    # POST /receive
    # ========================================================

    def do_POST(self):

        if self.path != "/receive":

            self.send_json(
                {
                    "error":
                        "Unknown endpoint"
                },
                404
            )

            return

        try:

            # ------------------------------------------------
            # Read body
            # ------------------------------------------------

            content_length = int(
                self.headers.get(
                    "Content-Length",
                    0
                )
            )

            body = self.rfile.read(
                content_length
            )

            data = json.loads(
                body.decode(
                    "utf-8"
                )
            )

            # ------------------------------------------------
            # Read message
            # ------------------------------------------------

            message = data.get(
                "message",
                ""
            )

            channel = data.get(
                "channel",
                "unknown"
            )

            source = data.get(
                "source",
                "unknown"
            )

            session_id = data.get(
                "session_id",
                "agent-demo"
            )

            # ------------------------------------------------
            # Header
            # ------------------------------------------------

            print(
                "\n"
                + "=" * 70
            )

            print(
                "AGENT B"
            )

            print(
                "=" * 70
            )

            print(
                "Source:",
                source
            )

            print(
                "Channel:",
                channel
            )

            print(
                "Session:",
                session_id
            )

            print(
                "\nReceived message:"
            )

            print(
                message
            )

            # ------------------------------------------------
            # Find secure tokens
            # ------------------------------------------------

            tokens = find_tokens(
                message
            )

            secure_notes = []

            resolved_count = 0

            denied_count = 0

            # ------------------------------------------------
            # Secure token workflow
            # ------------------------------------------------

            if tokens:

                categories = list(
                    dict.fromkeys(
                        token["category"]
                        for token in tokens
                    )
                )

                purpose = infer_purpose(
                    message,
                    categories
                )

                print(
                    "\nSecure token detected."
                )

                print(
                    "Categories:",
                    categories
                )

                print(
                    "Requested purpose:",
                    purpose
                    or "NONE"
                )

                if purpose:

                    for token_info in tokens:

                        token = token_info[
                            "token"
                        ]

                        category = token_info[
                            "category"
                        ]

                        print(
                            "\nRequesting "
                            "authorized access:"
                        )

                        print(
                            "Token:",
                            token
                        )

                        print(
                            "Category:",
                            category
                        )

                        print(
                            "Purpose:",
                            purpose
                        )

                        result = (
                            resolve_secure_token(
                                token=token,
                                purpose=purpose,
                                session_id=session_id
                            )
                        )

                        if result.get(
                            "authorized",
                            False
                        ):

                            # --------------------------------
                            # IMPORTANT
                            # --------------------------------
                            # The raw value is deliberately
                            # not printed and not placed in
                            # the AI prompt.

                            secure_value = (
                                result.get(
                                    "value",
                                    ""
                                )
                            )

                            success, note = (
                                perform_secure_operation(
                                    category=category,
                                    secure_value=secure_value,
                                    purpose=purpose
                                )
                            )

                            if success:

                                resolved_count += 1

                                secure_notes.append(
                                    note
                                )

                                print(
                                    "Authorization:"
                                    " SUCCESS"
                                )

                                print(
                                    "Secure operation:"
                                    " SUCCESS"
                                )

                                print(
                                    "Raw value:"
                                    " NOT DISPLAYED"
                                )

                            else:

                                denied_count += 1

                                print(
                                    "Authorization:"
                                    " SUCCESS"
                                )

                                print(
                                    "Secure operation:"
                                    " FAILED"
                                )

                        else:

                            denied_count += 1

                            print(
                                "Authorization:"
                                " DENIED"
                            )

                            print(
                                "Reason:",
                                result.get(
                                    "reason",
                                    result.get(
                                        "error",
                                        "Unknown"
                                    )
                                )
                            )

                else:

                    print(
                        "\nNo legitimate secure "
                        "purpose was identified."
                    )

                    print(
                        "Tokens remain protected."
                    )

            # ------------------------------------------------
            # AI processing
            #
            # The AI receives the tokenized/safe message,
            # never the raw sensitive value.
            # ------------------------------------------------

            print(
                "\nSending safe message "
                "to local AI model..."
            )

            ai_response = ask_ai(
                message,
                secure_operation_notes=
                    secure_notes
            )

            if not ai_response:

                ai_response = (
                    "Agent B received the message "
                    "but the AI model returned no text."
                )

            # ------------------------------------------------
            # Output
            # ------------------------------------------------

            print(
                "\nAgent B AI response:"
            )

            print(
                ai_response
            )

            print(
                "\nSecure operations completed:",
                resolved_count
            )

            print(
                "Secure operations denied:",
                denied_count
            )

            print(
                "=" * 70
            )

            self.send_json(
                {
                    "agent":
                        "Agent B",

                    "status":
                        "processed",

                    "received_message":
                        message,

                    "secure_tokens_detected":
                        len(tokens),

                    "secure_operations_completed":
                        resolved_count,

                    "secure_operations_denied":
                        denied_count,

                    "response":
                        ai_response
                }
            )

        except RuntimeError as error:

            self.send_json(
                {
                    "error":
                        str(error)
                },
                503
            )

        except Exception as error:

            self.send_json(
                {
                    "error":
                        str(error)
                },
                500
            )


# ============================================================
# Start server
# ============================================================

def start_agent_b():

    server = HTTPServer(
        (
            HOST,
            PORT
        ),
        AgentBHandler
    )

    print(
        "=" * 70
    )

    print(
        "AGENT B IS RUNNING"
    )

    print(
        "=" * 70
    )

    print(
        f"Listening on "
        f"http://{HOST}:{PORT}"
    )

    print(
        "AI model:",
        OLLAMA_MODEL
    )

    print(
        "Agent identity:",
        AGENT_NAME
    )

    print(
        "Vault authentication:",
        (
            "CONFIGURED"
            if AGENT_KEY
            else "NOT CONFIGURED"
        )
    )

    print(
        "Thinking mode: OFF"
    )

    print(
        "Secure token retrieval: ENABLED"
    )

    print(
        "Raw token values are never "
        "displayed or sent to the AI prompt."
    )

    print(
        "Waiting for messages..."
    )

    print(
        "Press CTRL+C to stop."
    )

    print(
        "=" * 70
    )

    try:

        server.serve_forever()

    except KeyboardInterrupt:

        print(
            "\nAgent B stopped."
        )

    finally:

        server.server_close()


# ============================================================
# Main
# ============================================================

if __name__ == "__main__":

    start_agent_b()