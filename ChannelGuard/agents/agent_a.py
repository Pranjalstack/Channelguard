import requests


# ============================================================
# Configuration
# ============================================================

CHANNELGUARD_URL = "http://127.0.0.1:8000"

AGENT_B_URL = "http://127.0.0.1:8002/receive"

OLLAMA_URL = "http://127.0.0.1:11434/api/generate"

OLLAMA_MODEL = "qwen3.5:0.8b"

SESSION_ID = "agent-demo"


# ============================================================
# Purpose inference
# ============================================================

def infer_purpose(text):

    lower_text = text.lower()

    # --------------------------------------------------------
    # Email delivery
    # --------------------------------------------------------

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
        keyword in lower_text
        for keyword in email_keywords
    ):

        return "email_delivery"

    # --------------------------------------------------------
    # Phone verification
    # --------------------------------------------------------

    phone_keywords = [
        "verify phone",
        "phone verification",
        "verify the phone",
        "otp",
        "one-time password",
        "phone number"
    ]

    if any(
        keyword in lower_text
        for keyword in phone_keywords
    ):

        return "phone_verification"

    # --------------------------------------------------------
    # Payment
    # --------------------------------------------------------

    payment_keywords = [
        "payment",
        "pay",
        "charge",
        "transaction",
        "card payment",
        "process payment"
    ]

    if any(
        keyword in lower_text
        for keyword in payment_keywords
    ):

        return "payment_processing"

    # --------------------------------------------------------
    # Identity verification
    # --------------------------------------------------------

    identity_keywords = [
        "verify identity",
        "identity verification",
        "kyc",
        "identity check"
    ]

    if any(
        keyword in lower_text
        for keyword in identity_keywords
    ):

        return "identity_verification"

    return None


# ============================================================
# AI generation
# ============================================================

def generate_agent_a_message(
    user_instruction
):

    prompt = f"""
You are Agent A in a multi-agent system.

Your job is to convert the user's instruction into
one concise message for Agent B.

Return ONLY the message that should be sent to Agent B.

Important:
- Preserve important task details.
- If the user provides sensitive information such as
  an email, phone number, payment card, name or location,
  preserve it in the generated message.
- Do not explain your reasoning.

User instruction:
{user_instruction}
""".strip()

    payload = {

        "model":
            OLLAMA_MODEL,

        "prompt":
            prompt,

        "stream":
            False,

        "think":
            False
    }

    try:

        response = requests.post(
            OLLAMA_URL,
            json=payload,
            timeout=120
        )

        response.raise_for_status()

        data = response.json()

        message = data.get(
            "response",
            ""
        ).strip()

        if not message:

            return (
                None,
                "Ollama returned an empty response."
            )

        return (
            message,
            None
        )

    except requests.exceptions.ConnectionError:

        return (
            None,
            "Could not connect to Ollama."
        )

    except requests.exceptions.Timeout:

        return (
            None,
            "Ollama request timed out."
        )

    except Exception as error:

        return (
            None,
            str(error)
        )


# ============================================================
# ChannelGuard scan
# ============================================================

def scan_with_channelguard(
    message,
    purpose
):

    # --------------------------------------------------------
    # Use tokenization when there is a legitimate operation
    # that may need the sensitive value.
    #
    # Otherwise use normal redaction.
    # --------------------------------------------------------

    if purpose:

        forwarding_mode = "tokenize"

    else:

        forwarding_mode = "redact"


    payload = {

        "session_id":
            SESSION_ID,

        "channel":
            "agent_message",

        "content":
            message,

        "forwarding_mode":
            forwarding_mode,

        "requester":
            "Agent B",

        "purpose":
            purpose or ""
    }


    try:

        response = requests.post(

            f"{CHANNELGUARD_URL}/scan",

            json=payload,

            timeout=30
        )

        response.raise_for_status()

        return (
            response.json(),
            None
        )

    except requests.exceptions.ConnectionError:

        return (
            None,
            "Could not connect to ChannelGuard."
        )

    except requests.exceptions.Timeout:

        return (
            None,
            "ChannelGuard request timed out."
        )

    except Exception as error:

        return (
            None,
            str(error)
        )


# ============================================================
# Send sanitized/tokenized message to Agent B
# ============================================================

def send_to_agent_b(
    message
):

    payload = {

        "source":
            "Agent A",

        "channel":
            "agent_message",

        "session_id":
            SESSION_ID,

        "message":
            message
    }


    try:

        response = requests.post(

            AGENT_B_URL,

            json=payload,

            timeout=120
        )

        response.raise_for_status()

        return (
            response.json(),
            None
        )

    except requests.exceptions.ConnectionError:

        return (
            None,
            "Could not connect to Agent B."
        )

    except requests.exceptions.Timeout:

        return (
            None,
            "Agent B request timed out."
        )

    except Exception as error:

        return (
            None,
            str(error)
        )


# ============================================================
# Printing helper
# ============================================================

def print_separator():

    print(
        "\n"
        + "=" * 70
    )


# ============================================================
# Main
# ============================================================

def main():

    print_separator()

    print(
        "CHANNELGUARD - AI AGENT A"
    )

    print(
        "=" * 70
    )

    print(
        "Ollama Model :",
        OLLAMA_MODEL
    )

    print(
        "Thinking     : OFF"
    )

    print(
        "Channel      : agent_message"
    )

    print(
        "Session      :",
        SESSION_ID
    )

    print(
        "Secure token workflow: ENABLED"
    )

    print(
        "=" * 70
    )

    print(
        "\nAgent A is ready."
    )

    print(
        "Type an instruction for Agent A."
    )

    print(
        "Type 'exit' to stop.\n"
    )


    while True:

        try:

            user_instruction = input(
                "You → Agent A: "
            ).strip()

        except (
            KeyboardInterrupt,
            EOFError
        ):

            print(
                "\nExiting Agent A."
            )

            break


        if not user_instruction:

            continue


        if user_instruction.lower() == "exit":

            print(
                "Exiting Agent A."
            )

            break


        # ====================================================
        # STEP 1 — Agent A generates AI message
        # ====================================================

        print(
            "\n[1] Agent A is thinking..."
        )


        generated_message, error = (
            generate_agent_a_message(
                user_instruction
            )
        )


        if error:

            print(
                "[ERROR]",
                error
            )

            continue


        print(
            "\nAgent A generated:"
        )

        print(
            generated_message
        )


        # ====================================================
        # STEP 2 — Determine legitimate purpose
        # ====================================================

        purpose = infer_purpose(

            user_instruction

            + " "

            + generated_message
        )


        print(
            "\nDetected task purpose:",
            purpose or "none"
        )


        # ====================================================
        # STEP 3 — ChannelGuard
        # ====================================================

        print(
            "\n[2] Sending message through ChannelGuard..."
        )


        result, error = (
            scan_with_channelguard(

                generated_message,

                purpose
            )
        )


        if error:

            print(
                "[ERROR]",
                error
            )

            continue


        status = result.get(
            "status",
            "UNKNOWN"
        )


        categories = result.get(
            "categories",
            []
        )


        sanitized_content = result.get(
            "sanitized_content",
            generated_message
        )


        memory_hit = result.get(
            "memory_hit",
            False
        )


        forwarding_mode = result.get(
            "forwarding_mode",
            "redact"
        )


        audit_id = result.get(
            "audit_id",
            ""
        )


        token_records = result.get(
            "token_records",
            []
        )


        print(
            "\nChannelGuard Decision :",
            status
        )


        print(
            "Categories            :",
            categories
        )


        print(
            "Memory Hit            :",
            memory_hit
        )


        print(
            "Forwarding Mode       :",
            forwarding_mode
        )


        print(
            "Purpose               :",
            purpose or "none"
        )


        print(
            "Audit ID              :",
            audit_id
        )


        print(
            "\nOriginal:"
        )


        print(
            generated_message
        )


        print(
            "\nAfter ChannelGuard:"
        )


        print(
            sanitized_content
        )


        if token_records:

            print(
                "\nSecure token(s) created:"
            )

            for record in token_records:

                print(
                    "Category:",
                    record.get(
                        "category"
                    )
                )

                print(
                    "Token:",
                    record.get(
                        "token"
                    )
                )

                print(
                    "Intended requester:",
                    record.get(
                        "intended_requester"
                    )
                )


        # ====================================================
        # STEP 4 — Forward to Agent B
        # ====================================================

        if status == "BLOCK":

            print(
                "\n[3] Message BLOCKED."
            )

            print(
                "Agent B did not receive the message."
            )

            continue


        if (
            forwarding_mode
            == "tokenize"
            and token_records
        ):

            print(
                "\n[3] Sensitive information detected."
            )

            print(
                "Forwarding secure token reference "
                "to Agent B."
            )

        elif status == "REDACT":

            print(
                "\n[3] Sensitive information detected."
            )

            print(
                "Forwarding redacted message "
                "to Agent B."
            )

        elif status == "ALERT":

            print(
                "\n[3] ALERT: forwarding "
                "sanitized message to Agent B."
            )

        else:

            print(
                "\n[3] Message allowed."
            )


        # ====================================================
        # STEP 5 — Agent B
        # ====================================================

        print(
            "\n[4] Sending message to Agent B..."
        )


        agent_b_result, error = (
            send_to_agent_b(

                sanitized_content
            )
        )


        if error:

            print(
                "[ERROR]",
                error
            )

            continue


        print(
            "\nAgent B received:"
        )

        print(
            agent_b_result.get(
                "received_message",
                sanitized_content
            )
        )


        print(
            "\nAgent B AI response:"
        )

        print(
            agent_b_result.get(
                "response",
                "(No response returned)"
            )
        )


        print(
            "\nSecure operations completed:",
            agent_b_result.get(
                "secure_operations_completed",
                0
            )
        )


        print(
            "Secure operations denied:",
            agent_b_result.get(
                "secure_operations_denied",
                0
            )
        )


        print_separator()


# ============================================================
# Main
# ============================================================

if __name__ == "__main__":

    main()