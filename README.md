# ChannelGuard

### Runtime Internal-Channel Privacy Protection for AI Agents

ChannelGuard is a runtime privacy and security layer designed to protect sensitive information moving through **internal AI-agent communication channels**.

Instead of relying only on the AI model to protect private information, ChannelGuard acts as an **independent security boundary** that inspects data before it reaches the next component.

> **AI handles intelligence. ChannelGuard handles trust.**

---

## Overview

Modern AI systems can contain multiple agents and internal components that exchange information.

Sensitive data can appear in:

* Agent-to-agent messages
* Tool outputs
* Runtime logs
* Debug events

ChannelGuard detects sensitive information in these internal channels and applies a security policy before the information is passed downstream.

The system can:

* Detect sensitive information
* Normalize encoded or hidden content
* Remember sensitive values within a session
* Apply channel-specific policies
* Redact sensitive information
* Replace sensitive information with secure tokens
* Control token access using authentication and authorization
* Record secure audit events

---

## Architecture

```text
                    User Instruction
                           |
                           v
                    +-------------+
                    |   Agent A   |
                    | Qwen 3.5    |
                    |    0.8B     |
                    +-------------+
                           |
                           | Internal Event
                           v
              +----------------------------+
              |        ChannelGuard        |
              |                            |
              |  1. Normalize              |
              |  2. Detect PII             |
              |  3. Session Memory         |
              |  4. Channel Policy         |
              |  5. Redact / Tokenize      |
              |  6. Audit Logging          |
              +----------------------------+
                           |
                    ALLOW / REDACT / ALERT
                           |
                           v
                    +-------------+
                    |   Agent B   |
                    | Qwen 3.5    |
                    |    0.8B     |
                    +-------------+
```

---

## Key Features

### 1. Multi-Channel Protection

ChannelGuard supports four internal channels:

| Channel                | Security Action  |
| ---------------------- | ---------------- |
| Agent-to-Agent Message | REDACT           |
| Tool Output            | REDACT           |
| Runtime Log            | ALERT + SANITIZE |
| Debug Event            | ALERT + SANITIZE |

---

### 2. Sensitive Data Detection

The system can detect:

* Email addresses
* Phone numbers
* Payment card numbers
* Person names
* Locations
* IP addresses

Detection uses multiple layers:

* Regular Expressions
* Microsoft Presidio
* spaCy NER
* Session-memory matching

---

### 3. Data Normalization

Sensitive information may not always appear in plain text.

ChannelGuard normalizes content before detection, including:

* URL decoding
* Base64 decoding
* Unicode escape decoding
* Nested JSON extraction

This helps detect sensitive information even when it is encoded or hidden inside structured data.

---

### 4. Session Memory

ChannelGuard maintains session-level memory for previously detected:

* Email addresses
* Phone numbers
* Card numbers

This helps identify previously seen sensitive values when they appear again in the same session, including different formatting.

---

### 5. Security Decisions

After detection, ChannelGuard applies the policy for the channel.

The system produces one of three main decisions:

```text
ALLOW
REDACT
ALERT
```

#### ALLOW

No sensitive information was detected.

#### REDACT

Sensitive information is replaced with safe placeholders.

Example:

```text
Original:
Send confirmation to ravi@gmail.com

Sanitized:
Send confirmation to [EMAIL]
```

#### ALERT

A sensitive value is detected in a higher-risk situation. The event is sanitized and an alert-producing decision is generated.

---

## Secure Tokenization

ChannelGuard supports tokenization when the sensitive value may still be required for a legitimate downstream operation.

Example:

```text
Original:
Send confirmation to ravi@gmail.com
```

After tokenization:

```text
Send confirmation to [EMAIL_TOKEN:CG-EMAIL-Aueo1ldfXqo]
```

The original value is kept inside the **ChannelGuard secure token vault**.

The downstream component receives the token instead of the raw value.

### Token Flow

```text
Sensitive Value
      |
      v
ChannelGuard Detection
      |
      v
Secure Token Vault
      |
      +---- Original value stored internally
      |
      +---- Opaque token generated
                    |
                    v
          Downstream Component
```

The prototype uses a **15-minute / 900-second token lifetime**.

---

## Token Authorization

Possessing a token does not automatically provide access to the original value.

A downstream agent must request token resolution through ChannelGuard.

```text
Agent B
   |
   | Token + Purpose + Session
   v
ChannelGuard
   |
   +--> Authentication
   |
   +--> Purpose Check
   |
   +--> Session Check
   |
   +--> Token Expiry Check
   |
   v
ALLOW / DENY
   |
   v
Secure Vault
```

Example purpose policies:

| Purpose                 | Allowed Data                   |
| ----------------------- | ------------------------------ |
| `email_delivery`        | EMAIL                          |
| `phone_verification`    | PHONE                          |
| `payment_processing`    | CARD                           |
| `identity_verification` | EMAIL, PHONE, PERSON, LOCATION |

---

## Authentication

Agent access uses a configured agent credential.

The Agent B key is supplied through an environment variable rather than being hard-coded into the application.

Example on Windows PowerShell:

```powershell
$env:CHANNELGUARD_AGENT_B_KEY = "CG-AGENT-B-KEY-2026"
```

ChannelGuard validates the credential before allowing token resolution.

---

## Audit Logging

ChannelGuard maintains a secure JSONL audit log.

The audit system records information such as:

* Audit ID
* Timestamp
* Session ID
* Channel
* Security status
* Sensitive categories
* Sanitized content
* Detection metadata

Raw sensitive values are not intentionally stored in the audit log.

Where applicable, SHA-256 hashes are used for value-related tracking without storing the original value directly.

Audit file:

```text
data/audit.jsonl
```

---

## AI Agents

The prototype uses two local AI agents powered by:

```text
Ollama
    +
Qwen 3.5 0.8B
```

The AI agents are separate from the ChannelGuard security layer.

This means the privacy controls do not depend entirely on the AI model itself.

---

## Technology Stack

### Backend

* Python
* FastAPI
* Uvicorn

### AI

* Ollama
* Qwen 3.5 0.8B

### Security / Detection

* Microsoft Presidio
* spaCy
* Regular Expressions
* Custom policy engine
* Custom secure token vault
* Session memory

### Frontend

* HTML
* CSS
* JavaScript

### Logging / Storage

* JSONL audit logging
* In-memory session storage
* In-memory token vault for the prototype

---

## Project Structure

```text
ChannelGuard/
│
├── agents/
│   ├── agent_a.py
│   └── agent_b.py
│
├── backend/
│   ├── main.py
│   ├── audit_log.py
│   ├── session_memory.py
│   ├── replay.py
│   ├── evaluator.py
│   ├── token_vault.py
│   │
│   └── detectors/
│       └── pii_detector.py
│
├── frontend/
│   ├── index.html
│   ├── style.css
│   └── script.js
│
├── data/
│   ├── audit.jsonl
│   ├── agentleak_sample.json
│   └── evaluation_cases.json
│
├── requirements.txt
└── README.md
```

---

## Requirements

* Windows 10 / 11
* Python 3.x
* Ollama

Install the required AI model:

```powershell
ollama pull qwen3.5:0.8b
```

If Ollama is not available in PATH:

```powershell
& "$env:LOCALAPPDATA\Programs\Ollama\ollama.exe" pull qwen3.5:0.8b
```

---

## Installation

Clone the repository:

```powershell
git clone <YOUR_GITHUB_REPOSITORY_URL>
cd ChannelGuard
```

Create a virtual environment:

```powershell
python -m venv .venv
```

Activate it:

```powershell
.\.venv\Scripts\Activate.ps1
```

Install dependencies:

```powershell
pip install -r requirements.txt
```

Configure the Agent B credential:

```powershell
$env:CHANNELGUARD_AGENT_B_KEY = "CG-AGENT-B-KEY-2026"
```

---

## Running the Project

### Terminal 1 — ChannelGuard

```powershell
cd "C:\Users\Pranjal Aggarwal\Desktop\ChannelGuard"
.\.venv\Scripts\Activate.ps1
uvicorn backend.main:app --reload
```

ChannelGuard runs at:

```text
http://127.0.0.1:8000
```

Dashboard:

```text
http://127.0.0.1:8000/dashboard
```

---

### Terminal 2 — Agent B

```powershell
cd "C:\Users\Pranjal Aggarwal\Desktop\ChannelGuard"
.\.venv\Scripts\Activate.ps1
python agents\agent_b.py
```

Agent B listens for requests from Agent A.

---

### Terminal 3 — Agent A

```powershell
cd "C:\Users\Pranjal Aggarwal\Desktop\ChannelGuard"
.\.venv\Scripts\Activate.ps1
python agents\agent_a.py
```

Agent A uses Ollama + Qwen and sends internal events through ChannelGuard before they reach the downstream component.

---

## Example

### Input

```text
Send confirmation to ravi@gmail.com
```

### Detection

```text
Category: EMAIL
```

### Redaction Mode

```text
Send confirmation to [EMAIL]
```

### Tokenization Mode

```text
Send confirmation to [EMAIL_TOKEN:CG-EMAIL-XXXXXXXX]
```

The original email remains inside the secure token vault.

---

## Runtime Flow

```text
Agent A
   |
   v
ChannelGuard
   |
   +--> Normalize
   |
   +--> Detect
   |
   +--> Session Memory
   |
   +--> Policy Check
   |
   +--> Redact / Tokenize
   |
   +--> Audit
   |
   v
Agent B
```

---

## Replay and Evaluation

The project includes:

* Synthetic trace replay
* Local evaluation dataset
* Security metrics

The local evaluation uses a **10-case synthetic dataset**.

### Local Synthetic Results

| Metric                | Result |
| --------------------- | -----: |
| Detection Recall      |   100% |
| Precision             |   100% |
| Redaction Accuracy    |   100% |
| Channel Coverage      |    4/4 |
| False-Positive Rate   |     0% |
| Residual Leakage Rate |     0% |

> **Important:** These results are from the project's local synthetic test dataset and should not be interpreted as official results on an external benchmark.

---

## Security Design

ChannelGuard follows the principle that **privacy enforcement should not depend entirely on the AI model**.

Instead:

```text
AI Model
   ↓
Independent Privacy Boundary
   ↓
Policy Enforcement
   ↓
Sanitized Data
```

This allows the security layer to remain useful even if the underlying AI model changes.

---

## Demo Flow

A simple demonstration can be performed as follows:

1. Start ChannelGuard.
2. Start Agent B.
3. Start Agent A.
4. Open the dashboard.
5. Send a normal message → `ALLOW`.
6. Send an email → `REDACT`.
7. Enable secure tokenization → generate a secure token.
8. Demonstrate token authorization and expiry.
9. Try different internal channels.
10. Review the resulting security and audit information.

---

## Hackathon

ChannelGuard was developed as part of the:

**“Win If You Can – Code the Solution” Hackathon**

at **SRM Institute of Science and Technology**.

The project focuses on runtime privacy protection for AI-agent internal communication.

---

## Disclaimer

ChannelGuard is a **prototype / hackathon project** intended to demonstrate the architecture and security concepts of runtime internal-channel privacy protection.

The secure token vault and secure operations are implemented as a prototype and should be replaced with production-grade secure infrastructure, secret management, access controls, and real secure service integrations before use in a production environment.

---

## Contributors

* Pranjal Aggarwal
* Chetan Malik

---

## License

Add your preferred license here, such as MIT, Apache-2.0, or another license appropriate for your repository.
