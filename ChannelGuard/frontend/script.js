let totalEvents = 0;
let allowedEvents = 0;
let redactedEvents = 0;
let alertEvents = 0;


// ============================================================
// Update dashboard counters
// ============================================================

function renderCounters() {

    document.getElementById(
        "totalEvents"
    ).textContent = totalEvents;


    document.getElementById(
        "allowedEvents"
    ).textContent = allowedEvents;


    document.getElementById(
        "redactedEvents"
    ).textContent = redactedEvents;


    document.getElementById(
        "alertEvents"
    ).textContent = alertEvents;
}


function updateCounters(status) {

    totalEvents++;


    if (status === "ALLOW") {

        allowedEvents++;

    }

    else if (status === "REDACT") {

        redactedEvents++;

    }

    else if (status === "ALERT") {

        alertEvents++;
    }


    renderCounters();
}


// ============================================================
// Toggle secure token options
// ============================================================

function toggleSecureOptions() {

    const mode =
        document.getElementById(
            "forwardingMode"
        ).value;


    const secureOptions =
        document.getElementById(
            "secureOptions"
        );


    if (mode === "tokenize") {

        secureOptions.classList.remove(
            "hidden"
        );

    }

    else {

        secureOptions.classList.add(
            "hidden"
        );
    }
}


// ============================================================
// Format status
// ============================================================

function statusClass(status) {

    if (status === "ALLOW") {

        return "allow";
    }


    if (status === "REDACT") {

        return "redact";
    }


    return "alert";
}


// ============================================================
// Scan one event
// ============================================================

async function scanEvent() {

    const channel =
        document.getElementById(
            "channel"
        ).value;


    const content =
        document.getElementById(
            "content"
        ).value.trim();


    const sessionId =
        document.getElementById(
            "sessionId"
        ).value.trim()
        || "default";


    const forwardingMode =
        document.getElementById(
            "forwardingMode"
        ).value;


    const requester =
        document.getElementById(
            "requester"
        ).value;


    const purpose =
        document.getElementById(
            "purpose"
        ).value;


    const resultBox =
        document.getElementById(
            "resultBox"
        );


    if (!content) {

        resultBox.innerHTML = `
            <div class="empty-state">
                <span>⚠️</span>
                <p>Please enter event content first.</p>
            </div>
        `;

        return;
    }


    resultBox.innerHTML = `
        <div class="empty-state">
            <span>🛡️</span>
            <p>Scanning event through ChannelGuard...</p>
        </div>
    `;


    const payload = {

        channel:
            channel,

        content:
            content,

        session_id:
            sessionId,

        forwarding_mode:
            forwardingMode
    };


    if (forwardingMode === "tokenize") {

        payload.requester =
            requester;

        payload.purpose =
            purpose;
    }


    try {

        const response = await fetch(
            "/scan",
            {
                method:
                    "POST",

                headers: {
                    "Content-Type":
                        "application/json"
                },

                body:
                    JSON.stringify(
                        payload
                    )
            }
        );


        if (!response.ok) {

            let errorData;


            try {

                errorData =
                    await response.json();

            }

            catch {

                errorData = {
                    detail:
                        await response.text()
                };
            }


            throw new Error(
                buildServerError(
                    response.status,
                    errorData
                )
            );
        }


        const data =
            await response.json();


        updateCounters(
            data.status
        );


        displayScanResult(
            data
        );


        refreshVaultStatus();

    }

    catch (error) {

        resultBox.innerHTML = `
            <div
                style="
                    background:#0b0f14;
                    border:1px solid #4a3434;
                    border-radius:8px;
                    padding:18px;
                "
            >

                <div
                    style="
                        color:#d5a6a6;
                        font-weight:bold;
                        margin-bottom:8px;
                    "
                >
                    Security Request Rejected
                </div>

                <div
                    style="
                        color:#aeb8c2;
                        font-size:13px;
                        white-space:pre-wrap;
                        line-height:1.5;
                    "
                >
                    ${escapeHtml(
                        error.message
                    )}
                </div>

            </div>
        `;
    }
}


// ============================================================
// Build backend error message
// ============================================================

function buildServerError(
    status,
    errorData
) {

    const detail =
        errorData?.detail;


    if (
        detail &&
        typeof detail === "object"
    ) {

        let message =
            detail.message
            || detail.error
            || "Request rejected.";


        if (
            detail.required_purpose_options
            &&
            Array.isArray(
                detail.required_purpose_options
            )
        ) {

            const options =
                detail.required_purpose_options
                    .map(
                        (item) => {

                            const purposes =
                                (
                                    item.allowed_purposes
                                    || []
                                ).join(
                                    ", "
                                );


                            return (
                                item.category
                                + " → "
                                + purposes
                            );
                        }
                    )
                    .join(
                        "\n"
                    );


            if (options) {

                message +=
                    "\n\nAllowed purpose(s):\n"
                    + options;
            }
        }


        return (
            "HTTP "
            + status
            + "\n"
            + message
        );
    }


    if (
        typeof detail === "string"
    ) {

        return (
            "HTTP "
            + status
            + "\n"
            + detail
        );
    }


    return (
        "HTTP "
        + status
        + "\nRequest rejected."
    );
}


// ============================================================
// Display scan result
// ============================================================

function displayScanResult(data) {

    const resultBox =
        document.getElementById(
            "resultBox"
        );


    const resultSummary =
        document.getElementById(
            "resultSummary"
        );


    const categories =
        data.categories
        &&
        data.categories.length > 0

            ? data.categories.join(", ")

            : "None";


    const memoryStatus =
        data.memory_hit

            ? "YES (" +
              data.memory_hit_count +
              " match)"

            : "NO";


    const forwardingMode =
        data.forwarding_mode
        || "redact";


    resultSummary.textContent =
        data.reason
        || "Scan completed.";


    resultBox.innerHTML = `

        <div class="result-top">

            <div>

                <strong>
                    Security Decision
                </strong>

                <div
                    style="
                        color:#7f8c99;
                        font-size:12px;
                        margin-top:5px;
                    "
                >
                    Audit ID:
                    ${escapeHtml(
                        data.audit_id
                        || "N/A"
                    )}
                </div>

            </div>


            <span class="
                status-badge
                ${statusClass(data.status)}
            ">
                ${escapeHtml(
                    data.status
                    || "UNKNOWN"
                )}
            </span>

        </div>


        <div class="result-grid">

            <div class="result-item">

                <span>Channel</span>

                <strong>
                    ${escapeHtml(
                        data.channel_name
                        || data.channel
                        || "N/A"
                    )}
                </strong>

            </div>


            <div class="result-item">

                <span>Category</span>

                <strong>
                    ${escapeHtml(
                        categories
                    )}
                </strong>

            </div>


            <div class="result-item">

                <span>Memory Hit</span>

                <strong>
                    ${escapeHtml(
                        memoryStatus
                    )}
                </strong>

            </div>


            <div class="result-item">

                <span>Forwarding Mode</span>

                <strong>
                    ${escapeHtml(
                        forwardingMode
                    ).toUpperCase()}
                </strong>

            </div>


            <div class="result-item">

                <span>Policy</span>

                <strong>
                    ${escapeHtml(
                        data.policy_action
                        || "N/A"
                    )}
                </strong>

            </div>


            <div class="result-item">

                <span>Session</span>

                <strong>
                    ${escapeHtml(
                        data.session_id
                        || "default"
                    )}
                </strong>

            </div>


            <div class="result-item full">

                <span>Purpose</span>

                <strong>
                    ${escapeHtml(
                        data.purpose
                        || "N/A"
                    )}
                </strong>

            </div>


            <div class="result-item full">

                <span>Reason</span>

                <strong>
                    ${escapeHtml(
                        data.reason
                        || "N/A"
                    )}
                </strong>

            </div>


            <div class="result-item full">

                <span>Original Content</span>

                <div class="content-block">
                    ${escapeHtml(
                        data.original_content
                        || ""
                    )}
                </div>

            </div>


            <div class="result-item full">

                <span>
                    Sanitized / Forwarded Content
                </span>

                <div class="content-block">
                    ${escapeHtml(
                        data.sanitized_content
                        || ""
                    )}
                </div>

            </div>

        </div>
    `;


    displayTokenDetails(
        data
    );


    displayDetectionDetails(
        data
    );
}


// ============================================================
// Secure token details
// ============================================================

function displayTokenDetails(data) {

    const tokenSection =
        document.getElementById(
            "tokenSection"
        );


    const tokenDetails =
        document.getElementById(
            "tokenDetails"
        );


    const records =
        data.token_records
        || [];


    if (
        data.forwarding_mode
        !== "tokenize"
        || records.length === 0
    ) {

        tokenSection.classList.add(
            "hidden"
        );

        tokenDetails.innerHTML =
            "";

        return;
    }


    tokenSection.classList.remove(
        "hidden"
    );


    tokenDetails.innerHTML =
        records.map(
            (record) => `

                <div class="token-card">

                    <div class="token-title">

                        <strong>
                            ${escapeHtml(
                                record.category
                            )}
                        </strong>

                        <span class="token-pill">
                            SECURE REFERENCE
                        </span>

                    </div>


                    <div class="token-value">
                        ${escapeHtml(
                            record.token
                        )}
                    </div>


                    <div class="token-meta">

                        <div>

                            <span>
                                Intended Agent
                            </span>

                            <strong>
                                ${escapeHtml(
                                    record.intended_requester
                                    || data.requester
                                    || "Agent B"
                                )}
                            </strong>

                        </div>


                        <div>

                            <span>
                                Purpose
                            </span>

                            <strong>
                                ${escapeHtml(
                                    data.purpose
                                    || "N/A"
                                )}
                            </strong>

                        </div>


                        <div>

                            <span>
                                Lifetime
                            </span>

                            <strong>
                                ${escapeHtml(
                                    String(
                                        record
                                            .expires_in_seconds
                                    )
                                )}
                                seconds
                            </strong>

                        </div>

                    </div>

                </div>
            `
        ).join("");
}


// ============================================================
// Detection details
// ============================================================

function displayDetectionDetails(data) {

    const detailsSection =
        document.getElementById(
            "detailsSection"
        );


    const detectionDetails =
        document.getElementById(
            "detectionDetails"
        );


    const detections =
        data.detections
        || [];


    if (
        detections.length === 0
    ) {

        detailsSection.classList.add(
            "hidden"
        );

        detectionDetails.innerHTML =
            "";

        return;
    }


    detailsSection.classList.remove(
        "hidden"
    );


    detectionDetails.innerHTML =
        detections.map(
            (detection) => {

                let meta = "";


                if (
                    detection.normalization
                ) {

                    meta +=
                        "Normalization: "
                        + escapeHtml(
                            detection.normalization
                        );
                }


                if (
                    detection.confidence !==
                    undefined
                ) {

                    if (meta) {
                        meta += " · ";
                    }

                    meta +=
                        "Confidence: "
                        + escapeHtml(
                            String(
                                detection.confidence
                            )
                        );
                }


                if (
                    detection.source
                ) {

                    if (meta) {
                        meta += " · ";
                    }

                    meta +=
                        "Source: "
                        + escapeHtml(
                            detection.source
                        );
                }


                return `

                    <div class="detection-card">

                        <div class="detection-line">

                            <span
                                class="detection-category"
                            >
                                ${escapeHtml(
                                    detection.category
                                )}
                            </span>


                            <span
                                class="detection-source"
                            >
                                span:
                                ${escapeHtml(
                                    String(
                                        detection.start
                                    )
                                )}
                                -
                                ${escapeHtml(
                                    String(
                                        detection.end
                                    )
                                )}
                            </span>

                        </div>


                        <div class="detection-meta">
                            ${meta}
                        </div>

                    </div>
                `;
            }
        ).join("");
}


// ============================================================
// Vault status
// ============================================================

async function refreshVaultStatus() {

    try {

        const response =
            await fetch(
                "/vault/status"
            );


        if (!response.ok) {

            return;
        }


        const data =
            await response.json();


        document.getElementById(
            "activeTokens"
        ).textContent =
            data.active_tokens
            ?? 0;


        const ttl =
            Number(
                data.token_ttl_seconds
                ?? 900
            );


        document.getElementById(
            "tokenTTL"
        ).textContent =
            formatTTL(
                ttl
            );


        const categories =
            data.categories
            || {};


        const categoryNames =
            Object.keys(
                categories
            );


        document.getElementById(
            "vaultCategories"
        ).textContent =

            categoryNames.length

                ? categoryNames.join(", ")

                : "None";

    }

    catch (error) {

        // Supplementary status only.
    }
}


// ============================================================
// Format TTL
// ============================================================

function formatTTL(seconds) {

    if (seconds < 60) {

        return seconds + " sec";
    }


    const minutes =
        Math.floor(
            seconds / 60
        );


    if (minutes < 60) {

        return minutes + " min";
    }


    const hours =
        Math.floor(
            minutes / 60
        );


    return hours + " hr";
}


// ============================================================
// Replay sample trace
// ============================================================

async function replaySample() {

    const resultBox =
        document.getElementById(
            "resultBox"
        );


    const resultSummary =
        document.getElementById(
            "resultSummary"
        );


    resultBox.innerHTML = `
        <div class="empty-state">
            <span>🔄</span>
            <p>Replaying sample event stream...</p>
        </div>
    `;


    try {

        const response =
            await fetch(
                "/replay/sample"
            );


        if (!response.ok) {

            const errorText =
                await response.text();


            throw new Error(
                "Replay server error: "
                + response.status
                + "\n"
                + errorText
            );
        }


        const data =
            await response.json();


        totalEvents +=
            data.counts.ALLOW
            + data.counts.REDACT
            + data.counts.ALERT;


        allowedEvents +=
            data.counts.ALLOW;


        redactedEvents +=
            data.counts.REDACT;


        alertEvents +=
            data.counts.ALERT;


        renderCounters();


        resultSummary.textContent =
            "Sample trace replay completed.";


        let html = `

            <div class="result-top">

                <div>

                    <strong>
                        Replay Run
                    </strong>

                    <div
                        style="
                            color:#7f8c99;
                            font-size:12px;
                            margin-top:5px;
                        "
                    >
                        ${escapeHtml(
                            data.run_id
                        )}
                    </div>

                </div>

            </div>


            <div class="result-grid">

                <div class="result-item">

                    <span>Total Events</span>

                    <strong>
                        ${escapeHtml(
                            String(
                                data.total_events
                            )
                        )}
                    </strong>

                </div>


                <div class="result-item">

                    <span>Session</span>

                    <strong>
                        ${escapeHtml(
                            data.session_id
                        )}
                    </strong>

                </div>


                <div class="result-item">

                    <span>ALLOW</span>

                    <strong>
                        ${escapeHtml(
                            String(
                                data.counts.ALLOW
                            )
                        )}
                    </strong>

                </div>


                <div class="result-item">

                    <span>REDACT</span>

                    <strong>
                        ${escapeHtml(
                            String(
                                data.counts.REDACT
                            )
                        )}
                    </strong>

                </div>


                <div class="result-item">

                    <span>ALERT</span>

                    <strong>
                        ${escapeHtml(
                            String(
                                data.counts.ALERT
                            )
                        )}
                    </strong>

                </div>


                <div class="result-item">

                    <span>SKIPPED</span>

                    <strong>
                        ${escapeHtml(
                            String(
                                data.counts.SKIPPED
                            )
                        )}
                    </strong>

                </div>

            </div>
        `;


        data.events.forEach(
            (event, index) => {

                const categories =
                    event.categories
                    &&
                    event.categories.length

                        ? event.categories.join(
                            ", "
                        )

                        : "None";


                html += `

                    <div
                        style="
                            margin-top:15px;
                            background:#0b0f14;
                            border:1px solid #202a34;
                            border-radius:8px;
                            padding:14px;
                        "
                    >

                        <div
                            style="
                                font-weight:bold;
                                margin-bottom:10px;
                            "
                        >
                            Event ${index + 1}
                        </div>


                        <div class="detection-meta">

                            Channel:
                            ${escapeHtml(
                                event.channel
                            )}

                            <br>

                            Status:
                            ${escapeHtml(
                                event.status
                            )}

                            <br>

                            Category:
                            ${escapeHtml(
                                categories
                            )}

                            <br>

                            Memory Hit:
                            ${event.memory_hit
                                ? "YES"
                                : "NO"
                            }

                        </div>


                        <div
                            class="content-block"
                            style="
                                margin-top:10px;
                            "
                        >
                            ${escapeHtml(
                                event.sanitized_content
                                || ""
                            )}
                        </div>

                    </div>
                `;
            }
        );


        resultBox.innerHTML =
            html;


        refreshVaultStatus();

    }

    catch (error) {

        resultBox.innerHTML = `
            <div class="empty-state">

                <span>❌</span>

                <p>Replay error</p>

                <small>
                    ${escapeHtml(
                        error.message
                    )}
                </small>

            </div>
        `;
    }
}


// ============================================================
// HTML escaping
// ============================================================

function escapeHtml(value) {

    return String(
        value ?? ""
    )
        .replace(
            /&/g,
            "&amp;"
        )
        .replace(
            /</g,
            "&lt;"
        )
        .replace(
            />/g,
            "&gt;"
        )
        .replace(
            /"/g,
            "&quot;"
        )
        .replace(
            /'/g,
            "&#039;"
        );
}


// ============================================================
// Initial dashboard setup
// ============================================================

document.addEventListener(
    "DOMContentLoaded",
    () => {

        toggleSecureOptions();

        refreshVaultStatus();

        setInterval(
            refreshVaultStatus,
            5000
        );

    }
);