from backend.detectors.pii_detector import (
    detect_pii,
    redact_text
)


SUPPORTED_CHANNELS = {
    "agent_message",
    "tool_output",
    "runtime_log",
    "debug_event"
}


def normalize_category(category):
    """
    Keep category names consistent.
    """

    return str(category).strip().upper()


def evaluate_case(case):
    """
    Evaluate one labelled test case.

    Each case contains:
        channel
        content
        expected_sensitive
        expected_categories
    """

    channel = case["channel"]
    content = case["content"]

    expected_sensitive = case.get(
        "expected_sensitive",
        []
    )

    expected_categories = [
        normalize_category(category)
        for category in case.get(
            "expected_categories",
            []
        )
    ]

    # --------------------------------------------------------
    # Run ChannelGuard detector
    # --------------------------------------------------------

    detections = detect_pii(
        content
    )

    detected_categories = [
        normalize_category(
            detection["category"]
        )
        for detection in detections
    ]

    # --------------------------------------------------------
    # Detection matching
    # --------------------------------------------------------

    matched_sensitive = 0
    matched_expected_categories = set()

    for expected in expected_sensitive:

        expected_value = expected["value"]
        expected_category = normalize_category(
            expected["category"]
        )

        found = False

        for detection in detections:

            detected_category = normalize_category(
                detection["category"]
            )

            detected_value = detection.get(
                "value",
                ""
            )

            # Exact value match
            if (
                detected_category
                == expected_category
                and detected_value.lower()
                == expected_value.lower()
            ):
                found = True
                break

        if found:

            matched_sensitive += 1

            matched_expected_categories.add(
                expected_category
            )

    # --------------------------------------------------------
    # Ground truth items
    # --------------------------------------------------------

    total_sensitive = len(
        expected_sensitive
    )

    total_predictions = len(
        detections
    )

    true_positives = matched_sensitive

    # --------------------------------------------------------
    # Recall
    # --------------------------------------------------------

    if total_sensitive > 0:

        recall = (
            true_positives
            / total_sensitive
        )

    else:

        # Clean case does not contribute
        # to sensitive-item recall.
        recall = None

    # --------------------------------------------------------
    # Precision
    # --------------------------------------------------------

    if total_predictions > 0:

        precision = (
            true_positives
            / total_predictions
        )

    else:

        if total_sensitive == 0:
            precision = 1.0
        else:
            precision = 0.0

    # --------------------------------------------------------
    # Redaction
    # --------------------------------------------------------

    sanitized_content = redact_text(
        content,
        detections
    )

    correctly_redacted = 0

    for expected in expected_sensitive:

        expected_value = expected["value"]

        # The sensitive value should no longer
        # appear in the sanitized content.
        if expected_value.lower() not in (
            sanitized_content.lower()
        ):

            # Only count it as correctly redacted
            # if ChannelGuard actually detected it.
            detected = any(
                detection.get("category", "").upper()
                == expected["category"].upper()

                and detection.get("value", "").lower()
                == expected_value.lower()

                for detection in detections
            )

            if detected:
                correctly_redacted += 1

    if total_sensitive > 0:

        redaction_accuracy = (
            correctly_redacted
            / total_sensitive
        )

    else:

        redaction_accuracy = 1.0

    # --------------------------------------------------------
    # Residual leakage
    # --------------------------------------------------------

    residual_items = 0

    for expected in expected_sensitive:

        expected_value = expected["value"]

        if expected_value.lower() in (
            sanitized_content.lower()
        ):

            residual_items += 1

    if total_sensitive > 0:

        residual_leakage = (
            residual_items
            / total_sensitive
        )

    else:

        residual_leakage = 0.0

    # --------------------------------------------------------
    # False positive
    # --------------------------------------------------------

    is_clean_case = (
        total_sensitive == 0
    )

    false_positive = (
        is_clean_case
        and total_predictions > 0
    )

    # --------------------------------------------------------
    # Result
    # --------------------------------------------------------

    return {
        "channel": channel,

        "content": content,

        "expected_categories": (
            expected_categories
        ),

        "detected_categories": (
            detected_categories
        ),

        "expected_sensitive_count": (
            total_sensitive
        ),

        "detected_count": (
            total_predictions
        ),

        "true_positives": (
            true_positives
        ),

        "recall": recall,

        "precision": precision,

        "redaction_accuracy": (
            redaction_accuracy
        ),

        "residual_leakage": (
            residual_leakage
        ),

        "false_positive": (
            false_positive
        ),

        "sanitized_content": (
            sanitized_content
        )
    }


def evaluate_dataset(cases):
    """
    Evaluate the complete labelled dataset.
    """

    results = []

    total_sensitive = 0
    total_true_positives = 0

    total_predictions = 0

    total_redaction_correct = 0
    total_residual_leaks = 0

    clean_cases = 0
    false_positive_cases = 0

    covered_channels = set()

    for case in cases:

        result = evaluate_case(
            case
        )

        results.append(
            result
        )

        covered_channels.add(
            case["channel"]
        )

        total_sensitive += (
            result["expected_sensitive_count"]
        )

        total_true_positives += (
            result["true_positives"]
        )

        total_predictions += (
            result["detected_count"]
        )

        total_redaction_correct += (
            round(
                result["redaction_accuracy"]
                * result["expected_sensitive_count"]
            )
        )

        total_residual_leaks += (
            round(
                result["residual_leakage"]
                * result["expected_sensitive_count"]
            )
        )

        if result["expected_sensitive_count"] == 0:

            clean_cases += 1

            if result["false_positive"]:

                false_positive_cases += 1

    # --------------------------------------------------------
    # Detection recall
    # --------------------------------------------------------

    if total_sensitive > 0:

        detection_recall = (
            total_true_positives
            / total_sensitive
        )

    else:

        detection_recall = 0.0

    # --------------------------------------------------------
    # Precision
    # --------------------------------------------------------

    if total_predictions > 0:

        precision = (
            total_true_positives
            / total_predictions
        )

    else:

        precision = 0.0

    # --------------------------------------------------------
    # Redaction accuracy
    # --------------------------------------------------------

    if total_sensitive > 0:

        redaction_accuracy = (
            total_redaction_correct
            / total_sensitive
        )

    else:

        redaction_accuracy = 0.0

    # --------------------------------------------------------
    # Channel coverage
    # --------------------------------------------------------

    channel_coverage = (
        len(
            covered_channels
            & SUPPORTED_CHANNELS
        )
        / len(SUPPORTED_CHANNELS)
    )

    # --------------------------------------------------------
    # False-positive rate
    # --------------------------------------------------------

    if clean_cases > 0:

        false_positive_rate = (
            false_positive_cases
            / clean_cases
        )

    else:

        false_positive_rate = 0.0

    # --------------------------------------------------------
    # Residual leakage
    # --------------------------------------------------------

    if total_sensitive > 0:

        residual_leakage = (
            total_residual_leaks
            / total_sensitive
        )

    else:

        residual_leakage = 0.0

    # --------------------------------------------------------
    # Final report
    # --------------------------------------------------------

    return {
        "total_cases": len(cases),

        "total_sensitive_items": (
            total_sensitive
        ),

        "true_positives": (
            total_true_positives
        ),

        "total_predictions": (
            total_predictions
        ),

        "detection_recall": (
            round(
                detection_recall * 100,
                2
            )
        ),

        "precision": (
            round(
                precision * 100,
                2
            )
        ),

        "redaction_accuracy": (
            round(
                redaction_accuracy * 100,
                2
            )
        ),

        "channel_coverage": (
            f"{len(covered_channels & SUPPORTED_CHANNELS)}"
            f"/{len(SUPPORTED_CHANNELS)}"
        ),

        "channel_coverage_percent": (
            round(
                channel_coverage * 100,
                2
            )
        ),

        "false_positive_rate": (
            round(
                false_positive_rate * 100,
                2
            )
        ),

        "residual_leakage_rate": (
            round(
                residual_leakage * 100,
                2
            )
        ),

        "cases_with_false_positive": (
            false_positive_cases
        ),

        "clean_cases": (
            clean_cases
        ),

        "covered_channels": sorted(
            covered_channels
            & SUPPORTED_CHANNELS
        ),

        "cases": results
    }