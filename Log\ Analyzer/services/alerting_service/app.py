from datetime import datetime, timezone

import requests

from common.config import ALERT_SEVERITY_THRESHOLD, ENRICHED_ALERTS_TOPIC, WEBHOOK_URL
from common.kafka_utils import get_consumer
from common.logging_utils import get_logger

logger = get_logger("alerting_service")

SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}


def should_alert(severity: str) -> bool:
    current = SEVERITY_ORDER.get(severity, 1)
    minimum = SEVERITY_ORDER.get(ALERT_SEVERITY_THRESHOLD, 2)
    return current >= minimum


def send_webhook(payload: dict) -> None:
    if not WEBHOOK_URL:
        logger.info("Webhook simulation only: %s", payload)
        return
    try:
        resp = requests.post(WEBHOOK_URL, json=payload, timeout=5)
        logger.info("Webhook sent status=%s", resp.status_code)
    except requests.RequestException as exc:
        logger.warning("Webhook delivery failure: %s", exc)


def format_alert(alert: dict) -> dict:
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "ip": alert.get("ip"),
        "severity": alert.get("severity"),
        "threat_score": alert.get("threat_score"),
        "rules": alert.get("rule_ids", []),
        "source": alert.get("source"),
        "detector": alert.get("detector"),
        "geo": alert.get("geo", {}),
    }


def main() -> None:
    consumer = get_consumer([ENRICHED_ALERTS_TOPIC], group_id="alerting-service")

    logger.info("Alerting service started")
    for msg in consumer:
        enriched = msg.value
        try:
            severity = enriched.get("severity", "low")
            if not should_alert(severity):
                continue

            payload = format_alert(enriched)
            logger.warning(
                "ALERT severity=%s ip=%s score=%s rules=%s",
                payload["severity"],
                payload["ip"],
                payload["threat_score"],
                payload["rules"],
            )
            send_webhook(payload)
        except Exception as exc:
            logger.exception("Alert processing failure: %s alert=%s", exc, enriched)


if __name__ == "__main__":
    main()
