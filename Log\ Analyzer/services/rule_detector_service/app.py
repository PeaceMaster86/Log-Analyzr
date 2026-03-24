from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
from typing import Deque, Dict

from dateutil.parser import isoparse

from common.config import (
    BRUTE_FORCE_THRESHOLD,
    BRUTE_FORCE_WINDOW_SECONDS,
    DETECTIONS_TOPIC,
    ERROR_RATE_THRESHOLD,
    PARSED_TOPIC,
    REQUEST_RATE_THRESHOLD,
)
from common.kafka_utils import get_consumer, get_producer
from common.logging_utils import get_logger

logger = get_logger("rule_detector_service")

SENSITIVE_ENDPOINTS = {"/admin", "/wp-admin", "/login", "/.env", "/etc/passwd", "/api/auth"}


class RuleEngine:
    def __init__(self) -> None:
        self.login_failures: Dict[str, Deque[datetime]] = defaultdict(deque)
        self.requests: Dict[str, Deque[datetime]] = defaultdict(deque)
        self.errors: Dict[str, Deque[datetime]] = defaultdict(deque)

    @staticmethod
    def _parse_ts(ts: str) -> datetime:
        return isoparse(ts).astimezone(timezone.utc)

    def _expire(self, bucket: Deque[datetime], now: datetime, window: timedelta) -> None:
        while bucket and (now - bucket[0]) > window:
            bucket.popleft()

    def process(self, event: dict) -> dict:
        ip = event.get("ip")
        if not ip:
            return {}

        now = self._parse_ts(event["timestamp"])
        rule_ids = []
        details = {}
        severity = "low"

        login_window = timedelta(seconds=BRUTE_FORCE_WINDOW_SECONDS)
        short_window = timedelta(minutes=2)

        if event.get("event_type") == "login_failure":
            bucket = self.login_failures[ip]
            bucket.append(now)
            self._expire(bucket, now, login_window)
            if len(bucket) >= BRUTE_FORCE_THRESHOLD:
                rule_ids.append("BRUTE_FORCE_LOGIN")
                details["failed_logins_window"] = len(bucket)
                severity = "high"

        if event.get("event_type") == "http_request":
            req_bucket = self.requests[ip]
            req_bucket.append(now)
            self._expire(req_bucket, now, short_window)

            if len(req_bucket) >= REQUEST_RATE_THRESHOLD:
                rule_ids.append("HIGH_REQUEST_RATE")
                details["requests_2m"] = len(req_bucket)
                severity = "medium" if severity == "low" else severity

            status_code = int(event.get("status_code", 0))
            if 400 <= status_code < 600:
                err_bucket = self.errors[ip]
                err_bucket.append(now)
                self._expire(err_bucket, now, short_window)
                error_rate = len(err_bucket) / max(len(req_bucket), 1)
                if error_rate >= ERROR_RATE_THRESHOLD:
                    rule_ids.append("ELEVATED_ERROR_RATE")
                    details["error_rate_2m"] = round(error_rate, 2)
                    severity = "medium" if severity == "low" else severity

            path = event.get("path", "")
            if path in SENSITIVE_ENDPOINTS or path.startswith("/.git"):
                rule_ids.append("SENSITIVE_ENDPOINT_ACCESS")
                details["sensitive_path"] = path
                severity = "high"

        if not rule_ids:
            return {}

        # Threat score combines count of rules and severity multiplier.
        severity_score = {"low": 20, "medium": 50, "high": 80}
        threat_score = min(100, severity_score[severity] + 5 * len(rule_ids))

        return {
            "timestamp": event["timestamp"],
            "source": event.get("source"),
            "ip": ip,
            "severity": severity,
            "rule_ids": sorted(set(rule_ids)),
            "details": details,
            "threat_score": threat_score,
            "event": event,
            "detector": "rules",
        }


def main() -> None:
    engine = RuleEngine()
    consumer = get_consumer([PARSED_TOPIC], group_id="rule-detector-service")
    producer = get_producer()

    logger.info("Rule detector service started")
    for msg in consumer:
        event = msg.value
        try:
            alert = engine.process(event)
            if alert:
                producer.send(DETECTIONS_TOPIC, alert)
                logger.info("Rule detection ip=%s rules=%s", alert["ip"], alert["rule_ids"])
        except Exception as exc:
            logger.exception("Rule detector failure: %s event=%s", exc, event)


if __name__ == "__main__":
    main()
