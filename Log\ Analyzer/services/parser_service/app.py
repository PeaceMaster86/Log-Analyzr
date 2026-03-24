import re
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from dateutil.parser import isoparse

from common.config import PARSED_TOPIC, RAW_TOPIC
from common.kafka_utils import get_consumer, get_producer
from common.logging_utils import get_logger
from common.storage import RawArchiveStore

logger = get_logger("parser_service")

SSH_FAIL_RE = re.compile(
    r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)"
)
SSH_OK_RE = re.compile(
    r"Accepted password for (?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)"
)
HTTP_RE = re.compile(
    r'(?P<ip>\d+\.\d+\.\d+\.\d+) [^\"]+ \"(?P<method>\S+) (?P<path>\S+) [^\"]+\" (?P<status>\d{3})'
)


def parse_ts(ts: Optional[str]) -> str:
    if not ts:
        return datetime.now(timezone.utc).isoformat()
    try:
        return isoparse(ts).astimezone(timezone.utc).isoformat()
    except ValueError:
        return datetime.now(timezone.utc).isoformat()


def normalize(payload: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    source = payload.get("source", "unknown").lower()
    raw_msg = payload.get("message", "")
    ts = parse_ts(payload.get("timestamp"))

    event: Dict[str, Any] = {
        "timestamp": ts,
        "source": source,
        "raw": raw_msg,
    }

    if source == "ssh":
        m_fail = SSH_FAIL_RE.search(raw_msg)
        if m_fail:
            event.update(
                {
                    "event_type": "login_failure",
                    "ip": m_fail.group("ip"),
                    "username": m_fail.group("user"),
                    "status_code": 401,
                }
            )
            return event

        m_ok = SSH_OK_RE.search(raw_msg)
        if m_ok:
            event.update(
                {
                    "event_type": "login_success",
                    "ip": m_ok.group("ip"),
                    "username": m_ok.group("user"),
                    "status_code": 200,
                }
            )
            return event

    if source in {"apache", "nginx"}:
        m_http = HTTP_RE.search(raw_msg)
        if not m_http:
            return None
        status = int(m_http.group("status"))
        event.update(
            {
                "event_type": "http_request",
                "ip": m_http.group("ip"),
                "method": m_http.group("method"),
                "path": m_http.group("path"),
                "status_code": status,
            }
        )
        return event

    return None


def main() -> None:
    consumer = get_consumer([RAW_TOPIC], group_id="parser-service")
    producer = get_producer()
    archive_store = RawArchiveStore()

    logger.info("Parser service started")
    for msg in consumer:
        payload = msg.value
        try:
            archive_store.write(payload)
            normalized = normalize(payload)
            if not normalized:
                logger.debug("Unable to parse event source=%s", payload.get("source"))
                continue
            producer.send(PARSED_TOPIC, normalized)
            logger.info(
                "Normalized event source=%s ip=%s type=%s",
                normalized.get("source"),
                normalized.get("ip"),
                normalized.get("event_type"),
            )
        except Exception as exc:
            logger.exception("Parser processing failure: %s payload=%s", exc, payload)


if __name__ == "__main__":
    main()
