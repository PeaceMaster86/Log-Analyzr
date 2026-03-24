import hashlib
from datetime import datetime, timezone
from typing import Dict

from common.config import DETECTIONS_TOPIC, ENRICHED_ALERTS_TOPIC
from common.kafka_utils import get_consumer, get_producer
from common.logging_utils import get_logger
from common.opensearch_store import OpenSearchStore

logger = get_logger("enrichment_service")

MOCK_REPUTATION = {
    "203.0.113.10": 95,
    "198.51.100.42": 88,
    "192.0.2.77": 70,
}
COUNTRIES = ["US", "DE", "BR", "IN", "SG", "JP", "NL", "GB"]


def mock_geo(ip: str) -> Dict[str, str]:
    h = int(hashlib.sha256(ip.encode("utf-8")).hexdigest(), 16)
    return {
        "country": COUNTRIES[h % len(COUNTRIES)],
        "city": f"City-{(h % 73) + 1}",
    }


def enrich(alert: dict) -> dict:
    ip = alert.get("ip", "0.0.0.0")
    rep = MOCK_REPUTATION.get(ip, 10)

    enriched = {
        **alert,
        "enriched_at": datetime.now(timezone.utc).isoformat(),
        "ip_reputation": rep,
        "geo": mock_geo(ip),
    }

    base_score = int(enriched.get("threat_score", 40))
    enriched["threat_score"] = min(100, base_score + int(rep * 0.2))

    if enriched["threat_score"] >= 85:
        enriched["severity"] = "critical"
    elif enriched["threat_score"] >= 65 and enriched.get("severity") == "low":
        enriched["severity"] = "medium"

    return enriched


def main() -> None:
    consumer = get_consumer([DETECTIONS_TOPIC], group_id="enrichment-service")
    producer = get_producer()
    index_store = OpenSearchStore()
    index_store.ensure_index()

    logger.info("Enrichment service started")
    for msg in consumer:
        detection = msg.value
        try:
            enriched = enrich(detection)
            index_store.index_document(enriched)
            producer.send(ENRICHED_ALERTS_TOPIC, enriched)
            logger.info(
                "Enriched alert ip=%s severity=%s threat_score=%s",
                enriched.get("ip"),
                enriched.get("severity"),
                enriched.get("threat_score"),
            )
        except Exception as exc:
            logger.exception("Enrichment failure: %s detection=%s", exc, detection)


if __name__ == "__main__":
    main()
