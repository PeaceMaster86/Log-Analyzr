from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
from typing import Deque, Dict, List

import numpy as np
from dateutil.parser import isoparse
from sklearn.ensemble import IsolationForest

from common.config import DETECTIONS_TOPIC, PARSED_TOPIC
from common.kafka_utils import get_consumer, get_producer
from common.logging_utils import get_logger

logger = get_logger("anomaly_service")


class AnomalyEngine:
    def __init__(self) -> None:
        self.requests: Dict[str, Deque[datetime]] = defaultdict(deque)
        self.errors: Dict[str, Deque[datetime]] = defaultdict(deque)
        self.sensitive_hits: Dict[str, Deque[datetime]] = defaultdict(deque)
        self.history: List[List[float]] = []
        self.model = IsolationForest(
            contamination=0.05,
            random_state=42,
            n_estimators=120,
        )
        self.model_fitted = False
        self.window = timedelta(minutes=2)

    @staticmethod
    def _parse_ts(ts: str) -> datetime:
        return isoparse(ts).astimezone(timezone.utc)

    def _expire(self, bucket: Deque[datetime], now: datetime) -> None:
        while bucket and (now - bucket[0]) > self.window:
            bucket.popleft()

    def build_features(self, event: dict) -> List[float]:
        ip = event.get("ip")
        now = self._parse_ts(event["timestamp"])

        req_bucket = self.requests[ip]
        req_bucket.append(now)
        self._expire(req_bucket, now)

        status = int(event.get("status_code", 200))
        err_bucket = self.errors[ip]
        if 400 <= status < 600:
            err_bucket.append(now)
        self._expire(err_bucket, now)

        path = event.get("path", "")
        sensitive_bucket = self.sensitive_hits[ip]
        if path.startswith("/admin") or path.startswith("/.env") or path.startswith("/api/auth"):
            sensitive_bucket.append(now)
        self._expire(sensitive_bucket, now)

        req_count = len(req_bucket)
        error_ratio = len(err_bucket) / max(req_count, 1)
        sensitive_count = len(sensitive_bucket)
        return [float(req_count), float(error_ratio), float(sensitive_count)]

    def detect(self, event: dict) -> dict:
        ip = event.get("ip")
        if not ip:
            return {}

        features = self.build_features(event)
        self.history.append(features)
        if len(self.history) > 5000:
            self.history = self.history[-5000:]

        alert = {}
        if len(self.history) >= 120 and len(self.history) % 20 == 0:
            self.model.fit(np.array(self.history))
            self.model_fitted = True

        if self.model_fitted:
            pred = self.model.predict([features])[0]
            anomaly_score = -float(self.model.score_samples([features])[0])
            if pred == -1:
                severity = "medium" if anomaly_score < 0.6 else "high"
                alert = {
                    "timestamp": event["timestamp"],
                    "source": event.get("source"),
                    "ip": ip,
                    "severity": severity,
                    "rule_ids": ["ML_TRAFFIC_ANOMALY"],
                    "details": {
                        "features": {
                            "requests_2m": int(features[0]),
                            "error_ratio_2m": round(features[1], 2),
                            "sensitive_hits_2m": int(features[2]),
                        },
                        "anomaly_score": round(anomaly_score, 4),
                    },
                    "threat_score": 65 if severity == "medium" else 85,
                    "event": event,
                    "detector": "isolation_forest",
                }

        # Backstop statistical signal before model warmup.
        if not alert and (features[0] >= 150 or features[1] >= 0.6):
            alert = {
                "timestamp": event["timestamp"],
                "source": event.get("source"),
                "ip": ip,
                "severity": "medium",
                "rule_ids": ["STAT_TRAFFIC_DEVIATION"],
                "details": {
                    "requests_2m": int(features[0]),
                    "error_ratio_2m": round(features[1], 2),
                },
                "threat_score": 60,
                "event": event,
                "detector": "statistical",
            }

        return alert


def main() -> None:
    engine = AnomalyEngine()
    consumer = get_consumer([PARSED_TOPIC], group_id="anomaly-service")
    producer = get_producer()

    logger.info("Anomaly service started")
    for msg in consumer:
        event = msg.value
        if event.get("event_type") != "http_request":
            continue
        try:
            anomaly = engine.detect(event)
            if anomaly:
                producer.send(DETECTIONS_TOPIC, anomaly)
                logger.info(
                    "Anomaly detected ip=%s detector=%s score=%s",
                    anomaly["ip"],
                    anomaly["detector"],
                    anomaly["details"].get("anomaly_score", "n/a"),
                )
        except Exception as exc:
            logger.exception("Anomaly detector failure: %s event=%s", exc, event)


if __name__ == "__main__":
    main()
