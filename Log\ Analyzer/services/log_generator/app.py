import json
import random
import time
from datetime import datetime, timezone
from pathlib import Path

from common.config import RAW_TOPIC
from common.kafka_utils import get_producer
from common.logging_utils import get_logger

logger = get_logger("log_generator")
SAMPLE_FILE = Path("/app/samples/sample_logs.jsonl")


def load_samples() -> list:
    if not SAMPLE_FILE.exists():
        return []
    logs = []
    with SAMPLE_FILE.open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            logs.append(json.loads(line))
    return logs


def main() -> None:
    producer = get_producer()
    samples = load_samples()
    if not samples:
        logger.error("No sample logs found at %s", SAMPLE_FILE)
        return

    logger.info("Log generator started with %s samples", len(samples))
    while True:
        event = random.choice(samples)
        event["timestamp"] = datetime.now(timezone.utc).isoformat()
        producer.send(RAW_TOPIC, event)
        logger.info("Produced raw log source=%s", event.get("source"))
        time.sleep(0.2)


if __name__ == "__main__":
    main()
