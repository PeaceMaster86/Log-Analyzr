import json
import time
from typing import Any, Dict, Iterable

from kafka import KafkaConsumer, KafkaProducer
from kafka.errors import NoBrokersAvailable

from common.config import KAFKA_BOOTSTRAP_SERVERS
from common.logging_utils import get_logger

logger = get_logger("kafka_utils")


def _json_serializer(value: Dict[str, Any]) -> bytes:
    return json.dumps(value).encode("utf-8")


def _json_deserializer(value: bytes) -> Dict[str, Any]:
    return json.loads(value.decode("utf-8"))


def get_producer(max_retries: int = 20, delay_seconds: int = 3) -> KafkaProducer:
    for attempt in range(1, max_retries + 1):
        try:
            producer = KafkaProducer(
                bootstrap_servers=KAFKA_BOOTSTRAP_SERVERS,
                value_serializer=_json_serializer,
                linger_ms=25,
                retries=5,
                acks="all",
            )
            logger.info("Connected producer to Kafka on %s", KAFKA_BOOTSTRAP_SERVERS)
            return producer
        except NoBrokersAvailable:
            logger.warning("Kafka producer connection failed (attempt %s/%s)", attempt, max_retries)
            time.sleep(delay_seconds)
    raise RuntimeError("Unable to connect Kafka producer")


def get_consumer(topics: Iterable[str], group_id: str, max_retries: int = 20, delay_seconds: int = 3) -> KafkaConsumer:
    topics = list(topics)
    for attempt in range(1, max_retries + 1):
        try:
            consumer = KafkaConsumer(
                *topics,
                bootstrap_servers=KAFKA_BOOTSTRAP_SERVERS,
                group_id=group_id,
                auto_offset_reset="earliest",
                enable_auto_commit=True,
                value_deserializer=_json_deserializer,
                consumer_timeout_ms=0,
            )
            logger.info("Connected consumer %s to topics=%s", group_id, topics)
            return consumer
        except NoBrokersAvailable:
            logger.warning("Kafka consumer connection failed (attempt %s/%s)", attempt, max_retries)
            time.sleep(delay_seconds)
    raise RuntimeError(f"Unable to connect Kafka consumer {group_id}")
