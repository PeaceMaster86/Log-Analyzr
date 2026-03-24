import os


def get_env(name: str, default: str) -> str:
    return os.getenv(name, default)


KAFKA_BOOTSTRAP_SERVERS = get_env("KAFKA_BOOTSTRAP_SERVERS", "kafka:9092")
RAW_TOPIC = get_env("RAW_TOPIC", "raw_logs")
PARSED_TOPIC = get_env("PARSED_TOPIC", "parsed_logs")
DETECTIONS_TOPIC = get_env("DETECTIONS_TOPIC", "detections")
ENRICHED_ALERTS_TOPIC = get_env("ENRICHED_ALERTS_TOPIC", "enriched_alerts")

BRUTE_FORCE_THRESHOLD = int(get_env("BRUTE_FORCE_THRESHOLD", "5"))
BRUTE_FORCE_WINDOW_SECONDS = int(get_env("BRUTE_FORCE_WINDOW_SECONDS", "120"))
REQUEST_RATE_THRESHOLD = int(get_env("REQUEST_RATE_THRESHOLD", "120"))
ERROR_RATE_THRESHOLD = float(get_env("ERROR_RATE_THRESHOLD", "0.35"))
ALERT_SEVERITY_THRESHOLD = get_env("ALERT_SEVERITY_THRESHOLD", "medium")

S3_BUCKET = get_env("S3_BUCKET", "siem-raw-logs")
S3_REGION = get_env("AWS_REGION", "us-east-1")
RAW_ARCHIVE_DIR = get_env("RAW_ARCHIVE_DIR", "/tmp/raw_archive")

OPENSEARCH_HOST = get_env("OPENSEARCH_HOST", "opensearch")
OPENSEARCH_PORT = int(get_env("OPENSEARCH_PORT", "9200"))
OPENSEARCH_INDEX = get_env("OPENSEARCH_INDEX", "siem-alerts")

WEBHOOK_URL = get_env("WEBHOOK_URL", "")
