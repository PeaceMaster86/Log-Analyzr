# SIEM-like Distributed Log Analyzer

A cloud-native Python microservices pipeline for real-time detection of brute-force attempts and suspicious IP behavior.

## 1) High-Level Architecture Diagram (Text)

```text
[SSH / Apache / Nginx Logs]
            |
            v
      Topic: raw_logs  (Kafka / MSK / PubSub equivalent)
            |
            v
+-------------------------+
| parser-service          |
| - normalize log formats |
| - archive raw to S3     |
+-------------------------+
            |
            v
      Topic: parsed_logs
       /               \
      v                 v
+----------------+   +----------------------+
| rule-detector  |   | anomaly-service      |
| - brute force  |   | - Isolation Forest   |
| - thresholds   |   | - statistical backup |
+----------------+   +----------------------+
       \               /
        v             v
         Topic: detections
                |
                v
+-------------------------+
| enrichment-service      |
| - IP reputation (mock)  |
| - geo lookup (mock)     |
| - index OpenSearch      |
+-------------------------+
                |
                v
      Topic: enriched_alerts
                |
                v
+-------------------------+
| alerting-service        |
| - severity gating       |
| - console + webhook     |
+-------------------------+
```

## 2) Microservices Breakdown

- `parser-service`
  - Consumes `raw_logs`
  - Parses SSH + Apache + Nginx logs into normalized schema
  - Archives raw events to local gzip and attempts S3 write
  - Produces to `parsed_logs`
- `rule-detector-service`
  - Detects brute-force auth failures (default 5 in 2 minutes)
  - Detects high request rate, high error ratio, and sensitive endpoint access
  - Emits rule-based alerts to `detections`
- `anomaly-service`
  - Builds rolling per-IP feature vectors
  - Runs `IsolationForest` after warmup
  - Uses statistical fallback during model warmup
  - Emits anomalies to `detections`
- `enrichment-service`
  - Adds mock IP reputation and deterministic mock geo
  - Computes threat scoring and final severity boost
  - Indexes documents in OpenSearch
  - Produces to `enriched_alerts`
- `alerting-service`
  - Severity threshold filtering
  - Outputs alert messages to logs
  - Simulates webhook delivery (Slack/email style)
- `log-generator`
  - Replays synthetic malicious + benign samples into `raw_logs`

## 3) Key Python Service Implementations (Core Parts)

- Log normalization: `services/parser_service/app.py`
- Rule detection logic: `services/rule_detector_service/app.py`
- ML + statistical anomaly detection: `services/anomaly_service/app.py`
- Enrichment + threat scoring + OpenSearch indexing: `services/enrichment_service/app.py`
- Alert fanout with webhook simulation: `services/alerting_service/app.py`

## 4) Local Runtime (Docker Compose)

### Start stack

```bash
docker compose up --build
```

### Stop stack

```bash
docker compose down
```

### Optional webhook listener

Run this in another shell, then set `WEBHOOK_URL=http://host.docker.internal:8081` for `alerting-service`:

```bash
python scripts/webhook_receiver.py
```

## 5) Sample Logs + Expected Detection Output

Sample input file: `samples/sample_logs.jsonl`.

