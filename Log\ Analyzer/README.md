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

Examples included:
- Repeated SSH login failures from `203.0.113.10`
- Sensitive endpoint probes (`/admin`, `/.env`, `/.git/config`)
- Repeated 4xx HTTP responses

Expected alert examples from `alerting-service` logs:

```text
ALERT severity=high ip=203.0.113.10 score=99 rules=['BRUTE_FORCE_LOGIN']
ALERT severity=critical ip=198.51.100.42 score=91 rules=['SENSITIVE_ENDPOINT_ACCESS','ELEVATED_ERROR_RATE']
ALERT severity=medium ip=192.0.2.77 score=60 rules=['STAT_TRAFFIC_DEVIATION']
```

## 6) AWS Deployment Outline (Production)

### Core managed services

- Compute: ECS Fargate services for each Python microservice
- Messaging: Amazon MSK (Kafka) or Kinesis (if replacing Kafka client layer)
- Raw storage: S3 bucket (`raw/...` key prefix)
- Search/index: Amazon OpenSearch Service
- Optional visualization: OpenSearch Dashboards / Kibana compatible layer

### Deployment flow

1. Build and push service images to ECR.
2. Provision infrastructure (`infra/terraform/aws`) for S3, MSK, OpenSearch, ECS cluster.
3. Create ECS task definitions with environment variables mirroring `.env.example`.
4. Deploy services in dependency order:
   - parser, rule-detector, anomaly, enrichment, alerting
5. Wire CloudWatch logs, alarms, and autoscaling policies.
6. Set alerting webhook endpoint (API Gateway + Lambda, Slack app, or email bridge).

### Scaling guidance

- Increase Kafka partitions to scale horizontally by consumer group.
- Run multiple replicas of parser/rule/anomaly services.
- Use ECS autoscaling on CPU and Kafka lag.
- Keep model warmup local per replica or externalize features/state to Redis.

## 7) IaC Notes

Terraform skeleton files are under `infra/terraform/aws`:
- `main.tf` (S3, OpenSearch, MSK, ECS cluster baseline)
- `variables.tf`
- `outputs.tf`

This is intentionally minimal as a starting point; for production, add VPC, IAM least privilege, ECS task/service resources, security groups, and secret management.

## 8) Security and Reliability Considerations

- Add mTLS/SASL for Kafka in production.
- Store secrets in AWS Secrets Manager or GCP Secret Manager.
- Add dead-letter topics for malformed payloads.
- Add idempotency keys to avoid duplicate alerting.
- Add Redis cache for shared IP threat score state.
