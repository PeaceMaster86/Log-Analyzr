import gzip
import json
import os
from datetime import datetime, timezone
from pathlib import Path

import boto3
from botocore.exceptions import BotoCoreError, ClientError, NoCredentialsError

from common.config import RAW_ARCHIVE_DIR, S3_BUCKET, S3_REGION
from common.logging_utils import get_logger

logger = get_logger("storage")


class RawArchiveStore:
    def __init__(self) -> None:
        self.local_dir = Path(RAW_ARCHIVE_DIR)
        self.local_dir.mkdir(parents=True, exist_ok=True)
        self.s3_client = boto3.client("s3", region_name=S3_REGION)

    def _local_write(self, payload: dict) -> str:
        ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%f")
        filename = self.local_dir / f"raw-{ts}.json.gz"
        with gzip.open(filename, "wt", encoding="utf-8") as fh:
            fh.write(json.dumps(payload) + "\n")
        return str(filename)

    def _s3_write(self, payload: dict, object_key: str) -> None:
        body = (json.dumps(payload) + "\n").encode("utf-8")
        self.s3_client.put_object(Bucket=S3_BUCKET, Key=object_key, Body=body)

    def write(self, payload: dict) -> None:
        local_file = self._local_write(payload)
        logger.debug("Archived raw event locally at %s", local_file)

        object_key = f"raw/{datetime.now(timezone.utc).strftime('%Y/%m/%d/%H')}/{os.path.basename(local_file)}"
        try:
            self._s3_write(payload, object_key)
            logger.debug("Archived raw event to s3://%s/%s", S3_BUCKET, object_key)
        except (NoCredentialsError, ClientError, BotoCoreError) as exc:
            logger.warning("S3 archive skipped (using local only): %s", exc)
