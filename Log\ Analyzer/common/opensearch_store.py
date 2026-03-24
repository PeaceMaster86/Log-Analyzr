from opensearchpy import OpenSearch
from opensearchpy.exceptions import OpenSearchException

from common.config import OPENSEARCH_HOST, OPENSEARCH_INDEX, OPENSEARCH_PORT
from common.logging_utils import get_logger

logger = get_logger("opensearch_store")


class OpenSearchStore:
    def __init__(self) -> None:
        self.client = OpenSearch(
            hosts=[{"host": OPENSEARCH_HOST, "port": OPENSEARCH_PORT}],
            http_compress=True,
            use_ssl=False,
            verify_certs=False,
        )
        self.index_name = OPENSEARCH_INDEX

    def ensure_index(self) -> None:
        try:
            if not self.client.indices.exists(index=self.index_name):
                self.client.indices.create(
                    index=self.index_name,
                    body={
                        "mappings": {
                            "properties": {
                                "timestamp": {"type": "date"},
                                "source": {"type": "keyword"},
                                "ip": {"type": "ip"},
                                "severity": {"type": "keyword"},
                                "rule_ids": {"type": "keyword"},
                                "threat_score": {"type": "integer"},
                            }
                        }
                    },
                )
        except OpenSearchException as exc:
            logger.warning("Could not ensure index %s: %s", self.index_name, exc)

    def index_document(self, document: dict) -> None:
        try:
            self.client.index(index=self.index_name, body=document)
        except OpenSearchException as exc:
            logger.warning("OpenSearch indexing skipped: %s", exc)
