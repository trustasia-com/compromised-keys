import csv
import hashlib
import json
import logging
import os
from datetime import datetime, timezone
from typing import Dict, List

from pybloom_live import BloomFilter

from compromised_keys import config
from compromised_keys.atomic_io import atomic_write
from compromised_keys.data_manager import SCHEMA_VERSION

logger = logging.getLogger(__name__)


class Exporter:
    def __init__(self, csv_dir: str = "", bf_dir: str = ""):
        self.csv_dir = csv_dir or config.DATA_DIR
        self.bf_dir = bf_dir or self.csv_dir
        self.csv_path = os.path.join(self.csv_dir, "compromised_keys.csv")
        self.bf_path = os.path.join(self.bf_dir, "compromised_keys.bf")
        self.metadata_path = os.path.join(self.csv_dir, "metadata.json")

        os.makedirs(self.csv_dir, exist_ok=True)
        os.makedirs(self.bf_dir, exist_ok=True)

    def _calculate_sha256(self, file_path):
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()

    def generate_metadata(self, version: str, total_keys: int):
        meta = {
            "version": version,
            "updated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "total_keys": total_keys,
            "files": {
                "csv": {
                    "filename": "compromised_keys.csv",
                    "sha256": self._calculate_sha256(self.csv_path),
                },
                "bloom_filter": {
                    "filename": "compromised_keys.bf",
                    "sha256": self._calculate_sha256(self.bf_path),
                },
            },
            "schema_version": f"{SCHEMA_VERSION}.0",
        }

        with atomic_write(self.metadata_path, "w", encoding="utf-8") as f:
            json.dump(meta, f, indent=4, ensure_ascii=False)
        logger.info(f"Metadata manifest generated at {self.metadata_path}")

    def export_to_csv(self, compromised_keys: List[Dict]):
        field_order = [
            "serial_number",
            "issuer",
            "revocation_date",
            "crt_sh_url",
            "key_hash",
            "cert_sha256",
            "key_algorithm",
            "key_size",
            "is_precert",
            "validated_type",
            "notbefore",
            "notafter",
            "public_key_source",
            "public_key_obtained_at",
            "public_key",
        ]

        with atomic_write(self.csv_path, "w", newline="", encoding="utf-8") as f:
            dict_writer = csv.DictWriter(f, fieldnames=field_order)
            dict_writer.writeheader()
            for item in compromised_keys:
                row = {key: item.get(key) for key in field_order}
                row["crt_sh_url"] = f"https://crt.sh/?serial={item.get('serial_number', '')}"
                dict_writer.writerow(row)
        logger.info("Exported %d keys to %s", len(compromised_keys), self.csv_path)

    def generate_bloom_filter(self, compromised_keys: List[Dict], error_rate: float = 0.001):
        valid_hashes = {k["key_hash"] for k in compromised_keys if k.get("key_hash")}
        capacity = max(1, len(valid_hashes))
        bf = BloomFilter(capacity=capacity, error_rate=error_rate)

        for h in sorted(valid_hashes):
            bf.add(h)

        with atomic_write(self.bf_path, "wb") as f:
            bf.tofile(f)
        logger.info(
            "Generated Bloom filter with %d unique keys at %s", len(valid_hashes), self.bf_path
        )

    def export_all(self, compromised_keys: List[Dict]) -> str:
        """Write data first and the checksum manifest last; propagate failures."""
        self.export_to_csv(compromised_keys)
        self.generate_bloom_filter(compromised_keys)
        version = datetime.now(timezone.utc).strftime("data-v%Y.%m.%d.%H%M")
        self.generate_metadata(version, len(compromised_keys))
        return version
