"""Centralized configuration via environment variables."""

import os

# Optional compatible CT search provider
CT_SERVER_HOST = os.environ.get("CT_SERVER_HOST", "")

# crt.sh PostgreSQL direct connection (public read-only)
CRTSH_PG_DSN = os.environ.get("CRTSH_PG_DSN", "postgresql://guest@crt.sh:5432/certwatch")

# crt.sh supplementation mode: "postgres" or "http"
CRTSH_MODE = os.environ.get("CRTSH_MODE", "postgres")

# Database
DB_PATH = os.environ.get("COMPROMISED_KEYS_DB", "compromised_keys.db")

# Output directories
DATA_DIR = os.environ.get("COMPROMISED_KEYS_DATA_DIR", "data/latest")
CACHE_DIR = os.environ.get("COMPROMISED_KEYS_CACHE_DIR", "cache")

# CCADB AllCertificateRecords REST API
CCADB_API_URL = os.environ.get(
    "CCADB_API_URL",
    "https://ccadb.my.site.com/services/apexrest/v1/allcertificaterecords",
)
CCADB_API_START_DECADE = int(os.environ.get("CCADB_API_START_DECADE", "1990"))
CCADB_API_END_DECADE = int(os.environ.get("CCADB_API_END_DECADE", "2100"))
CCADB_CACHE_TTL_HOURS = int(os.environ.get("CCADB_CACHE_TTL_HOURS", "24"))

# Download settings
CRL_DOWNLOAD_CONCURRENCY = int(os.environ.get("CRL_DOWNLOAD_CONCURRENCY", "50"))
CRL_MAX_RETRIES = int(os.environ.get("CRL_MAX_RETRIES", "3"))
CRL_MAX_BYTES = int(os.environ.get("CRL_MAX_BYTES", str(128 * 1024 * 1024)))
CRL_PARSE_WORKERS = int(os.environ.get("CRL_PARSE_WORKERS", str(min(4, os.cpu_count() or 1))))

# CT query settings
CT_BATCH_SIZE = int(os.environ.get("CT_BATCH_SIZE", "1000"))
CT_CONCURRENCY = int(os.environ.get("CT_CONCURRENCY", "5"))
CT_MAX_RETRIES = int(os.environ.get("CT_MAX_RETRIES", "3"))
CT_TIMEOUT_SECONDS = int(os.environ.get("CT_TIMEOUT_SECONDS", "600"))

# crt.sh PostgreSQL batch size (serials per SQL query)
CRTSH_PG_BATCH_SIZE = int(os.environ.get("CRTSH_PG_BATCH_SIZE", "20"))
CRTSH_MAX_SECONDS = int(os.environ.get("CRTSH_MAX_SECONDS", "3600"))

# crt.sh HTTP crawler settings
CRTSH_HTTP_CONCURRENCY = int(os.environ.get("CRTSH_HTTP_CONCURRENCY", "5"))

# Sync interval (hours)
SYNC_INTERVAL_HOURS = int(os.environ.get("SYNC_INTERVAL_HOURS", "6"))
