"""Shared public-key lookup outcomes and source-level circuit breaking."""

import asyncio
from collections import deque
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional


class LookupOutcome(str, Enum):
    FOUND = "found"
    NOT_FOUND = "not_found"
    INVALID_LOCAL_IDENTITY = "invalid_local_identity"
    MALFORMED_RESPONSE = "malformed_response"
    MISSING_DER = "missing_der"
    IDENTITY_MISMATCH = "identity_mismatch"
    UNSUPPORTED_KEY = "unsupported_key"
    RATE_LIMITED = "rate_limited"
    HTTP_CLIENT_ERROR = "http_client_error"
    HTTP_SERVER_ERROR = "http_server_error"
    TIMEOUT = "timeout"
    NETWORK_ERROR = "network_error"
    PROVIDER_UNAVAILABLE = "provider_unavailable"


@dataclass
class LookupRecordResult:
    record: Dict
    outcome: LookupOutcome
    info: Optional[Dict] = None
    status_code: Optional[int] = None
    error_class: str = ""


@dataclass
class LookupProviderResult:
    records: List[LookupRecordResult] = field(default_factory=list)
    requests_total: int = 0
    requests_failed: int = 0
    circuit_open: bool = False
    circuit_reason: str = ""
    persisted_counts: Optional[Dict[str, int]] = None


class SourceCircuitBreaker:
    """Stop one unhealthy source without suppressing other lookup sources."""

    def __init__(
        self,
        consecutive_failure_limit: int = 5,
        window_size: int = 20,
        minimum_window_samples: int = 10,
        failure_ratio: float = 0.5,
        rate_limit_limit: int = 3,
    ):
        self.consecutive_failure_limit = consecutive_failure_limit
        self.minimum_window_samples = minimum_window_samples
        self.failure_ratio = failure_ratio
        self.rate_limit_limit = rate_limit_limit
        self._recent = deque(maxlen=window_size)
        self._consecutive_failures = 0
        self._consecutive_rate_limits = 0
        self._open = False
        self._reason = ""
        self._lock = asyncio.Lock()

    @property
    def is_open(self) -> bool:
        return self._open

    @property
    def reason(self) -> str:
        return self._reason

    async def allow_request(self) -> bool:
        async with self._lock:
            return not self._open

    async def record_success(self):
        async with self._lock:
            self._recent.append(False)
            self._consecutive_failures = 0
            self._consecutive_rate_limits = 0

    async def record_failure(self, outcome: LookupOutcome, status_code: Optional[int] = None):
        async with self._lock:
            self._recent.append(True)
            self._consecutive_failures += 1
            if outcome == LookupOutcome.RATE_LIMITED:
                self._consecutive_rate_limits += 1
            else:
                self._consecutive_rate_limits = 0

            if outcome == LookupOutcome.HTTP_CLIENT_ERROR and status_code != 429:
                self._open_with(f"http_client_error:{status_code or 'unknown'}")
            elif self._consecutive_rate_limits >= self.rate_limit_limit:
                self._open_with("consecutive_rate_limits")
            elif self._consecutive_failures >= self.consecutive_failure_limit:
                self._open_with("consecutive_request_failures")
            elif len(self._recent) >= self.minimum_window_samples:
                failures = sum(self._recent)
                if failures / len(self._recent) >= self.failure_ratio:
                    self._open_with("request_failure_ratio")

    def _open_with(self, reason: str):
        if not self._open:
            self._open = True
            self._reason = reason
