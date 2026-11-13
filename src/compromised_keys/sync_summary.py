"""Allowlisted synchronization diagnostics for public Actions summaries."""

ERROR_CODES = {
    "ccadb_http_error",
    "ccadb_network_error",
    "ccadb_invalid_response",
    "ccadb_invalid_data",
    "ccadb_local_io_error",
    "ccadb_invalid_configuration",
}
BLOCKERS = {
    "required_crl_stage_failed",
    "export_failed",
    "crl_parse_failed",
    "ccadb_scope_empty",
    "crl_success_rate_below_95_percent",
    "crl_success_rate_drop_over_2_points",
    "sqlite_integrity_check_failed",
    "active_record_count_decreased",
    "public_key_count_decreased",
    "export_hash_mismatch",
}


def render_sync_summary(report: dict) -> str:
    release = report.get("release", {})
    status = release.get("status")
    if status not in {"ready", "degraded", "blocked"}:
        status = "unknown"
    lines = [f"- Release gate: `{status}`"]
    for blocker in release.get("blockers", []):
        lines.append(f"- Blocker: `{blocker if blocker in BLOCKERS else 'unknown'}`")
    for name in ("crl", "ct", "crtsh", "export"):
        stage = report.get("stages", {}).get(name, {})
        if stage.get("status") not in {"failed", "degraded"}:
            continue
        lines.append(f"- Stage: `{name}` / `{stage['status']}`")
        code = stage.get("error_code")
        if code in ERROR_CODES:
            lines.append(f"  - Error category: `{code}`")
        for field in ("http_status", "attempts", "decade", "page"):
            value = stage.get(field)
            if type(value) is int and value >= 0:
                lines.append(f"  - {field}: `{value}`")
        if type(stage.get("retryable")) is bool:
            lines.append(f"  - Transient/retryable: `{str(stage['retryable']).lower()}`")
    return "\n".join(lines)
