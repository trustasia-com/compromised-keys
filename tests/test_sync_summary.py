from compromised_keys.sync_summary import render_sync_summary


def test_summary_only_exposes_allowlisted_diagnostics():
    private = "/home/private-user/runner https://internal.example/token"
    report = {
        "release": {"status": "blocked", "blockers": ["required_crl_stage_failed", private]},
        "stages": {
            "crl": {
                "status": "failed",
                "error": private,
                "error_code": "ccadb_http_error",
                "http_status": 500,
                "attempts": 6,
                "retryable": True,
            },
            "ct": {"status": "failed", "error_code": private, "http_status": private},
        },
    }
    result = render_sync_summary(report)
    assert private not in result
    assert "required_crl_stage_failed" in result
    assert "ccadb_http_error" in result
    assert "500" in result and "6" in result and "true" in result


def test_summary_supports_older_reports():
    assert "unknown" in render_sync_summary({})
    assert "crl" in render_sync_summary(
        {"stages": {"crl": {"status": "failed", "error": "private"}}}
    )
