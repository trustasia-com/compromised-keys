"""Command-line interface for compromised-keys."""

import argparse
import asyncio
import logging
import os
import sqlite3
import sys
from pathlib import Path

from compromised_keys import __version__


def setup_logging(verbose: bool = False, quiet: bool = False):
    level = logging.DEBUG if verbose else (logging.WARNING if quiet else logging.INFO)
    logging.basicConfig(
        level=level,
        format="%(asctime)s - %(levelname)s - %(message)s",
    )


def cmd_sync(args):
    """Full public sync cycle with optional CT supplementation."""
    setup_logging(args.verbose, args.quiet)
    from compromised_keys.main import CompromisedKeysManager, SyncError

    manager = CompromisedKeysManager()
    if args.loop:
        asyncio.run(
            manager.run_forever(
                interval_hours=args.interval,
                crtsh_mode=args.crtsh_mode,
                crtsh_limit=args.crtsh_limit,
                include_crtsh=not args.no_crtsh,
            )
        )
    else:
        try:
            report = asyncio.run(
                manager.run_once(
                    crtsh_mode=args.crtsh_mode,
                    crtsh_limit=args.crtsh_limit,
                    include_crtsh=not args.no_crtsh,
                )
            )
        except SyncError as error:
            if error.report is None:
                raise
            report = error.report
            logging.getLogger(__name__).error("Synchronization failed: %s", error)
        if args.report:
            import json

            from compromised_keys.atomic_io import atomic_write

            report_path = Path(args.report)
            report_path.parent.mkdir(parents=True, exist_ok=True)
            with atomic_write(report_path, encoding="utf-8") as stream:
                json.dump(report, stream, indent=2, sort_keys=True)
                stream.write("\n")
        if report.get("release", {}).get("status") not in {"ready", "degraded"}:
            sys.exit(1)


def cmd_crl_sync(args):
    """Download CCADB + CRLs and parse keyCompromise revocations only.

    Does not query CT or crt.sh.
    """
    setup_logging(args.verbose, args.quiet)
    from compromised_keys.main import CompromisedKeysManager

    manager = CompromisedKeysManager()
    asyncio.run(manager.crl_sync_only())


def cmd_supplement(args):
    """Run crt.sh supplementation to fill in missing public keys."""
    setup_logging(args.verbose, args.quiet)
    from compromised_keys.crt_sh_crawler import CrtShSupplementer

    supplementer = CrtShSupplementer(mode=args.mode)
    result = asyncio.run(supplementer.run(limit=args.limit))
    print(result)


def cmd_ct_sync(args):
    """Optional CT Provider supplementation (requires CT_SERVER_HOST)."""
    setup_logging(args.verbose, args.quiet)
    from compromised_keys import config

    if not config.CT_SERVER_HOST:
        print(
            "Error: CT_SERVER_HOST environment variable is not set.\n"
            "This command requires access to a compatible CT indexing provider.\n"
            "Example: export CT_SERVER_HOST=https://ct.example.com",
            file=sys.stderr,
        )
        sys.exit(1)

    from compromised_keys.ct_client import CTClient
    from compromised_keys.main import CompromisedKeysManager

    manager = CompromisedKeysManager(ct_provider=CTClient(full_history=args.full_history))
    asyncio.run(manager.ct_sync_only(ignore_retry=args.full_history))


def cmd_export(args):
    """Export CSV and Bloom filter from existing database."""
    setup_logging(args.verbose, args.quiet)
    from compromised_keys.data_manager import DataManager
    from compromised_keys.exporter import Exporter

    dm = DataManager()
    exporter = Exporter()
    keys = dm.get_all_compromised_keys()
    version = exporter.export_all(keys)
    print(f"Exported {len(keys)} keys. Version: {version}")


def cmd_check(args):
    """Check a CSR file against the Bloom filter blacklist."""
    setup_logging(args.verbose, args.quiet)
    from cryptography import x509
    from pybloom_live import BloomFilter

    from compromised_keys import config
    from compromised_keys.crypto_utils import compute_key_hash_from_public_key

    bf_path = os.path.join(config.DATA_DIR, "compromised_keys.bf")
    if not os.path.exists(bf_path):
        print(f"Error: Bloom filter not found at {bf_path}", file=sys.stderr)
        print("Run 'compromised-keys sync' or 'compromised-keys export' first.")
        sys.exit(1)

    with open(bf_path, "rb") as f:
        bf = BloomFilter.fromfile(f)

    matched = False
    failed = False
    for csr_path in args.csr_files:
        if not os.path.exists(csr_path):
            print(f"ERROR: {csr_path} (file not found)", file=sys.stderr)
            failed = True
            continue

        try:
            with open(csr_path, "rb") as f:
                csr_data = f.read()

            csr = x509.load_pem_x509_csr(csr_data)
            if not csr.is_signature_valid:
                raise ValueError("CSR signature is invalid")
            fp, _algorithm, _size = compute_key_hash_from_public_key(csr.public_key())
            if not fp:
                raise ValueError("Unsupported key type")

            if fp in bf:
                print(f"POSSIBLE MATCH: {csr_path}; confirm against same-version CSV (hash: {fp})")
                matched = True
            else:
                print(f"NOT LISTED: {csr_path} (hash: {fp})")

        except Exception as e:
            failed = True
            print(f"ERROR: {csr_path}: {e}", file=sys.stderr)
    if matched or failed:
        sys.exit(2 if matched else 1)


def cmd_stats(args):
    """Show database statistics."""
    setup_logging(args.verbose, args.quiet)
    import json

    from compromised_keys.data_manager import DataManager

    dm = DataManager()
    stats = dm.get_db_stats()
    print(json.dumps(stats, indent=2))


def cmd_doctor(args):
    """Check local prerequisites before starting a synchronization run."""
    setup_logging(args.verbose, args.quiet)
    from compromised_keys import config

    failures = 0
    warnings = 0

    def emit(status: str, name: str, detail: str):
        nonlocal failures, warnings
        if status == "FAIL":
            failures += 1
        elif status == "WARN":
            warnings += 1
        print(f"[{status}] {name}: {detail}")

    emit("OK", "Python", f"{sys.version.split()[0]} (package requires 3.10+)")

    paths = {
        "database directory": Path(config.DB_PATH).expanduser().parent,
        "data directory": Path(config.DATA_DIR).expanduser(),
        "cache directory": Path(config.CACHE_DIR).expanduser(),
    }
    for name, path in paths.items():
        try:
            path.mkdir(parents=True, exist_ok=True)
        except OSError as error:
            emit("FAIL", name, f"cannot create {path}: {error}")
            continue
        if os.access(path, os.W_OK):
            emit("OK", name, str(path.resolve()))
        else:
            emit("FAIL", name, f"not writable: {path.resolve()}")

    db_path = Path(config.DB_PATH).expanduser()
    if not db_path.exists():
        emit(
            "WARN",
            "history database",
            "not found; sync will create an empty database that does not contain release history",
        )
    else:
        try:
            with sqlite3.connect(f"file:{db_path.resolve()}?mode=ro", uri=True) as connection:
                integrity = connection.execute("PRAGMA quick_check").fetchone()[0]
                table = connection.execute(
                    "SELECT 1 FROM sqlite_master WHERE type='table' AND name='revoked_certs'"
                ).fetchone()
                if integrity != "ok":
                    emit("FAIL", "history database", f"SQLite quick_check returned {integrity}")
                elif not table:
                    emit("WARN", "history database", "SQLite file has no revoked_certs table yet")
                else:
                    from compromised_keys.release_assets import check_database

                    checked = check_database(db_path)
                    count = checked["tables"]["revoked_certs"]
                    emit("OK", "history database", f"{db_path.resolve()} ({count} records)")
        except (sqlite3.Error, RuntimeError) as error:
            emit("FAIL", "history database", f"cannot open {db_path}: {error}")

    crtsh_mode = args.crtsh_mode or config.CRTSH_MODE
    if args.no_crtsh:
        emit("OK", "crt.sh", "disabled for the planned sync")
    elif crtsh_mode == "postgres":
        try:
            import psycopg2  # noqa: F401

            emit("OK", "crt.sh", "PostgreSQL mode and psycopg2 are available")
        except ImportError:
            emit(
                "FAIL",
                "crt.sh",
                'PostgreSQL mode requires: python -m pip install ".[postgres]"',
            )
    elif crtsh_mode == "http":
        emit("OK", "crt.sh", "HTTP mode selected (slower and rate limited)")
    else:
        emit("FAIL", "crt.sh", f"unsupported mode: {crtsh_mode!r}")

    if config.CT_SERVER_HOST:
        emit("OK", "CT Provider", "configured")
    else:
        emit("OK", "CT Provider", "not configured; optional stage will be skipped")

    print(f"Doctor summary: {failures} failure(s), {warnings} warning(s).")
    if failures:
        sys.exit(1)


def cmd_validate_cert(args):
    """Validate a community-submitted certificate."""
    setup_logging(args.verbose, args.quiet)
    from compromised_keys.cert_validator import CertValidator

    with open(args.cert_file, "rb") as f:
        cert_data = f.read()

    validator = CertValidator()
    result = validator.validate_submission(
        cert_data,
        claimed_serial=args.serial or "",
        claimed_issuer=args.issuer or "",
    )

    if result.is_valid:
        print("VALID: Certificate matches revoked record.")
        print(f"  Serial: {result.serial_number}")
        print(f"  Key Hash: {result.key_hash}")
        print(f"  Algorithm: {result.key_algorithm} ({result.key_size} bits)")

        if args.apply:
            validator.apply_submission(result)
            print("Applied to database.")
    else:
        print(f"INVALID: {result.error}", file=sys.stderr)
        sys.exit(1)


def cmd_exclude_record(args):
    """Preview or apply an exclusion for one exact revoked record."""
    setup_logging(args.verbose, args.quiet)
    import json

    from compromised_keys.data_manager import DataManager

    dm = DataManager()
    record = dm.get_record_by_serial_and_issuer(args.serial, args.issuer)
    preview = {
        "action": "exclude_record",
        "apply": args.apply,
        "record_exists": record is not None,
        "serial_number": args.serial,
        "issuer": args.issuer,
        "reason_code": args.reason_code,
        "rationale": args.rationale,
        "created_by": args.created_by,
        "expires_at": args.expires_at or None,
    }
    if args.apply and record:
        preview["changed"] = dm.set_record_exclusion(
            args.serial,
            args.issuer,
            reason_code=args.reason_code,
            rationale=args.rationale,
            created_by=args.created_by,
            expires_at=args.expires_at or None,
        )
    print(json.dumps(preview, indent=2, ensure_ascii=False))
    if not record:
        sys.exit(1)


def cmd_clear_exclusion(args):
    """Preview or clear an exclusion for one exact revoked record."""
    setup_logging(args.verbose, args.quiet)
    import json

    from compromised_keys.data_manager import DataManager

    dm = DataManager()
    result = {
        "action": "clear_exclusion",
        "apply": args.apply,
        "serial_number": args.serial,
        "issuer": args.issuer,
    }
    if args.apply:
        result["changed"] = dm.clear_record_exclusion(args.serial, args.issuer)
    print(json.dumps(result, indent=2, ensure_ascii=False))


def cmd_analyze_misses(args):
    """Print a breakdown of revoked records currently missing a public key."""
    setup_logging(args.verbose, args.quiet)
    import json
    import sqlite3

    from compromised_keys.data_manager import DataManager

    dm = DataManager()
    out = {}
    with sqlite3.connect(dm.db_path) as conn:
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        cur.execute(
            """
            SELECT count(*) AS n FROM revoked_certs
            WHERE public_key IS NULL AND cleaned_at IS NULL
            """
        )
        out["total_missing"] = cur.fetchone()["n"]

        cur.execute(
            """
            SELECT count(*) AS n FROM revoked_certs
            WHERE public_key IS NULL AND cleaned_at IS NULL AND EXISTS (
                SELECT 1 FROM record_exclusions e
                WHERE e.serial_number = revoked_certs.serial_number
                  AND e.issuer = revoked_certs.issuer
                  AND e.active = 1
                  AND (e.expires_at IS NULL OR e.expires_at > datetime('now'))
              )
            """
        )
        out["active_exclusions"] = cur.fetchone()["n"]

        cur.execute(
            """
            SELECT source, count(*) AS n FROM lookup_state s
            JOIN revoked_certs r USING (serial_number, issuer)
            WHERE r.public_key IS NULL AND r.cleaned_at IS NULL
              AND s.next_retry_after > datetime('now')
            GROUP BY source ORDER BY source
            """
        )
        out["in_backoff_by_source"] = [dict(row) for row in cur.fetchall()]

        cur.execute(
            """
            SELECT source, last_outcome AS outcome, count(*) AS n
            FROM lookup_state s JOIN revoked_certs r USING (serial_number, issuer)
            WHERE r.public_key IS NULL AND r.cleaned_at IS NULL
            GROUP BY source, last_outcome ORDER BY source, n DESC
            """
        )
        out["lookup_outcomes"] = [dict(row) for row in cur.fetchall()]

        cur.execute(
            """
            SELECT source, count(*) AS n FROM lookup_state s
            JOIN revoked_certs r USING (serial_number, issuer)
            WHERE r.public_key IS NULL AND r.cleaned_at IS NULL
              AND s.last_outcome = 'missing_der'
            GROUP BY source ORDER BY source
            """
        )
        out["missing_der_by_source"] = [dict(row) for row in cur.fetchall()]

        cur.execute(
            """
            SELECT substr(revocation_date, 1, 4) AS year, count(*) AS n
            FROM revoked_certs
            WHERE public_key IS NULL AND cleaned_at IS NULL
            GROUP BY year ORDER BY year DESC LIMIT 15
            """
        )
        out["by_year"] = [dict(r) for r in cur.fetchall()]

        cur.execute(
            """
            SELECT issuer, count(*) AS n
            FROM revoked_certs
            WHERE public_key IS NULL AND cleaned_at IS NULL
            GROUP BY issuer ORDER BY n DESC LIMIT 20
            """
        )
        out["top_issuers"] = [dict(r) for r in cur.fetchall()]

    print(json.dumps(out, indent=2, ensure_ascii=False))


def cmd_crl_health(args):
    """Emit a JSON health report of CRL download failures."""
    setup_logging(args.verbose, args.quiet)
    import json

    from compromised_keys.data_manager import DataManager

    dm = DataManager()
    failures = dm.get_crl_failures()

    classified = []
    for f in failures:
        consecutive = f.get("consecutive_failures") or 0
        status = f.get("download_status")
        if consecutive >= args.policy_threshold and status in (403, 404, 410):
            category = "potential_policy_violation"
        elif status == -2:
            category = "corrupt_crl"
        elif consecutive >= 3:
            category = "transient_network"
        else:
            category = "transient"
        f["category"] = category
        classified.append(f)

    if args.out:
        os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
        with open(args.out, "w", encoding="utf-8") as fp:
            json.dump(classified, fp, indent=2, ensure_ascii=False)
        print(f"Wrote {len(classified)} CRL failure records to {args.out}")
    else:
        print(json.dumps(classified, indent=2, ensure_ascii=False))


def cmd_prepare_release(args):
    """Create a complete, checksummed data-release directory."""
    setup_logging(args.verbose, args.quiet)
    import json
    from pathlib import Path

    from compromised_keys.release_assets import prepare_release

    sync_status = None
    if args.sync_report:
        sync_status = json.loads(Path(args.sync_report).read_text(encoding="utf-8"))
    manifest = prepare_release(
        Path(args.db),
        Path(args.export_dir),
        Path(args.output_dir),
        sync_status,
    )
    print(json.dumps(manifest, indent=2, sort_keys=True))


def cmd_restore_release(args):
    """Verify and restore a database from a data-release directory."""
    setup_logging(args.verbose, args.quiet)
    import json
    from pathlib import Path

    from compromised_keys.release_assets import restore_release

    manifest = restore_release(Path(args.asset_dir), Path(args.output))
    print(json.dumps(manifest, indent=2, sort_keys=True))


def build_parser():
    parser = argparse.ArgumentParser(
        prog="compromised-keys",
        description="WebPKI compromised-key data collection and screening toolkit",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # sync
    p_sync = subparsers.add_parser("sync", help="Full sync cycle (CRL + CT + crt.sh + export)")
    p_sync.add_argument("--loop", action="store_true", help="Run continuously")
    p_sync.add_argument("--interval", type=int, default=6, help="Hours between cycles (default: 6)")
    p_sync.add_argument(
        "--crtsh-mode",
        choices=["postgres", "http"],
        default="",
        help="crt.sh query mode (default: from configuration)",
    )
    p_sync.add_argument(
        "--crtsh-limit",
        type=int,
        default=5000,
        help="Maximum crt.sh records per cycle (default: 5000)",
    )
    p_sync.add_argument(
        "--no-crtsh",
        action="store_true",
        help="Skip public crt.sh supplementation",
    )
    p_sync.add_argument(
        "--report",
        default="",
        help="Write the structured sync report to this JSON file",
    )
    p_sync.add_argument("-v", "--verbose", action="store_true")
    p_sync.add_argument("-q", "--quiet", action="store_true")
    p_sync.set_defaults(func=cmd_sync)

    # crl-sync
    p_crl = subparsers.add_parser(
        "crl-sync", help="Download CCADB + CRLs and parse keyCompromise revocations only"
    )
    p_crl.add_argument("-v", "--verbose", action="store_true")
    p_crl.add_argument("-q", "--quiet", action="store_true")
    p_crl.set_defaults(func=cmd_crl_sync)

    # supplement
    p_supp = subparsers.add_parser("supplement", help="Run crt.sh supplementation")
    p_supp.add_argument(
        "--mode",
        choices=["postgres", "http"],
        default="",
        help="crt.sh query mode (default: from config)",
    )
    p_supp.add_argument("--limit", type=int, default=500, help="Max records to process")
    p_supp.add_argument("-v", "--verbose", action="store_true")
    p_supp.add_argument("-q", "--quiet", action="store_true")
    p_supp.set_defaults(func=cmd_supplement)

    # ct-sync
    p_ct = subparsers.add_parser("ct-sync", help="Optional CT Provider supplementation")
    p_ct.add_argument(
        "--full-history",
        action="store_true",
        help=(
            "Ignore retry times; query revocation-based windows, then retry misses "
            "from 2010-01-01 with not-before through today and not-after through next year"
        ),
    )
    p_ct.add_argument("-v", "--verbose", action="store_true")
    p_ct.add_argument("-q", "--quiet", action="store_true")
    p_ct.set_defaults(func=cmd_ct_sync)

    # export
    p_exp = subparsers.add_parser("export", help="Export CSV + Bloom filter")
    p_exp.add_argument("-v", "--verbose", action="store_true")
    p_exp.add_argument("-q", "--quiet", action="store_true")
    p_exp.set_defaults(func=cmd_export)

    # check
    p_check = subparsers.add_parser("check", help="Check CSR files against blacklist")
    p_check.add_argument("csr_files", nargs="+", help="CSR file paths to check")
    p_check.add_argument("-v", "--verbose", action="store_true")
    p_check.add_argument("-q", "--quiet", action="store_true")
    p_check.set_defaults(func=cmd_check)

    # stats
    p_stats = subparsers.add_parser("stats", help="Show database statistics")
    p_stats.add_argument("-v", "--verbose", action="store_true")
    p_stats.add_argument("-q", "--quiet", action="store_true")
    p_stats.set_defaults(func=cmd_stats)

    # doctor
    p_doctor = subparsers.add_parser(
        "doctor",
        help="Check local prerequisites before synchronization",
    )
    p_doctor.add_argument(
        "--crtsh-mode",
        choices=["postgres", "http"],
        default="",
        help="crt.sh mode to validate (default: from configuration)",
    )
    p_doctor.add_argument(
        "--no-crtsh",
        action="store_true",
        help="Validate a sync that skips crt.sh supplementation",
    )
    p_doctor.add_argument("-v", "--verbose", action="store_true")
    p_doctor.add_argument("-q", "--quiet", action="store_true")
    p_doctor.set_defaults(func=cmd_doctor)

    # validate-cert
    p_val = subparsers.add_parser(
        "validate-cert", help="Validate a community-submitted certificate"
    )
    p_val.add_argument("cert_file", help="Certificate file (PEM or DER)")
    p_val.add_argument("--serial", help="Claimed serial number")
    p_val.add_argument("--issuer", help="Claimed issuer")
    p_val.add_argument("--apply", action="store_true", help="Apply to database if valid")
    p_val.add_argument("-v", "--verbose", action="store_true")
    p_val.add_argument("-q", "--quiet", action="store_true")
    p_val.set_defaults(func=cmd_validate_cert)

    # exact record exclusions
    p_exclude = subparsers.add_parser(
        "exclude-record",
        help="Preview or exclude one exact serial+issuer record",
    )
    p_exclude.add_argument("serial")
    p_exclude.add_argument("issuer")
    p_exclude.add_argument("--reason-code", required=True)
    p_exclude.add_argument("--rationale", required=True)
    p_exclude.add_argument("--created-by", required=True)
    p_exclude.add_argument("--expires-at", default="")
    p_exclude.add_argument("--apply", action="store_true")
    p_exclude.add_argument("-v", "--verbose", action="store_true")
    p_exclude.add_argument("-q", "--quiet", action="store_true")
    p_exclude.set_defaults(func=cmd_exclude_record)

    p_clear = subparsers.add_parser(
        "clear-exclusion",
        help="Preview or clear one exact serial+issuer exclusion",
    )
    p_clear.add_argument("serial")
    p_clear.add_argument("issuer")
    p_clear.add_argument("--apply", action="store_true")
    p_clear.add_argument("-v", "--verbose", action="store_true")
    p_clear.add_argument("-q", "--quiet", action="store_true")
    p_clear.set_defaults(func=cmd_clear_exclusion)

    # analyze-misses
    p_an = subparsers.add_parser(
        "analyze-misses",
        help="Print a JSON breakdown of revoked records still missing a public key",
    )
    p_an.add_argument("-v", "--verbose", action="store_true")
    p_an.add_argument("-q", "--quiet", action="store_true")
    p_an.set_defaults(func=cmd_analyze_misses)

    # crl-health
    p_health = subparsers.add_parser(
        "crl-health",
        help="Print or write a JSON report of CRLs that are currently failing to download",
    )
    p_health.add_argument(
        "--out",
        default="",
        help="Write JSON to this path; if empty, print to stdout",
    )
    p_health.add_argument(
        "--policy-threshold",
        type=int,
        default=7,
        help="consecutive_failures at which a 4xx CRL is flagged as potential CCADB policy violation (default: 7)",
    )
    p_health.add_argument("-v", "--verbose", action="store_true")
    p_health.add_argument("-q", "--quiet", action="store_true")
    p_health.set_defaults(func=cmd_crl_health)

    # prepare-release
    p_prepare = subparsers.add_parser(
        "prepare-release",
        help="Build a checksummed database and export asset directory",
    )
    p_prepare.add_argument("--db", default="compromised_keys.db")
    p_prepare.add_argument("--export-dir", default="data/latest")
    p_prepare.add_argument("--output-dir", default="dist/data-release")
    p_prepare.add_argument("--sync-report", default="")
    p_prepare.add_argument("-v", "--verbose", action="store_true")
    p_prepare.add_argument("-q", "--quiet", action="store_true")
    p_prepare.set_defaults(func=cmd_prepare_release)

    # restore-release
    p_restore = subparsers.add_parser(
        "restore-release",
        help="Verify release assets and restore their SQLite database",
    )
    p_restore.add_argument("--asset-dir", required=True)
    p_restore.add_argument("--output", default="compromised_keys.db")
    p_restore.add_argument("-v", "--verbose", action="store_true")
    p_restore.add_argument("-q", "--quiet", action="store_true")
    p_restore.set_defaults(func=cmd_restore_release)

    return parser


def parse_args(argv=None):
    return build_parser().parse_args(argv)


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.command:
        parser.print_help()
        sys.exit(1)

    write_commands = {
        "sync",
        "crl-sync",
        "ct-sync",
        "supplement",
        "export",
        "exclude-record",
        "clear-exclusion",
        "validate-cert",
        "prepare-release",
        "restore-release",
    }
    if args.command not in write_commands:
        args.func(args)
        return

    from filelock import FileLock, Timeout

    from compromised_keys import config

    database = (
        args.output
        if args.command == "restore-release"
        else args.db
        if args.command == "prepare-release"
        else config.DB_PATH
    )
    lock_path = Path(str(Path(database).resolve()) + ".lock")
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with FileLock(lock_path, timeout=0):
            args.func(args)
    except Timeout:
        parser.exit(1, "Another update is using this database; retry after it finishes.\n")
    except (OSError, ValueError, sqlite3.Error, RuntimeError) as error:
        if getattr(args, "verbose", False):
            logging.getLogger(__name__).exception("Command failed")
        parser.exit(1, f"Error: {error}\n")


if __name__ == "__main__":
    main()
