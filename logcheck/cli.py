"""Command line: ``logcheck scan``, ``logcheck detectors`` and ``logcheck hash-pans``.

Exit codes: 0 = no finding at or above --fail-on, 1 = findings at or above --fail-on,
2 = nothing could be scanned or the options/config are wrong.
"""

from __future__ import annotations

import argparse
import datetime as _dt
import os
import sys

from logcheck import __version__
from logcheck.cards import hash_pans_cli
from logcheck.config import CONFIDENCE_ORDER, REPORT_FORMATS, SEVERITY_ORDER, ConfigError, load_config
from logcheck.detectors import all_detectors
from logcheck.engine import run_scan
from logcheck.report import print_summary, write_reports

COMMANDS = ("scan", "detectors", "hash-pans")


def _csv(text: str) -> list[str]:
    return [t.strip() for t in text.split(",") if t.strip()]


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="logcheck", description="Find sensitive data written to log files.")
    p.add_argument("--version", action="version", version=f"LogCheck {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("scan", help="scan files or folders (the default command)")
    s.add_argument("paths", nargs="+", help="log files, folders (scanned recursively) or glob patterns")
    s.add_argument("-c", "--config", help="TOML settings file (see logcheck.example.toml)")
    s.add_argument("-o", "--out", help="report folder (default: ./logcheck-report-<date-time>)")
    s.add_argument("--formats", type=_csv, help=f"report formats, comma-separated: {', '.join(REPORT_FORMATS)}")
    s.add_argument("--detectors", type=_csv, help="run only these detector ids (see `logcheck detectors`)")
    s.add_argument("--disable", type=_csv, help="detector ids to skip")
    s.add_argument("--min-confidence", choices=list(CONFIDENCE_ORDER), help="drop findings below this confidence")
    s.add_argument("--workers", type=int, help="parallel processes (0 = one per CPU, 1 = no parallelism)")
    s.add_argument("--context", type=int, dest="context_chars", help="evidence characters either side of a finding")
    s.add_argument("--include", type=_csv, help="file name patterns to scan inside folders")
    s.add_argument("--exclude", type=_csv, help="file name or relative path patterns to skip")
    s.add_argument("--bin-list", help="file with your issuer BIN prefixes, one per line")
    s.add_argument("--pan-hashes", help="file of HMAC-SHA256 PAN digests (see `logcheck hash-pans`)")
    s.add_argument("--include-values", action="store_true", default=None,
                   help="also write the raw detected values into the reports (they are sensitive)")
    s.add_argument("--ai", action="store_true", default=None, dest="ai_enabled",
                   help="experimental: ask an OpenAI model to triage masked findings (needs OPENAI_API_KEY)")
    s.add_argument("--fail-on", default="low", choices=[*SEVERITY_ORDER, "never"],
                   help="exit with 1 when a finding of this severity or higher exists (default: low)")
    s.add_argument("-q", "--quiet", action="store_true", help="no progress output")

    sub.add_parser("detectors", help="list the detectors")

    h = sub.add_parser("hash-pans", help="turn card numbers into the digest list used by --pan-hashes")
    h.add_argument("file", nargs="?", help="file with one card number per line (default: standard input)")
    return p


def _apply_options(cfg, args) -> None:
    for name in ("formats", "min_confidence", "workers", "context_chars", "include", "exclude", "bin_list",
                 "pan_hashes", "include_values", "ai_enabled"):
        value = getattr(args, name)
        if value is not None:
            setattr(cfg, name, value)
    if args.detectors is not None:
        cfg.enable = args.detectors
    if args.disable is not None:
        cfg.disable = args.disable
    if args.out:
        cfg.output_dir = args.out
    cfg.validate()


def cmd_scan(args) -> int:
    try:
        cfg = load_config(args.config)
        _apply_options(cfg, args)
    except ConfigError as exc:
        print(f"logcheck: {exc}", file=sys.stderr)
        return 2
    out_dir = cfg.output_dir or f"logcheck-report-{_dt.datetime.now():%Y%m%d-%H%M%S}"

    def progress(result, done, total):
        if not args.quiet:
            print(f"[{done}/{total}] {result.path}: {result.status}, {len(result.findings)} finding(s)", file=sys.stderr)

    try:
        result = run_scan(args.paths, cfg, skip_dirs=[out_dir], progress=progress)
    except (ValueError, OSError) as exc:  # unknown detector id, unreadable BIN/hash list, missing hash key
        print(f"logcheck: {exc}", file=sys.stderr)
        return 2
    if not result.files:
        print_summary(result, sys.stdout)
        print("logcheck: no files to scan", file=sys.stderr)
        return 2

    extra = {}
    if cfg.ai_enabled:
        from logcheck.ai.triage import Triage
        try:
            stats = Triage(cfg.ai_model, cfg.ai_max_calls, cfg.ai_endpoint).run(result.findings)
            extra["ai_triage"] = {"model": cfg.ai_model, "experimental": True, **vars(stats)}
        except RuntimeError as exc:
            print(f"logcheck: AI triage skipped: {exc}", file=sys.stderr)
    paths = write_reports(result, out_dir, cfg.formats, cfg.include_values, extra)
    print_summary(result, sys.stdout)
    if "xlsx" in cfg.formats and not any(p.endswith(".xlsx") for p in paths):
        print("  NOTE: Excel report skipped: install openpyxl (pip install openpyxl)")
    for p in paths:
        print(f"Report: {os.path.abspath(p)}")
    if cfg.include_values:
        print("WARNING: the reports contain the raw sensitive values; store and share them like the logs themselves.")

    if args.fail_on == "never":
        return 0
    threshold = SEVERITY_ORDER[args.fail_on]
    return 1 if any(SEVERITY_ORDER[f.severity] >= threshold for f in result.findings) else 0


def cmd_detectors() -> int:
    detectors = all_detectors()
    width = max(len(d.id) for d in detectors)
    for d in detectors:
        state = "" if d.enabled_by_default else "  (off by default)"
        print(f"{d.id:<{width}}  {d.severity:<8}  {d.title}{state}")
    return 0


def cmd_hash_pans(args) -> int:
    try:
        if args.file:
            with open(args.file, encoding="utf-8-sig") as fh:
                count = hash_pans_cli(fh)
        else:
            count = hash_pans_cli(sys.stdin)
    except (ValueError, OSError) as exc:
        print(f"logcheck: {exc}", file=sys.stderr)
        return 2
    print(f"logcheck: {count} digest(s) written", file=sys.stderr)
    return 0


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    parser = build_parser()
    if not argv:
        parser.print_help()
        return 2
    if argv[0] not in COMMANDS and not argv[0].startswith("-"):
        argv.insert(0, "scan")  # `logcheck <path>` means `logcheck scan <path>`
    args = parser.parse_args(argv)
    if args.command == "detectors":
        return cmd_detectors()
    if args.command == "hash-pans":
        return cmd_hash_pans(args)
    return cmd_scan(args)
