"""Command line interface."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from . import __version__, audit, catalog, report
from . import baseline as baseline_module
from .knowledge import check_ids
from .model import Severity

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_USAGE = 2
EXIT_ERROR = 3

EPILOG = """\
rls-probe issues only SELECT statements against pg_catalog, on a connection it
puts into read-only mode before the first query. It never reads application
data and never writes anything.

examples:
  rls-probe audit --dsn postgresql://postgres@localhost:5432/mydb
  rls-probe audit --schema public --format markdown > rls-report.md
  rls-probe audit --severity-threshold high --exit-code
  rls-probe audit --baseline .rls-probe-baseline.json --exit-code
  rls-probe explain RLS001
  rls-probe list-checks
"""


def _severity(value: str) -> Severity:
    try:
        return Severity.parse(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from None


def _check_id(value: str) -> str:
    key = value.strip().upper()
    if key not in check_ids():
        raise argparse.ArgumentTypeError(
            f"unknown check {value!r}; known checks: " + ", ".join(check_ids())
        )
    return key


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="rls-probe",
        description=(
            "Audit the row-level-security posture of a PostgreSQL database, with "
            "specific support for Supabase and PostgREST deployments."
        ),
        epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=f"rls-probe {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # -- audit ------------------------------------------------------------
    audit_parser = subparsers.add_parser(
        "audit",
        help="audit a database and report findings",
        description=(
            "Connect read-only, read the catalogs, run every check and report. "
            "Exits 1 when --exit-code is given and anything is reported."
        ),
        epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    audit_parser.add_argument(
        "--dsn",
        help=(
            "libpq connection string or URI. Defaults to $DATABASE_URL, then to the "
            "standard libpq environment (PGHOST, PGDATABASE, ...)."
        ),
    )
    audit_parser.add_argument(
        "--schema",
        action="append",
        metavar="NAME",
        help=(
            "Audit only this schema; repeatable. Default: every schema except the "
            "system ones and the ones a managed platform owns (auth, storage, "
            "realtime, vault, ... -- see --include-managed-schemas)."
        ),
    )
    audit_parser.add_argument(
        "--exposed-schema",
        action="append",
        metavar="NAME",
        help=(
            "A schema your REST layer serves; repeatable. Default: public, which is "
            "PostgREST's and Supabase's default. Everything in an exposed schema is a "
            "callable endpoint, which is what RLS002, RLS007 and RLS010 turn on."
        ),
    )
    audit_parser.add_argument(
        "--exposed-role",
        action="append",
        metavar="NAME",
        help=(
            "A role an inbound request can authenticate as; repeatable. "
            "Default: anon, authenticated (Supabase's)."
        ),
    )
    audit_parser.add_argument(
        "--anon-role",
        action="append",
        metavar="NAME",
        help=(
            "Of the exposed roles, the ones an unauthenticated request becomes; "
            "repeatable. Default: anon."
        ),
    )
    audit_parser.add_argument(
        "--include-managed-schemas",
        action="store_true",
        help=(
            "Also audit schemas owned by a managed platform. Off by default because "
            "you cannot ALTER Supabase's auth schema to satisfy a finding."
        ),
    )
    audit_parser.add_argument(
        "--include-extension-objects",
        action="store_true",
        help="Also audit functions that belong to an extension.",
    )
    audit_parser.add_argument(
        "--check",
        action="append",
        type=_check_id,
        metavar="ID",
        help="Run only this check; repeatable. Default: all of them.",
    )
    audit_parser.add_argument(
        "--format",
        choices=("text", "json", "markdown"),
        default="text",
        help="Output format (default: text).",
    )
    audit_parser.add_argument(
        "--severity-threshold",
        type=_severity,
        default=Severity.INFO,
        metavar="LEVEL",
        help=(
            "Report only findings at this severity or above: "
            "info, low, medium, high, critical (default: info)."
        ),
    )
    audit_parser.add_argument(
        "--baseline",
        metavar="FILE",
        help=(
            "Accept the findings recorded in this file, so only new ones are reported. "
            "Use with --exit-code in CI."
        ),
    )
    audit_parser.add_argument(
        "--write-baseline",
        metavar="FILE",
        help=(
            "Write the findings of this run to a baseline file and exit 0. Review the "
            "file before committing it: every line is a finding you are accepting."
        ),
    )
    audit_parser.add_argument(
        "--exit-code",
        action="store_true",
        help="Exit 1 when anything is reported. Off by default so a bare run is quiet.",
    )
    audit_parser.add_argument(
        "--no-evidence",
        action="store_true",
        help="Leave the evidence lines out of the text report.",
    )
    audit_parser.add_argument(
        "--no-color",
        action="store_true",
        help="Never colourise. Colour is also off when stdout is not a terminal.",
    )
    audit_parser.add_argument(
        "--statement-timeout",
        type=int,
        default=30_000,
        metavar="MS",
        help="Server-side statement timeout in milliseconds (default: 30000).",
    )

    # -- explain ----------------------------------------------------------
    explain_parser = subparsers.add_parser(
        "explain",
        help="print the mechanism and the fix for one check, in full",
    )
    explain_parser.add_argument("check_id", type=_check_id, metavar="CHECK-ID")
    explain_parser.add_argument("--no-color", action="store_true")

    # -- list-checks ------------------------------------------------------
    list_parser = subparsers.add_parser("list-checks", help="list every check")
    list_parser.add_argument("--no-color", action="store_true")
    list_parser.add_argument(
        "--format",
        choices=("text", "json"),
        default="text",
        help="Output format (default: text).",
    )

    return parser


def _use_color(args: argparse.Namespace, stream) -> bool:
    if getattr(args, "no_color", False):
        return False
    if os.environ.get("NO_COLOR"):
        return False
    return bool(getattr(stream, "isatty", lambda: False)())


def _cmd_audit(args: argparse.Namespace) -> int:
    dsn = args.dsn or os.environ.get("DATABASE_URL")

    if args.baseline and args.write_baseline:
        print(
            "rls-probe: --baseline and --write-baseline do not make sense together; "
            "--write-baseline records this run, --baseline filters against a previous one",
            file=sys.stderr,
        )
        return EXIT_USAGE

    loaded_baseline = None
    if args.baseline:
        try:
            loaded_baseline = baseline_module.load(args.baseline)
        except baseline_module.BaselineError as exc:
            print(f"rls-probe: {exc}", file=sys.stderr)
            return EXIT_USAGE

    try:
        connection = catalog.connect(dsn, statement_timeout_ms=args.statement_timeout)
    except catalog.CatalogError as exc:
        print(f"rls-probe: {exc}", file=sys.stderr)
        return EXIT_ERROR
    except Exception as exc:  # psycopg.OperationalError and friends
        target = catalog.redact_dsn(dsn) if dsn else "the libpq environment"
        print(f"rls-probe: could not connect using {target}: {exc}", file=sys.stderr)
        return EXIT_ERROR

    try:
        with connection:
            snapshot, notes = catalog.collect(
                connection,
                schemas=tuple(args.schema) if args.schema else None,
                exposed_schemas=tuple(args.exposed_schema or catalog.DEFAULT_EXPOSED_SCHEMAS),
                exposed_roles=tuple(args.exposed_role or catalog.DEFAULT_EXPOSED_ROLES),
                anonymous_roles=tuple(args.anon_role or catalog.DEFAULT_ANONYMOUS_ROLES),
                include_managed_schemas=args.include_managed_schemas,
                include_extension_objects=args.include_extension_objects,
            )
            audited_schemas = catalog.resolve_schemas(
                connection,
                tuple(args.schema) if args.schema else None,
                args.include_managed_schemas,
            )
    except catalog.CatalogError as exc:
        print(f"rls-probe: {exc}", file=sys.stderr)
        return EXIT_ERROR
    except Exception as exc:
        print(f"rls-probe: reading the catalogs failed: {exc}", file=sys.stderr)
        return EXIT_ERROR

    result = audit.run(
        snapshot,
        checks=args.check,
        threshold=args.severity_threshold,
        notes=notes,
        baseline=loaded_baseline,
        baseline_path=args.baseline,
        schemas=audited_schemas,
    )

    if args.write_baseline:
        try:
            count = baseline_module.write(
                args.write_baseline,
                result.reported,
                database=snapshot.database,
            )
        except OSError as exc:
            print(f"rls-probe: could not write baseline: {exc}", file=sys.stderr)
            return EXIT_ERROR
        print(
            f"rls-probe: wrote {count} finding(s) to {Path(args.write_baseline)}. "
            f"Review it before committing: every entry is a finding you are accepting.",
            file=sys.stderr,
        )
        return EXIT_OK

    if args.format == "json":
        sys.stdout.write(report.render_json(result))
    elif args.format == "markdown":
        sys.stdout.write(report.render_markdown(result))
    else:
        sys.stdout.write(
            report.render_text(
                result,
                color=_use_color(args, sys.stdout),
                show_evidence=not args.no_evidence,
            )
        )

    if args.exit_code and result.reported:
        return EXIT_FINDINGS
    return EXIT_OK


def _cmd_explain(args: argparse.Namespace) -> int:
    sys.stdout.write(
        report.render_explanation(args.check_id, color=_use_color(args, sys.stdout))
    )
    return EXIT_OK


def _cmd_list_checks(args: argparse.Namespace) -> int:
    if args.format == "json":
        import json

        from .knowledge import CHECK_DOCS

        payload = [
            {
                "id": doc.check_id,
                "title": doc.title,
                "default_severity": doc.default_severity.label,
                "summary": doc.summary,
                "catalogs": list(doc.catalogs),
                "references": list(doc.references),
            }
            for doc in (CHECK_DOCS[k] for k in sorted(CHECK_DOCS))
        ]
        sys.stdout.write(json.dumps(payload, indent=2) + "\n")
    else:
        sys.stdout.write(report.render_check_list(color=_use_color(args, sys.stdout)))
    return EXIT_OK


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "audit":
        return _cmd_audit(args)
    if args.command == "explain":
        return _cmd_explain(args)
    if args.command == "list-checks":
        return _cmd_list_checks(args)
    parser.error(f"unknown command {args.command!r}")
    return EXIT_USAGE  # pragma: no cover


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
