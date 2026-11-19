"""
Command line interface for forensic verification and inspection of tezca ledgers.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from tezca.ledger import Ledger


def cmd_verify(args: argparse.Namespace) -> int:
    path = Path(args.ledger)
    if not path.exists():
        print(f"[ERROR] Ledger file not found: {path}", file=sys.stderr)
        return 1

    try:
        with Ledger(path) as ledger:
            valid, report = ledger.verify()

        if valid:
            total = report["verified_events"]
            latest = report["latest_hash"]
            print(f"[OK] {total:,} events verified.")
            print(f"[OK] Chain integrity: INTACT (Genesis: {report['genesis_hash'][:16]}... -> Latest: {latest[:16]}...)")
            return 0
        else:
            print(f"[FAIL] Tampering detected at record #{report.get('failed_at_index')}", file=sys.stderr)
            print(f"Error: {report.get('error')}", file=sys.stderr)
            if "expected_prev_hash" in report:
                print(f"Expected prev_hash: {report['expected_prev_hash']}", file=sys.stderr)
                print(f"Actual prev_hash:   {report['actual_prev_hash']}", file=sys.stderr)
            print("Chain broken.", file=sys.stderr)
            return 1
    except Exception as exc:
        print(f"[ERROR] Verification failed: {exc}", file=sys.stderr)
        return 1


def cmd_tail(args: argparse.Namespace) -> int:
    path = Path(args.ledger)
    if not path.exists():
        print(f"[ERROR] Ledger file not found: {path}", file=sys.stderr)
        return 1

    with Ledger(path) as ledger:
        receipts = ledger.tail(n=args.n)

    if args.json:
        for r in receipts:
            print(json.dumps(r.to_dict(), ensure_ascii=False))
    else:
        for r in receipts:
            print(f"#{r.index} [{r.timestamp}] agent={r.agent_id} type={r.event_type} hash={r.hash[:16]}...")
    return 0


def cmd_export(args: argparse.Namespace) -> int:
    path = Path(args.ledger)
    if not path.exists():
        print(f"[ERROR] Ledger file not found: {path}", file=sys.stderr)
        return 1

    out_file = None
    if args.output:
        out_file = open(args.output, "w", encoding="utf-8")

    try:
        with Ledger(path) as ledger:
            for r in ledger:
                line = json.dumps(r.to_dict(), ensure_ascii=False) + "\n"
                if out_file:
                    out_file.write(line)
                else:
                    sys.stdout.write(line)
        if args.output:
            print(f"[OK] Exported ledger to {args.output}")
        return 0
    finally:
        if out_file:
            out_file.close()


def cmd_inspect(args: argparse.Namespace) -> int:
    path = Path(args.ledger)
    if not path.exists():
        print(f"[ERROR] Ledger file not found: {path}", file=sys.stderr)
        return 1

    with Ledger(path) as ledger:
        target = ledger.storage.get_by_index(args.index)

    if not target:
        print(f"[ERROR] Record #{args.index} not found.", file=sys.stderr)
        return 1

    print(json.dumps(target.to_dict(), indent=2, ensure_ascii=False))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="tezca",
        description="Zero-dependency, hash-chained forensic ledger CLI for AI agents.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # verify
    p_verify = subparsers.add_parser("verify", help="Verify cryptographic integrity of a ledger.")
    p_verify.add_argument("ledger", help="Path to audit.db or audit.jsonl")
    p_verify.set_defaults(func=cmd_verify)

    # tail
    p_tail = subparsers.add_parser("tail", help="Show the most recent receipts.")
    p_tail.add_argument("ledger", help="Path to audit.db or audit.jsonl")
    p_tail.add_argument("-n", type=int, default=10, help="Number of records to show (default: 10)")
    p_tail.add_argument("--json", action="store_true", help="Output raw JSON format")
    p_tail.set_defaults(func=cmd_tail)

    # export
    p_export = subparsers.add_parser("export", help="Export ledger records to JSON Lines.")
    p_export.add_argument("ledger", help="Path to audit.db or audit.jsonl")
    p_export.add_argument("-o", "--output", help="Output file path (default: stdout)")
    p_export.set_defaults(func=cmd_export)

    # inspect
    p_inspect = subparsers.add_parser("inspect", help="Inspect a specific receipt by index.")
    p_inspect.add_argument("ledger", help="Path to audit.db or audit.jsonl")
    p_inspect.add_argument("index", type=int, help="Record index number")
    p_inspect.set_defaults(func=cmd_inspect)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
