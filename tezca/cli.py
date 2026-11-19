"""
Command line interface for forensic verification and inspection of tezca ledgers.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from tezca.ledger import Ledger
from tezca.proof import ProofBundle


def cmd_verify(args: argparse.Namespace) -> int:
    path = Path(args.ledger)
    if not path.exists():
        print(f"[ERROR] Ledger file not found: {path}", file=sys.stderr)
        return 1

    try:
        with Ledger(path, secret_key=args.secret_key) as ledger:
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
            sig_badge = " [signed]" if r.signature else ""
            print(f"#{r.index} [{r.timestamp}] agent={r.agent_id} type={r.event_type} hash={r.hash[:16]}...{sig_badge}")
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


def cmd_proof(args: argparse.Namespace) -> int:
    path = Path(args.ledger)
    if not path.exists():
        print(f"[ERROR] Ledger file not found: {path}", file=sys.stderr)
        return 1

    try:
        with Ledger(path) as ledger:
            out_path = args.output or f"{path.stem}_event_{args.index}.tezcaproof"
            bundle = ledger.export_proof(args.index, output_path=out_path)

        print(f"[OK] Cryptographic proof bundle exported to {out_path}")
        print(f"[OK] Merkle root: {bundle.merkle_root}")
        print(f"[OK] Receipt hash: {bundle.receipt.hash}")
        return 0
    except IndexError as ex:
        print(f"[ERROR] {ex}", file=sys.stderr)
        return 1
    except Exception as exc:
        print(f"[ERROR] Failed to export proof: {exc}", file=sys.stderr)
        return 1


def cmd_verify_proof(args: argparse.Namespace) -> int:
    path = Path(args.proof_file)
    if not path.exists():
        print(f"[ERROR] Proof file not found: {path}", file=sys.stderr)
        return 1

    try:
        bundle = ProofBundle.load(path)
        valid, msg = bundle.verify(secret_key=args.secret_key)
        if valid:
            print(f"[OK] Proof verified: Receipt #{bundle.receipt.index} is cryptographically sealed.")
            print(f"[OK] Merkle Root: {bundle.merkle_root}")
            print(f"[OK] Event Hash:  {bundle.receipt.hash}")
            return 0
        else:
            print(f"[FAIL] Proof verification failed: {msg}", file=sys.stderr)
            return 1
    except Exception as exc:
        print(f"[ERROR] Invalid proof bundle: {exc}", file=sys.stderr)
        return 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="tezca",
        description="Zero-dependency, hash-chained forensic ledger CLI for AI agents.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # verify
    p_verify = subparsers.add_parser("verify", help="Verify cryptographic integrity of a ledger.")
    p_verify.add_argument("ledger", help="Path to audit.db or audit.jsonl")
    p_verify.add_argument("--secret-key", help="Optional HMAC secret key to verify receipt signatures")
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

    # proof
    p_proof = subparsers.add_parser("proof", help="Export a standalone cryptographic proof bundle (.tezcaproof).")
    p_proof.add_argument("ledger", help="Path to audit.db or audit.jsonl")
    p_proof.add_argument("index", type=int, help="Record index to prove")
    p_proof.add_argument("-o", "--output", help="Output path (default: <ledger>_event_<idx>.tezcaproof)")
    p_proof.set_defaults(func=cmd_proof)

    # verify-proof
    p_vproof = subparsers.add_parser("verify-proof", help="Verify an offline cryptographic proof bundle.")
    p_vproof.add_argument("proof_file", help="Path to .tezcaproof file")
    p_vproof.add_argument("--secret-key", help="Optional secret key to verify HMAC signature")
    p_vproof.set_defaults(func=cmd_verify_proof)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
