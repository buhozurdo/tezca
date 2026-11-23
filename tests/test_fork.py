"""
Unit tests for fork, split-chain, and divergence anomaly detection.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from tezca.fork import ForkReport, ForkStatus, detect_fork, detect_forks
from tezca.ledger import Ledger
from tezca.storage import JSONLStorage, SQLiteStorage


class TestForkDetection:
    def test_both_empty_ledgers(self, tmp_path: Path):
        p1 = tmp_path / "primary.db"
        p2 = tmp_path / "replica.db"

        with Ledger(p1) as l1, Ledger(p2) as l2:
            report = detect_fork(l1, l2)
            assert report.status == ForkStatus.BOTH_EMPTY
            assert report.is_identical is True
            assert report.is_forked is False
            assert report.is_compatible is True
            assert report.genesis_match is True
            assert report.common_ancestor_index is None
            assert report.divergence_index is None
            assert "Both ledgers are empty" in report.summary()

    def test_primary_empty_replica_populated(self, tmp_path: Path):
        p1 = tmp_path / "primary.db"
        p2 = tmp_path / "replica.db"

        with Ledger(p1) as l1, Ledger(p2) as l2:
            l2.record("agent-b", "init", {"v": 1})
            report = l1.compare_with(l2)

            assert report.status == ForkStatus.PRIMARY_EMPTY
            assert report.is_identical is False
            assert report.is_forked is False
            assert report.is_compatible is False
            assert report.genesis_match is False
            assert report.primary_length == 0
            assert report.replica_length == 1
            assert "Primary ledger is empty" in report.summary()

    def test_replica_empty_primary_populated(self, tmp_path: Path):
        p1 = tmp_path / "primary.db"
        p2 = tmp_path / "replica.db"

        with Ledger(p1) as l1, Ledger(p2) as l2:
            l1.record("agent-a", "init", {"v": 1})
            report = l1.compare_with(l2)

            assert report.status == ForkStatus.REPLICA_EMPTY
            assert report.is_identical is False
            assert report.is_forked is False
            assert report.is_compatible is False
            assert report.genesis_match is False
            assert report.primary_length == 1
            assert report.replica_length == 0
            assert "Replica ledger is empty" in report.summary()

    def test_identical_chains(self, tmp_path: Path):
        p1 = tmp_path / "primary.db"
        p2 = tmp_path / "replica.db"

        ts0 = "2026-11-23T10:00:00Z"
        ts1 = "2026-11-23T10:01:00Z"

        with Ledger(p1) as l1, Ledger(p2) as l2:
            l1.record("agent-a", "action-0", {"x": 10}, timestamp=ts0)
            l2.record("agent-a", "action-0", {"x": 10}, timestamp=ts0)

            l1.record("agent-a", "action-1", {"x": 20}, timestamp=ts1)
            l2.record("agent-a", "action-1", {"x": 20}, timestamp=ts1)

            report = l1.compare_with(l2)
            assert report.status == ForkStatus.IDENTICAL
            assert report.is_identical is True
            assert report.is_forked is False
            assert report.is_compatible is True
            assert report.genesis_match is True
            assert report.common_ancestor_index == 1
            assert report.divergence_index is None
            assert report.primary_length == 2
            assert report.replica_length == 2
            assert "IN_SYNC" in report.summary()

    def test_replica_ahead_and_behind(self, tmp_path: Path):
        p1 = tmp_path / "primary.db"
        p2 = tmp_path / "replica.jsonl"

        ts0 = "2026-11-23T10:00:00Z"
        ts1 = "2026-11-23T10:01:00Z"
        ts2 = "2026-11-23T10:02:00Z"

        with Ledger(p1) as l1, Ledger(p2) as l2:
            l1.record("agent", "start", {"val": 1}, timestamp=ts0)
            l2.record("agent", "start", {"val": 1}, timestamp=ts0)

            l1.record("agent", "step1", {"val": 2}, timestamp=ts1)
            l2.record("agent", "step1", {"val": 2}, timestamp=ts1)

            # replica gets an extra event
            l2.record("agent", "step2", {"val": 3}, timestamp=ts2)

            report_ahead = l1.compare_with(l2)
            assert report_ahead.status == ForkStatus.REPLICA_AHEAD
            assert report_ahead.is_forked is False
            assert report_ahead.is_compatible is True
            assert report_ahead.common_ancestor_index == 1
            assert report_ahead.divergence_index is None
            assert report_ahead.primary_length == 2
            assert report_ahead.replica_length == 3
            assert "ahead of primary" in report_ahead.summary()

            report_behind = l2.compare_with(l1)
            assert report_behind.status == ForkStatus.REPLICA_BEHIND
            assert report_behind.is_forked is False
            assert report_behind.is_compatible is True
            assert report_behind.common_ancestor_index == 1
            assert report_behind.divergence_index is None
            assert report_behind.primary_length == 3
            assert report_behind.replica_length == 2
            assert "behind primary" in report_behind.summary()

    def test_disjoint_genesis(self, tmp_path: Path):
        p1 = tmp_path / "primary.db"
        p2 = tmp_path / "replica.db"

        with Ledger(p1) as l1, Ledger(p2) as l2:
            l1.record("agent-1", "init", {"seed": "alpha"}, timestamp="2026-11-23T00:00:00Z")
            l2.record("agent-2", "init", {"seed": "beta"}, timestamp="2026-11-23T00:00:00Z")

            report = l1.detect_fork(l2)
            assert report.status == ForkStatus.DISJOINT
            assert report.is_forked is True
            assert report.is_compatible is False
            assert report.genesis_match is False
            assert report.common_ancestor_index is None
            assert report.divergence_index == 0
            assert "Disjoint ledgers" in report.summary()

    def test_forked_chains_divergence_point(self, tmp_path: Path):
        p1 = tmp_path / "primary.db"
        p2 = tmp_path / "replica.db"

        ts0 = "2026-11-23T12:00:00Z"
        ts1 = "2026-11-23T12:01:00Z"

        with Ledger(p1) as l1, Ledger(p2) as l2:
            # Common history index 0
            l1.record("agent", "start", {"val": 100}, timestamp=ts0)
            l2.record("agent", "start", {"val": 100}, timestamp=ts0)

            # Divergence at index 1
            l1.record("agent", "commit", {"branch": "main"}, timestamp=ts1)
            l2.record("agent", "commit", {"branch": "fork"}, timestamp=ts1)

            # Additional events on primary and replica
            l1.record("agent", "after_prim", {"x": 1})
            l2.record("agent", "after_repl_1", {"y": 1})
            l2.record("agent", "after_repl_2", {"y": 2})

            report = l1.compare_with(l2)
            assert report.status == ForkStatus.FORKED
            assert report.is_forked is True
            assert report.is_compatible is False
            assert report.genesis_match is True
            assert report.common_ancestor_index == 0
            assert report.divergence_index == 1
            assert report.primary_length == 3
            assert report.replica_length == 4
            assert report.primary_divergent_hash is not None
            assert report.replica_divergent_hash is not None
            assert report.primary_divergent_hash != report.replica_divergent_hash
            assert report.primary_divergent_summary["event_type"] == "commit"
            assert report.replica_divergent_summary["event_type"] == "commit"
            assert "FORK DETECTED at index #1" in report.summary()

    def test_fork_with_replay_attack_detection(self, tmp_path: Path):
        import dataclasses
        p1 = tmp_path / "primary.db"
        p2 = tmp_path / "replica.db"

        ts0 = "2026-11-23T14:00:00Z"
        ts1 = "2026-11-23T14:01:00Z"
        ts2 = "2026-11-23T14:02:00Z"

        with Ledger(p1) as l1, Ledger(p2) as l2:
            # Common root at index 0
            l1.record("agent", "init", {"step": 0}, timestamp=ts0)
            l2.record("agent", "init", {"step": 0}, timestamp=ts0)

            # Primary advances with events 1 and 2
            r1 = l1.record("agent", "event_one", {"auth": "token-1"}, timestamp=ts1)
            l1.record("agent", "event_two", {"auth": "token-2"}, timestamp=ts2)

            # Replica diverges at index 1 by doing something else
            l2.record("agent", "unauthorized_step", {"auth": "rogue"}, timestamp=ts1)

            # Replica then attempts to inject/replay the identical receipt hash of primary index 1
            # at index 2
            replayed_receipt = dataclasses.replace(r1, index=2)
            l2.storage.append(replayed_receipt)

            report = l1.compare_with(l2)
            assert report.status == ForkStatus.FORKED
            assert report.is_forked is True
            assert report.replay_detected is True
            assert 2 in report.replayed_indices
            assert "[REPLAY DETECTED]" in report.summary()

    def test_detect_forks_multi_replicas(self, tmp_path: Path):
        p_prim = tmp_path / "primary.db"
        p_rep1 = tmp_path / "rep1.db"
        p_rep2 = tmp_path / "rep2.db"

        ts0 = "2026-11-23T15:00:00Z"

        with Ledger(p_prim) as prim, Ledger(p_rep1) as r1, Ledger(p_rep2) as r2:
            prim.record("agent", "boot", {}, timestamp=ts0)
            r1.record("agent", "boot", {}, timestamp=ts0)
            r2.record("agent", "different_boot", {}, timestamp=ts0)

            reports = detect_forks(prim, [r1, r2])
            assert len(reports) == 2
            assert reports[0].is_identical is True
            assert reports[1].status == ForkStatus.DISJOINT

    def test_serialization_to_dict_and_json(self, tmp_path: Path):
        p1 = tmp_path / "primary.db"
        p2 = tmp_path / "replica.db"

        ts = "2026-11-23T16:00:00Z"
        with Ledger(p1) as l1, Ledger(p2) as l2:
            l1.record("agent", "a", {}, timestamp=ts)
            l2.record("agent", "a", {}, timestamp=ts)

            report = l1.compare_with(l2)
            d = report.to_dict()
            assert d["status"] == "identical"
            assert d["is_compatible"] is True

            j = report.to_json()
            parsed = json.loads(j)
            assert parsed["status"] == "identical"
            assert parsed["primary_length"] == 1
