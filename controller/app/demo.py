"""Guarded local demo CLI for the fixed remediation sandbox and decoy simulator.

No HTTP mutation route calls this module. All mutation commands require an
explicit local environment opt-in and persist only demo records.
"""

import argparse
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import subprocess
import sys
from uuid import uuid4

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from app.audit.service import append_event
from app.db.database import SessionLocal, engine
from app.db.models import Base, DemoDecoyEvent, SandboxRemediationRun


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
AGENT_DIRECTORY = REPOSITORY_ROOT / "agent"
DECOY_ID = "loopback-decoy-simulator"
SAMPLE_EVENTS = (
    ("connection_attempt", "198.51.100.10"),
    ("authentication_probe_simulated", "203.0.113.21"),
    ("path_request_simulated", "192.0.2.32"),
    ("protocol_banner_probe_simulated", "198.51.100.43"),
    ("connection_attempt", "203.0.113.54"),
    ("authentication_probe_simulated", "192.0.2.65"),
    ("invalid_method_simulated", "198.51.100.76"),
    ("path_request_simulated", "203.0.113.87"),
    ("protocol_banner_probe_simulated", "192.0.2.98"),
    ("connection_attempt", "198.51.100.109"),
)
REMEDIATION_SCENARIOS = ("roundtrip", "compliant", "precedence-conflict")


def generate_decoy_events(db: Session, *, occurred_at: datetime | None = None) -> tuple[str, int]:
    batch_id = str(uuid4())
    base_time = occurred_at or datetime.now(timezone.utc)
    for index, (category, source_address) in enumerate(SAMPLE_EVENTS):
        db.add(
            DemoDecoyEvent(
                event_id=str(uuid4()),
                batch_id=batch_id,
                decoy_id=DECOY_ID,
                occurred_at=base_time + timedelta(seconds=index),
                category=category,
                source_address=source_address,
                source_classification="RFC5737_DOCUMENTATION_RANGE_SIMULATED",
                correlation_id=f"{batch_id}:{index + 1:02d}",
                outcome="simulated_event_recorded",
                simulation_mode="SIMULATED",
            )
        )
    append_event(
        db,
        event_type="decoy.simulated_batch_created",
        metadata={"batch_id": batch_id, "decoy_id": DECOY_ID, "event_count": len(SAMPLE_EVENTS), "mode": "SIMULATED"},
    )
    db.commit()
    return batch_id, len(SAMPLE_EVENTS)


def reset_decoy_events(db: Session) -> int:
    result = db.execute(delete(DemoDecoyEvent).where(DemoDecoyEvent.simulation_mode == "SIMULATED"))
    deleted_count = int(result.rowcount or 0)
    append_event(
        db,
        event_type="decoy.simulated_events_reset",
        metadata={"deleted_event_count": deleted_count, "mode": "SIMULATED"},
    )
    db.commit()
    return deleted_count


def run_remediation_scenario(db: Session, scenario: str) -> dict:
    if scenario not in REMEDIATION_SCENARIOS:
        raise ValueError("unsupported sandbox scenario")
    env = {key: os.environ[key] for key in ("PATH", "HOME", "TMPDIR", "GOCACHE", "GOMODCACHE") if os.environ.get(key)}
    env.update({"GOTOOLCHAIN": "local", "GOPROXY": "off"})
    process = subprocess.run(
        ["go", "run", "./cmd/sandbox-demo", "--scenario", scenario],
        cwd=AGENT_DIRECTORY,
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    if len(process.stdout.encode("utf-8", errors="replace")) > 512_000:
        raise RuntimeError("sandbox runner returned an oversized result")
    try:
        result = json.loads(process.stdout)
    except (json.JSONDecodeError, TypeError) as exc:
        message = process.stderr.strip()[:1000]
        raise RuntimeError(f"sandbox runner did not return a valid result (exit {process.returncode}): {message}") from exc
    if not isinstance(result, dict) or result.get("schema") != "aha-remediation-sandbox-run/v1":
        raise RuntimeError("sandbox runner returned an unexpected result schema")
    if result.get("scenario") != scenario or result.get("sandbox_only") is not True or result.get("test_only_trust") is not True or result.get("live_target_modified") is not False:
        raise RuntimeError("sandbox result did not satisfy the local-only safety contract")
    if not isinstance(result.get("run_id"), str) or not isinstance(result.get("status"), str):
        raise RuntimeError("sandbox result is missing its run identity or status")
    if not isinstance(result.get("target_id"), str) or not result["target_id"].startswith("sandbox-local-") or result.get("platform") != "ubuntu-sandbox-fixture":
        raise RuntimeError("sandbox result named a non-fixture target or platform")
    # The generated state path is temporary and deleted before the runner exits.
    # Do not publish the user's temp directory through the dashboard API.
    execution = result.get("execution")
    if isinstance(execution, dict):
        execution["state_path"] = ""
    row = SandboxRemediationRun(
        run_id=result["run_id"],
        target_id=result["target_id"],
        platform=result["platform"],
        scenario=result["scenario"],
        status=result["status"],
        sandbox_only=True,
        test_only_trust=True,
        live_target_modified=False,
        result_json=json.dumps(result, ensure_ascii=False, separators=(",", ":")),
        recorded_at=datetime.now(timezone.utc),
    )
    db.add(row)
    append_event(
        db,
        event_type="sandbox.remediation_run_recorded",
        metadata={"run_id": row.run_id, "scenario": row.scenario, "status": row.status, "sandbox_only": True},
    )
    db.commit()
    return result


def list_decoy_events(db: Session, limit: int = 100) -> list[dict]:
    rows = db.scalars(select(DemoDecoyEvent).order_by(DemoDecoyEvent.occurred_at.desc()).limit(limit)).all()
    return [
        {"event_id": row.event_id, "batch_id": row.batch_id, "decoy_id": row.decoy_id, "occurred_at": row.occurred_at.isoformat(), "category": row.category, "source_address": row.source_address, "source_classification": row.source_classification, "correlation_id": row.correlation_id, "outcome": row.outcome, "simulation_mode": row.simulation_mode}
        for row in rows
    ]


def list_remediation_runs(db: Session, limit: int = 25) -> list[dict]:
    rows = db.scalars(select(SandboxRemediationRun).order_by(SandboxRemediationRun.recorded_at.desc()).limit(limit)).all()
    return [{"run_id": row.run_id, "status": row.status, "scenario": row.scenario, "recorded_at": row.recorded_at.isoformat(), "result": json.loads(row.result_json)} for row in rows]


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Local-only demonstration utilities; no network listener or remediation API")
    commands = parser.add_subparsers(dest="domain", required=True)
    decoy = commands.add_parser("decoy", help="safe simulated event feed")
    decoy_commands = decoy.add_subparsers(dest="action", required=True)
    decoy_commands.add_parser("generate", help="record the fixed set of ten synthetic events")
    decoy_commands.add_parser("list", help="list synthetic events")
    decoy_commands.add_parser("reset", help="delete only synthetic decoy-event rows")
    remediation = commands.add_parser("remediation", help="fixed local OpenSSH fixture")
    remediation_commands = remediation.add_subparsers(dest="action", required=True)
    run = remediation_commands.add_parser("run", help="run one of the fixed local-only lifecycle scenarios")
    run.add_argument("--scenario", required=True, choices=REMEDIATION_SCENARIOS)
    remediation_commands.add_parser("list", help="list persisted local sandbox runs")
    return parser


def main(argv: list[str] | None = None) -> int:
    if os.environ.get("AHA_ENABLE_LOCAL_DEMO_CLI", "").strip() != "1":
        print("Local demo CLI is disabled; set AHA_ENABLE_LOCAL_DEMO_CLI=1 for an explicit local demonstration.", file=sys.stderr)
        return 2
    args = _parser().parse_args(argv)
    Base.metadata.create_all(bind=engine)
    with SessionLocal() as db:
        try:
            if args.domain == "decoy" and args.action == "generate":
                batch_id, count = generate_decoy_events(db)
                print(json.dumps({"mode": "SIMULATED", "batch_id": batch_id, "created": count, "listener": "none", "executor_connected": False}))
            elif args.domain == "decoy" and args.action == "list":
                print(json.dumps({"mode": "SIMULATED", "events": list_decoy_events(db)}))
            elif args.domain == "decoy" and args.action == "reset":
                print(json.dumps({"mode": "SIMULATED", "deleted": reset_decoy_events(db), "scope": "demo_decoy_events only"}))
            elif args.domain == "remediation" and args.action == "run":
                print(json.dumps(run_remediation_scenario(db, args.scenario), ensure_ascii=False, separators=(",", ":")))
            elif args.domain == "remediation" and args.action == "list":
                print(json.dumps({"classification": "LOCAL_SANDBOX_ONLY", "runs": list_remediation_runs(db)}))
        except Exception as exc:  # CLI error text is intentionally short and contains no token material.
            db.rollback()
            print(f"demo command failed: {type(exc).__name__}: {exc}", file=sys.stderr)
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
