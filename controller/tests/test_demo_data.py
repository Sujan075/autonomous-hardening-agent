from datetime import datetime, timezone
import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from app.audit.service import verify_chain
from app.db.models import Base, DemoDecoyEvent, SandboxRemediationRun, Target
from app.demo import (
    SAMPLE_EVENTS,
    generate_decoy_events,
    list_decoy_events,
    list_remediation_runs,
    reset_decoy_events,
    run_remediation_scenario,
)


class DemoDataTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.engine = create_engine(f"sqlite:///{Path(self.temp.name) / 'demo.sqlite'}")
        Base.metadata.create_all(self.engine)
        self.Session = sessionmaker(bind=self.engine, expire_on_commit=False)

    def tearDown(self):
        self.engine.dispose()
        self.temp.cleanup()

    def test_decoy_batch_is_deterministic_simulated_and_retrievable(self):
        with self.Session() as db:
            batch_id, count = generate_decoy_events(db, occurred_at=datetime(2026, 10, 24, tzinfo=timezone.utc))
            events = list_decoy_events(db, limit=100)
            self.assertEqual(count, 10)
            self.assertEqual(len(events), 10)
            self.assertTrue(all(event["batch_id"] == batch_id for event in events))
            self.assertTrue(all(event["simulation_mode"] == "SIMULATED" for event in events))
            self.assertTrue(all(event["source_classification"] == "RFC5737_DOCUMENTATION_RANGE_SIMULATED" for event in events))
            self.assertEqual(len({event["correlation_id"] for event in events}), 10)
            self.assertEqual(len({event["category"] for event in events}), 5)
            self.assertTrue(verify_chain(db).valid)

    def test_ten_decoy_event_scenarios_are_simulated_and_cannot_invoke_executor(self):
        expected = [category for category, _address in SAMPLE_EVENTS]
        with self.Session() as db, patch("app.demo.subprocess.run") as process:
            _batch_id, count = generate_decoy_events(db)
            self.assertEqual(count, 10)
            process.assert_not_called()
            events = list_decoy_events(db, limit=100)
            for index, category in enumerate(expected):
                with self.subTest(scenario=index + 1, category=category):
                    event = events[9 - index]
                    self.assertEqual(event["category"], category)
                    self.assertEqual(event["simulation_mode"], "SIMULATED")
                    self.assertEqual(event["outcome"], "simulated_event_recorded")

    def test_reset_deletes_only_demo_events_and_keeps_project_records_and_audit(self):
        with self.Session() as db:
            db.add(Target(name="existing-target", platform="ubuntu"))
            db.add(SandboxRemediationRun(run_id="run-one", target_id="sandbox-local-one", platform="ubuntu-sandbox-fixture", scenario="roundtrip", status="ROLLED_BACK", result_json="{}"))
            db.commit()
            generate_decoy_events(db)
            self.assertEqual(reset_decoy_events(db), 10)
            self.assertEqual(db.scalars(select(DemoDecoyEvent)).all(), [])
            self.assertEqual(len(db.scalars(select(Target)).all()), 1)
            self.assertEqual(len(db.scalars(select(SandboxRemediationRun)).all()), 1)
            self.assertTrue(verify_chain(db).valid)

    def test_fixed_remediation_scenario_persists_sanitized_result_and_audit(self):
        result = {
            "schema": "aha-remediation-sandbox-run/v1", "run_id": "run-two", "target_id": "sandbox-local-two",
            "platform": "ubuntu-sandbox-fixture", "scenario": "roundtrip", "status": "ROLLED_BACK",
            "sandbox_only": True, "test_only_trust": True, "live_target_modified": False,
            "execution": {"state_path": "/private/tmp/removed/state.json"}, "lifecycle": [],
        }
        process = type("Process", (), {"stdout": json.dumps(result), "stderr": "", "returncode": 0})()
        with self.Session() as db, patch("app.demo.subprocess.run", return_value=process) as run:
            saved = run_remediation_scenario(db, "roundtrip")
            self.assertEqual(saved["execution"]["state_path"], "")
            self.assertTrue(run.call_args.args[0][:3] == ["go", "run", "./cmd/sandbox-demo"])
            self.assertEqual(run.call_args.kwargs["shell"] if "shell" in run.call_args.kwargs else False, False)
            self.assertEqual(len(list_remediation_runs(db)), 1)
            self.assertTrue(verify_chain(db).valid)

    def test_remediation_cli_scenario_allowlist_is_closed(self):
        with self.Session() as db, patch("app.demo.subprocess.run") as run:
            with self.assertRaises(ValueError):
                run_remediation_scenario(db, "arbitrary-command")
            run.assert_not_called()

    @unittest.skipUnless(shutil.which("go") and Path("/usr/sbin/sshd").exists(), "Go and OpenSSH are required for the composed demo")
    def test_python_controller_persists_actual_go_execute_verify_and_rollback_run(self):
        with self.Session() as db, patch.dict(os.environ, {"GOCACHE": str(Path(self.temp.name) / "go-cache")}):
            result = run_remediation_scenario(db, "roundtrip")
            self.assertEqual(result["status"], "ROLLED_BACK")
            self.assertTrue(result["sandbox_only"])
            self.assertFalse(result["live_target_modified"])
            self.assertEqual(result["verification"]["status"], "VERIFIED")
            self.assertEqual(result["recovery"]["status"], "ROLLED_BACK")
            self.assertEqual(result["execution"]["state_path"], "")
            self.assertEqual(len(list_remediation_runs(db)), 1)
            self.assertTrue(verify_chain(db).valid)


if __name__ == "__main__":
    unittest.main()
