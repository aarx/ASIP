import json
import pathlib
import sys
import unittest
from unittest import mock

BACKEND = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND))

import stage_progress  # noqa: E402
import scan_diagnostics  # noqa: E402


class _ProgressCursor:
    def __init__(self, document):
        self.document = document
        self.rowcount = 0
        self.params = None

    def execute(self, query, params=None):
        self.query = query
        self.params = params
        if query.lstrip().startswith("UPDATE scans"):
            self.rowcount = 1

    def fetchone(self):
        return self.document, None


class _ProgressConnection:
    def __init__(self, document):
        self.cursor_value = _ProgressCursor(document)
        self.commits = 0
        self.rollbacks = 0

    def cursor(self):
        return self.cursor_value

    def commit(self):
        self.commits += 1

    def rollback(self):
        self.rollbacks += 1


class StageProgressTests(unittest.TestCase):
    def test_initial_progress_and_unknown_total_have_no_fake_percentage_or_eta(self):
        initial = stage_progress.progress_payload(
            7, "Recon", selected=None, total=None, processed=0, elapsed_seconds=0,
        )
        self.assertIsNone(initial["throughput"])
        self.assertIsNone(initial["estimated_remaining_seconds"])
        unknown = stage_progress.progress_payload(
            7, "Recon", selected=None, total=None, processed=12, elapsed_seconds=30,
        )
        self.assertEqual(unknown["processed"], 12)
        self.assertIsNone(unknown["estimated_remaining_seconds"])

    def test_progress_rate_and_eta_use_processed_count(self):
        progress = stage_progress.progress_payload(
            7, "DNS Security", selected=100, total=100, processed=25,
            completed=25, elapsed_seconds=30,
        )
        self.assertEqual(progress["throughput"], 0.833)
        self.assertEqual(progress["estimated_remaining_seconds"], 90.0)

    def test_progress_is_emitted_as_a_single_standard_marker(self):
        with mock.patch("builtins.print") as output:
            stage_progress.emit_stage_progress(
                7, "DNS Security", selected=10, total=10, processed=0,
            )
        line = output.call_args.args[0]
        self.assertTrue(line.startswith("ASIP_STAGE_PROGRESS "))
        payload = json.loads(line.split(" ", 1)[1])
        self.assertEqual(payload["scan_id"], 7)
        self.assertEqual(payload["status"], "RUNNING")
        self.assertEqual(payload["selected"], 10)

    def test_persisted_progress_updates_only_the_current_runner_stage(self):
        document = scan_diagnostics.empty_diagnostics()
        document["attempts"].append({
            "stage": "DNS Security", "order": 7, "attempt": 1,
            "status": "RUNNING", "progress": None,
        })
        document["current_stage"] = {
            "stage": "DNS Security", "order": 7, "attempt": 1,
            "started_at": "start",
        }
        connection = _ProgressConnection(document)
        with mock.patch.object(
            scan_diagnostics, "datetime"
        ) as datetime_mock:
            datetime_mock.now.return_value.isoformat.return_value = "now"
            updated = scan_diagnostics.update_stage_progress(
                connection, 7, "runner", "DNS Security", 7, 1,
                {"selected": 10, "total": 10, "processed": 3,
                 "elapsed_seconds": 15, "status": "RUNNING"},
            )
        self.assertTrue(updated)
        self.assertEqual(connection.commits, 1)
        self.assertEqual(connection.cursor_value.params[0], json.dumps(document, separators=(",", ":")))
        self.assertEqual(document["current_stage"]["progress"]["processed"], 3)
        self.assertEqual(document["attempts"][0]["progress"]["selected"], 10)

    def test_mismatched_current_stage_is_not_overwritten(self):
        document = scan_diagnostics.empty_diagnostics()
        document["current_stage"] = {
            "stage": "DNS Resolution", "order": 6, "attempt": 1,
        }
        connection = _ProgressConnection(document)
        updated = scan_diagnostics.update_stage_progress(
            connection, 7, "runner", "DNS Security", 7, 1, {"processed": 4},
        )
        self.assertFalse(updated)
        self.assertEqual(connection.commits, 0)
        self.assertEqual(connection.rollbacks, 1)


if __name__ == "__main__":
    unittest.main()
