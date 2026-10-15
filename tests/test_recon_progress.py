import os
import sys
import threading
import unittest
from unittest.mock import patch

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "lib"))

import recon
import autopilot
from db import DB


class _Rows:
    def __init__(self, hosts):
        self.hosts = hosts

    def execute(self, query, params):
        return [{"host": host} for host in self.hosts]


class _FakeDB:
    def __init__(self, hosts):
        self.conn = _Rows(hosts)
        self.unreachable = []
        self.metadata = []
        self.seeded = []

    def upsert_host(self, program, host, source):
        self.seeded.append((program, host, source))

    def mark_host_unreachable(self, program, host):
        self.unreachable.append((program, host))

    def set_host_meta(self, *args, **kwargs):
        self.metadata.append((args, kwargs))


class _FakePipelineDB:
    def __init__(self, programs):
        self._programs = programs
        self.touched = []

    def programs(self):
        return self._programs

    def touch_program(self, name, field):
        self.touched.append(name)

    def log_run(self, *args, **kwargs):
        pass


class ReconProgressTests(unittest.TestCase):
    def test_passive_enumeration_has_a_per_apex_time_limit(self):
        db = _FakeDB([])
        program = {
            "name": "Example",
            "scope": '["*.example.com", "*.example.net"]',
            "exclusions": "[]",
        }
        calls = []

        def fake_run(cmd, timeout):
            calls.append((cmd, timeout))
            return "www.example.com\n", 0

        with patch.object(recon, "tool", return_value="subfinder"), \
                patch.object(recon, "run", side_effect=fake_run):
            count = recon.enumerate_subdomains(
                db, program,
                {"recon": {
                    "subfinder_args": ["-silent", "-all"],
                    "subfinder_max_time_minutes": 2,
                }},
            )

        self.assertEqual(count, 2)
        self.assertEqual(len(calls), 2)
        for cmd, timeout in calls:
            self.assertIn("-max-time", cmd)
            self.assertEqual(cmd[cmd.index("-max-time") + 1], "2")
            self.assertEqual(timeout, 150)

    def test_empty_dns_result_is_skipped_and_incomplete_probe_is_retryable(self):
        db = _FakeDB(["a.example.com", "b.example.com", "c.example.com"])
        program = {
            "name": "Example",
            "scope": '["*.example.com"]',
            "exclusions": "[]",
        }
        cfg = {
            "recon": {
                "probe_chunk": 1,
                "httpx_rps": 40,
                "httpx_threads": 1,
                "httpx_args": [],
                "dnsx_args": [],
            }
        }
        probe_calls = []

        def fake_probe(tool, config, hosts, timeout):
            probe_calls.append(hosts)
            return [], len(probe_calls) == 2

        with patch.object(recon, "tool", return_value="httpx"), \
                patch.object(recon, "_resolve_chunk",
                             side_effect=[set(), None, {"c.example.com"}]), \
                patch.object(recon, "_probe_chunk", side_effect=fake_probe):
            recon.resolve_and_probe(db, program, cfg, 3)

        self.assertEqual(probe_calls, [["b.example.com"], ["c.example.com"]])
        self.assertEqual(
            db.unreachable,
            [("Example", "a.example.com"), ("Example", "c.example.com")],
        )

    def test_unreachable_hosts_are_not_live_and_are_retried_when_rediscovered(self):
        db = DB(os.path.join(self._temp_dir.name, "state.db"))
        db.upsert_program({
            "name": "Example",
            "platform": "test",
            "policy": "test",
            "scope": ["example.com"],
        })
        db.upsert_host("Example", "dead.example.com", "test")
        db.mark_host_unreachable("Example", "dead.example.com")
        db.upsert_host("Example", "live.example.com", "test")
        db.set_host_meta("Example", "live.example.com", 200, "", "", "", False)

        self.assertEqual(
            [host["host"] for host in db.live_hosts("Example")],
            ["live.example.com"],
        )
        db.upsert_host("Example", "dead.example.com", "test")
        status = db.conn.execute(
            "SELECT status FROM hosts WHERE host='dead.example.com'"
        ).fetchone()["status"]
        self.assertIsNone(status)
        db.conn.close()

    def test_state_round_trip_preserves_exact_live_url(self):
        source = DB(os.path.join(self._temp_dir.name, "source.db"))
        program = {
            "name": "Example",
            "platform": "test",
            "policy": "test",
            "scope": ["example.com"],
        }
        source.upsert_program(program)
        source.upsert_host("Example", "live.example.com", "test")
        source.set_host_meta(
            "Example", "live.example.com", 200, "", "", "", False,
            url="https://live.example.com:8443")
        state_path = os.path.join(self._temp_dir.name, "state.json")
        source.export_state(state_path)

        restored = DB(os.path.join(self._temp_dir.name, "restored.db"))
        restored.upsert_program(program)
        restored.import_state(state_path)
        url = restored.conn.execute(
            "SELECT url FROM hosts WHERE host='live.example.com'"
        ).fetchone()["url"]

        self.assertEqual(url, "https://live.example.com:8443")
        source.conn.close()
        restored.conn.close()

    def test_recon_selects_only_the_oldest_due_program_per_cycle(self):
        runner = autopilot.AutoBounty.__new__(autopilot.AutoBounty)
        runner.cfg = {
            "recon": {
                "recon_every_hours": 12,
                "programs_per_cycle": 1,
                "max_hosts_per_program": 10,
            }
        }
        runner.paused = threading.Event()
        runner.db = _FakePipelineDB([
            {"name": "New", "last_recon_at": 9999999999},
            {"name": "Old", "last_recon_at": 1},
        ])
        with patch.object(autopilot.recon, "seed_hosts", return_value=0), \
                patch.object(autopilot.recon, "enumerate_subdomains", return_value=0), \
                patch.object(autopilot.recon, "resolve_and_probe", return_value=2) as probe, \
                patch.object(autopilot.time, "sleep"):
            self.assertEqual(runner.phase_recon(), 2)

        self.assertEqual(probe.call_args.args[1]["name"], "Old")
        self.assertEqual(runner.db.touched, ["Old"])

    def setUp(self):
        import tempfile
        self._temp_dir = tempfile.TemporaryDirectory()

    def tearDown(self):
        self._temp_dir.cleanup()


if __name__ == "__main__":
    unittest.main()
