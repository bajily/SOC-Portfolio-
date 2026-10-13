import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from soc_triage import analyze, read_events


def event(seconds, kind="login_failure", user="analyst", ip="192.0.2.10"):
    return {"timestamp": datetime(2026, 1, 15, tzinfo=timezone.utc) + timedelta(seconds=seconds),
            "source_ip": ip, "event": kind, "user": user}


class TriageTests(unittest.TestCase):
    def test_threshold_and_success(self):
        result = analyze([event(i * 20) for i in range(5)] + [event(110, "login_success")])
        self.assertEqual([x["severity"] for x in result["findings"]], ["medium", "high"])

    def test_below_threshold(self):
        self.assertEqual(analyze([event(i) for i in range(4)])["findings"], [])

    def test_expired_failures(self):
        self.assertEqual(analyze([event(i * 301) for i in range(5)])["findings"], [])

    def test_window_boundary_is_inclusive(self):
        self.assertEqual(len(analyze([event(0), event(300)], 2)["findings"]), 1)

    def test_no_duplicate_alert_in_same_burst(self):
        self.assertEqual(len(analyze([event(i) for i in range(10)])["findings"]), 1)

    def test_success_is_user_scoped(self):
        rows = [event(i) for i in range(5)] + [event(6, "login_success", "other")]
        self.assertEqual(len(analyze(rows)["findings"]), 1)

    def test_source_ips_are_separate(self):
        rows = [event(i, ip=f"192.0.2.{i}") for i in range(5)]
        self.assertEqual(analyze(rows)["findings"], [])

    def test_unsorted_input(self):
        rows = [event(i) for i in range(5)] + [event(6, "login_success")]
        self.assertEqual(analyze(rows), analyze(list(reversed(rows))))

    def test_success_resets_burst(self):
        rows = [event(i) for i in range(5)] + [event(6, "login_success"), event(7)]
        self.assertEqual(len(analyze(rows)["findings"]), 2)

    def test_invalid_parameters(self):
        for threshold, window in [(0, 300), (5, 0), (-1, 300)]:
            with self.assertRaises(ValueError):
                analyze([], threshold, window)

    def test_csv_rejects_bad_rows_and_normalizes_timezone(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "events.csv"
            path.write_text("timestamp,source_ip,event,user\n"
                            "2026-01-15T12:00:00+03:00,2001:db8::1,login_success,u\n"
                            "2026-01-15T12:00:00,192.0.2.1,login_failure,u\n"
                            "bad,not-an-ip,login_failure,u\n", encoding="utf-8")
            rows, rejected = read_events(path)
            self.assertEqual(rows[0]["timestamp"].hour, 9)
            self.assertEqual(len(rejected), 2)

    def test_csv_requires_schema(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "events.csv"
            path.write_text("x,y\n1,2\n", encoding="utf-8")
            with self.assertRaises(ValueError):
                read_events(path)


if __name__ == "__main__":
    unittest.main()
