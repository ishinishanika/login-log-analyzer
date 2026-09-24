import unittest
from datetime import datetime, timedelta

from analyzer import (
    detect_repeated_failures,
    detect_success_after_failures,
)


BASE_TIME = datetime(2026, 9, 24, 10, 0, 0)


def event(seconds, status="failed", username="admin",
          source_ip="198.51.100.20"):
    """Create one synthetic login event."""
    return {
        "timestamp": BASE_TIME + timedelta(seconds=seconds),
        "username": username,
        "source_ip": source_ip,
        "status": status,
    }


class TestLoginDetection(unittest.TestCase):

    def test_four_failures_do_not_alert(self):
        logs = [event(second) for second in [0, 30, 60, 90]]

        alerts = detect_repeated_failures(logs)

        self.assertEqual(len(alerts), 0)

    def test_five_failures_within_window_alert(self):
        logs = [
            event(second)
            for second in [0, 30, 60, 90, 120]
        ]

        alerts = detect_repeated_failures(logs)

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["source_ip"], "198.51.100.20")
        self.assertEqual(alerts[0]["failure_count"], 5)

    def test_exact_five_minute_boundary_is_included(self):
        logs = [
            event(second)
            for second in [0, 60, 120, 180, 300]
        ]

        alerts = detect_repeated_failures(logs)

        self.assertEqual(len(alerts), 1)

    def test_failure_outside_window_is_excluded(self):
        logs = [
            event(second)
            for second in [0, 60, 120, 180, 301]
        ]

        alerts = detect_repeated_failures(logs)

        self.assertEqual(len(alerts), 0)

    def test_different_ips_are_counted_separately(self):
        logs = [
            event(0),
            event(30),
            event(60),
            event(90, source_ip="203.0.113.40"),
            event(120, source_ip="203.0.113.40"),
        ]

        alerts = detect_repeated_failures(logs)

        self.assertEqual(len(alerts), 0)

    def test_matching_success_alerts(self):
        logs = [
            event(second)
            for second in [0, 30, 60, 90, 120]
        ]
        logs.append(event(180, status="success"))

        alerts = detect_success_after_failures(logs)

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["username"], "admin")
        self.assertEqual(
            alerts[0]["success_time"],
            BASE_TIME + timedelta(seconds=180),
        )

    def test_unrelated_success_does_not_alert(self):
        for changed_field in [
            {"username": "alice"},
            {"source_ip": "203.0.113.40"},
        ]:
            with self.subTest(changed_field=changed_field):
                logs = [
                    event(second)
                    for second in [0, 30, 60, 90, 120]
                ]
                logs.append(
                    event(180, status="success", **changed_field)
                )

                alerts = detect_success_after_failures(logs)

                self.assertEqual(len(alerts), 0)

    def test_success_window_boundary(self):
        # The last qualifying failure is at second 120.
        for success_second, expected_count in [
            (720, 1),   # Exactly 10 minutes later: alert.
            (721, 0),   # 10 minutes and 1 second: no alert.
        ]:
            with self.subTest(success_second=success_second):
                logs = [
                    event(second)
                    for second in [0, 30, 60, 90, 120]
                ]
                logs.append(
                    event(success_second, status="success")
                )

                alerts = detect_success_after_failures(logs)

                self.assertEqual(len(alerts), expected_count)

    def test_second_success_does_not_repeat_alert(self):
        logs = [
            event(second)
            for second in [0, 30, 60, 90, 120]
        ]
        logs.extend([
            event(180, status="success"),
            event(240, status="success"),
        ])

        alerts = detect_success_after_failures(logs)

        self.assertEqual(len(alerts), 1)

    def test_failures_across_accounts_do_not_combine_for_success(self):
        logs = [
            event(0, username="admin"),
            event(30, username="alice"),
            event(60, username="admin"),
            event(90, username="alice"),
            event(120, username="admin"),
            event(180, status="success", username="admin"),
        ]

        # Five failures share an IP, so the IP rule alerts.
        self.assertEqual(
            len(detect_repeated_failures(logs)), 1
        )

        # Neither account has five failures, so correlation
        # with the successful login should not alert.
        self.assertEqual(
            len(detect_success_after_failures(logs)), 0
        )


if __name__ == "__main__":
    unittest.main()