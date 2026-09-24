import csv
import ipaddress
import argparse
from collections import Counter, defaultdict, deque
from datetime import datetime, timedelta
from pathlib import Path


REQUIRED_COLUMNS = {
    "timestamp",
    "username",
    "source_ip",
    "status",
}


def read_logs(file_path):
    """Read and validate login records."""
    valid_logs = []
    skipped_rows = 0

    with file_path.open(
        mode="r",
        encoding="utf-8-sig",
        newline=""
    ) as file:
        reader = csv.DictReader(file)

        columns = set(reader.fieldnames or [])
        missing_columns = REQUIRED_COLUMNS - columns

        if missing_columns:
            missing = ", ".join(sorted(missing_columns))
            raise ValueError(f"Missing required columns: {missing}")

        for line_number, row in enumerate(reader, start=2):
            try:
                timestamp_text = (row["timestamp"] or "").strip()
                username = (row["username"] or "").strip()
                source_ip = (row["source_ip"] or "").strip()
                status = (row["status"] or "").strip().lower()

                # Our input format requires UTC timestamps ending in Z.
                timestamp = datetime.strptime(
                    timestamp_text,
                    "%Y-%m-%dT%H:%M:%SZ"
                )

                if not username:
                    raise ValueError("Username is empty")

                # Validate and normalize the IP address.
                source_ip = str(ipaddress.ip_address(source_ip))

                if status not in {"success", "failed"}:
                    raise ValueError(
                        "Status must be 'success' or 'failed'"
                    )

                valid_logs.append({
                    "timestamp": timestamp,
                    "username": username,
                    "source_ip": source_ip,
                    "status": status,
                })

            except ValueError as error:
                skipped_rows += 1
                print(f"Skipping CSV line {line_number}: {error}")

    # Detection requires events in chronological order.
    valid_logs.sort(key=lambda log: log["timestamp"])

    return valid_logs, skipped_rows


def display_summary(logs, skipped_rows):
    """Print counts for valid login records."""
    status_counts = Counter(log["status"] for log in logs)

    unique_users = {log["username"] for log in logs}
    unique_ips = {log["source_ip"] for log in logs}

    failed_by_ip = Counter(
        log["source_ip"]
        for log in logs
        if log["status"] == "failed"
    )

    print("\nLOGIN ACTIVITY SUMMARY")
    print(f"Valid events: {len(logs)}")
    print(f"Skipped rows: {skipped_rows}")
    print(f"Successful logins: {status_counts['success']}")
    print(f"Failed logins: {status_counts['failed']}")
    print(f"Unique usernames: {len(unique_users)}")
    print(f"Unique source IPs: {len(unique_ips)}")

    print("\nFAILED LOGINS BY IP")

    if not failed_by_ip:
        print("No failed logins found.")

    for ip, count in failed_by_ip.most_common():
        print(f"{ip}: {count}")


def detect_repeated_failures(logs, threshold=5, window_minutes=5):
    """Alert when an IP's failure count crosses the threshold."""
    failures_by_ip = defaultdict(deque)
    alerts = []

    window = timedelta(minutes=window_minutes)

    for log in logs:
        if log["status"] != "failed":
            continue

        ip = log["source_ip"]
        current_time = log["timestamp"]
        recent_failures = failures_by_ip[ip]

        # Remove failures outside the current time window.
        while (
            recent_failures
            and current_time - recent_failures[0]["timestamp"] > window
        ):
            recent_failures.popleft()

        previous_count = len(recent_failures)
        recent_failures.append(log)

        # Alert on a threshold crossing, avoiding an alert for
        # every additional failure while the count stays high.
        if previous_count < threshold <= len(recent_failures):
            alerts.append({
                "source_ip": ip,
                "failure_count": len(recent_failures),
                "start_time": recent_failures[0]["timestamp"],
                "end_time": current_time,
                "usernames": sorted({
                    event["username"]
                    for event in recent_failures
                }),
            })

    return alerts


def display_alerts(alerts):
    """Print the evidence behind each detection."""
    print("\nSECURITY ALERTS")

    if not alerts:
        print("No repeated-failure alerts detected.")
        return

    for number, alert in enumerate(alerts, start=1):
        print(f"\nAlert {number}: Repeated login failures")
        print(f"Source IP: {alert['source_ip']}")
        print(f"Failures at detection: {alert['failure_count']}")
        print(f"Accounts: {', '.join(alert['usernames'])}")
        print(f"Window start (UTC): {alert['start_time']}")
        print(f"Detected at (UTC): {alert['end_time']}")
        print("Assessment: Possible password guessing; investigate.")

def detect_success_after_failures(
    logs,
    threshold=5,
    failure_window_minutes=5,
    success_window_minutes=10,
):
    """Find successes following repeated failures for an account/IP pair."""
    failures_by_pair = defaultdict(deque)
    pending_patterns = {}
    alerts = []

    failure_window = timedelta(minutes=failure_window_minutes)
    success_window = timedelta(minutes=success_window_minutes)

    for log in logs:
        # Both the username AND IP must match.
        key = (log["username"], log["source_ip"])
        current_time = log["timestamp"]
        recent_failures = failures_by_pair[key]

        if log["status"] == "failed":
            # Keep only failures within the five-minute window.
            while (
                recent_failures
                and current_time - recent_failures[0]["timestamp"]
                > failure_window
            ):
                recent_failures.popleft()

            recent_failures.append(log)

            if len(recent_failures) >= threshold:
                # Save the latest qualifying group of failures.
                pending_patterns[key] = {
                    "first_failure": recent_failures[0]["timestamp"],
                    "last_failure": current_time,
                    "failure_count": len(recent_failures),
                }

        elif log["status"] == "success":
            # Consume this pattern so later successes do not
            # repeatedly alert on the same failed attempts.
            pattern = pending_patterns.pop(key, None)

            if pattern is not None:
                elapsed = current_time - pattern["last_failure"]

                if timedelta(0) <= elapsed <= success_window:
                    alerts.append({
                        "username": log["username"],
                        "source_ip": log["source_ip"],
                        "failure_count": pattern["failure_count"],
                        "first_failure": pattern["first_failure"],
                        "last_failure": pattern["last_failure"],
                        "success_time": current_time,
                    })

            # A success ends the failure sequence for this pair.
            recent_failures.clear()

    return alerts

def display_success_alerts(alerts):
    """Display successful logins that need further investigation."""
    print("\nSUCCESS AFTER REPEATED FAILURES")

    if not alerts:
        print("No matching successful logins detected.")
        return

    for number, alert in enumerate(alerts, start=1):
        print(f"\nAlert {number}: Success after repeated failures")
        print(f"Account: {alert['username']}")
        print(f"Source IP: {alert['source_ip']}")
        print(f"Failures in qualifying window: {alert['failure_count']}")
        print(f"First failure (UTC): {alert['first_failure']}")
        print(f"Last failure (UTC): {alert['last_failure']}")
        print(f"Successful login (UTC): {alert['success_time']}")
        print(
            "Assessment: Investigate whether this login "
            "was made by the legitimate user."
        )

def export_alerts(failure_alerts, success_alerts, output_path):
    """Export both alert types using a consistent CSV structure."""
    output_path.parent.mkdir(parents=True, exist_ok=True)

    columns = [
        "alert_id",
        "rule",
        "source_ip",
        "accounts",
        "failure_count",
        "first_failure_utc",
        "last_failure_utc",
        "success_time_utc",
        "assessment",
    ]

    def format_time(value):
        return value.strftime("%Y-%m-%dT%H:%M:%SZ")

    rows = []

    for alert in failure_alerts:
        rows.append({
            "rule": "repeated_login_failures",
            "source_ip": alert["source_ip"],
            "accounts": "; ".join(alert["usernames"]),
            "failure_count": alert["failure_count"],
            "first_failure_utc": format_time(alert["start_time"]),
            "last_failure_utc": format_time(alert["end_time"]),
            "success_time_utc": "",
            "assessment": "Possible password guessing; investigate.",
        })

    for alert in success_alerts:
        rows.append({
            "rule": "success_after_repeated_failures",
            "source_ip": alert["source_ip"],
            "accounts": alert["username"],
            "failure_count": alert["failure_count"],
            "first_failure_utc": format_time(alert["first_failure"]),
            "last_failure_utc": format_time(alert["last_failure"]),
            "success_time_utc": format_time(alert["success_time"]),
            "assessment": "Verify whether the login was legitimate.",
        })

    # Place alerts in detection-time order.
    rows.sort(
        key=lambda row: (
            row["success_time_utc"] or row["last_failure_utc"]
        )
    )

    with output_path.open(
        mode="w",
        encoding="utf-8",
        newline=""
    ) as file:
        writer = csv.DictWriter(file, fieldnames=columns)
        writer.writeheader()

        for number, row in enumerate(rows, start=1):
            row["alert_id"] = f"ALERT-{number:03d}"
            writer.writerow(row)

    return len(rows)

def main():
    project_folder = Path(__file__).resolve().parent

    parser = argparse.ArgumentParser(
        description=(
            "Analyze login CSV records for repeated failures "
            "and successful logins after repeated failures."
        )
    )

    parser.add_argument(
        "--input",
        type=Path,
        default=project_folder / "data" / "sample_logins.csv",
        help="Path to the login CSV file.",
    )

    parser.add_argument(
        "--output",
        type=Path,
        default=project_folder / "reports" / "alerts.csv",
        help="Path for the exported alert CSV; overwrites this file.",
    )

    args = parser.parse_args()

    log_file = args.input.resolve()
    report_file = args.output.resolve()

    # Prevent accidentally replacing the source data with a report.
    if log_file == report_file:
        parser.error("--input and --output must be different files.")

    try:
        logs, skipped_rows = read_logs(log_file)
    except (OSError, ValueError) as error:
        print(f"Could not load logs: {error}")
        return

    display_summary(logs, skipped_rows)

    # An empty or entirely invalid dataset cannot support analysis.
    if not logs:
        print("\nNo valid events to analyze. No report was written.")
        print("Any existing report remains from an earlier run.")
        return

    failure_alerts = detect_repeated_failures(logs)
    display_alerts(failure_alerts)

    success_alerts = detect_success_after_failures(logs)
    display_success_alerts(success_alerts)

    try:
        count = export_alerts(
            failure_alerts,
            success_alerts,
            report_file,
        )
    except OSError as error:
        print(f"\nCould not save the report: {error}")
        return

    print(f"\nExported {count} alerts to: {report_file}")

    if skipped_rows:
        print(
            "Analysis is incomplete: some input rows were skipped. "
            "Review the validation messages above."
        )


if __name__ == "__main__":
    main()