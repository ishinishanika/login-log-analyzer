import csv
import io
from collections import Counter
from pathlib import Path
from tempfile import TemporaryDirectory

import streamlit as st

from analyzer import (
    read_logs,
    detect_repeated_failures,
    detect_success_after_failures,
    export_alerts,
)


PROJECT_FOLDER = Path(__file__).resolve().parent
MAX_UPLOAD_BYTES = 5 * 1024 * 1024


st.set_page_config(
    page_title="Login Log Analyzer",
    page_icon="🛡️",
    layout="wide",
)

st.title("🛡️ Login Log Analyzer")
st.caption(
    "Review authentication activity, investigate suspicious "
    "patterns, and export the supporting evidence."
)

with st.sidebar:
    st.header("Data source")

    source = st.radio(
        "Choose records to analyze",
        ["Sample dataset", "Upload CSV"],
    )

    st.divider()
    st.subheader("Detection rules")
    st.write("**Repeated failures**")
    st.caption("At least 5 failures from one IP within 5 minutes.")

    st.write("**Success after failures**")
    st.caption(
        "A matching account and IP succeed within 10 minutes "
        "of the latest qualifying failure pattern."
    )

    st.divider()
    st.caption(
        "This version analyzes uploaded files in batches. "
        "It does not monitor live logins."
    )


if source == "Upload CSV":
    uploaded_file = st.file_uploader(
        "Upload login records",
        type=["csv"],
        help=(
            "Required columns: timestamp, username, source_ip, status. "
            "This dashboard accepts files up to 5 MiB."
        ),
    )

    if uploaded_file is None:
        st.info("Upload a CSV to begin, or select the sample dataset.")
        st.stop()

    if uploaded_file.size > MAX_UPLOAD_BYTES:
        st.error("Please choose a CSV file smaller than 5 MiB.")
        st.stop()

    input_bytes = uploaded_file.getvalue()
    source_label = uploaded_file.name

else:
    sample_path = PROJECT_FOLDER / "data" / "sample_logins.csv"

    try:
        input_bytes = sample_path.read_bytes()
    except OSError as error:
        st.error(f"Could not open the sample dataset: {error}")
        st.stop()

    source_label = "sample_logins.csv"


# Existing analyzer functions accept paths.
# A temporary folder lets us reuse them without overwriting
# the project's input files or saved reports.
try:
    with TemporaryDirectory(prefix="login_analyzer_") as temp_folder:
        temp_path = Path(temp_folder)
        input_path = temp_path / "input.csv"
        report_path = temp_path / "alerts.csv"

        input_path.write_bytes(input_bytes)
        logs, skipped_rows = read_logs(input_path)

        if not logs:
            st.error("No valid login records were found.")
            st.caption(
                "Check the required columns and UTC timestamp format: "
                "2026-09-24T10:00:00Z"
            )
            st.stop()

        failure_alerts = detect_repeated_failures(logs)
        success_alerts = detect_success_after_failures(logs)

        export_alerts(
            failure_alerts,
            success_alerts,
            report_path,
        )

        # Read the report before the temporary folder is removed.
        report_bytes = report_path.read_bytes()

except (OSError, ValueError, csv.Error) as error:
    st.error(f"Could not analyze this file: {error}")
    st.stop()


st.caption(f"Analyzing: {source_label} · All displayed times are UTC")

if skipped_rows:
    st.warning(
        f"{skipped_rows} row(s) were skipped because of invalid data. "
        "Results cover only valid records. Detailed validation messages "
        "appear in the terminal running this app."
    )

status_counts = Counter(log["status"] for log in logs)

cards = st.columns(4)
cards[0].metric("Valid events", len(logs))
cards[1].metric("Successful logins", status_counts["success"])
cards[2].metric("Failed logins", status_counts["failed"])
cards[3].metric(
    "Detection alerts",
    len(failure_alerts) + len(success_alerts),
)

st.caption(
    "Related alerts may describe the same activity. "
    "The alert count is not an incident count."
)

overview_tab, alerts_tab, records_tab = st.tabs(
    ["Activity overview", "Detection alerts", "Valid records"]
)

with overview_tab:
    left, right = st.columns(2)

    left.metric(
        "Unique usernames",
        len({log["username"] for log in logs}),
    )
    right.metric(
        "Unique source IPs",
        len({log["source_ip"] for log in logs}),
    )

    st.subheader("Failed logins by source IP")

    failures_by_ip = Counter(
        log["source_ip"]
        for log in logs
        if log["status"] == "failed"
    )

    if failures_by_ip:
        rows = [
            {"Source IP": ip, "Failed logins": count}
            for ip, count in failures_by_ip.most_common()
        ]
        st.dataframe(rows, hide_index=True)
    else:
        st.info("No failed logins were found in the valid records.")

with alerts_tab:
    report_rows = list(
        csv.DictReader(io.StringIO(report_bytes.decode("utf-8")))
    )

    if report_rows:
        st.warning(
            "Patterns requiring investigation were detected. "
            "These alerts do not establish that an attack occurred."
        )

        st.subheader("Repeated login failures")
        failure_rows = [
            row for row in report_rows
            if row["rule"] == "repeated_login_failures"
        ]

        if failure_rows:
            st.dataframe(failure_rows, hide_index=True)
        else:
            st.info("No repeated-failure alerts.")

        st.subheader("Success after repeated failures")
        success_rows = [
            row for row in report_rows
            if row["rule"] == "success_after_repeated_failures"
        ]

        if success_rows:
            st.dataframe(success_rows, hide_index=True)
        else:
            st.info("No success-after-failures alerts.")

    else:
        st.info(
            "Neither detection rule matched the valid records. "
            "This does not establish that all activity was legitimate."
        )

    st.download_button(
        label="Download alert report",
        data=report_bytes,
        file_name="login_alerts.csv",
        mime="text/csv",
    )

with records_tab:
    st.caption("Validated records, sorted from earliest to latest.")

    display_logs = [
        {
            "Time (UTC)": log["timestamp"].strftime(
                "%Y-%m-%d %H:%M:%S"
            ),
            "Username": log["username"],
            "Source IP": log["source_ip"],
            "Status": log["status"],
        }
        for log in logs
    ]

    st.dataframe(display_logs, hide_index=True)