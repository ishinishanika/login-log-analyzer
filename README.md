# Login Log Analyzer

A Python cybersecurity learning project that analyzes login records, detects suspicious authentication patterns, and exports evidence for investigation. Includes a command-line interface and a local Streamlit dashboard.

**An alert is a reason to investigate, not proof that an attack occurred.**

## Live Demo

**[Open Nyxie Log Analyzer](https://nyxie-log-analyzer.streamlit.app/)**

Try the built-in sample dataset or upload a synthetic CSV to explore
login activity, review detection alerts, and download a report.

No local installation is required. Uploaded files are processed on
the hosting provider's server. Please use synthetic data only; do not
upload real authentication logs, credentials, or personal information.

## Features

- Validate timestamps, usernames, IP addresses, and login statuses.
- Exclude invalid rows and report how many were skipped.
- Sort valid events chronologically before analysis.
- Summarize successful and failed logins, unique accounts, and source IPs.
- Detect repeated login failures from a source IP.
- Correlate a successful login with repeated failures for the same account and IP.
- Export alerts to CSV.
- Explore sample data or uploaded CSV files through a browser dashboard.
- Run ten automated detection tests.

## Project Files

| File | Purpose |
| --- | --- |
| `analyzer.py` | CSV validation, detection logic, report export, and command-line entry point |
| `app.py` | Streamlit dashboard that reuses the analyzer functions |
| `test_analyzer.py` | Automated tests for detection behavior |
| `data/sample_logins.csv` | Synthetic example dataset |
| `reports/investigation_report.md` | Analysis of the sample activity |
| `requirements.txt` | Dashboard environment dependencies, once generated |
| `.gitignore` | Excludes the virtual environment, generated reports, and other local files |

Generated CSV reports are excluded from Git. The synthetic sample and investigation write-up are retained.

## Requirements

- Python 3; the development environment uses Python 3.12 on Windows.
- The command-line analyzer uses only Python's standard library.
- The optional dashboard requires Streamlit and its dependencies.

The commands below use Windows PowerShell and should be run from the project folder.

## Installation

If you already have this project locally, open its folder and skip cloning.

```powershell
git clone https://github.com/ishinishanika/login-log-analyzer.git
cd login-log-analyzer
```

Use a branch that contains `app.py` for the dashboard. While the UI upgrade is on the `feature/ui` branch, switch to it after that branch has been pushed:

```powershell
git switch feature/ui
```

Once the UI is merged into `main`, this branch switch is unnecessary.

Create a virtual environment:

```powershell
py -m venv .venv
```

If `requirements.txt` is available, install its recorded dependencies:

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

For the initial dashboard setup before that file exists, install Streamlit directly:

```powershell
.\.venv\Scripts\python.exe -m pip install streamlit
```

The commands use the virtual environment's Python directly; environment activation is not required.

## Run the Browser Dashboard

```powershell
.\.venv\Scripts\python.exe -m streamlit run app.py --server.address 127.0.0.1
```

Open [http://localhost:8501](http://localhost:8501), or use the local address printed in the terminal if a different port is selected.

1. Select **Sample dataset** or **Upload CSV** in the sidebar.
2. Review the summary cards.
3. Open **Activity overview** to inspect failures by IP.
4. Open **Detection alerts** to review evidence and download the report.
5. Open **Valid records** to inspect events in chronological order.

Keep the terminal running while using the dashboard. Press **Ctrl+C** to stop it.

The dashboard accepts individual CSV uploads up to 5 MiB. Files are analyzed when selected; no separate Analyze button is required. Uploaded data is processed using temporary files that are removed after processing. Report bytes remain available for download while the app runs. The UI does not overwrite the project's saved reports.

Invalid-row details are printed in the server terminal. The dashboard displays the skipped-row count and warns when analysis is incomplete.

This launch command binds the server to the local computer. Pushing the source to GitHub does not host the dashboard online.

## Run the Command-Line Analyzer

Analyze the default sample and write `reports/alerts.csv`:

```powershell
py analyzer.py
```

Choose the input and output paths:

```powershell
py analyzer.py --input data/sample_logins.csv --output reports/sample_alerts.csv
```

Display help:

```powershell
py analyzer.py --help
```

Quote paths containing spaces:

```powershell
py analyzer.py --input "D:\My Logs\logins.csv" --output "reports\my_alerts.csv"
```

User-supplied relative paths are resolved from the terminal's current directory. Default paths are resolved relative to `analyzer.py`.

## Input Format

The CSV must contain these column names:

```csv
timestamp,username,source_ip,status
2026-09-24T10:00:00Z,alice,192.0.2.10,success
2026-09-24T10:01:00Z,admin,198.51.100.20,failed
```

| Field | Expected value |
| --- | --- |
| `timestamp` | UTC timestamp in `YYYY-MM-DDTHH:MM:SSZ` format |
| `username` | Nonempty account name; matching is case-sensitive |
| `source_ip` | Valid IPv4 or IPv6 address |
| `status` | `success` or `failed`; letter case is normalized |

The reader accepts UTF-8, including files with a UTF-8 byte-order mark. Leading and trailing whitespace is removed from field values. Invalid records are skipped; missing required columns prevent analysis. Valid events are sorted by timestamp.

## Detection Rules

### 1. Repeated Login Failures

Alerts when a source IP reaches at least **five failures within five minutes**.

- Counts failures across all accounts sharing that IP.
- Includes events exactly five minutes apart.
- Removes older failures from a sliding time window.
- Alerts when the count crosses the threshold; additional failures do not generate another alert while the count remains at or above it.
- A successful login does not reset this IP-level rule.
- The reported count is the count at detection, not the final total for the activity.

### 2. Success After Repeated Failures

Tracks each **username and source IP pair** independently.

1. A qualifying pattern contains at least five failures within five minutes.
2. Further failures refresh the stored pattern when their current five-minute window still meets the threshold.
3. A success for that same pair triggers an alert if it occurs within ten minutes of the latest qualifying pattern's last failure, including the exact boundary.
4. A success clears that pair's failure history and consumes its stored pattern, preventing later successes from repeatedly alerting on it.

Failures against different accounts do not combine for this second rule. These thresholds are fixed in the current interface and are learning defaults, not universal security standards.

## Expected Sample Results

| Metric | Expected result |
| --- | ---: |
| Valid events | 10 |
| Skipped rows | 0 |
| Successful logins | 4 |
| Failed logins | 6 |
| Unique usernames | 3 |
| Unique source IPs | 3 |
| Detection alerts | 2 |

The sample contains five failed attempts against `admin` from `198.51.100.20` between 10:01 and 10:03 UTC, followed by a successful login at 10:04 UTC.

Both rules match this sequence. The two alerts describe related activity and should not automatically be counted as two separate incidents. See [the sample investigation report](reports/investigation_report.md) for interpretation and follow-up questions.

## CSV Report

The report contains:

| Column | Meaning |
| --- | --- |
| `alert_id` | Sequential identifier within this report |
| `rule` | Name of the triggered rule |
| `source_ip` | Source address associated with the alert |
| `accounts` | Account or accounts involved |
| `failure_count` | Failures in the qualifying window |
| `first_failure_utc` | First failure in that window |
| `last_failure_utc` | Last failure in that window |
| `success_time_utc` | Correlated success time, if applicable |
| `assessment` | Short investigation prompt |

Alert IDs are local to each report, not permanent incident identifiers.

Command-line runs overwrite the selected output report. Valid records with no matches produce a header-only report. If there are zero valid records, no report is written and an older report may remain on disk. The dashboard stops analysis when there are no valid records.

## Tests

```powershell
.\.venv\Scripts\python.exe -m unittest -v test_analyzer
```

For the standard-library-only command-line setup, `py -m unittest -v test_analyzer` also works.

The ten detection tests cover:

- Four failures producing no alert.
- Five failures within the window producing an alert.
- Inclusion of the exact five-minute boundary.
- Exclusion of failures outside the window.
- Separate counts for different source IPs.
- A matching successful login producing an alert.
- Unrelated account or IP successes producing no correlation alert.
- The exact ten-minute success boundary and just beyond it.
- Suppression of repeated alerts for later successes.
- Separation of accounts when correlating success with failures.

The detection suite has passed all ten tests in the development environment. These tests do not cover CSV parsing, command-line error handling, CSV export, or the dashboard itself.

### Manual Dashboard Checks

- Confirm the sample metrics match the table above.
- Upload `data/sample_logins.csv` and verify the same results.
- Check that the valid-records tab contains ten records.
- Download the report and confirm it contains a header and two alert rows.

## Record Dependencies

After installing and verifying the dashboard, record the virtual environment's installed versions:

```powershell
.\.venv\Scripts\python.exe -m pip freeze | Out-File -Encoding utf8 requirements.txt
```

Commit `requirements.txt` with the UI changes. Do not commit `.venv`.

## Limitations

- Educational batch analyzer, not a production SIEM or real-time monitor.
- Accepts the defined CSV schema, not native Windows Event Logs or Linux authentication logs directly.
- Loads valid records into memory, so large datasets require a different processing approach.
- Has no enrichment from device information, MFA results, geolocation, or post-login activity.
- Shared IP addresses and legitimate password mistakes can trigger alerts.
- Slow, distributed, or otherwise different attack patterns may evade these rules.
- An IP address does not uniquely identify a person or device.
- Invalid records are excluded, which can hide relevant activity.
- No authentication, case management, or automatic containment is implemented in the dashboard.
- CSV exports preserve input account text; spreadsheet applications may interpret formula-like values. Use synthetic/trusted data for this version or inspect untrusted reports as plain text.

**No alerts means neither rule matched the valid records. It does not establish that the activity was safe.**

## Skills Practised

Python programming, log validation, sliding time windows, event correlation, evidence-based investigation, automated testing, Streamlit UI development, Git, and technical documentation.

## Sample Data and Responsible Use

The supplied dataset is synthetic, uses documentation IP addresses, and contains no real credentials. Analyze only records you are authorized to access. Keep real authentication records and secrets out of public repositories.
