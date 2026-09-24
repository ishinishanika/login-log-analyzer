# Login Log Analyzer

A beginner cybersecurity project built with Python that analyzes
CSV login records and identifies suspicious authentication patterns.

## Features

- Validates timestamps, usernames, IP addresses, and login statuses.
- Reports invalid records and excludes them from analysis.
- Sorts valid events chronologically.
- Summarizes successful and failed logins.
- Detects repeated failures from an IP address.
- Detects a successful login after repeated failures for the
  same account and IP.
- Exports alerts to CSV.
- Supports input and output paths through command-line arguments.

## Requirements

- Python 3
- No third-party packages required.

## Run

Use the sample dataset:

    py analyzer.py

Choose input and output files:

    py analyzer.py --input data/sample_logins.csv --output reports/sample_alerts.csv

Show help:

    py analyzer.py --help

On systems without the Windows Python launcher, use python or python3
instead of py.

## Input Format

Required columns:

    timestamp,username,source_ip,status

Example record:

    2026-09-24T10:00:00Z,alice,192.0.2.10,success

Timestamps must use YYYY-MM-DDTHH:MM:SSZ.
The Z indicates UTC.

Status must be success or failed, ignoring letter case.

## Detection Rules

### Repeated login failures

Triggers when an IP reaches at least five failed logins within
five minutes. Failures exactly five minutes apart are included.

The rule counts failures across accounts sharing that IP.
It alerts when the count crosses the threshold, rather than
for every additional failure while the count stays high.

### Success after repeated failures

Tracks each username and IP combination separately.

A qualifying pattern contains at least five failures within
five minutes. Further failures refresh the stored pattern
when they also meet this condition.

Triggers when the same account and IP succeed within ten minutes
of the latest qualifying pattern's last failure.

A success clears that pair's failure sequence and consumes
the stored pattern, preventing repeated alerts from later successes.

## Output

The default report is reports/alerts.csv.

It includes the rule, source IP, accounts, failure count,
relevant UTC timestamps, and an assessment.

Each run overwrites the selected report.
Alert IDs are local to that report, not permanent incident IDs.

If valid events produce no alerts, the report contains only headers.
If no valid events exist, no report is written; an earlier report
may still exist.

## Tests

Run:

    py -m unittest -v test_analyzer

The ten tests cover thresholds, time boundaries, IP separation,
account matching, and duplicate-success suppression.

They do not yet cover input validation, command-line handling,
or report export.

## Limitations

- Analyzes a defined CSV format, not native Windows or Linux logs.
- Processes files in batches; it is not a real-time monitor.
- Loads valid records into memory.
- Uses fixed thresholds that may not suit other environments.
- Shared IPs and legitimate password mistakes can trigger alerts.
- Slow or distributed guessing may evade these rules.
- Matching an IP does not prove that events came from one person.
- Alerts indicate patterns requiring investigation, not proven attacks.
- Skipped records can cause relevant activity to be missed.

## Sample Data

The supplied sample is synthetic and uses documentation IP addresses.
It contains no real credentials.

## Skills Practised

Python, log validation, time-based detection, event correlation,
automated testing, and security investigation reporting.