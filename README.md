# Security Log Analysis Tool

This Tool scans SSH/auth logs and Apache-style HTTP access logs for signs of
attack activity — brute-force login attempts and requests from known
scanning/exploitation tools (`sqlmap`, `curl`, `wget` hitting sensitive
paths) — and reports the results through an interactive terminal menu.

## Features

- **Brute-force detection**: flags any IP with 5+ failed login attempts
  within a 10-minute sliding window (SSH `Failed password` / HTTP 4xx/5xx
  and sensitive-path requests).
- **Suspicious tool detection**: flags IPs whose HTTP requests combine a
  sensitive path (`admin`, `login`, `phpinfo`, `secret`, `passwd`) with a
  known scanning/automation user agent (`sqlmap`, `curl`, `wget`).
- **GeoIP lookup**: resolves the country of origin for public IPs (private
  IPs are labeled `Private Address`).
- **Interactive menu**: analyze logs, view incidents, view suspicious IPs,
  generate a bar chart of top attackers, and export a text report — all
  without re-running the script.
- **Bar chart export**: saves a `top_attackers.png` chart of failed attempts
  per IP.
- **Text report export**: saves a full incident + suspicious-IP summary to
  a file you name.

## Requirements

- Python 3.8+
- Packages:
  ```bash
  pip install matplotlib geocoder questionary
  ```

## Input

A log file named `log_file.log` in the same directory as the script,
containing a mix of (or either of):

- **SSH/auth log lines**, e.g.:
  ```
  Mar 10 15:46:11 sshd[1234]: Failed password for root from 203.0.113.7 port 51515 ssh2
  ```
- **Apache-style HTTP access log lines**, e.g.:
  ```
  203.0.113.7 - - [10/Mar/2025:15:46:11 +0000] "GET /admin HTTP/1.1" 401 512 "-" "sqlmap/1.7"
  ```

> The script assumes the year **2025** for auth-log timestamps (since
> syslog-style auth logs don't include a year). Change this in
> `parse_auth_line` if your logs are from a different year.

## Usage

1. Place your log file in the script's directory and name it `log_file.log`
   (or edit the `LOGFILE` variable at the top of the script).
2. Run the script:
   ```bash
   python log_analyzer.py
   ```
3. Use the interactive menu:
   | Option | Action |
   |---|---|
   | 1. Analyze Logs | Parses the log file and detects incidents/suspicious IPs |
   | 2. Show Brute Force Incidents | Prints all detected brute-force clusters, grouped by IP |
   | 3. Show Suspicious Tool Usage | Prints IPs that used scanning tools against sensitive paths |
   | 4. Generate Bar Chart of Top Attackers | Saves and displays `top_attackers.png` |
   | 5. Save Results to File | Exports a full report to a text file you name |
   | 6. Exit | Quits the program |

   You must run **Analyze Logs** first — the other options depend on its
   results for that session.

## Output

- `top_attackers.png` — bar chart of failed-attempt counts per attacking IP.
- `security_report.txt` (or your chosen filename) — plain-text report of all
  incidents and suspicious IPs.

## How detection works

- **Brute force**: failed-attempt timestamps are grouped per IP and sorted.
  A sliding 10-minute window is walked across each IP's timestamps; any
  window containing 5 or more failed attempts is reported as one incident
  (overlapping attempts inside a detected cluster aren't double-counted).
- **Tool usage**: for each HTTP log line, if the request path contains a
  sensitive keyword *and* the user agent matches a known tool, the IP is
  added to the suspicious set.

## Limitations / notes

- GeoIP lookups depend on the `geocoder` package and an external service —
  results may be `"Unknown"` or `"Lookup Failed"` if the service is
  unreachable or rate-limited.
- Auth-log parsing assumes a fixed year (2025); adjust as needed.
- Only IPv4 addresses (dotted-decimal) are recognized by the IP-matching
  regex.
- The brute-force threshold (5 attempts / 10 minutes) is hardcoded; adjust
  the `window` and `count >= 5` values in `analyze_logs()` to tune
  sensitivity.