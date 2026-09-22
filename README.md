# C++ Log Analyzer

A C++ command-line tool that reads Apache access logs, Apache error logs, and OpenSSH logs, and writes a summary report covering traffic patterns, log-level activity, and authentication activity. Built with the C++ standard library only — file handling, string parsing, `map`-based counting — plus one rule-based check for SSH authentication failures.

---

## Project Structure

```text
log-analyzer/
├── data/
│   └── .gitkeep
├── output/
│   └── .gitkeep
├── sample_output/
│   └── log_analysis_report.txt
├── src/
│   └── main.cpp
├── .gitignore
├── LICENSE
└── README.md
```

`data/` and `output/` hold only a `.gitkeep` placeholder so the folders exist after cloning. Log files and generated reports are excluded via `.gitignore`.

---

## Dataset

Developed and tested with logs from the [Rootly AI Labs Logs Dataset](https://github.com/Rootly-AI-Labs/logs-dataset). The log files are **not included** here — download them and place them in `data/` using exactly these names:

```text
data/apache_access.log
data/apache_error.log
data/openssh.log
```

These paths are read directly in `main()` (`src/main.cpp`). If a file is missing, that section of the report prints `Error: Could not open <path>` and the program continues with the next file. Results depend on the dataset version used and are examples, not universal values.

---

## Build and Run

Requires a C++11-or-later compiler (e.g. `g++`); no external libraries. Must be run from the **project root** (paths like `data/...` and `output/...` are relative).

```bash
g++ src/main.cpp -o log_analyzer
```

```powershell
.\log_analyzer.exe        # Windows
```
```bash
./log_analyzer             # Linux / macOS
```

The report is overwritten on every run and written to `output/log_analysis_report.txt`. The program exits with code 1 only if that file itself can't be created (e.g. a missing `output/` folder).

---

## What It Analyzes

**Apache access log** — for each line, the IP is the text before the first space, and the status is the first token after the closing quote of the quoted request field. Lines missing that structure are counted as `Skipped Lines`. Reports total requests, HTTP errors (status starting with 4 or 5), most common status, and most active IP. The request path/method itself isn't analyzed.

**Apache error log** — the first `]` ends the timestamp field, the next bracketed field is the log level, and everything after it (minus a leading space) is the message. Non-matching lines are `Skipped Lines`. Reports total log entries, most common level, and most repeated message — **across all levels, not just `error`**.

**OpenSSH log** — every line counts toward `Total Events`. A line is a *failed event* if it contains `Failed password`, `authentication failure`, or `Invalid user`, and a *successful event* if it contains `Accepted password` or `Accepted publickey`. If the line contains `from `, the following token is recorded as that event's source IP.

**Security summary** — if the IP with the most failed events reaches `suspiciousThreshold` (currently `5`, a constant in `src/main.cpp`), the report prints `Suspicious authentication activity detected.` This applies to the SSH log only and is a demonstration rule, not an intrusion-detection system.

---

## Example Output

A sample report generated from the development dataset is available at
[`sample_output/log_analysis_report.txt`](sample_output/log_analysis_report.txt).

---

## Limitations

**Format assumptions** — the parsers match the dataset's log formats, not every Apache/OpenSSH variant:
- *Access log:* expects `IP … "request" status`. The status isn't validated as a real 3-digit code, and escaped quotes in the request field can throw off the parse.
- *Error log:* expects `[timestamp] [level] message`. Extra fields after the level (PIDs, client addresses) stay inside the message, so otherwise-identical errors may not group together. Module-style levels (`core:error`) are treated as distinct levels.
- *SSH log:* the token after `from ` is assumed to be an IP but isn't validated — it could be a hostname or other text.

**What the counts mean**
- SSH counts are **matching log lines, not unique attempts or sessions** — one login attempt can produce several matching lines (e.g. `Invalid user` then `Failed password`).
- SSH per-IP attribution only works for lines containing `from`; events using another source-field format, such as `rhost=`, are counted as events but aren't attributed to an IP.
- Apache error counts include all levels, not just `error` — in the sample output, only 12,395 of 19,524 entries are at the `error` level.
- `Skipped Lines` only catches lines that don't match the expected structure, not other bad data.

**Security rule**
- One fixed threshold on one IP's total failed events — no time window, failure rate, username tracking, cross-IP correlation, or check for a later successful login.
- Counts events rather than unique attempts, so the threshold may be reached by multiple log lines from the same authentication activity.
- Doesn't apply to the Apache logs.

**Edge cases**
- Ties for "most common" resolve to the first entry in map order, not all tied values.
- Empty/unparsable files print blank names with zero counts (e.g. `Most Common Status:  (0)`) instead of a "no data" message.
- Exit code is 0 even when an input file is missing.
- Paths are hardcoded relative paths — must run from the project root.

---

## Future Improvements

- Command-line arguments for log-file paths
- Count unique SSH attempts/sessions instead of raw lines; attribute `rhost=` lines to an IP
- Time-window-based failure detection, and detection of a failing IP that later succeeds
- Normalize Apache error messages before counting; filter/report by level
- Report all ties; clear message for empty files
- Configurable threshold; CSV/JSON output

---

## License

MIT — see [LICENSE](LICENSE).