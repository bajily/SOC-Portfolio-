# SOC Portfolio · Authentication Log Triage

An offline Python project for turning authentication events into explainable triage findings. Includes synthetic logs, detection rules, tests, and an analyst investigation walkthrough.

**Python 3.11+ · Standard library only · No network access**

## Quick start

```bash
git clone https://github.com/bajily/SOC-Portfolio-.git
cd SOC-Portfolio-
python soc_triage.py samples/auth_events.csv
python -m unittest discover -s tests -v
```

The sample produces **7 analyzed events**, one medium-severity repeated-failure finding, and one high-severity success-after-failures finding.

```bash
python soc_triage.py samples/auth_events.csv --threshold 5 --window-seconds 300 --output report.json
```

## Detection logic

| Rule | Condition | Triage priority |
|---|---|---|
| `repeated_login_failures` | At least 5 failures for the same source IP and user in an inclusive 300-second window | Medium |
| `success_after_repeated_failures` | A success for that same IP and user while at least 5 failures remain in the window | High |

Events are sorted by timestamp and normalized to UTC. One repeated-failure alert is emitted per burst; a success resets that IP/user pair. Thresholds and window duration are configurable. Invalid rows are reported by line number instead of silently discarded.

## Input format

CSV columns: `timestamp,source_ip,event,user`. Timestamps must be ISO 8601 with a timezone. IPv4 and IPv6 are supported. Accepted event values: `login_failure` and `login_success`.

All included data is synthetic and uses documentation IP ranges. Do not commit real authentication logs or reports containing personal data.

## Analyst workflow

See [the investigation walkthrough](docs/investigation.md) for evidence, interpretation, false-positive checks, and recommended next steps.

## Design and limitations

- Batch processing holds parsed events in memory; this is a learning project, not a production SIEM.
- Detection is scoped to an IP/user pair. Distributed password spraying and cross-account activity require additional rules.
- A successful login after failures is a signal to investigate, not proof of compromise.
- JSON output is intended for review or downstream automation. The tool takes no containment action.

## بالعربية

مشروع لتحليل سجلات تسجيل الدخول محليًا، مع قواعد واضحة لاكتشاف تكرار المحاولات الفاشلة ثم نجاح الدخول. يتضمن بيانات تجريبية واختبارات ودليل تحقيق، ويمكن تشغيله دون مكتبات خارجية.
