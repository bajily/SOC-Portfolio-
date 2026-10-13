"""Offline authentication-log triage using explicit, explainable rules."""
from __future__ import annotations

import argparse
import csv
import ipaddress
import json
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
from pathlib import Path


def read_events(path: Path) -> tuple[list[dict], list[dict]]:
    events, rejected = [], []
    with path.open(encoding="utf-8-sig", newline="") as stream:
        reader = csv.DictReader(stream)
        required = {"timestamp", "source_ip", "event", "user"}
        if not required.issubset(reader.fieldnames or []):
            raise ValueError("CSV requires timestamp, source_ip, event, user columns")
        for line, row in enumerate(reader, 2):
            try:
                timestamp = datetime.fromisoformat(row["timestamp"].replace("Z", "+00:00"))
                if timestamp.tzinfo is None:
                    raise ValueError("timestamp must include a timezone")
                source_ip = str(ipaddress.ip_address(row["source_ip"].strip()))
                event = row["event"].strip()
                user = row["user"].strip()
                if event not in {"login_failure", "login_success"}:
                    raise ValueError("unsupported event type")
                if not user:
                    raise ValueError("user must not be empty")
                events.append({"timestamp": timestamp.astimezone(timezone.utc),
                               "source_ip": source_ip, "event": event, "user": user})
            except (ValueError, AttributeError, KeyError) as exc:
                rejected.append({"line": line, "reason": str(exc)})
    return sorted(events, key=lambda event: event["timestamp"]), rejected


def analyze(events: list[dict], threshold: int = 5, window_seconds: int = 300) -> dict:
    if threshold < 1 or window_seconds < 1:
        raise ValueError("threshold and window_seconds must be positive")
    # User-scoped correlation avoids mistaking a different user's login for compromise.
    failures = defaultdict(deque)
    alerted = set()
    findings = []
    window = timedelta(seconds=window_seconds)
    ordered = sorted(events, key=lambda event: event["timestamp"])
    for event in ordered:
        key = event["source_ip"], event["user"]
        queue = failures[key]
        while queue and event["timestamp"] - queue[0] > window:
            queue.popleft()
        if len(queue) < threshold:
            alerted.discard(key)
        if event["event"] == "login_failure":
            queue.append(event["timestamp"])
            if len(queue) >= threshold and key not in alerted:
                findings.append({"rule": "repeated_login_failures", "severity": "medium",
                                 "timestamp": event["timestamp"].isoformat(),
                                 "source_ip": key[0], "user": key[1], "failure_count": len(queue)})
                alerted.add(key)
        elif event["event"] == "login_success":
            if len(queue) >= threshold:
                findings.append({"rule": "success_after_repeated_failures", "severity": "high",
                                 "timestamp": event["timestamp"].isoformat(),
                                 "source_ip": key[0], "user": key[1], "failure_count": len(queue)})
            queue.clear()
            alerted.discard(key)
        else:
            raise ValueError("unsupported event type")
    return {"events_analyzed": len(events), "threshold": threshold,
            "window_seconds": window_seconds, "findings": findings}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("csv", type=Path)
    parser.add_argument("--threshold", type=int, default=5)
    parser.add_argument("--window-seconds", type=int, default=300)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    try:
        events, rejected = read_events(args.csv)
        report = analyze(events, args.threshold, args.window_seconds)
        report["rejected_rows"] = rejected
        content = json.dumps(report, indent=2, ensure_ascii=False) + "\n"
        if args.output:
            args.output.write_text(content, encoding="utf-8")
        else:
            print(content, end="")
    except (OSError, ValueError, csv.Error) as exc:
        parser.exit(2, f"error: {exc}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
