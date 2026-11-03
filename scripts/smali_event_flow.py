#!/usr/bin/env python3
"""Build a redacted event-to-method report from textual Android Smali."""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

from smali_flow_analyzer import analyze_file

EVENT_RE = re.compile(
    r"(?i)\bGateway(Client|Server)Event(?:\$|\.)([A-Za-z][A-Za-z0-9_$]*)"
)
CATEGORY_RULES = (
    ("conversation", re.compile(r"(?i)conversation|chat|prompt|completion")),
    ("message", re.compile(r"(?i)message|send|receive|reply")),
    ("stream", re.compile(r"(?i)stream|delta|token|chunk")),
    ("subscription", re.compile(r"(?i)subscribe|unsubscribe|subscription")),
    ("audio", re.compile(r"(?i)audio|voice|speech|transcri")),
    ("image", re.compile(r"(?i)image|imagine|vision|media")),
    ("connection", re.compile(r"(?i)connect|disconnect|ping|pong|heartbeat")),
)


def classify(name: str) -> str:
    for category, pattern in CATEGORY_RULES:
        if pattern.search(name):
            return category
    return "other"


def build_report(source: Path, max_files: int, max_items: int, package_prefix: str | None) -> dict:
    if source.is_symlink():
        raise ValueError("symbolic-link inputs are not supported")
    if not source.exists():
        raise ValueError(f"input does not exist: {source}")
    if source.is_file():
        candidates = [source] if source.suffix == ".smali" else []
    elif source.is_dir():
        candidates = sorted(p for p in source.rglob("*.smali") if not p.is_symlink())
    else:
        candidates = []

    truncated = len(candidates) > max_files
    candidates = candidates[:max_files]
    results = []
    for path in candidates:
        item = analyze_file(path, max_items)
        descriptor = item.get("class") or ""
        if package_prefix:
            prefix = "L" + package_prefix.replace(".", "/") + "/"
            if not descriptor.startswith(prefix):
                continue
        results.append(item)

    events = []
    markers = []
    for item in results:
        for marker in item.get("protocol_strings", []):
            method = marker.get("method")
            value = marker.get("value", "")
            if len(markers) < max_items:
                markers.append({
                    "class": item.get("class"),
                    "method": method,
                    "line": marker.get("line"),
                    "value": value,
                })
            for match in EVENT_RE.finditer(value):
                if len(events) >= max_items:
                    break
                direction, event_name = match.groups()
                related = [
                    edge.get("callee")
                    for edge in item.get("call_edges", [])
                    if edge.get("caller_method") == method
                ]
                events.append({
                    "class": item.get("class"),
                    "method": method,
                    "line": marker.get("line"),
                    "direction": direction.lower(),
                    "event": event_name,
                    "category": classify(event_name),
                    "related_calls": related[:max_items],
                })

    return {
        "tool": "smali_event_flow",
        "mode": "read-only heuristic event-to-method mapping",
        "input": str(source),
        "files_scanned": len(results),
        "file_limit_reached": truncated,
        "package_prefix": package_prefix,
        "totals": {
            "classes": sum(bool(x.get("class")) for x in results),
            "methods": sum(len(x.get("methods", [])) for x in results),
            "call_edges": sum(len(x.get("call_edges", [])) for x in results),
            "protocol_markers": len(markers),
            "events": len(events),
        },
        "events": events,
        "protocol_markers": markers,
        "limitations": [
            "Event names are reported only when explicit GatewayClientEvent/GatewayServerEvent identifiers occur in captured const-string protocol literals.",
            "Related calls are invoke instructions in the same parsed method; this is not a complete interprocedural or runtime trace.",
            "Analysis is regex-based and can miss obfuscated, reflected, dynamically assembled or encrypted behavior.",
            "Sensitive key/value patterns are redacted by the underlying Smali flow analyzer; this is not a general-purpose secret scanner.",
            "No code is executed and no network connection or APK modification is performed.",
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path, help="Smali file or directory")
    parser.add_argument("--max-files", type=int, default=200, help="Maximum files scanned")
    parser.add_argument("--max-items", type=int, default=100, help="Maximum event/marker findings")
    parser.add_argument("--package-prefix", help="Java package prefix, e.g. ai.x.grok.chat.websocket")
    args = parser.parse_args()
    if args.max_files < 1 or args.max_items < 1:
        parser.error("--max-files and --max-items must be positive")
    try:
        report = build_report(args.input, args.max_files, args.max_items, args.package_prefix)
    except ValueError as exc:
        parser.error(str(exc))
    json.dump(report, sys.stdout, ensure_ascii=False, indent=2)
    print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
