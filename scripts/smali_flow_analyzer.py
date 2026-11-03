#!/usr/bin/env python3
"""Read-only, heuristic call-flow analysis for textual Android Smali files."""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

CLASS_RE = re.compile(r"^\s*\.class\b.*?\s+(L[^;\s]+;)")
METHOD_RE = re.compile(r"^\s*\.method\b.*?\s([^\s(]+)(\(.*)$")
INVOKE_RE = re.compile(
    r"^\s*invoke-[\w/-]+\s+\{[^}]*\},\s*(L[^;]+;)->([^\s(]+)(\(.*)$"
)
STRING_RE = re.compile(r'^\s*const-string(?:/jumbo)?\s+\w+,\s*"(.*)"\s*$')
URL_RE = re.compile(r"(?i)(?:wss?|https?)://[^\s\"'<>]+")
INTEREST_RE = re.compile(
    r"(?i)(?:/gateway|/graphql|/websocket|/socket|gateway|websocket|"
    r"protocol|event|subscribe|stream|conversation|message)"
)
NETWORK_PREFIXES = (
    "Ljava/net/", "Ljavax/net/", "Lokhttp3/", "Lokio/",
    "Lretrofit2/", "Lcom/android/volley/", "Lorg/java_websocket/",
    "Lio/netty/", "Lorg/apache/http/", "Landroid/webkit/WebView;",
)
SENSITIVE_RE = re.compile(
    r"(?i)(bearer\s+\S+|(?:access[_-]?token|refresh[_-]?token|api[_-]?key|"
    r"authorization|password|passwd|secret)\s*[:=]\s*[^&\s,;]+)"
)


def safe_value(value: str) -> str:
    value = value.replace(r"\/", "/")
    value = SENSITIVE_RE.sub("[REDACTED]", value)
    if len(value) > 300:
        value = value[:297] + "..."
    return value


def analyze_file(path: Path, max_items: int) -> dict:
    result = {
        "file": str(path),
        "class": None,
        "methods": [],
        "call_edges": [],
        "network_calls": [],
        "endpoints": [],
        "protocol_strings": [],
        "parse_warnings": [],
    }
    current_method = None
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError as exc:
        result["parse_warnings"].append(type(exc).__name__)
        return result

    for line_no, line in enumerate(lines, 1):
        cm = CLASS_RE.match(line)
        if cm:
            result["class"] = cm.group(1)

        mm = METHOD_RE.match(line)
        if mm:
            current_method = mm.group(1) + mm.group(2)
            if len(result["methods"]) < max_items:
                result["methods"].append({"name": current_method, "line": line_no})
            continue
        if line.strip() == ".end method":
            current_method = None
            continue

        im = INVOKE_RE.match(line)
        if im and current_method:
            owner, method, proto = im.groups()
            callee = owner + "->" + method + proto
            edge = {
                "caller_class": result["class"],
                "caller_method": current_method,
                "callee": callee,
                "line": line_no,
            }
            if len(result["call_edges"]) < max_items:
                result["call_edges"].append(edge)
            if owner.startswith(NETWORK_PREFIXES) and len(result["network_calls"]) < max_items:
                result["network_calls"].append({
                    "owner": owner, "method": method, "caller_method": current_method,
                    "line": line_no,
                })

        sm = STRING_RE.match(line)
        if sm:
            value = safe_value(sm.group(1))
            urls = URL_RE.findall(value)
            for url in urls:
                if len(result["endpoints"]) < max_items:
                    result["endpoints"].append({"value": url, "method": current_method, "line": line_no})
            if INTEREST_RE.search(value) and len(result["protocol_strings"]) < max_items:
                result["protocol_strings"].append({
                    "value": value, "method": current_method, "line": line_no
                })
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path, help="Smali file or directory")
    parser.add_argument("--max-files", type=int, default=500, help="Maximum files scanned (default: 500)")
    parser.add_argument("--max-items", type=int, default=300, help="Maximum findings per category per file")
    parser.add_argument("--package-prefix", help="Only include class descriptors under this Java package, e.g. com.example")
    args = parser.parse_args()

    if args.max_files < 1 or args.max_items < 1:
        parser.error("--max-files and --max-items must be positive")
    source = args.input
    if source.is_symlink():
        parser.error("symbolic-link inputs are not supported")
    if not source.exists():
        parser.error(f"input does not exist: {source}")
    if source.is_file():
        candidates = [source] if source.suffix == ".smali" else []
    elif source.is_dir():
        candidates = sorted(p for p in source.rglob("*.smali") if not p.is_symlink())
    else:
        candidates = []

    truncated = len(candidates) > args.max_files
    candidates = candidates[:args.max_files]
    files = []
    for path in candidates:
        item = analyze_file(path, args.max_items)
        if args.package_prefix:
            prefix = "L" + args.package_prefix.replace(".", "/") + "/"
            if not (item["class"] or "").startswith(prefix):
                continue
        files.append(item)

    summary = {
        "input": str(source),
        "files_scanned": len(files),
        "file_limit_reached": truncated,
        "package_prefix": args.package_prefix,
        "totals": {
            "classes": sum(bool(x["class"]) for x in files),
            "methods": sum(len(x["methods"]) for x in files),
            "call_edges": sum(len(x["call_edges"]) for x in files),
            "network_calls": sum(len(x["network_calls"]) for x in files),
            "endpoints": sum(len(x["endpoints"]) for x in files),
            "protocol_strings": sum(len(x["protocol_strings"]) for x in files),
        },
        "results": files,
    }
    json.dump(summary, sys.stdout, ensure_ascii=False, indent=2)
    print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
