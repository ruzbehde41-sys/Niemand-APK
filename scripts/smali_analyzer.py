#!/usr/bin/env python3
"""Read-only heuristic analyzer for Smali source files. Never executes input."""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

CLASS_RE = re.compile(r"^\s*\.class\b.*?\s(L[^;\s]+;)", re.MULTILINE)
METHOD_RE = re.compile(r"^\s*\.method\b.*?\s([^\s(]+\([^)]*\).+?)\s*$", re.MULTILINE)
STRING_RE = re.compile(r'^\s*const-string(?:/jumbo)?\s+\S+,\s*"((?:\\.|[^"\\])*)"', re.MULTILINE)
URL_RE = re.compile(r"https?://[^\s\"'<>\\]+", re.IGNORECASE)
NETWORK_RE = re.compile(
    r"L(?:java/net/(?:URL|URLConnection|HttpURLConnection|Socket|DatagramSocket)"
    r"|javax/net/|okhttp3/|retrofit2/|com/android/volley/"
    r"|org/apache/http/|android/webkit/WebView)",
    re.IGNORECASE,
)


def collect_files(target: Path, max_files: int) -> list[Path]:
    if target.is_symlink():
        raise ValueError("Symbolic-link inputs are not followed.")
    if target.is_file():
        if target.suffix.lower() != ".smali":
            raise ValueError("Input file must have a .smali extension.")
        return [target]
    if not target.is_dir():
        raise ValueError(f"Input does not exist or is not a file/directory: {target}")
    found: list[Path] = []
    for path in target.rglob("*.smali"):
        if path.is_symlink() or not path.is_file():
            continue
        found.append(path)
        if len(found) > max_files:
            raise ValueError(f"File limit exceeded ({max_files}); narrow the input directory.")
    return sorted(found)


def analyze_file(path: Path, root: Path, max_items: int) -> dict:
    text = path.read_text(encoding="utf-8", errors="replace")
    rel = str(path.relative_to(root)) if root.is_dir() else path.name

    def matches(pattern: re.Pattern, group: int = 1) -> list[dict]:
        output = []
        for match in pattern.finditer(text):
            line = text.count("\n", 0, match.start()) + 1
            value = match.group(group) if group else match.group(0)
            output.append({"value": value, "line": line, "file": rel})
            if len(output) >= max_items:
                break
        return output

    strings = matches(STRING_RE)
    urls = matches(URL_RE, 0)
    network_calls = []
    for line_no, line in enumerate(text.splitlines(), 1):
        if "invoke-" in line and NETWORK_RE.search(line):
            network_calls.append({"value": line.strip(), "line": line_no, "file": rel})
            if len(network_calls) >= max_items:
                break
    return {
        "file": rel,
        "classes": matches(CLASS_RE),
        "methods": matches(METHOD_RE),
        "strings": strings,
        "urls": urls,
        "network_calls": network_calls,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", help="A .smali file or directory containing Smali files")
    parser.add_argument("--max-items", type=int, default=200, help="Maximum samples per category per file (default: 200)")
    parser.add_argument("--max-files", type=int, default=10000, help="Maximum files to scan (default: 10000)")
    args = parser.parse_args()
    if args.max_items < 1 or args.max_files < 1:
        parser.error("--max-items and --max-files must be positive integers")
    target = Path(args.input).expanduser()
    try:
        files = collect_files(target, args.max_files)
        reports = [analyze_file(path, target if target.is_dir() else path, args.max_items) for path in files]
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    categories = ("classes", "methods", "strings", "urls", "network_calls")
    totals = {key: sum(len(report[key]) for report in reports) for key in categories}
    result = {
        "tool": "smali_analyzer",
        "mode": "read-only heuristic static analysis",
        "files_scanned": len(files),
        "counts": totals,
        "files": reports,
        "limitations": [
            "Regex-based findings are heuristic and may contain false positives or miss obfuscated/dynamic behavior.",
            "Only textual .smali files are scanned; no APK extraction, decompilation, bytecode execution or network access occurs.",
            "String samples are taken from const-string instructions, not every string in the source.",
            "Network-call matches identify selected API namespaces, not proof that a connection occurs."
        ],
    }
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
