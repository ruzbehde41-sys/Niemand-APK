#!/usr/bin/env python3
"""Read-only APK file inventory: hashes and ZIP metadata; never extracts or executes."""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import zipfile

def inventory(path: Path) -> dict:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    result = {
        "file": path.name,
        "size_bytes": path.stat().st_size,
        "sha256": digest.hexdigest(),
        "is_zip": zipfile.is_zipfile(path),
        "dex_files": [],
        "manifest_present": False,
        "entry_count": 0,
    }
    if result["is_zip"]:
        with zipfile.ZipFile(path) as archive:
            names = archive.namelist()
            result["entry_count"] = len(names)
            result["dex_files"] = sorted(
                name for name in names
                if name == "classes.dex" or
                (name.startswith("classes") and name.endswith(".dex"))
            )
            result["manifest_present"] = "AndroidManifest.xml" in names
    return result

def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("apk", type=Path, help="Path to an APK file")
    args = parser.parse_args()
    if not args.apk.is_file():
        parser.error(f"not a regular file: {args.apk}")
    try:
        print(json.dumps(inventory(args.apk), indent=2, ensure_ascii=False))
    except (OSError, zipfile.BadZipFile) as exc:
        parser.exit(1, f"inventory failed: {exc}\n")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
