#!/usr/bin/env python3
"""Read-only structural APK inspector. Does not extract or execute archive contents."""
from __future__ import annotations

import argparse
import json
from pathlib import Path, PurePosixPath
import zipfile


def _safe_member_name(name: str) -> bool:
    normalized = name.replace("\\", "/")
    path = PurePosixPath(normalized)
    return not path.is_absolute() and ".." not in path.parts


def inspect_apk(path: Path) -> dict:
    """Return structural metadata and conservative warnings for an APK/ZIP file."""
    if not path.is_file():
        raise FileNotFoundError(f"not a regular file: {path}")

    result = {
        "file": path.name,
        "size_bytes": path.stat().st_size,
        "is_zip": zipfile.is_zipfile(path),
        "manifest_present": False,
        "resources_table_present": False,
        "dex_files": [],
        "native_libraries": [],
        "asset_file_count": 0,
        "signature_files": [],
        "entry_count": 0,
        "total_uncompressed_bytes": 0,
        "duplicate_entries": [],
        "unsafe_paths": [],
        "large_entries": [],
        "warnings": [],
        "limitations": [
            "AndroidManifest.xml is detected by name only; binary XML is not decoded.",
            "Certificate files are detected by name only; signatures are not verified.",
            "Archive contents are not extracted or executed.",
        ],
    }

    if not result["is_zip"]:
        result["warnings"].append("Input is not a ZIP/APK archive.")
        return result

    with zipfile.ZipFile(path, "r") as archive:
        infos = archive.infolist()
        names = [item.filename for item in infos]
        lower_names = [name.lower() for name in names]
        result["entry_count"] = len(infos)
        result["total_uncompressed_bytes"] = sum(item.file_size for item in infos)
        result["manifest_present"] = "androidmanifest.xml" in lower_names
        result["resources_table_present"] = "resources.arsc" in lower_names
        result["dex_files"] = sorted(
            name for name in names
            if name.lower() == "classes.dex"
            or (
                name.lower().startswith("classes")
                and name.lower().endswith(".dex")
                and name[7:-4].isdigit()
            )
        )
        result["native_libraries"] = sorted(
            name for name in names
            if name.lower().startswith("lib/") and name.lower().endswith(".so")
        )
        result["asset_file_count"] = sum(
            1 for name in names if name.lower().startswith("assets/")
        )
        result["signature_files"] = sorted(
            name for name in names
            if name.upper().startswith("META-INF/")
            and name.upper().endswith((".RSA", ".DSA", ".EC"))
        )

        seen = set()
        duplicates = set()
        for name in names:
            if name in seen:
                duplicates.add(name)
            seen.add(name)
            if not _safe_member_name(name):
                result["unsafe_paths"].append(name)

        result["duplicate_entries"] = sorted(duplicates)
        result["unsafe_paths"] = sorted(set(result["unsafe_paths"]))
        result["large_entries"] = sorted(
            item.filename for item in infos if item.file_size >= 100 * 1024 * 1024
        )

    if not result["manifest_present"]:
        result["warnings"].append("AndroidManifest.xml was not found.")
    if not result["dex_files"]:
        result["warnings"].append("No DEX files were detected.")
    if result["unsafe_paths"]:
        result["warnings"].append("Archive contains absolute or parent-traversal paths.")
    if result["duplicate_entries"]:
        result["warnings"].append("Archive contains duplicate member names.")
    if result["large_entries"]:
        result["warnings"].append("Archive contains entries of at least 100 MiB.")
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("apk", type=Path, help="Path to an APK or ZIP file")
    args = parser.parse_args()
    try:
        print(json.dumps(inspect_apk(args.apk), indent=2, ensure_ascii=False))
    except (OSError, zipfile.BadZipFile) as exc:
        parser.exit(1, f"inspection failed: {exc}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
