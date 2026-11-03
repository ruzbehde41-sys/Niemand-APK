# Tools

This directory documents tool integrations and wrappers; it does not vendor third-party binaries by default.

- **apktool**: APK resource and Smali inspection.
- **jadx**: DEX decompilation for static analysis.
- **automation**: project-owned scripts with documented inputs, outputs and safety properties.

Check official sources, versions, licenses and platform compatibility before use.

## Project-owned APK inspection

- `scripts/apk_inventory.py`: SHA-256 and basic ZIP/DEX inventory.
- `scripts/apk_inspector.py`: read-only APK structure report, including DEX files, native libraries, assets, signature-file names, duplicate entries and unsafe archive paths.

Run from the repository root:

```sh
python scripts/apk_inspector.py /path/to/file.apk
python -m unittest discover -s tests -v
```

The inspector does not extract or execute archive contents. It detects the manifest and signature-related files by name only; it does not decode binary Android XML or cryptographically verify APK signatures.
