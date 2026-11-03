# Tools

This directory documents tool integrations and wrappers; it does not vendor third-party binaries by default.

- **apktool**: APK resource and Smali inspection.
- **jadx**: DEX decompilation for static analysis.
- **automation**: project-owned scripts with documented inputs, outputs and safety properties.

Check official sources, versions, licenses and platform compatibility before use.

## Project-owned APK inspection

- \`scripts/apk_inventory.py\`: SHA-256 and basic ZIP/DEX inventory.
- \`scripts/apk_inspector.py\`: read-only APK structure report, including DEX files, native libraries, assets, signature-file names, duplicate entries and unsafe archive paths.

Run from the repository root:

\`\`\`sh
python scripts/apk_inspector.py /path/to/file.apk
python -m unittest discover -s tests -v
\`\`\`

The inspector does not extract or execute archive contents. It detects the manifest and signature-related files by name only; it does not decode binary Android XML or cryptographically verify APK signatures.

## DEX identifier inspection

- \`scripts/dex_inspector.py\`: read-only DEX header, string, type descriptor, class-definition and method-identifier inspection.
- \`tests/test_dex_inspector.py\`: synthetic DEX fixtures and malformed-input checks.

Run from the repository root:

\`\`\`sh
python scripts/dex_inspector.py /path/to/classes.dex
python -m unittest discover -s tests -v
\`\`\`

The inspector does not execute bytecode or decode method bodies. It does not verify DEX checksums/signatures, and its modified UTF-8 decoding is conservative. JSON output is limited to 5,000 strings/classes/methods by default; use \`--max-items\` to change the output cap.

## Smali source analysis

- \`scripts/smali_analyzer.py\`: read-only, regex-based inspection of textual Smali files for class declarations, method declarations, \`const-string\` values, URL-like strings and selected network API invocations.
- \`tests/test_smali_analyzer.py\`: synthetic fixtures covering extraction, nested-directory scanning and invalid inputs.

Run from the repository root:

\`\`\`sh
python scripts/smali_analyzer.py /path/to/classes/smali
python scripts/smali_analyzer.py /path/to/Example.smali --max-items 100
python -m unittest discover -s tests -v
\`\`\`

The analyzer does not execute Smali, access the network, extract APKs or follow symbolic-link inputs. Findings are heuristic: obfuscation, reflection, dynamically assembled strings and APIs outside the selected namespaces can cause missed findings; pattern matches can also be false positives. Only \`const-string\` instructions are sampled, not every literal in the source. Output is JSON and capped per category per file (200 by default); directory scans are capped at 10,000 files.
