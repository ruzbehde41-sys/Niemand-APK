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


## Smali call-flow analysis

- \`scripts/smali_flow_analyzer.py\`: read-only, heuristic extraction of method declarations, invoke call edges, selected network-library calls, URL endpoints and protocol/event-like string literals.
- \`tests/test_smali_flow_analyzer.py\`: synthetic tests for call attribution, network namespaces, URL/protocol literals, redaction, limits and package filtering.

Examples:

\`\`\`sh
python scripts/smali_flow_analyzer.py /path/to/smali --max-files 500
python scripts/smali_flow_analyzer.py /path/to/smali --package-prefix com.example --max-files 300
python scripts/smali_flow_analyzer.py /path/to/Example.smali --max-items 100
python -m unittest discover -s tests -v
\`\`\`

The analyzer reads text only; it does not execute code, access the network, extract APKs or follow symbolic-link inputs. Call edges are limited to explicit Smali \`invoke-*\` instructions inside parsed method blocks. Network namespaces are a curated list, not an exhaustive API catalogue. URL and protocol-string matches are heuristic and can miss dynamically assembled, encrypted, obfuscated or otherwise indirect values. Token-like key/value literals are redacted, but this is not a general-purpose secret scanner. Directory scans default to at most 500 files; output findings are capped per category per file (300 by default). Use a narrow package or directory scope first.
