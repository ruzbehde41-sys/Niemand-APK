# Android tools

## Tool selection
Choose tools by task, platform compatibility, maintenance status, license, provenance, resource use and reproducibility.

- **Android SDK / Gradle**: app builds and tests; verify JDK and Android Gradle Plugin compatibility first.
- **APKTool**: APK resources and Smali-oriented inspection; do not assume rebuilt APKs are equivalent to originals.
- **JADX**: DEX-to-Java decompilation for analysis; output is approximate and may be incomplete.
- **Python / Shell**: metadata inventory and repeatable read-only workflows.
- **Termux**: mobile command-line environment; Android is not a general-purpose desktop Linux distribution.

## Installation policy
Audit existing versions before installing or upgrading. Prefer official project releases and package sources. Record versions and checksums where practical. Do not bundle third-party binaries without reviewing redistribution terms.
