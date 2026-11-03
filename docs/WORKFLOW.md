# Engineering workflow

1. Identify the project, owner, goal and expected deliverable.
2. Audit existing files, OS/device, architecture, tool versions, storage and dependencies.
3. Plan the smallest change that meets the requirement.
4. Check compatibility, provenance, licensing, privacy and security.
5. Implement in an isolated project directory.
6. Test with reproducible commands and record actual results.
7. Document setup, usage, dependencies, limitations and recovery.
8. Commit focused changes with descriptive messages.

## Safety defaults
- Read-only inspection is the default for unfamiliar APKs and devices.
- Preserve original samples; work on copies only when modification is authorized.
- Never overwrite unrelated project files.
- Do not commit generated build output, secrets, signing keys, personal data or large decompilation directories.
- Do not install, remove, upgrade, patch, sign, publish or reconfigure software without a clearly authorized task.

## Termux
Prefer portable scripts, detect tools rather than assuming availability, explain shared-storage permissions, and conserve mobile storage/RAM/CPU. A Linux binary or package is not automatically compatible with Android.
