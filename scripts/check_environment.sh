#!/usr/bin/env sh
# Read-only inventory of common Android/Termux development tools.
set -u
printf '%s\n' 'Niemand-APK environment check (read-only)'
printf 'OS: '; uname -a 2>/dev/null || true
printf 'Architecture: '; uname -m 2>/dev/null || true
for tool in python python3 node npm git java adb apktool jadx sqlite3; do
  if command -v "$tool" >/dev/null 2>&1; then
    printf '%-10s %s\n' "$tool" "$(command -v "$tool")"
  else
    printf '%-10s %s\n' "$tool" 'not found in PATH'
  fi
done
if [ -n "${PREFIX:-}" ]; then printf 'PREFIX: %s\n' "$PREFIX"; fi
if [ -n "${HOME:-}" ]; then printf 'HOME: %s\n' "$HOME"; fi
printf '%s\n' 'No packages were installed or modified.'
