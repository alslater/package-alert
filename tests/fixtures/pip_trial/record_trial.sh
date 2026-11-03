#!/bin/bash
# usage: PA_PIPX_SCRATCH=<dir> record_trial.sh CASE APP "REQS (\n separated)" "CONSTRAINTS" [extra pip args...]
# Runs `pipx runpip APP install --dry-run --report ...` (no --quiet: pip prints the conflict cause on stdout) in the scratch pipx home and writes
# $FIX/CASE.{report.json,stderr.txt,stdout.txt,exitcode.txt} ($FIX defaults to this script's directory).
# Paths in the recorded files are NOT normalised here; see README ("Placeholders").
set -eu
here=$(cd "$(dirname "$0")" && pwd)
. "$here/env.example.sh"
[ "$#" -ge 4 ] || { sed -n 2,3p "$0" >&2; exit 2; }
case=$1; app=$2; reqs=$3; cons=$4; shift 4
pa_plain_name CASE "$case" || exit 2; pa_plain_name APP "$app" || exit 2
F=${FIX:-$here}
W=$S/work/$case; rm -rf "$W"; mkdir -p "$W"
printf '%b\n' "$reqs" > "$W/reqs.txt"; printf '%b\n' "$cons" > "$W/cons.txt"
cp "$PIPX_HOME/venvs/$app/pipx_metadata.json" "$W/meta.before"
rc=0
pipx runpip "$app" install --dry-run --report "$W/report.json" -r "$W/reqs.txt" -c "$W/cons.txt" "$@" </dev/null >"$W/stdout.txt" 2>"$W/stderr.txt" || rc=$?
cmp -s "$W/meta.before" "$PIPX_HOME/venvs/$app/pipx_metadata.json" && m=unchanged || m=CHANGED
echo "$case rc=$rc metadata=$m report=$( [ -s "$W/report.json" ] && echo yes || echo no)"
if [ -f "$W/report.json" ]; then cp "$W/report.json" "$F/$case.report.json"; else : > "$F/$case.report.json"; fi
cp "$W/stderr.txt" "$F/$case.stderr.txt"
echo "$rc" > "$F/$case.exitcode.txt"
cp "$W/stdout.txt" "$F/$case.stdout.txt"
