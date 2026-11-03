#!/bin/bash
# usage: PA_PIPX_SCRATCH=<dir> readonly_trial.sh CASE APP [extra pip args...]
# Runs the trial of an existing record_trial.sh CASE (its reqs.txt/cons.txt under $S/work/CASE) under bwrap with
# / read-only; only pipx_home/logs, $S/work, the app's lock file and /tmp are writable. Writes the report and the
# captured streams to a fresh directory under $S/work (printed), then prints rc, stderr tail and every file newer than
# the start (outside work/ and logs/).
set -eu
here=$(cd "$(dirname "$0")" && pwd)
. "$here/env.example.sh"
[ "$#" -ge 2 ] || { sed -n 2,5p "$0" >&2; exit 2; }
case=$1; app=$2; shift 2
pa_plain_name CASE "$case" || exit 2; pa_plain_name APP "$app" || exit 2
lock=$S/pipx_home/venvs/.$app.lock
[ -f "$lock" ] || { echo "missing lock file $lock" >&2; exit 1; }
# A fresh directory of this run's own: a reused one could be a link leading the output elsewhere.
out=$(mktemp -d "$S/work/ro.XXXXXX"); echo "output in $out"
touch "$out/ts"; sleep 1.1
rc=0
bwrap --ro-bind / / --dev /dev --proc /proc --tmpfs /tmp \
  --bind "$S/pipx_home/logs" "$S/pipx_home/logs" --bind "$S/work" "$S/work" --bind "$lock" "$lock" --die-with-parent \
  pipx runpip "$app" install --dry-run --report "$out/$case.json" --quiet -r "$S/work/$case/reqs.txt" -c "$S/work/$case/cons.txt" "$@" \
  </dev/null > "$out/$case.out" 2> "$out/$case.err" || rc=$?
echo "$case rc=$rc"; tail -3 "$out/$case.err" | cut -c1-220
echo "newer than start (excluding work/ and logs/):"
find "$S" -newer "$out/ts" -not -path "$S/work/*" -not -path "$S/pipx_home/logs*" 2>/dev/null || true
