# npm trial fixtures

Recorded with npm 11.8.0 on node v24.13.1 (2026-10-08), in a fresh
`mktemp -d` scratch directory, with `F="--package-lock-only --ignore-scripts --no-audit --no-fund"`.

`package.json` is the fixture project's manifest:

```json
{"name":"fx","version":"1.0.0","dependencies":{"express":"4.17.1"},"devDependencies":{"@babel/core":"7.1.0"}}
```

Each `*_after.json` starts from that `package.json` and `before.json`.

| File | Command |
|------|---------|
| `before.json` | `npm install $F` |
| `override_after.json` | `npm pkg set 'overrides[qs@>5 <6.14.0]=6.14.0'`, then `npm install $F` (the unscoped key `qs@<6.14.0` gives the identical lock: every qs copy is on 6.x) |
| `parent_after.json` | `npm install express@4.21.2 $F` |
| `scoped_after.json` | `npm install @babel/core@7.26.10 $F` |
| `etarget.txt` | stderr of `npm install express@99.0.0 $F` (exit 1; the lock is unchanged) |
| `eresolve.txt` | stderr of `npm install $F` in a second project whose `package.json` is `{"dependencies":{"react":"17.0.2","react-dom":"18.2.0"}}` (exit 1) |

The `semver_*` files are a second project, recorded in another fresh
directory, whose lock holds `semver` on three major lines: 5.7.2 (under
normalize-package-data), 6.3.1 (under @babel/core and
@babel/helper-compilation-targets) and 7.5.4 (hoisted, used by make-dir):

| File | Command |
|------|---------|
| `semver_before.json` | with `package.json` `{"name":"fx-semver","version":"1.0.0","dependencies":{"normalize-package-data":"2.5.0","@babel/core":"7.22.0","make-dir":"4.0.0","semver":"7.5.4"}}`, `npm install $F`; then drop `semver` from `dependencies` and `npm install $F` again (the lock keeps 7.5.4) |
| `semver_scoped_after.json` | from that `package.json` (without `semver`) and `semver_before.json`: `npm pkg set 'overrides[semver@>6 <7.6.0]=7.6.0'`, then `npm install $F` — only 7.5.4 moves |
| `semver_unscoped_after.json` | the same with the key `semver@<7.6.0` (written into `package.json` directly) — 5.7.2 and 6.3.1 are moved to 7.6.0 as well |

`npm pkg set 'overrides[semver@>=7.0.0 <7.6.0]=7.6.0'` exits 0 but writes the
key `overrides[semver@>` with the value `7.0.0 <7.6.0]=7.6.0` (it splits at
the first `=`), which is why the override key spells its lower bound `>6`.

`before.json` locks `qs` 6.7.0 (pinned exactly by express 4.17.1);
`override_after.json` locks 6.14.0 and `parent_after.json` 6.13.0.

In `etarget.txt` and `eresolve.txt` the npm cache's log directory
(`~/.npm/_logs/`, an absolute home path) is replaced by `<npm-cache>/_logs/`;
the text is otherwise verbatim.

Re-record on an npm upgrade and re-run
`tests/unit/languages/node_fix/test_npm_trial.py`: the trial parses npm's
`ETARGET` and `ERESOLVE` stderr, which is not a documented interface.
