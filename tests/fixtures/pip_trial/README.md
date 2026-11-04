# pip trial fixtures (pa fix --tools --pipx)

Recorded 2026-11-02 from real runs of `pipx runpip <app> install --dry-run --report … --quiet -r reqs.txt -c cons.txt …`
(`conflict` and `capped_conflict` without `--quiet`, as the trial now runs: see "Without --quiet" below)
in a scratch pipx home. Nothing touched the real `~/.local/pipx`: every command ran with
`PIPX_HOME`, `PIPX_BIN_DIR`, `PIPX_MAN_DIR`, `PIPX_COMPLETION_DIR`, `PIPX_SHARED_LIBS` (and the `*_GLOBAL_*` ones) under
`/SCRATCH/`, checked with `pipx environment` first.

Each case is `<case>.report.json` (pip's `--report` file; **empty when pip wrote none**, i.e. whenever pip failed),
`<case>.stderr.txt`, `<case>.stdout.txt` (empty unless noted) and `<case>.exitcode.txt` (pipx's exit code).
### Files, placeholders, isolation

- **Placeholders.** The recorded files were normalised after recording and are otherwise byte-for-byte as pip/pipx/uv printed them: the scratch root is `/SCRATCH`, this repository `/REPO`, the user's home `/HOME`. (`file:///SCRATCH/src/localapp` in a report is the local checkout.)
- **Isolation.** Every script sources `env.example.sh`, which needs `PA_PIPX_SCRATCH` (an absolute scratch directory; refused if it is `$HOME`, `/` or under `~/.local`), sets every `PIPX_*` location under it, forces `PIPX_DEFAULT_BACKEND=pip`, and then checks what `pipx environment` derives (`PIPX_HOME`, `PIPX_BIN_DIR`, `PIPX_MAN_DIR`, `PIPX_SHARED_LIBS`, `PIPX_LOCAL_VENVS`, `PIPX_LOG_DIR`, `PIPX_TRASH_DIR`, `PIPX_COMPLETION_DIR`) is under it, else exits. Optional `PA_PIPX_PYTHON` (absolute) sets `PIPX_DEFAULT_PYTHON`. Reproduce: `export PA_PIPX_SCRATCH=$HOME/pa-scratch-pipx; mkdir -p $PA_PIPX_SCRATCH; . env.example.sh`, then install the apps as in "Environment" with plain `pipx install` in that shell.
- `record_trial.sh CASE APP 'reqs lines' 'constraint lines' [extra pip args]` records one case (all three scripts `set -eu`); `readonly_trial.sh CASE APP [extra pip args]` re-runs an already recorded case's reqs/constraints under bwrap with `/` read-only (only `pipx_home/logs`, `$PA_PIPX_SCRATCH/work`, the app's lock file and `/tmp` writable) and lists files changed; `srv401.py` is the 401 server (127.0.0.1:8401); `wrset.py LOG` summarises a strace log (it only reads it).
- Most `*.stdout.txt` are empty by design: with `--quiet` pip prints nothing to stdout, and the report goes to the file. The non-empty ones are the 401 prompt (`index_401_prompt`, 25 bytes) and the four conflicts recorded without `--quiet` (`conflict`, `capped_conflict`, `deep_capped_conflict`, `deep_range_conflict`), where pip prints the conflict's cause.
- Counts: 24 cases (24 `*.exitcode.txt`), 102 files in the directory including this README, `env.example.sh`, the three scripts and `wrset.py`. Every case is read by `tests/unit/languages/python_fix/test_pipx_app.py`.
- Runs that only answered a design question (the read-only runs of (c), the upgrade strategies of (d), the uv backend, and constraints the trial never writes) were recorded but are not kept as fixtures; their results are written up below, with the commands that reproduce them.


## Environment

| | |
|---|---|
| pipx | 1.18.4, `/HOME/.local/bin/pipx` (the first `pipx` on the PATH `pa run` uses; the repo's `.venv/bin` has none) |
| shared pip | 26.2.2 (python 3.12.12) |
| apps | `httpie==3.2.2` installed with `--pip-args 'requests==2.25.1'`, then (through `pipx runpip httpie install`) `urllib3==1.26.5 certifi==2020.12.5 pygments==2.7.4` and a local-path dependency `localdep` (1.0) forced in; `localapp` (plain local checkout, `pipx install ./src/localapp`); `editapp` (`pipx install -e ./src/editapp`). The checkouts are tiny setuptools projects (`dependencies=["idna"]`). |
| requirements file | `httpie==3.2.2` and `requests==2.25.1` (what pipx recorded), constraints file `httpie==3.2.2`; pins are positional (`urllib3==1.26.20`). For local apps the requirements line is the checkout path (`-e <path>` for the editable one) and the constraint `<name>==1.0`. |

### Surprise: pipx 1.18.4 picks the uv backend when `uv` is on the PATH

`pipx install` auto-selects the **uv** backend when it finds a uv (the repo's `.venv/bin/uv` 0.13.5 was on the PATH). The first scratch
install therefore made a uv venv (`"backend": "uv"` in `pipx_metadata.json`) whose `runpip` ran `uv pip …` and
whose shared pip was not used. Every pip fixture below was recorded with `PIPX_DEFAULT_BACKEND=pip` (metadata `"backend": "pip"`);
an existing venv keeps its recorded backend regardless. (All 17 apps in the user's real pipx home record `"backend": "pip"`,
read from the metadata files only.) The uv-backend behaviour is in its own section.

## Cases (Step 2)

Exit codes are pipx's. Report column: bytes of `report.json`.

| case | what | exit | report | stderr |
|---|---|---|---|---|
| `baseline` | no pins | 0 | 4034 | empty |
| `upgrade` | pin `urllib3==1.26.20` | 0 | 56668 | empty |
| `conflict` | pin `urllib3==2.2.2` (requests 2.25.1 forbids it); re-recorded without `--quiet` | 1 | none | `ResolutionImpossible`, "Cannot install -r /SCRATCH/work/conflict/reqs.txt (line 2) and urllib3==2.2.2 because these package versions have conflicting dependencies." (pipx appends `'<cmd>' failed`); **stdout** has "The conflict is caused by:" … "requests 2.25.1 depends on urllib3<1.27 and >=1.21.1" |
| `capped_conflict` | an app whose own requirement caps the pin (`cappedapp`, a local checkout with `dependencies=["urllib3<1.26.17"]`, as awscli v1's botocore caps urllib3), pin `urllib3==1.26.19`, `--no-input`, no `--quiet` | 1 | none | "Cannot install -r /SCRATCH/work/capped_conflict/reqs.txt (line 1) and urllib3==1.26.19 …"; stdout: "cappedapp 1.0 depends on urllib3<1.26.17" |
| `deep_capped_conflict`, `deep_range_conflict` | the cap one level down, recorded 2026-11-03 on python 3.13: a local app requiring `requests==2.25.1` (`deepcapapp`), or `requests>=2.25,<2.26` (`deeprangeapp`), pin `urllib3==2.2.2`, `--no-input`, no `--quiet` | 1, 1 | none | "Cannot install requests==2.25.1 and urllib3==2.2.2 …", and with the range "Cannot install deeprangeapp, requests==2.25.1 and urllib3==2.2.2 …" (the app named too); stdout: "requests 2.25.1 depends on urllib3<1.27 and >=1.21.1" (and 2.25.0's with the range) |
| `nosuch` | pin `urllib3==99.0` | 1 | none | "Could not find a version that satisfies the requirement urllib3==99.0 (from versions: …)", "No matching distribution found" |
| `yanked` | pin `certifi==2022.5.18` (yanked) | 0 | 7749 | `WARNING: The candidate selected for download or install is a yanked version: …` + `Reason for being yanked: …`; the report lists it |
| `sdist_only` | pin `pycrypto==2.6.1` (sdist only) | 0 | 5473 | empty. The dry run prepared the sdist's metadata (a build ran, hence the sandbox); the report has `pycrypto` with `requested: true` |
| `main_moves` | requirements `httpie>=3.2.4` with no constraint on httpie | 0 | 12452 | empty; the report lists `httpie 3.2.4` |
| `index_401` | local server answering 401, `--no-input` (Step 5b) | 1 | none | "No matching distribution found for urllib3==1.26.20 (from versions: none)" — **no mention of 401** |
| `index_401_prompt` | same, no `--no-input`, stdin `/dev/null` (Step 5b) | 2 | none | pip prompted, traceback ending `EOFError: EOF when reading a line` (`handle_401` → `_prompt_for_password`); the prompt text `User for 127.0.0.1:8401: ` is on **stdout** |
| `local_unchanged` | local app unchanged | 0 | 919 | empty; the report lists `localapp 1.0`, `is_direct: true` |
| `editable_unchanged` | editable app unchanged | 0 | 953 | empty; lists `editapp 1.0` |
| `local_main_bumped` | checkout bumped to 1.1, constraint `localapp==1.0` | 1 | none | "Cannot install localapp 1.1 (from /…/src/localapp) because these package versions have conflicting dependencies." |
| `local_main_bumped_noconstraint` | same bump, no constraint | 0 | 919 | lists `localapp 1.1` |
| `sourced_dep_bumped` | `localdep` (installed from a path) bumped to 1.1, requirement is its path, no constraint | 0 | 4363 | lists `localdep 1.1` (and Pygments, see below) |
| `sourced_dep_unchanged` | `localdep` unchanged | 0 | 4363 | lists `localdep 1.0` |
| `pip_too_old` | shared pip 22.1 on a python 3.11 pipx home (Step 3) | 2 | none | pip's usage text then `no such option: --dry-run`; nothing is repaired |
| `pip_too_old_py312_repaired` | shared pip 22.1 on the python 3.12 home | 0 | 76438 | the same `no such option: --dry-run`, then `pip in the shared libraries at … does not import, rebuilding them`; pipx rebuilt shared (pip 26.2.2) and re-ran the trial, which succeeded (see "Old pip") |
| `baseline_only_if_needed` | no pins, `--upgrade --upgrade-strategy only-if-needed` (question (d)) | 0 | | empty |
| `pip2621_baseline`, `pip2621_upgrade`, `pip2621_conflict` | shared pip **26.2.1** (the reference machine's), recorded later (Task 4) after the app had been reinstalled: installed `urllib3 1.26.20`, `certifi 2026.10.23`, `pygments 2.21.0`; no pin, pin `urllib3==1.26.19`, pin `urllib3==2.2.2` | 0, 0, 1 | 533, 52362, none | empty, empty, the same `ResolutionImpossible` text as `conflict`. Same shapes as 26.2.2, so 26.2.1 is the oldest verified pip (`pipx_app.OLDEST_VERIFIED_PIP`) |

`baseline`'s report lists `Pygments 2.21.0`: the scratch app was deliberately forced to `pygments==2.7.4`, which `rich 15` (a dependency)
forbids, so pip repairs it. That is a defect of the fixture app, not a pip quirk, but every report of this app carries it.
`pipx_metadata.json` was byte-identical before and after every trial (the recorder compares), because the main package is only
named through `-r`/`-c`.

In every successful report `version` is `"1"`, `pip_version` is `26.2.2` and `environment.python_version` is `3.12`; `install` holds
what pip *would install*, each item with `metadata.name`/`version`, `requested`, `is_direct`, `is_yanked` and `download_info`.

## Step 4

**(a) Does pip honour `-c name==X` for a name it installs from a local path? Yes.** `local_main_bumped` (constraint `localapp==1.0`,
checkout now 1.1) fails with `ResolutionImpossible`; with `localapp==1.1` (not kept: the trial only ever constrains the main package to its installed version) or no constraint it succeeds. The same held for a dependency
installed from a path constrained to its old version (`Cannot install localdep 1.1 (from /…/src/localdep) because …`, exit 1; not kept, for the same reason). So the constraint can pin a local app, and a bumped checkout then surfaces
as a conflict naming the app ("Cannot install localapp 1.1 (from /path)"). Note the conflict message does not say "needs the main
package to move"; the caller must recognise the app's own name in it.

**(b) What does `--report` list for a package already installed at the same version?** Nothing, for a registry package: `baseline`
lists none of httpie, requests, urllib3 …, and `upgrade` lists only `urllib3` (and the fixture's Pygments repair). **A requirement
that names a path is the exception**: `local_unchanged`, `editable_unchanged`, `sourced_dep_unchanged` list the path package at its
*unchanged* version, with `is_direct: true` and a `file://` `download_info.url`, because pip rebuilds a direct-URL requirement every
time. A parser must not read a listed item as "changed" unless its version differs from the installed one.
With `--upgrade`, registry requirements pinned by `==` in the requirements file are *not* listed either (`baseline_only_if_needed`, identical to `baseline`).

**(c) Does pipx write anything outside the venv on a failed trial with `shared` read-only?** No, apart from its own log. Run under
bwrap with `/` read-only and only `pipx_home/logs`, the work directory and the app's lock file writable
(`readonly_trial.sh`), the `conflict` and `nosuch` trials failed with the same pip errors as unsandboxed, and `find -newer` found no
changed file except a new `pipx_home/logs/cmd_*.log` (pipx also deletes old ones). Nothing in `shared`, `.trash`, `bin`, `man`, `venvs/<app>`, the
checkout. **But `pipx runpip` opens the lock `pipx_home/venvs/.<app>.lock` read-write before running pip.** With it on a read-only
mount pipx crashes with a traceback (`OSError: [Errno 30] Read-only file system: '…/venvs/.httpie.lock'`) before pip starts, and pipx does not
create a missing lock when the directory is read-only. The sandbox must bind that one existing file writable (the name is the
canonicalised app name). A successful trial run read-only also printed, on stderr, `WARNING: The directory '/…/.cache/pip' or its parent
directory is not owned or is not writable by the current user. The cache has been disabled.` — exit 0, so stderr is not empty on success.
Outside a sandbox `runpip` for a **local or editable app writes into the source checkout** (see Step 5).

**(c) continued: the local and the editable app, read-only.** `readonly_trial.sh local_unchanged localapp` and `… editable_unchanged editapp`
(same bwrap as above: only logs, work, the app's lock and /tmp writable) **fail, exit 1** (not kept as fixtures; `readonly_trial.sh` reproduces them): pip builds the checkout
in place to get its metadata and setuptools cannot write `<checkout>/<name>.egg-info`
(`error: Cannot update time stamp of directory 'localapp.egg-info'` → `ERROR: Failed to build 'file:///SCRATCH/src/localapp' when getting requirements to build wheel`;
for the editable one `… to build editable`). Nothing else failed first and no other path changed. With the checkout directory additionally bound writable
(`--bind $S/src $S/src`, i.e. whatever holds the checkout) both trials **succeed, exit 0**, and the only files
that changed outside work/ and logs/ were `<checkout>/<name>.egg-info/{PKG-INFO,SOURCES.txt,requires.txt,entry_points.txt,top_level.txt,dependency_links.txt}`.
So a local or editable app's trial must either have its checkout writable (leaving `egg-info` behind in the user's source tree) or run on a copy of the
checkout; with the checkout read-only it cannot be verified and the app must be held (its dependencies can still be planned from the requirements).

**(d) Does a pinned trial with `only-if-needed` change nothing else? Yes, only the pin (plus the fixture's Pygments repair, which the
baseline has too).** With `--upgrade --upgrade-strategy only-if-needed`: baseline = `Pygments`; `urllib3==1.26.20` pin = `urllib3`, `Pygments`;
`markdown-it-py==3.0.0` pin = `markdown-it-py`, `Pygments`. Without `--upgrade`, pip's default behaves the same (`baseline`,
`upgrade`). Contrast `--upgrade-strategy eager`: it also moves `certifi` 2020.12.5 → 2026.10.23. A pin never moved `httpie` or `requests`.

## Old pip (Step 3)

pip 22.1 does not know `--dry-run` or `--report`: exit status 2 (pipx) with `no such option: --dry-run` after pip's usage text and no
report (`pip_too_old`). The shared pip was set with `<shared>/bin/python -m pip install pip==22.1`; `pipx upgrade-shared --pip-args 'pip==22.1'`
cannot do it because pipx adds its own `pip >= 26.1` requirement (ResolutionImpossible). On python 3.12 pip 22.1 cannot even import (no
`distutils`), and `pipx runpip` then **rebuilds the shared libraries itself** and retries, so the trial succeeds with pip 26.2.2
(`pip_too_old_py312_repaired`) — with `shared` read-only that repair would fail. The reliable too-old signal is therefore
reading the shared pip's version (`<PIPX_SHARED_LIBS>/bin/python -m pip --version`, `pip 22.1 from …`) before the trial, as the design says.

## 401 (Step 5b)

- **With `--no-input`:** pip does not prompt and does not hang; it exits 1 at once with "No matching distribution found … (from versions: none)".
  The 401 is **not visible** in stderr, with or without `--quiet` and even with `-v`. A 401 cannot be recognised from pip's output under `--no-input`.
- **Without `--no-input`:** pip prompts `User for <host>:` on **stdout** and reads stdin. With stdin at `/dev/null` it ends at once with
  an `EOFError` traceback (pipx exit 2). With a stdin that stays open it **hangs** (a `sleep 30 |` pipe, run under `timeout`, was killed by the timeout, rc 124).
  So the trial needs `--no-input` (or a closed stdin), and a 401 is then indistinguishable from "no such version" in stderr; the prompt text/`EOFError` is
  the only 401 signature, and only without `--no-input`. Reported to the controller as a design issue: detect credentials some other way, or run the first
  attempt without `--no-input` and stdin closed and look for `handle_401` / `User for`.
- 403 was not recorded.

## uv backend (design: "same call, without --report")

Observed (not kept as fixtures; pa never runs the trial on a uv-backend app) in a home whose app has `"backend": "uv"` (`uv 0.13.5`). pipx turns `runpip … install …` into `uv pip install --python <venv>/bin/python …`:
- with `--report`: `--report` is rejected, `error: unexpected argument '--report' found`, exit 2. It must not be passed.
- `--dry-run --quiet`: uv prints nothing, exit 0. The `Would install` lines need no `--quiet`.
- without `--quiet`, pin `urllib3==1.26.20`: `Resolved 17 packages`, `Would uninstall 1 package`, `Would install 1 package`, ` - urllib3==1.26.5`, ` + urllib3==1.26.20`.
- without `--quiet`, the 401 server: exit 1, "urllib3 was not found in the package registry" **plus** `hint: An index URL (…) could not be queried due to a lack of valid authentication credentials (401 Unauthorized)` — uv does name the 401.

## Step 5 (#73): what writes outside the app's venv

Method (re-derivable; raw strace logs are not kept). In the scratch shell (`. env.example.sh`), per command and app:
`strace -f -e trace=%file -o $S/work/strace/<name>.log <command>` then `python wrset.py $S/work/strace/<name>.log`. Commands:
`pipx reinstall <app>`, `pipx upgrade <app>`, `pipx install --force [-e] <spec>` (`<spec>` is `httpie==3.2.2`, `$S/src/localapp`, or `-e $S/src/editapp`),
`pipx runpip <app> install --dry-run --report $S/work/rp_<app>.json --quiet -r $S/work/r_<app>.txt -c $S/work/c_<app>.txt` (r_ file: the requirement/path/`-e path` line;
c_ file: `<app>==<version>`), and `pipx reinstall-all` once, each for `httpie`, `localapp` (plain local) and `editapp` (editable). `wrset.py` keeps successful writes
only (write-mode opens, mkdir, rename, unlink, symlink, chmod, …). strace shows many `unlinkat`s relative to a directory fd that cannot be placed, so the runpip rows
were cross-checked with `touch $S/work/ts2; sleep 1.1; pipx runpip … ; find $S/pipx_home $S/src $S/bin $S/man -newer $S/work/ts2`, which showed only `logs/cmd_*.log`
(all apps), plus `<checkout>/<name>.egg-info/*` (local, editable) and nothing under `shared`.

| command | outside the venv, other than `/tmp` pip scratch dirs |
|---|---|
| `reinstall <app>` | `pipx_home/.trash/` (mkdir), `.trash/<app>-<rand>-pipx-reinstall` (mkdir, rename of the old venv into it, rmdir); `pipx_home/logs/cmd_*.log` (create, unlink old); `pipx_home/.shared.lock` (open, create); `bin/<exe>` symlinks (unlink, symlink); `man/man1/*` symlinks (httpie only); `<checkout>/<name>.egg-info/tmp*` (local and editable: setuptools metadata in the source tree); `/tmp/pip-*` |
| `upgrade <app>` | `logs/cmd_*.log`; `.trash` (rmdir); `~/.cache/pip` (httpie; pip's cache); the checkout's `egg-info/` (local, editable). No bin/man change, no `.shared.lock` |
| `install --force [-e] <spec>` | `logs/cmd_*.log`; `.shared.lock`; `bin/` and `man/` symlinks; the checkout's `egg-info/` (local, editable). No `.trash` use |
| `reinstall-all` | everything `reinstall` does for the three apps: `.trash/<app>-*-pipx-reinstall` for each, `logs/`, `.shared.lock`, `bin/` (5 links), `man/` (3), `egg-info/` in both checkouts |
| `runpip <app> install --dry-run …` | `logs/cmd_*.log` (create, unlink old); `venvs/.<app>.lock` (opened read-write); `/tmp/pip-*`; the `--report` file; **local and editable apps: `<checkout>/<name>.egg-info/*`** (metadata generation in the source tree; the `build/` dir also appeared there from the install). Nothing in `shared`, `.trash`, `bin`, `man` |

None of these wrote into `pipx_home/shared` (no `shared` path was opened for writing; `.shared.lock` beside it is). `pipx_home/py` (standalone pythons) was not touched.
Note for the sandbox: `.trash` and `.shared.lock` live directly in `PIPX_HOME`, `logs` too; `bin` and `man` are separate directories
(`PIPX_BIN_DIR`, `PIPX_MAN_DIR`, the latter not forwarded by `pa run`); the source checkout is written by every command that builds a local app.

Also observed: **`reinstall`, `upgrade`, `install --force` and `reinstall-all` all drop what an earlier `pipx runpip … install` forced into the
venv** (`urllib3`, `certifi`, `pygments` and even `requests` went to the newest versions: `requests` 2.25.1 → 2.34.2, `urllib3` 1.26.5 → 2.8.0; the recorded `pip_args` were `[]` by then, because my later `install --force` calls omitted `--pip-args`), so a later `pipx reinstall` undoes pinned fixes, as the design warns. `pipx upgrade httpie` moved httpie 3.2.2 → 3.2.4.

### Reproducing the user's failure on main with `pa run pipx reinstall <local app>`

Run from `/SCRATCH`, repo `.venv/bin/pa` (HEAD `76560da`, branch `pa-fix-pipx-tools`), real `HOME`, with the scratch `PIPX_HOME`/`PIPX_BIN_DIR` exported
(`pa run` forwards `PIPX_HOME`, and passes `PIPX_BIN_DIR` itself; the real pipx home is not in the command at all, and `localapp` exists
only in the scratch home), after `pipx environment` showed scratch paths.

1. `pa run pipx reinstall localapp` with only those two variables: exit 1 — **"Post-run scan target is missing after the install: …/venvs/localapp/lib/python3.12/site-packages. Cannot safely scan for new packages — treating as scan failure."**, then "Restored site-packages (38 files)" / "Restored bin". pipx itself printed `installed package localapp 1.0, installed using Python 3.13.13`: inside the sandbox `PIPX_DEFAULT_PYTHON`
   (set in my environment to 3.12) is not forwarded, so pipx made a 3.13 venv, the scan target `lib/python3.12/site-packages` no longer existed, and the snapshot restore put a 3.12 `site-packages`
   into the 3.13 venv (`lib/` then held both `python3.12` and `python3.13`). Not the #73 text. Caveat: this is caused by my scratch default python differing from pipx's own; I could not tell whether it matches the user's report.
2. With `--env PIPX_DEFAULT_PYTHON --env PIPX_DEFAULT_BACKEND --env PIPX_MAN_DIR`: `pa run pipx reinstall localapp`, `reinstall httpie`, `reinstall editapp`, `reinstall-all` and `install --force <local path>` all **succeeded** (exit 0, "Post-install scan: no new packages detected").
   **The #73 error ("Failed to delete <venv>. Will move it to a temp folder", `OSError: [Errno 30] Read-only file system`) did not reproduce on this machine** with pipx 1.18.4 and this `pa`.
   `.trash` was never used. I could not see the sandbox's bind list (`pa -v run` prints none). The sandbox's targets for a named tool
   do list the venv's `site-packages` as a write dir (`languages/python.py` `resolve_sandbox_targets`), as the issue says, but removal worked here.
   Likely differences to check on the user's machine: its pipx (different version, or uv-tool pipx on python 3.13), a venv created by a different python, filesystem (EXDEV across mounts is filesystem specific).

Outputs of both runs are quoted from `work/pa_reinstall_run1_py313.out` and `work/pa_reinstall.out` in the scratch directory.

## The trial in pa fix's own sandbox (Task 4, Steps 0a and 0b)

Measured 2026-11-02 against this scratch home (`PA_PIPX_SCRATCH=$HOME/pa-scratch-pipx`, `. env.example.sh`), never the real `~/.local/pipx`,
by running `pipx_app.trial_argv()` through `_FixTrialRunner.in_copy()` and `SandboxRunner.run_captured(scratch=True)` as pa fix does,
with the real bwrap sandbox. Container isolation (`PA_SANDBOX_ISOLATION=container`) **could not be measured here**: it refuses to run
with credentials in `$HOME` (`.ssh`, `.aws`, `.gnupg`, `.git-credentials`, `.docker`), so the container trial is "could not verify".

**Step 0a — what pipx needs in the trial sandbox.**
- **pipx runs pip in the app's venv directory** (`PipBackend.run_raw_pip()` passes `run_dir=<venv>`), not in its own working directory. With
  `-r reqs.txt -c cons.txt --report report.json` relative, pip failed (`Could not open constraint file: … 'cons.txt'`) although both files were in the
  sandbox's working directory, and a relative `--report` would be written into the venv. The trial therefore names its files by absolute path in the
  scratch copy (`trial_argv(…, workdir=<copy>)`); `in_copy()` builds that argv from the copy's path. The Task 1 recordings used absolute paths, which is
  why they did not show this.
- **Startup:** pipx (a uv tool, `~/.local/share/uv/tools/pipx`), the app venv, `shared` and the pip config files were all readable through the
  sandbox's read-only binds (`PIPX_HOME` is a runtime home directory). pipx's log went to the existing tmpfs over `PIPX_HOME/logs`
  (`_post_ro_tmpfs_dirs`): the host's `logs/` kept its 10 files, nothing new. pipx 1.18.4 has no `PIPX_LOG_DIR`.
- **The lock:** without a writable `venvs/.<app>.lock` pipx crashed (`OSError: [Errno 30] Read-only file system: '…/venvs/.httpie.lock'`, the
  traceback through `filelock`) before pip ran. With that one file bound writable (`scratch_write_files()`) the trials ran: no pin (exit 0, empty
  report), `urllib3==1.26.19` (exit 0, lists `urllib3 1.26.19`), `urllib3==2.2.2` (exit 0 here, since `requests==2.25.1` is not a recorded requirement
  of this app; lists `urllib3 2.2.2`, `requests 2.34.2`). Every app's `pipx_metadata.json` was byte-identical afterwards, and nothing under the
  scratch home changed (`find -newer`) except, for the local apps, their checkouts' `egg-info`.
- **Local and editable apps:** with the checkout outside `sandbox.editable_roots` the run is refused before pipx starts
  (`sandbox.editable_roots does not include /SCRATCH/src/localapp, which this command builds in place`); with `/SCRATCH/src` added, `localapp` and
  `editapp` both resolved (reports list `localapp 1.0`, `editapp 1.0`) and only `<checkout>/<name>.egg-info/*` changed, as in (c).

**Step 0b — configuration parity.** `pipx runpip httpie config debug` run with the trial's exact binds and environment (scratch run) and with the
fix's (`_assemble_sandbox(read_only=False)` for `pipx runpip httpie install urllib3==1.26.19`, as `pa run` assembles it), plus `env`:
- identical environment: `HOME`, `PIPX_HOME`, `PIP_REQUIRE_VIRTUALENV=true` and `VIRTUAL_ENV` (both from this shell), and the variables pipx itself sets
  (`PIP_DISABLE_PIP_VERSION_CHECK=1`, `PIP_KEYRING_PROVIDER=subprocess`, `PIP_USER=0`);
- identical files: `/etc/xdg/pip/pip.conf`, `/etc/pip.conf` (absent), `<venv>/pip.conf` (absent), `~/.pip/pip.conf` (absent),
  `~/.config/pip/pip.conf` (present, readable in both);
- the only differences were the working directory (the scratch copy; the fix's directory) and what is writable (the fix: its directory, `venvs`, the
  app's `site-packages` and `bin`, `~/.cache/pip`, `~/.cache/uv`; the trial: the copy and the app's lock). pip's own working directory is the venv
  in both, so a relative path in a setting names the same file. What can still differ is the extra environment each is given (`--env`), which
  `pipx_app.config_problem(trial_env, apply_env)` compares.

## Without --quiet

pip prints a conflict's cause ("The conflict is caused by:" and one "<parent> <version> depends on <requirement>"
line per requirement) at its default verbosity only, and on **stdout**; with `--quiet` it prints only stderr's
"Cannot install …", which names a requirement from a file as `-r <path> (line N)` (the trial's scratch file). So the
trial runs without `--quiet` and `parse_pip_trial()` reads the cause from stdout, and `record_trial.sh` no longer
passes `--quiet`. Re-recorded (with pip 26.2.2): `conflict` (in the Task 1 home, with the same requirements and pin) and
the new `capped_conflict` (a second scratch home, `cappedapp` installed from `/SCRATCH/src/cappedapp` with
`urllib3==1.26.5` forced in). Re-running `nosuch` and `yanked` without `--quiet` changed stderr only in the command
pipx echoes (no `--quiet` in it); those fixtures were kept. Without `--quiet` stdout also carries pip's progress lines
(`Collecting …`), which the parser does not read.
