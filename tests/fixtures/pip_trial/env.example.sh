# Isolation for every pipx command in this directory. Source it (the scripts do);
# it refuses to continue unless every pipx location is under $PA_PIPX_SCRATCH.
#   export PA_PIPX_SCRATCH=$HOME/pa-scratch-pipx   # must be an existing, empty-or-scratch directory, never ~/.local/...
#   export PA_PIPX_PYTHON=/path/to/python3.12      # optional, absolute
: "${PA_PIPX_SCRATCH:?set PA_PIPX_SCRATCH to a scratch directory first}"
case "$PA_PIPX_SCRATCH" in /*) ;; *) echo "PA_PIPX_SCRATCH must be absolute" >&2; return 1 2>/dev/null || exit 1;; esac
S=$(cd "$PA_PIPX_SCRATCH" && pwd -P) || { echo "no such directory: $PA_PIPX_SCRATCH" >&2; return 1 2>/dev/null || exit 1; }
# Both compared canonically: $S is, and a $HOME that is a link must not let the real home through.
REAL_HOME=$(cd "$HOME" && pwd -P) || { echo "no such directory: $HOME" >&2; return 1 2>/dev/null || exit 1; }
# ~/.local may itself be a link: its target is refused too, under either spelling.
REAL_LOCAL=$(cd "$REAL_HOME/.local" 2>/dev/null && pwd -P) || REAL_LOCAL=$REAL_HOME/.local
case "$S" in "$REAL_HOME/.local"*|"$REAL_LOCAL"|"$REAL_LOCAL"/*|"$REAL_HOME"|/) echo "refusing scratch root $S" >&2; return 1 2>/dev/null || exit 1;; esac
export S
# A name the scripts join onto a path (a case, an app) must be one plain component.
pa_plain_name() {
  case "$2" in ""|.|..|*/*) echo "$1 must be a single path component, not '$2'" >&2; return 1;; esac
}
export PIPX_HOME=$S/pipx_home PIPX_SHARED_LIBS=$S/pipx_home/shared
export PIPX_BIN_DIR=$S/bin PIPX_MAN_DIR=$S/man PIPX_COMPLETION_DIR=$S/comp
export PIPX_GLOBAL_HOME=$S/gh PIPX_GLOBAL_BIN_DIR=$S/gbin PIPX_GLOBAL_MAN_DIR=$S/gman PIPX_GLOBAL_COMPLETION_DIR=$S/gcomp
export PIPX_DEFAULT_BACKEND=pip   # pipx 1.18.4 picks uv when uv is on the PATH
[ -n "${PA_PIPX_PYTHON:-}" ] && export PIPX_DEFAULT_PYTHON=$PA_PIPX_PYTHON
# Whether $1, resolved (what does not exist yet as written), lies under $S. A link anywhere on
# the way (pipx_home, its venvs, work) must not lead the scripts outside the scratch root.
pa_in_scratch() {
  _r=$(realpath -m -- "$1") || return 1
  case "$_r" in "$S"|"$S"/*) return 0;; *) return 1;; esac
}
# The recorders delete under $S/work: a link there would have them delete wherever it leads.
for d in "$S/bin" "$S/work"; do
  [ -L "$d" ] && { echo "$d is a link; remove it" >&2; return 1 2>/dev/null || exit 1; }
done
mkdir -p "$S/bin" "$S/work"
# Verify what pipx itself derives, not just what we set.
for v in PIPX_HOME PIPX_BIN_DIR PIPX_MAN_DIR PIPX_SHARED_LIBS PIPX_LOCAL_VENVS PIPX_LOG_DIR PIPX_TRASH_DIR PIPX_COMPLETION_DIR; do
  p=$(pipx environment 2>/dev/null | sed -n "s/^$v=//p" | tail -1)
  case "$p" in "$S"/*|"$S") ;; *) echo "isolation check failed: $v=$p is not under $S" >&2; return 1 2>/dev/null || exit 1;; esac
  pa_in_scratch "$p" || { echo "isolation check failed: $v=$p resolves outside $S" >&2; return 1 2>/dev/null || exit 1; }
done
