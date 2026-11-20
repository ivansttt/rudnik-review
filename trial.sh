#!/bin/sh
# The release on a clean machine (spec 1746, 13 Nov 2026): 12 Nov's worst defects were found by hand, a wheel installed into an empty HOME
# and run on a two-file repository, and nothing repeated that run. This is it, in plain sh so Git Bash on Windows runs it as a Mac does:
# `sh trial.sh [<what uv installs>]`, the release repository by default. It needs the network for setup, as a developer does.
set -u
what=${1:-git+https://github.com/ivansttt/rudnik-review}
t=$(mktemp -d) || exit 2
trap 'rm -rf "$t"' EXIT
# an empty HOME: uv's tool folders named too, since uv and Python on Windows read the profile folder, not HOME. git keeps the developer's own
# config and gh login, as the release repository is private (13 Nov 2026: uv's clone asked for a username in the empty HOME)
export GIT_CONFIG_GLOBAL="${GIT_CONFIG_GLOBAL:-$HOME/.gitconfig}" GH_CONFIG_DIR="${GH_CONFIG_DIR:-$HOME/.config/gh}"
export HOME="$t/home" USERPROFILE="$t/home" UV_TOOL_DIR="$t/home/tools" UV_TOOL_BIN_DIR="$t/home/bin" PATH="$t/home/bin:$PATH"
unset XDG_CONFIG_HOME XDG_DATA_HOME XDG_STATE_HOME XDG_CACHE_HOME XDG_BIN_HOME
mkdir "$HOME" "$t/repo" || exit 2
fail() { echo "trial: failed on $(uname -s) $(uname -m): $*"; exit 1; }
run() {   # <name> <command...>: its lines and its exit printed, the lines kept in $t/<name> and the whole run's in $t/all
  name=$1; shift; echo "\$ $*"; "$@" >"$t/$name" 2>&1; rc=$?; cat "$t/$name"; cat "$t/$name" >>"$t/all"; echo "exit $rc"; return "$rc"
}
run install uv tool install "$what" || fail "uv tool install $what exited $rc"
cd "$t/repo" || exit 2
git init -q -b master || fail "no git"
git -c user.name=trial -c user.email=trial@example.invalid commit -q --allow-empty -m trial || fail "no first commit"
printf 'import os\n\neval(input())\n\n\ndef double(x):\n    return x * 2\n' >a.py
printf 'eval(location.hash);\n' >b.ts
run help rudnik-review --help || fail "--help exited $rc"
run setup rudnik-review setup || fail "setup exited $rc"
checked() {   # <name>: `check` run as <name>, judged: exit 1, each file's eval an error and no annotation an error
  run "$1" rudnik-review check; [ "$rc" -eq 1 ] || fail "$1 exited $rc, not 1"
  grep -q '^error a\.py:3 ' "$t/$1" || fail "$1: a.py:3 eval(input()) does not block"
  grep -q '^error b\.ts:1 ' "$t/$1" || fail "$1: b.ts:1 eval(location.hash) does not block"
  ! grep '^error .* ANN[0-9]' "$t/$1" || fail "$1: an annotation blocks"
  ! grep 'site-packages' "$t/$1" || fail "$1: a rule is named by this machine's path, not as the gate names it"
}
checked check
run init rudnik-review init || fail "init exited $rc"
checked "check after init"
# the change made clean passes (14 Nov 2026: the trial proved only that a defect blocks)
printf 'def double(x: int) -> int:\n    return x * 2\n' >a.py
printf 'export const double = (x: number): number => x * 2;\n' >b.ts
run clean rudnik-review check; [ "$rc" -eq 0 ] || fail "a clean change exited $rc, not 0"
! grep -E 'Traceback|\[Errno|fatal:' "$t/all" || fail "the run above broke"
echo "trial: ok on $(uname -s) $(uname -m)"
