#!/usr/bin/env bash
#
# determinism.sh — the engine's output must be byte-identical at any thread
# count, and identical to the pre-parallel binary.
#
# For every CGF fixture set scripts/e2e-core.sh uses (every dir under
# testdata/cgf, plus the cross-repo multi---cgf combos) it runs
#
#   taint --threads 1   twice
#   taint --threads 8   twice
#   the BASELINE binary once (built from the unmodified phase-timing tree)
#
# and diffs the four stdout captures byte-for-byte. stderr is NOT diffed (the
# phase meters carry wall time), but every run of the new binary must print
# at least one {"phase":...} JSON line — the meters must survive.
#
# Differences fall in two classes, both reported, never hidden:
#   THREAD-DIFF   the new binary disagrees with itself across runs/threads —
#                 a determinism bug, the harness fails.
#   CHAIN-DIFF    the new binary (threads=1) differs from the baseline. The
#                 old load order came from read_dir, which is filesystem
#                 order — if sorted load order changes chains on a fixture,
#                 the old binary's output there was run-to-run random. That
#                 is a found bug in the OLD binary; the harness prints the
#                 diff and fails so the finding cannot be missed.
#
# Usage:  scripts/determinism.sh
# Env:
#   PC            new binary          (default: core/target/release/panopticode, built if absent)
#   BASE          baseline binary     (default: built from a temp copy of PHASE_TIMING/core)
#   PHASE_TIMING  unmodified source tree of the pre-parallel branch
#                 (default: auto-detect .worktrees/phase-timing next to the repo)
#   CGF           golden CGF root     (default: testdata/cgf)
#   CATALOG       catalog file        (default: catalog.example.toml)
#   THREADS_A     first thread count  (default 1)
#   THREADS_B     second thread count (default 8)
#   NOBUILD       set to 1 to skip cargo builds
# ---------------------------------------------------------------------------
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PC="${PC:-$ROOT/core/target/release/panopticode}"
CGF="${CGF:-$ROOT/testdata/cgf}"
CATALOG="${CATALOG:-$ROOT/catalog.example.toml}"
THREADS_A="${THREADS_A:-1}"
THREADS_B="${THREADS_B:-8}"
OUT="${OUT:-${TMPDIR:-/tmp}/pc-determinism}"

FAILED=0
TOTAL=0
declare -a THREAD_DIFFS=() CHAIN_DIFFS=()

die() { echo "determinism.sh: $*" >&2; exit 2; }

if [ "${NOBUILD:-0}" != "1" ]; then
  echo "== build new binary (release) =="
  ( cd "$ROOT/core" && cargo build --release ) || die "cargo build --release (new)"
fi
[ -x "$PC" ] || die "no new binary at $PC"
[ -d "$CGF" ] || die "no golden CGF at $CGF"
[ -f "$CATALOG" ] || die "no catalog at $CATALOG"

# ---- baseline: the unmodified pre-parallel tree ----
if [ -z "${BASE:-}" ]; then
  PT="${PHASE_TIMING:-}"
  if [ -z "$PT" ]; then
    for c in "$ROOT/.worktrees/phase-timing" "$ROOT/../phase-timing"; do
      [ -d "$c/core/src" ] && { PT="$(cd "$c" && pwd)"; break; }
    done
  fi
  [ -n "$PT" ] || die "cannot find the phase-timing tree; set PHASE_TIMING or BASE"
  BLD="${TMPDIR:-/tmp}/pc-det-baseline-src"
  echo "== build baseline from $PT (copy at $BLD) =="
  rm -rf "$BLD"; mkdir -p "$BLD/core"
  # copy WITHOUT target/: the source of truth is the working tree, uncommitted
  # changes included, and the copy must not touch that tree. core/build.rs
  # compiles ../proto/cgf.proto, so the copy mirrors core/ + proto/.
  ( cd "$PT/core" && tar -cf - --exclude target . ) | ( cd "$BLD/core" && tar -xf - )
  ( cd "$PT" && tar -cf - proto catalog.example.toml ) | ( cd "$BLD" && tar -xf - )
  ( cd "$BLD/core" && cargo build --release ) || die "cargo build --release (baseline)"
  BASE="$BLD/core/target/release/panopticode"
fi
[ -x "$BASE" ] || die "no baseline binary at $BASE"
echo "new:      $PC"
echo "baseline: $BASE"
echo

rm -rf "$OUT"; mkdir -p "$OUT"

# run <tag> <binary> [taint args...] — stdout to $OUT/<tag>.json, stderr tagged
run() {
  local tag="$1"; shift
  "$1" taint --catalog "$CATALOG" "${@:2}" > "$OUT/$tag.json" 2> "$OUT/$tag.err"
}

check() { # check <fixture> <a-tag> <b-tag> <what>
  if ! cmp -s "$OUT/$2.json" "$OUT/$3.json"; then
    echo "  $4 on $1:"
    diff "$OUT/$2.json" "$OUT/$3.json" | head -8 | sed 's/^/    /'
    echo "    (full diff: $OUT/$2.json vs $OUT/$3.json)"
    return 1
  fi
  return 0
}

fixture() { # fixture <name> [cgf dirs...] — NOBASE=1 skips the baseline gate
  local name="$1"; shift
  TOTAL=$((TOTAL + 1))
  local dirs=() d
  for d in "$@"; do dirs+=(--cgf "$CGF/$d"); done

  run "$name-a1"      "$PC" "${dirs[@]}" --threads "$THREADS_A"
  run "$name-a1-rep"  "$PC" "${dirs[@]}" --threads "$THREADS_A"
  run "$name-a8"      "$PC" "${dirs[@]}" --threads "$THREADS_B"
  run "$name-a8-rep"  "$PC" "${dirs[@]}" --threads "$THREADS_B"
  run "$name-base"    "$BASE" "${dirs[@]}"

  local bad=0 chain=0
  # the phase meters must survive threading
  for t in a1 a1-rep a8 a8-rep; do
    grep -q '"phase":' "$OUT/$name-$t.err" \
      || { echo "  no {\"phase\":...} meter line on stderr ($name-$t)"; bad=1; }
  done
  check "$name" "$name-a1" "$name-a1-rep" "repeat at --threads $THREADS_A differs"   || bad=1
  check "$name" "$name-a8" "$name-a8-rep" "repeat at --threads $THREADS_B differs"   || bad=1
  check "$name" "$name-a1" "$name-a8"     "--threads $THREADS_A vs $THREADS_B differ" || bad=1
  # CHAIN-DIFF vs the baseline is reported, never hidden — but it is a
  # finding against the OLD binary's read_dir order, not thread nondeterminism.
  # NOBASE=1: the fixture was built to expose a defect the baseline binary
  # CONTAINS (it predates the fix), so its output there is the very
  # run-to-run coin toss under test — the comparison is shown, not gated, and
  # the baseline is run a second time to demonstrate the old binary
  # disagreeing with ITSELF.
  if [ "${NOBASE:-0}" = 1 ]; then
    run "$name-base2" "$BASE" "${dirs[@]}"
    if ! cmp -s "$OUT/$name-base.json" "$OUT/$name-base2.json"; then
      echo "  old binary disagrees with itself on $name across two runs — the \
run-to-run randomness this fixture exposes (informational, not a gate)"
    fi
    if ! cmp -s "$OUT/$name-a1.json" "$OUT/$name-base.json"; then
      echo "  differs from the baseline binary on $name — expected: the \
baseline predates the fix this fixture verifies (informational, not a gate)"
    fi
  else
    check "$name" "$name-a1" "$name-base" "differs from baseline binary" || chain=1
  fi
  if [ "$chain" = 1 ]; then
    CHAIN_DIFFS+=("$name")
    echo "FAIL: $name (CHAIN-DIFF vs baseline)"
    FAILED=1
  elif [ "$bad" = 1 ]; then
    THREAD_DIFFS+=("$name")
    echo "FAIL: $name (THREAD-DIFF — determinism bug)"
    FAILED=1
  else
    echo "PASS: $name"
  fi
}

# ---- every fixture set e2e-core.sh uses: all dirs under testdata/cgf ----
# routeorder gates on the new binary only: the baseline's route choice
# depends on its per-process hash order, so its output flips between runs
# (the comparison still runs and is reported).
for f in "$CGF"/*/; do
  n="$(basename "$f")"
  case "$n" in
    routeorder) NOBASE=1 fixture "$n" "$n" ;;
    *) fixture "$n" "$n" ;;
  esac
done

# ---- cross-repo combos, both --cgf orders (dir order decides last-wins) ----
fixture xrepo-fbd federation backend downstream
fixture xrepo-dbf downstream backend federation
fixture xrepo-wfb webapp federation backend

# ---- contested contract names: two repos define the same GraphQL field ----
# gviolet's resolver reaches a SQL sink over the ledger service, gquiet's
# reaches a sink-less handler; gweb's TS $op calls the shared field by name.
# The published view of the shared contract decides whether the client has a
# finding, so any per-process choice between the two repos shows up here.
fixture sharer-ledger sharer-gledger
fixture sharer-ping sharer-gping
fixture sharer-violet sharer-gviolet
fixture sharer-quiet sharer-gquiet
fixture sharer-gweb sharer-gweb
# The combos gate on the new binary only: the baseline predates the union
# contract view, so on them its output is the coin toss this fixture group
# exists to expose (the comparison still runs and is reported).
NOBASE=1 fixture sharer-all sharer-gledger sharer-gping sharer-gquiet sharer-gviolet sharer-gweb
NOBASE=1 fixture sharer-all-rev sharer-gweb sharer-gviolet sharer-gquiet sharer-gping sharer-gledger

# ---- cross-process: N separate processes must agree byte for byte ----
# Threads and repeats inside one process cannot catch a per-PROCESS seed: the
# engine's HashMap iteration order is re-randomised by the OS for every exec,
# so state built once per process (contract views, compose fixpoint winners)
# can still flip across processes at --threads 1. That is exactly the
# world-scale defect: two runs, same binary, same flags, different chains.
# Run the input N times as N processes and require one distinct stdout.
CROSSRUNS="${CROSSRUNS:-12}"
crossproc() { # crossproc <name> [cgf dirs...]
  local name="$1"; shift
  TOTAL=$((TOTAL + 1))
  local dirs=() d
  for d in "$@"; do dirs+=(--cgf "$CGF/$d"); done

  local i=0 bad=0
  while [ "$i" -lt "$CROSSRUNS" ]; do
    run "$name-x$i" "$PC" "${dirs[@]}" --threads 1
    i=$((i + 1))
  done
  i=1
  while [ "$i" -lt "$CROSSRUNS" ]; do
    check "$name" "$name-x0" "$name-x$i" "cross-process run $i differs" || bad=1
    i=$((i + 1))
  done
  if [ "$bad" = 1 ]; then
    THREAD_DIFFS+=("$name (cross-process)")
    echo "FAIL: $name (CROSS-PROCESS — a fresh exec changed the output)"
    FAILED=1
  else
    echo "PASS: $name (cross-process, $CROSSRUNS execs)"
  fi
}

crossproc xcross-fbd federation backend downstream
crossproc xcross-wfb webapp federation backend
crossproc xcross-sharer sharer-gledger sharer-gping sharer-gquiet sharer-gviolet sharer-gweb
crossproc xcross-routeorder routeorder

echo
echo "==== summary ===="
echo "fixtures passed: $((TOTAL - ${#THREAD_DIFFS[@]} - ${#CHAIN_DIFFS[@]})) of $TOTAL"
echo "thread diffs:  ${#THREAD_DIFFS[@]}  ${THREAD_DIFFS[*]:-}"
echo "chain diffs:   ${#CHAIN_DIFFS[@]}  ${CHAIN_DIFFS[*]:-}"
if [ "$FAILED" = 0 ]; then
  echo "ALL IDENTICAL — stdout is byte-equal across $THREADS_A/$THREADS_B threads and vs the baseline."
else
  echo "DIFFERENCES FOUND — see above; chain diffs are findings against the OLD binary's read_dir order, not noise."
fi
exit "$FAILED"
