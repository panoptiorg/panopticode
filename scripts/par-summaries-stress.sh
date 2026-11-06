#!/bin/sh
#
# par-summaries-stress.sh — the parallel-summaries correctness battery.
#
# The summaries phase schedules SCCs onto a thread pool; its result must not
# depend on the schedule. This script pins that down end to end on the corpus
# that carries the production edge class (a TS $op callsite in webapp linked
# to the GraphQL contract whose Go resolver in federation/backend holds the
# sink):
#
#   1. --threads 1 / 8 / 64, twice at 1 — stdout must be byte-identical;
#   2. PC_SCHED_SHUFFLE=1 stress rounds (shuffled ready-scan + randomized
#      per-SCC delays) at 8 and 64 threads — same stdout;
#   3. --verify-summaries on every run: after the parallel phase every
#      summary is recomputed sequentially in SCC order and compared; the
#      check must report 0 differences.
#
# Usage: scripts/par-summaries-stress.sh [path-to-panopticode]
#   (default: core/target/release/panopticode; build it first)
set -eu
cd "$(cd "$(dirname "$0")/.." && pwd)"
PC="${1:-core/target/release/panopticode}"
[ -x "$PC" ] || { echo "no binary at $PC (cargo build --release)" >&2; exit 2; }

OUT="${OUT:-$(mktemp -d)}"
trap 'rm -rf "$OUT"' EXIT
CGF="--cgf testdata/cgf/webapp --cgf testdata/cgf/federation --cgf testdata/cgf/backend"

run() {
  tag=$1
  shift
  env "$@" "$PC" taint $CGF --verify-summaries > "$OUT/$tag.out" 2> "$OUT/$tag.err"
  v=$(grep verify-summaries "$OUT/$tag.err")
  case "$v" in
    "verify-summaries: 0 differences") ;;
    *) echo "FAIL $tag: $v" >&2; exit 1 ;;
  esac
  echo "ok  $tag  findings=$(wc -l < "$OUT/$tag.out" | tr -d ' ')  ($v)"
}

run t1        PANOPTICODE_THREADS=1
run t8        PANOPTICODE_THREADS=8
run t64       PANOPTICODE_THREADS=64
run t1-again  PANOPTICODE_THREADS=1
run s8a       PC_SCHED_SHUFFLE=1 PANOPTICODE_THREADS=8
run s8b       PC_SCHED_SHUFFLE=1 PANOPTICODE_THREADS=8
run s64a      PC_SCHED_SHUFFLE=1 PANOPTICODE_THREADS=64
run s64b      PC_SCHED_SHUFFLE=1 PANOPTICODE_THREADS=64

echo "--- stdout cmp vs t1 ---"
fail=0
for t in t8 t64 t1-again s8a s8b s64a s64b; do
  if cmp -s "$OUT/t1.out" "$OUT/$t.out"; then
    echo "identical  $t"
  else
    echo "DIFFERS    $t" >&2
    fail=1
  fi
done
exit $fail
