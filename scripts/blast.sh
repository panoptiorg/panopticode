#!/usr/bin/env bash
#
# blast.sh — PG-backed blast radius for a changed repo.
# NO extraction: computes the repo's changed files (git diff vs --base,
# including uncommitted worktree changes) and hands them to
# `panopticode query blast`, which maps them to persisted fn nodes via
# nodes.span_file and walks edges backwards (calls / binds_to /
# invokes_remote) to every upstream repo and boundary endpoint.
#
# Usage:
#   scripts/blast.sh <repo-path> [--base <ref>]
#
# Env:
#   PC_PG_PORT  host port for Postgres (default 5433)
#   PC_PG_URL   connection URL (default postgres://panopticode:panopticode@localhost:$PC_PG_PORT/panopticode)
#   PC          core binary    (default <root>/core/target/debug/panopticode)
#
# Examples:
#   scripts/blast.sh "$CORPUS/ledger-svc" --base origin/main
#
# Prereq: a full `scripts/analyze.sh --pg` run keeps the PG graph fresh; a
# staleness warning is printed when repos.commit_sha differs from the repo HEAD.
#
# This walks the CALL graph persisted in Postgres. The dataflow graph is never
# persisted — it exists only in memory during a taint run — so this answers
# "which repos and endpoints can reach this change", not "is it tainted".
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PC="${PC:-$ROOT/core/target/debug/panopticode}"
PC_PG_PORT="${PC_PG_PORT:-5433}"
PC_PG_URL="${PC_PG_URL:-postgres://panopticode:panopticode@localhost:$PC_PG_PORT/panopticode}"

REPO_PATH=""
BASE="origin/master"
while [ $# -gt 0 ]; do
  case "$1" in
    --base) BASE="$2"; shift 2 ;;
    -*) echo "blast.sh: unknown flag $1" >&2; exit 1 ;;
    *) REPO_PATH="$1"; shift ;;
  esac
done
[ -n "$REPO_PATH" ] && [ -d "$REPO_PATH" ] || { sed -n '2,18p' "$0"; exit 1; }
[ -x "$PC" ] || { echo "blast.sh: $PC not built — run 'cargo build' in core/" >&2; exit 1; }

# canonical repo id = go.mod module path (what pc-fe emits as CgfPackage.repo)
REPO="$(awk '/^module /{print $2; exit}' "$REPO_PATH/go.mod" 2>/dev/null || true)"
[ -n "$REPO" ] || { echo "blast.sh: no go.mod module in $REPO_PATH" >&2; exit 1; }

# changed files vs base (falls back to HEAD when base ref doesn't exist),
# INCLUDING uncommitted worktree changes
if ! git -C "$REPO_PATH" rev-parse --verify -q "$BASE" >/dev/null; then
  echo ">> base '$BASE' not found, using HEAD" >&2
  BASE="HEAD"
fi
CHANGED="$(git -C "$REPO_PATH" diff --name-only "$BASE" -- '*.go' | sort -u)"
[ -n "$CHANGED" ] || { echo "no changed .go files vs $BASE — empty blast radius"; exit 0; }
echo ">> repo: $REPO  base: $BASE" >&2
echo ">> changed files:" >&2; sed 's/^/     /' <<<"$CHANGED" >&2

FILE_ARGS=()
while IFS= read -r f; do FILE_ARGS+=(--file "$f"); done <<<"$CHANGED"

# nonzero exit (e.g. repo not in PG) already printed its message to stderr
JSON="$("$PC" query blast --pg "$PC_PG_URL" --repo "$REPO" "${FILE_ARGS[@]}")" || exit 1

HEAD_SHA="$(git -C "$REPO_PATH" rev-parse HEAD 2>/dev/null || true)" \
  BLAST_JSON="$JSON" python3 <<'PY'
import json, os, sys
r = json.loads(os.environ["BLAST_JSON"])
pg, head = r["graph_commit_sha"], os.environ["HEAD_SHA"]
if pg and head and pg != head:
    print(f"WARNING: PG graph is at {pg[:8]} but repo HEAD is {head[:8]} — re-run analyze.sh for accuracy", file=sys.stderr)
if not r["repos"]:
    print("no persisted fn nodes match the changed files — empty blast radius")
    sys.exit(0)
print()
print("affected repos:")
for x in r["repos"]:
    print(f"  {x}")
print("boundary endpoints:")
if r["endpoints"]:
    for x in r["endpoints"]:
        print(f"  {x}")
else:
    print("  (none)")
print()
print("next: scripts/analyze.sh --pg <checkout>[:<scope>] for each affected repo above")
PY
