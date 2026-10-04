#!/usr/bin/env bash
#
# analyze.sh — one-shot local analysis of one or more real Go repos: extract to
# CGF with the Go frontend, run cross-repo taint, optionally persist the call
# graph to Postgres and warm the summary store.
#
# This is a WORKED EXAMPLE, not a product. Read it before running it — it is
# ~100 lines and every step is a plain command you can run yourself.
#
# Usage:
#   scripts/analyze.sh [options] <repo>[:scope] [<repo>[:scope] ...]
#
#   <repo>   path to a Go module directory (has go.mod)
#   :scope   optional per-repo package pattern(s), comma separated;
#            defaults to --scope, or ./...
#
# Options:
#   -s, --scope <pat>     default scope for repos without an explicit :scope
#   -e, --endpoint <str>  only print chains whose source fn fqn contains <str>
#   -c, --catalog <path>  catalog file (default: <root>/catalog.example.toml)
#   -o, --out <dir>       CGF output root (default: <root>/output/cgf)
#       --pg              also persist graph + contracts + summaries to Postgres,
#                         bringing it up with deploy/docker-compose.yml
#       --store <dir>     FS summary store (warms the cache `impact` reuses)
#       --json            print raw chains JSON only (no stderr stats)
#   -h, --help
#
# Env:
#   PC_FE       Go frontend binary            (default: pc-fe, from PATH)
#   PC          core binary                   (default: <root>/core/target/debug/panopticode)
#   PC_PG_PORT  host port for Postgres        (default 5433)
#   PC_PG_URL   connection URL                (default postgres://panopticode:panopticode@localhost:$PC_PG_PORT/panopticode)
#
# Examples:
#   scripts/analyze.sh "$CORPUS/gateway" "$CORPUS/ledger-svc"
#
#   scripts/analyze.sh -e accountResolver \
#     "$CORPUS/gateway:./internal/app/graph/..." \
#     "$CORPUS/ledger-svc:./internal/app/...,./internal/pkg/store/..."
#
# On scope: scope is a SOUNDNESS input, not a coverage knob. Code outside it has
# no analysable body and becomes a maximally-tainting opaque leaf, so a sink one
# level behind an out-of-scope wrapper is invisible and an out-of-scope
# sanitizer is silently ignored. Prefer the whole module and narrow only when
# extraction cost forces you to. See docs/limitations.md.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FE="${PC_FE:-pc-fe}"
PC="${PC:-$ROOT/core/target/debug/panopticode}"
COMPOSE="$ROOT/deploy/docker-compose.yml"

SCOPE_DEFAULT="./..."
ENDPOINT=""
CATALOG="$ROOT/catalog.example.toml"
OUT="$ROOT/output/cgf"
USE_PG=0
STORE=""
JSON_ONLY=0
REPOS=()

PC_PG_PORT="${PC_PG_PORT:-5433}"
PC_PG_URL="${PC_PG_URL:-postgres://panopticode:panopticode@localhost:$PC_PG_PORT/panopticode}"

die() { echo "analyze.sh: $*" >&2; exit 1; }

while [ $# -gt 0 ]; do
  case "$1" in
    -s|--scope)    SCOPE_DEFAULT="$2"; shift 2 ;;
    -e|--endpoint) ENDPOINT="$2"; shift 2 ;;
    -c|--catalog)  CATALOG="$2"; shift 2 ;;
    -o|--out)      OUT="$2"; shift 2 ;;
    --pg)          USE_PG=1; shift ;;
    --store)       STORE="$2"; shift 2 ;;
    --json)        JSON_ONLY=1; shift ;;
    -h|--help)     sed -n '2,45p' "$0"; exit 0 ;;
    -*)            die "unknown option $1" ;;
    *)             REPOS+=("$1"); shift ;;
  esac
done

[ ${#REPOS[@]} -gt 0 ] || { sed -n '2,45p' "$0"; exit 1; }
[ -f "$CATALOG" ] || die "catalog not found: $CATALOG"
command -v "$FE" >/dev/null 2>&1 || [ -x "$FE" ] \
  || die "no Go frontend at '$FE' — build it from the panoptife-go repo and set PC_FE"
[ -x "$PC" ] || die "$PC not built — run 'cargo build' in core/"

# --- optional Postgres ------------------------------------------------------
if [ $USE_PG -eq 1 ]; then
  echo ">> postgres up (port $PC_PG_PORT)" >&2
  PC_PG_PORT="$PC_PG_PORT" docker compose -f "$COMPOSE" up -d --wait
  # schema is auto-applied on first volume init; re-apply idempotently for
  # pre-existing volumes (every statement is IF NOT EXISTS)
  docker exec -i -e PGOPTIONS='-c client_min_messages=warning' panopticode-pg \
    psql -q -U panopticode -d panopticode < "$ROOT/deploy/schema.sql"
fi

# --- extract each repo ------------------------------------------------------
mkdir -p "$OUT"
CGF_ARGS=()
for spec in "${REPOS[@]}"; do
  # split on the FIRST colon: repo[:scope]
  if [[ "$spec" == *:* ]]; then repo="${spec%%:*}"; scope="${spec#*:}"
  else repo="$spec"; scope="$SCOPE_DEFAULT"; fi
  repo="${repo/#\~/$HOME}"
  [ -f "$repo/go.mod" ] || die "no go.mod in $repo"
  name="$(basename "$repo")"
  echo ">> extract $name  (scope: $scope)" >&2
  # --require-contracts turns the monoculture failure mode (see docs/limitations.md)
  # from a stderr warning into a nonzero exit, which is what you want here.
  "$FE" build "$repo" --scope "$scope" --out "$OUT/$name" --require-contracts >&2
  CGF_ARGS+=(--cgf "$OUT/$name")
done

# --- taint ------------------------------------------------------------------
echo ">> taint (${#REPOS[@]} repo(s))" >&2
TAINT=("$PC" taint "${CGF_ARGS[@]}" --catalog "$CATALOG")
[ -n "$ENDPOINT" ] && TAINT+=(--endpoint "$ENDPOINT")
[ $USE_PG -eq 1 ] && TAINT+=(--pg "$PC_PG_URL")
[ -n "$STORE" ]  && { mkdir -p "$STORE"; TAINT+=(--store "$STORE"); }

if [ $JSON_ONLY -eq 1 ]; then
  "${TAINT[@]}" 2>/dev/null
else
  "${TAINT[@]}"
fi

if [ $USE_PG -eq 1 ]; then
  echo ">> psql: docker exec -it panopticode-pg psql -U panopticode -d panopticode" >&2
  echo ">> blast radius of a diff: scripts/blast.sh <repo-path>" >&2
fi
