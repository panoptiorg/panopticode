#!/usr/bin/env bash
#
# regen-testdata.sh — regenerate the golden CGF corpus under testdata/cgf/.
#
# The core repo ships pre-extracted CGF so that `scripts/e2e-core.sh` can
# exercise the whole analysis without a Go or Node toolchain. This script is how
# those directories are produced; it is the ONLY thing in this repo that needs
# the frontends.
#
# Usage:
#   PC_FE=../panoptife-go/bin/pc-fe PC_FE_TS=../panoptife-ts/bin/pc-fe-ts \
#     scripts/regen-testdata.sh
#
# Env:
#   PC_FE           path to the Go frontend binary       (default: pc-fe on PATH)
#   PC_FE_TS        path to the TS frontend binary       (default: pc-fe-ts on PATH)
#   PC_FIXTURES_GO  Go fixture root      (default: ../panoptife-go/fixtures)
#   PC_FIXTURES_TS  TS fixture root      (default: ../panoptife-ts/fixtures)
#   PC_TS_ADAPTER   adapter for fixtures/webapp          (default: bff-gateway)
#   DEST            output root                          (default: testdata/cgf)
#   STAGE           staging dir for fixture sources      (default: /tmp/panopticode-fixtures)
#
# Why STAGE: go/packages reports ABSOLUTE file paths, and pc-fe records them in
# CGF spans. Extracting straight out of a developer's checkout would bake that
# developer's home directory into a committed artifact and make the bytes differ
# per machine. Copying the fixtures to a fixed neutral path first makes the
# golden CGF byte-reproducible anywhere.
#
# Build the frontends first:
#   ( cd ../panoptife-go && go build -o bin/pc-fe ./cmd/pc-fe )
#   ( cd ../panoptife-ts && npm ci && npm run build )
#
# After regenerating, record the frontend commits in testdata/cgf/README.md and
# re-run scripts/e2e-core.sh. Extraction is deterministic: re-running this script
# against the same frontend commits must produce byte-identical output, and a
# diff that is not explained by a frontend change is a bug.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FE="${PC_FE:-pc-fe}"
FE_TS="${PC_FE_TS:-pc-fe-ts}"
FIX_GO="${PC_FIXTURES_GO:-$ROOT/../panoptife-go/fixtures}"
FIX_TS="${PC_FIXTURES_TS:-$ROOT/../panoptife-ts/fixtures}"
ADAPTER="${PC_TS_ADAPTER:-bff-gateway}"
DEST="${DEST:-$ROOT/testdata/cgf}"
STAGE="${STAGE:-/tmp/panopticode-fixtures}"

command -v "$FE"    >/dev/null 2>&1 || [ -x "$FE" ]    || { echo "regen: no pc-fe at '$FE' (set PC_FE)" >&2; exit 2; }
command -v "$FE_TS" >/dev/null 2>&1 || [ -x "$FE_TS" ] || { echo "regen: no pc-fe-ts at '$FE_TS' (set PC_FE_TS)" >&2; exit 2; }
[ -d "$FIX_GO" ] || { echo "regen: no Go fixtures at $FIX_GO (set PC_FIXTURES_GO)" >&2; exit 2; }
[ -d "$FIX_TS" ] || { echo "regen: no TS fixtures at $FIX_TS (set PC_FIXTURES_TS)" >&2; exit 2; }

# Stage the fixture sources at a fixed neutral path (see the STAGE note above).
echo ">> staging fixtures into $STAGE" >&2
rm -rf "$STAGE"
mkdir -p "$STAGE"
cp -R "$FIX_GO/." "$STAGE/"
cp -R "$FIX_TS/." "$STAGE/"

# go_fixture <dest-name> <fixture> [extra pc-fe flags...]
go_fixture() {
  local name="$1" fixture="$2"; shift 2
  echo ">> $name  ($fixture ${*:-})" >&2
  rm -rf "$DEST/$name"
  ( cd "$STAGE/$fixture" && "$FE" build . --scope './...' --out "$DEST/$name" "$@" ) >/dev/null
}

mkdir -p "$DEST"

# --- e2e / e2e-multihop / e2e-route / e2e-graphql / e2e-ts -------------------
go_fixture backend    backend
go_fixture federation federation
go_fixture downstream downstream

# --- e2e-dispatch: one CGF per dispatch mode --------------------------------
for mode in vta cha off; do
  go_fixture "dispatch-$mode" dispatch --dispatch "$mode"
done

# --- e2e-fieldpath: field paths on (default) vs the --field-paths=false hatch
go_fixture fieldpath-on  fieldpath --dispatch vta
go_fixture fieldpath-off fieldpath --dispatch vta --field-paths=false

# --- e2e-wrappers: synthetic ssa wrappers ($bound/$thunk/promoted) ----------
go_fixture wrappers wrappers

# --- e2e-closure: closure free variables ------------------------------------
go_fixture closureflow-on  closureflow --dispatch vta
go_fixture closureflow-off closureflow --dispatch vta --closure-flow=false

# --- e2e-heapslots: abstract heap cells, five configurations ----------------
go_fixture heapslots-on     heapslots --dispatch vta --heap-slots --heap-slots-scope=all
go_fixture heapslots-off    heapslots --dispatch vta
go_fixture heapslots-chan   heapslots --dispatch vta --heap-slots --heap-slots-scope=chan
go_fixture heapslots-narrow heapslots --dispatch vta --heap-slots --heap-slots-scope=all --heap-iface-narrow
go_fixture heapslots-drop   heapslots --dispatch vta --heap-slots --heap-slots-scope=all --heap-iface-drop

# --- e2e-byrefout: by-ref out params + receiver -----------------------------
go_fixture byrefout-on  byrefout --dispatch vta --byref-out
go_fixture byrefout-off byrefout --dispatch vta

# --- e2e-errorleaf: error-typed result ports --------------------------------
go_fixture errorleaf-on  errorleaf --dispatch vta --error-results
go_fixture errorleaf-off errorleaf --dispatch vta
go_fixture errorleaf-strict errorleaf --dispatch vta --error-results --error-results-strict

# --- e2e-miniledger: one CGF per dispatch mode ------------------------------
for mode in vta cha off; do
  go_fixture "miniledger-$mode" miniledger --dispatch "$mode"
done

# --- e2e-recursion: self-recursive SCC iteration, witness diamond + dispatch retry
go_fixture recursion recursion

# --- e2e-libwrites: library calls that write into an argument ---------------
# thirdparty/ stays OUT of scope (the later --scope wins over go_fixture's): it
# plays a dependency, a body-less call only a catalog propagator can describe.
# The -off variant is the --library-writeback=false hatch.
LIBWRITES_SCOPE='./app/...,./pb/...,./store/...'
go_fixture libwrites     libwrites --scope "$LIBWRITES_SCOPE"
go_fixture libwrites-off libwrites --scope "$LIBWRITES_SCOPE" --library-writeback=false

# --- e2e-ts: the TypeScript/Svelte fixture ----------------------------------
# fixtures/webapp mimics an in-house BFF gateway whose helper lives in an
# ADAPTER. The stand-in has no real dependency in its package.json, so
# auto-detection cannot see it and the adapter is named explicitly.
# coverage wave 1: HTTP routes / accessor reads / client sites, Kafka topic cells.
# The kafka fixtures are nested modules; httpapi and kafka/* pull their real
# libraries through the module proxy (or GOFLAGS=-mod=mod with a warm cache).
go_fixture httpapi           httpapi
go_fixture httpapi-nosurface httpapi --surface-reads=false
go_fixture httpclient        httpclient
go_fixture kafka-producer    kafka/producer
go_fixture kafka-consumer    kafka/consumer

echo ">> webapp (pc-fe-ts, adapter=$ADAPTER)" >&2
rm -rf "$DEST/webapp"
"$FE_TS" build --repo "$STAGE/webapp" --repo-id webapp --out "$DEST/webapp" \
  --adapter "$ADAPTER" --quiet

# --- e2e-libwrites, TS half: JS built-ins that write into an object -------
echo ">> weblib (pc-fe-ts), weblib-off (--no-library-writeback)" >&2
rm -rf "$DEST/weblib" "$DEST/weblib-off"
"$FE_TS" build --repo "$STAGE/weblib" --repo-id weblib --out "$DEST/weblib" --quiet
"$FE_TS" build --repo "$STAGE/weblib" --repo-id weblib --out "$DEST/weblib-off" --quiet \
  --no-library-writeback

echo ">> reactapp, reactapp-off (--no-jsx), nextapp (pc-fe-ts)" >&2
rm -rf "$DEST/reactapp" "$DEST/reactapp-off" "$DEST/nextapp"
"$FE_TS" build --repo "$STAGE/reactapp" --repo-id reactapp --out "$DEST/reactapp" --quiet
"$FE_TS" build --repo "$STAGE/reactapp" --repo-id reactapp --out "$DEST/reactapp-off" --quiet --no-jsx
"$FE_TS" build --repo "$STAGE/nextapp" --repo-id nextapp --out "$DEST/nextapp" --quiet

echo
rm -rf "$STAGE"
echo "regenerated into $DEST"
du -sh "$DEST"
