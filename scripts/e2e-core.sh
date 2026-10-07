#!/usr/bin/env bash
#
# e2e-core.sh — the core-only regression battery.
#
# Runs the whole analysis engine against the golden CGF committed under
# testdata/cgf/, so it needs NOTHING but a Rust toolchain: no Go, no Node, no
# Postgres, no Docker, no network. This is the suite CI runs and the one to run
# before sending a patch.
#
# Usage:  scripts/e2e-core.sh            # build + run every suite
#         PC=<binary> scripts/e2e-core.sh
#
# Env:
#   PC        panopticode binary   (default: core/target/debug/panopticode, built if absent)
#   CATALOG   catalog file         (default: catalog.example.toml)
#   OUT       scratch dir          (default: $TMPDIR/pc-e2e-core)
#   NOBUILD   set to 1 to skip cargo build
#   CGF       golden CGF root    (default: testdata/cgf) — e.g. a fresh regen-testdata.sh DEST
#
# ---------------------------------------------------------------------------
# WHAT THIS IS
#
# The assertions below are ported, statement for statement, from the cross-repo
# acceptance battery that drives the three repos together (a Go frontend, a TS
# frontend and this core). Everything that can be decided from a CGF corpus plus
# `panopticode` is reproduced here verbatim. Sixteen suites:
#
#   e2e          cross-repo unary / server-stream / client-stream chains
#   e2e-multihop two service boundaries; a boundary inside a local helper
#   e2e-route    every chain carries a complete, well-formed, stable route
#   e2e-graphql  endpoint-driven (structural) GraphQL sourcing
#   e2e-ts       a chain that starts in TypeScript and ends at a Go SQL sink
#   e2e-dispatch narrow interfaces resolve, wide ones stay capped-opaque
#   e2e-fieldpath k=2 field paths kill a disjoint-field false positive
#   e2e-wrappers  synthetic SSA wrappers ($bound / $thunk / promoted)
#   e2e-closure   closure free variables
#   e2e-heapslots abstract heap cells, five extraction configurations
#   e2e-byrefout  by-ref out params and the receiver
#   e2e-errorleaf error-typed result ports
#   e2e-miniledger dispatch-induced SCCs and the SCC fixpoint
#   e2e-backward  sink-seeded verdicts, with and without --backward-unview
#   e2e-recursion self-recursive SCC iteration, witness diamond + dispatch retry
#   e2e-libwrites library calls that write into an argument (catalog propagators,
#                 frontend write-back, --unmodeled)
#
# WHAT IS DEPRIVED FROM THE FULL BATTERY (and why)
#
#   * Every "extract twice, diff -r, byte-identical" determinism guard, and
#     every "flag-off emission differs" guard that compares two EXTRACTIONS.
#     Those test the frontends, not the core; they belong to the frontend
#     repos' own CI. Where the comparison is between two committed CGF dirs it
#     IS kept (see the `cgf_differs` checks below) — that costs nothing here.
#   * `grep "dangling callee iid"` on extraction stderr — needs pc-fe at runtime.
#   * e2e-fieldpath's "read the sink line markers out of the fixture source" —
#     the fixture sources live in the Go frontend repo. The two expected sink
#     lines are pinned as constants instead; see FIELDPATH_SINK_LINE below.
#   * e2e-miniledger's warm-summary-store cache probe (`taint --store`, cache
#     hits, "SCC members are not served from cache"). It tests the summary
#     store, and pinning a warm store as a committed artifact would pin the
#     cache-key derivation too. The chain and trace assertions are kept.
#   * The whole of e2e-cgstore (call-graph snapshot store — a frontend cache),
#     e2e-mr (MR/incremental mode — needs a git checkout to re-extract),
#     e2e-pg and e2e-blast (need a live Postgres).
#
# Everything skipped above is a frontend, a database, or a cache concern. No
# assertion about what the analysis REPORTS has been dropped.
# ---------------------------------------------------------------------------
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PC="${PC:-$ROOT/core/target/debug/panopticode}"
CATALOG="${CATALOG:-$ROOT/catalog.example.toml}"
CGF="${CGF:-$ROOT/testdata/cgf}"
OUT="${OUT:-${TMPDIR:-/tmp}/pc-e2e-core}"

# The two `Selectx` sink lines in the field-path fixture's store package. The
# full battery reads these out of the fixture source, which is not in this repo;
# they are pinned here and re-checked by the assertion that the two routes land
# on DIFFERENT lines, which is the half that cannot pass vacuously.
FIELDPATH_SINK_LINE_MASKEQ=46
FIELDPATH_SINK_LINE_NOTE=44

rm -rf "$OUT"; mkdir -p "$OUT"

FAILED=()
suite_fail() { echo "FAIL: $1"; FAILED+=("$1"); }

if [ "${NOBUILD:-0}" != "1" ]; then
  echo "== build core =="
  ( cd "$ROOT/core" && cargo build ) || { echo "FAIL: cargo build"; exit 1; }
fi
[ -x "$PC" ] || { echo "e2e-core: no binary at $PC" >&2; exit 2; }
[ -d "$CGF" ] || { echo "e2e-core: no golden CGF at $CGF (scripts/regen-testdata.sh)" >&2; exit 2; }
[ -f "$CATALOG" ] || { echo "e2e-core: no catalog at $CATALOG" >&2; exit 2; }

# taint <out-basename> <extra taint args...> — stdout to $OUT/<n>.json, stderr to .err
taint() {
  local n="$1"; shift
  "$PC" taint --catalog "$CATALOG" "$@" > "$OUT/$n.json" 2> "$OUT/$n.err"
}
# the two committed CGF dirs must really differ, or the flag under test is inert
cgf_differs() {
  diff -r "$CGF/$1" "$CGF/$2" > /dev/null 2>&1 \
    && { echo "  (!) $1 and $2 are identical CGF — the extraction flag is inert"; return 1; }
  return 0
}

# ===========================================================================
echo
echo "########## e2e — cross-repo unary + server-stream + client-stream"
# ===========================================================================
taint e2e-endpoint --cgf "$CGF/federation" --cgf "$CGF/backend" --endpoint federation
taint e2e-all      --cgf "$CGF/federation" --cgf "$CGF/backend"
cat "$OUT/e2e-endpoint.err"
python3 - "$OUT/e2e-endpoint.json" "$OUT/e2e-all.json" <<'PY' || suite_fail e2e
import json, sys
d = json.load(open(sys.argv[1]))
alld = json.load(open(sys.argv[2]))

def has(chains, src, sink, crossed=None):
    for c in chains:
        if src not in c["source_fn"] or c["sink_class"] != sink:
            continue
        details = [h["detail"] for h in c["hops"] if h["crossed_service_boundary"]]
        if crossed is None or any(crossed in x for x in details):
            return c
    raise AssertionError(f"no chain src~{src} sink={sink} crossed~{crossed}: "
                         + json.dumps([(c['source_fn'], c['sink_class']) for c in chains], indent=1))

# unary: GraphQL input -> gRPC Account/GetAccount -> backend SQL sink
c = has(d, "Details", "sqli", "pb.Account/GetAccount")
assert "federation" in c["source_repo"], c["source_repo"]

# server-stream: input -> remote Download, response via stream.Recv -> LOCAL sink
has(d, "StreamDetails", "sqli", "pb.Feed/Download")

# client-stream: input -> stream.Send -> BACKEND sink (surfaces at the Send hop)
has(d, "SendUpload", "sqli", "pb.Feed/Upload")

# backend-rooted: server stream.Recv is an unconditional source (Upload),
# and the unary-style request getter roots Download
has(alld, "FeedImpl", "sqli")
has(alld, "Download", "sqli")

print("PASS: unary + server-stream + client-stream cross-repo chains,",
      len(d), "endpoint chains /", len(alld), "total")
PY

# ===========================================================================
echo
echo "########## e2e-multihop — two boundaries; a boundary in a local helper"
# ===========================================================================
taint multihop --cgf "$CGF/federation" --cgf "$CGF/backend" --cgf "$CGF/downstream"
cat "$OUT/multihop.err"
python3 - "$OUT/multihop.json" <<'PY' || suite_fail e2e-multihop
import json, sys
chains = json.load(open(sys.argv[1]))

def has(chains, src, sink, crossed=None):
    for c in chains:
        if src not in c["source_fn"] or c["sink_class"] != sink:
            continue
        details = [h["detail"] for h in c["hops"] if h["crossed_service_boundary"]]
        if crossed is None or any(crossed in x for x in details):
            return c
    raise AssertionError(f"no chain src~{src} sink={sink} crossed~{crossed}: "
                         + json.dumps([(c['source_fn'], c['sink_class']) for c in chains], indent=1))

# Shape A: two boundaries. backend.Archive has NO local sink, so a sqli chain
# rooted at the federation Archive resolver proves the downstream sink was
# folded through backend's handler summary (fed -> backend -> downstream).
c = has(chains, "accountResolver).Archive", "sqli", "pb.Account/Archive")
assert "federation" in c["source_repo"], c["source_repo"]

# ... and the backend-rooted half of the same path (backend handler's request
# getter is a source; its only sqli sink is downstream's).
has(chains, "Implementation).Archive", "sqli", "pb.Ledger/Record")

# Shape B: the remote call lives in a local helper — pre-fixpoint the resolver
# composed the helper's stale default-leaf summary and no chain existed. The
# chain's hops stay inside the source fn body (local call, no crossed hop).
c = has(chains, "DetailsViaHelper", "sqli")
assert not any(h["crossed_service_boundary"] for h in c["hops"]), \
    f"Shape B chain must reach the sink through the LOCAL helper: {c['hops']}"

# Regression: the original single-boundary chain is intact in the 3-repo run.
has(chains, "Details", "sqli", "pb.Account/GetAccount")

print("PASS: Shape A (2 boundaries) + Shape B (local helper) + 1-boundary regression,",
      len(chains), "chains total")
PY

# ===========================================================================
echo
echo "########## e2e-route — every chain carries a complete route"
# ===========================================================================
# Two independent runs: `pred` in propagate is seeded from a HashSet walk and
# Rust randomizes hash seeds PER PROCESS, so this is a real test of route
# stability, not a no-op.
for i in 1 2; do
  taint "route-$i" --cgf "$CGF/federation" --cgf "$CGF/backend" --cgf "$CGF/downstream"
done
cat "$OUT/route-1.err"
if diff -q "$OUT/route-1.json" "$OUT/route-2.json" > /dev/null; then
  echo "PASS: route output stable across two independent runs"
else
  suite_fail "e2e-route (route output not stable across runs — hash-order leak)"
fi
python3 - "$OUT/route-1.json" <<'PY' || suite_fail e2e-route
import collections, json, sys
chains = json.load(open(sys.argv[1]))
assert chains, "no chains at all"

def find(src, sink="sqli", repo=None):
    for c in chains:
        if src in c["source_fn"] and c["sink_class"] == sink:
            if repo is None or repo in c["source_repo"]:
                return c
    raise AssertionError(f"no chain src~{src} sink={sink} repo~{repo}")

def kinds(c):
    return [h["kind"] for h in c["route"]["hops"]]

# ---- every chain must carry a route, and it must be well-formed ----
for c in chains:
    tag = f'{c["source_fn"]}/{c["sink_class"]}'
    r = c.get("route")
    assert r is not None, f"{tag}: no route emitted"
    hops = r["hops"]
    assert hops, f"{tag}: empty route"
    assert hops[0]["kind"] == "source", f"{tag}: route must start at a source, got {hops[0]['kind']}"
    # A route either reaches its sink or says why not — never silently short.
    if r.get("incomplete") is None:
        assert hops[-1]["kind"] == "sink", \
            f"{tag}: complete route must end at a sink, got {kinds(c)}"
    # No interior hop may be a source/sink; those are terminals only.
    for h in hops[1:-1]:
        assert h["kind"] in ("call", "boundary"), f"{tag}: bad interior hop {h['kind']}"
    # Spans must be real when present.
    for h in hops:
        if h.get("file"):
            assert h.get("line", 0) > 0, f"{tag}: hop with file but no line: {h}"
        assert h["repo"], f"{tag}: hop without a repo: {h}"
        assert 0.0 < h["confidence"] <= 1.0, f"{tag}: bad confidence {h['confidence']}"
    # boundaries count must match the hops
    assert r["boundaries"] == sum(1 for h in hops if h["kind"] == "boundary"), \
        f"{tag}: boundaries={r['boundaries']} disagrees with hops"

# On these fixtures every chain is fully resolvable — nothing may be truncated.
inc = [(c["source_fn"], c["route"]["incomplete"]) for c in chains
       if c["route"].get("incomplete") is not None]
assert not inc, f"routes should all reach their sink on these fixtures: {inc}"
print(f"PASS: all {len(chains)} chains carry a complete well-formed route")

# ---- dedupe invariant ----
# One chain per (source_fn, sink_class, sink_span, route.id). Before dedupe,
# `propagate` emitted one chain per tainted arg-port FIELD VARIANT, so on real
# corpora a single route was reported up to 20 times.
keys = [(c["source_fn"], c["sink_class"],
         tuple((c["sink_span"] or {}).items()), c["route"]["id"]) for c in chains]
dups = [k for k, n in collections.Counter(keys).items() if n > 1]
assert not dups, f"duplicate chains survived dedupe: {dups}"
# Merged variants must be reported, never silently dropped: when a chain carries
# sink_fields, its own sink_field must be one of them.
for c in chains:
    if c.get("sink_fields"):
        assert len(c["sink_fields"]) > 1, f"sink_fields with <2 entries: {c['sink_fields']}"
        assert c.get("sink_field") in c["sink_fields"], \
            f"{c['source_fn']}: sink_field {c.get('sink_field')} not in {c['sink_fields']}"
    for h in c["route"]["hops"]:
        if h.get("fields"):
            assert len(h["fields"]) > 1 and h.get("field") in h["fields"], \
                f"{c['source_fn']}: hop fields {h.get('fields')} inconsistent with {h.get('field')}"
print(f"PASS: dedupe invariant | {len(set(keys))} distinct (source_fn, sink, route) keys")

# ---- Shape A: 2 boundaries, 3 repos, terminal sink in downstream ----
c = find("accountResolver).Archive", repo="federation")
r = c["route"]
assert r["boundaries"] == 2, f"Shape A must cross 2 boundaries, got {r['boundaries']}: {kinds(c)}"
bnd = [h["callee"] for h in r["hops"] if h["kind"] == "boundary"]
assert any("pb.Account/Archive" in x for x in bnd), f"missing first boundary: {bnd}"
assert any("pb.Ledger/Record" in x for x in bnd), f"missing second boundary: {bnd}"
assert bnd.index(next(x for x in bnd if "pb.Account/Archive" in x)) \
     < bnd.index(next(x for x in bnd if "pb.Ledger/Record" in x)), \
     f"boundaries out of order: {bnd}"
last = r["hops"][-1]
assert "downstream" in last["repo"], f"Shape A sink must be in downstream, got {last['repo']}"
assert "Selectx" in last["callee"], f"Shape A must end at the SQL sink, got {last['callee']}"
# The three repos must all appear, in order, and the sink must NOT be attributed
# to the source function's file — that was the old sink_span bug.
repos = [h["repo"] for h in r["hops"]]
assert "federation" in repos[0] and "downstream" in repos[-1], f"repo order wrong: {repos}"
assert last["file"] != r["hops"][0].get("file"), "sink span must not be the source's"
print("PASS: Shape A route | 3 repos, 2 boundaries, terminal sink in downstream |",
      " -> ".join(h["kind"] for h in r["hops"]))

# ---- Shape B: the boundary lives in a LOCAL HELPER, not the source fn ----
c = find("DetailsViaHelper")
r = c["route"]
assert r["boundaries"] == 1, f"Shape B must cross exactly 1 boundary, got {r['boundaries']}"
bh = [h for h in r["hops"] if h["kind"] == "boundary"]
assert len(bh) == 1
assert "fetchDetails" in bh[0]["func"], \
    f"Shape B boundary must be crossed INSIDE the helper, got {bh[0]['func']}"
assert "DetailsViaHelper" not in bh[0]["func"], \
    "Shape B boundary must NOT be attributed to the source function"
# and it must keep descending inside backend past the boundary
after = r["hops"][r["hops"].index(bh[0]) + 1:]
assert after, "Shape B route stops at the boundary"
assert all("backend" in h["repo"] for h in after), f"post-boundary hops not in backend: {after}"
assert after[-1]["kind"] == "sink" and "Selectx" in after[-1]["callee"]
print("PASS: Shape B route | boundary inside the helper, then",
      len(after), "hops through backend to the sink")

# ---- the route must be strictly more informative than legacy hops ----
gains = [(len(c["route"]["hops"]), len(c["hops"])) for c in chains]
assert all(rt >= lg for rt, lg in gains), "route should never be shorter than legacy hops"
assert any(rt > lg for rt, lg in gains), "route adds nothing over legacy hops"
# Shape A specifically: legacy hops saw one boundary, route sees both.
c = find("accountResolver).Archive", repo="federation")
legacy_bnd = sum(1 for h in c["hops"] if h["crossed_service_boundary"])
assert c["route"]["boundaries"] > legacy_bnd, \
    f"route must see more boundaries than legacy hops ({c['route']['boundaries']} vs {legacy_bnd})"
print(f"PASS: route strictly more informative | Shape A boundaries {legacy_bnd} -> {c['route']['boundaries']}")
PY

# ===========================================================================
echo
echo "########## e2e-graphql — endpoint-driven (structural) GraphQL sourcing"
# ===========================================================================
# A resolver arg (bare `token`, no getter) must root a cross-repo chain purely
# via structural source_params seeding — proven by REMOVING the getter-based
# graphql_input source from the catalog and still finding the chain.
"$PC" graph-dump --cgf "$CGF/federation" | tee "$OUT/gql-dump.txt"
if grep -q 'graphql_fields=3' "$OUT/gql-dump.txt"; then
  echo "PASS: graph-dump reports graphql_fields=3"
else
  suite_fail "e2e-graphql (expected graphql_fields=3 in graph-dump)"
fi

python3 - "$CATALOG" "$OUT/catalog-nogetter.toml" <<'PY' || suite_fail "e2e-graphql (catalog surgery)"
import re, sys
src = open(sys.argv[1]).read()
blocks = re.split(r'(?m)^(?=\[\[)', src)
kept = [b for b in blocks if not re.search(r'kind\s*=\s*"graphql_input"', b)]
assert len(kept) == len(blocks) - 1, "expected exactly one graphql_input source block"
open(sys.argv[2], "w").write("".join(kept))
PY

"$PC" taint --cgf "$CGF/federation" --cgf "$CGF/backend" \
      --catalog "$OUT/catalog-nogetter.toml" > "$OUT/gql-nogetter.json" 2> "$OUT/gql-nogetter.err"
cat "$OUT/gql-nogetter.err"
taint gql-full --cgf "$CGF/federation" --cgf "$CGF/backend"

python3 - "$OUT/gql-nogetter.json" "$OUT/gql-full.json" <<'PY' || suite_fail e2e-graphql
import json, sys
nogetter = json.load(open(sys.argv[1]))
full = json.load(open(sys.argv[2]))

def has(chains, src, sink, crossed=None):
    for c in chains:
        if src not in c["source_fn"] or c["sink_class"] != sink:
            continue
        details = [h["detail"] for h in c["hops"] if h["crossed_service_boundary"]]
        if crossed is None or any(crossed in x for x in details):
            return c
    raise AssertionError(f"no chain src~{src} sink={sink} crossed~{crossed}: "
                         + json.dumps([(c['source_fn'], c['sink_class']) for c in chains], indent=1))

# THE structural chain: bare `token` arg -> invokes_remote -> backend SQL sink,
# with the getter source REMOVED from the catalog.
c = has(nogetter, "queryResolver).SearchByToken", "sqli", "pb.Account/GetAccount")
assert "federation" in c["source_repo"], c["source_repo"]

# obj (parent output) must NOT be seeded: with the getter source removed, the
# (ctx, obj)-only resolvers cannot root a chain.
for bad in ("accountResolver).Details", "accountResolver).Archive"):
    assert not any(bad in c["source_fn"] for c in nogetter), \
        f"obj wrongly seeded: {bad} rooted a chain without the getter source"

# full catalog: the new chain coexists with the getter-based ones (regression).
has(full, "queryResolver).SearchByToken", "sqli", "pb.Account/GetAccount")
has(full, "accountResolver).Details", "sqli", "pb.Account/GetAccount")

# The remote call goes through a hand-rolled `provider.Client` interface — named
# exactly `Client`, outside any pb package. The boundary must be linked by
# method-set identity and the route must cross it as a boundary hop (counted
# from route.hops, never the compact array).
c = has(full, "accountResolver).DetailsViaLocalClient", "sqli")
bh = [h for h in c["route"]["hops"] if h["kind"] == "boundary"]
assert len(bh) == 1 and "pb.Account/GetAccount" in bh[0].get("callee", ""), \
    f"local-client boundary not on the route: {c['route']['hops']}"
assert "incomplete" not in c["route"], c["route"]
assert c["route_confidence"] == 1.0, c["route_confidence"]

print(f"PASS: endpoint-driven GraphQL sourcing — {len(nogetter)} chains w/o getter,",
      f"{len(full)} with full catalog")
PY

# ===========================================================================
echo
echo "########## e2e-ts — a chain that starts in TypeScript"
# ===========================================================================
"$PC" graph-dump --cgf "$CGF/webapp" --cgf "$CGF/federation" --cgf "$CGF/backend" \
  | tee "$OUT/ts-dump.txt"
taint ts --cgf "$CGF/webapp" --cgf "$CGF/federation" --cgf "$CGF/backend"
tail -3 "$OUT/ts.err"
python3 - "$OUT/ts.json" "$OUT/ts-dump.txt" <<'PY' || suite_fail e2e-ts
import json, re, sys
chains = json.load(open(sys.argv[1]))
dump = open(sys.argv[2]).read()
fails = []

def find(pred, what):
    for c in chains:
        if pred(c):
            return c
    fails.append(what)
    return None

def boundaries(c):
    return [h.get("callee", "") for h in c.get("route", {}).get("hops", []) if h["kind"] == "boundary"]

def detail_hops(c):
    return [h["detail"] for h in c["hops"]]

# (1) THE cross-language chain: TS source -> graphql contract -> gRPC contract -> sqli.
def is_chain1(c):
    if c["source_repo"] != "webapp" or c["sink_class"] != "sqli":
        return False
    b = boundaries(c)
    return any("graphql:Query.searchByToken" in x for x in b) and \
           any("pb.Account/GetAccount" in x for x in b)
c1 = find(is_chain1, "(1) webapp -> graphql:Query.searchByToken -> pb.Account/GetAccount -> sqli")

# (2) intra-TS open_redirect: searchParams.get -> goto
c2 = find(lambda c: c["source_repo"] == "webapp" and c["sink_class"] == "open_redirect"
          and any("URLSearchParams.get" in d for d in detail_hops(c))
          and any("goto" in d for d in detail_hops(c)),
          "(2) intra-TS open_redirect searchParams.get -> goto")

# (3) intra-TS xss into the svelte template
c3 = find(lambda c: c["source_repo"] == "webapp" and c["sink_class"] == "xss"
          and any("svelte:html" in d for d in detail_hops(c)),
          "(3) intra-TS xss into svelte:html")

# (4) graph-dump reports the mixed-language corpus
m = re.search(r"languages=\{([^}]*)\}", dump)
if not m or "ts:" not in m.group(1) or "go:" not in m.group(1):
    fails.append("(4) graph-dump languages= with both go and ts (got: %r)" % (m.group(0) if m else None))

ts_chains = [c for c in chains if c["source_repo"] == "webapp"]
if fails:
    print("FAIL — assertions that did not hold:")
    for f in fails:
        print("  -", f)
    print("\nTS-rooted chains found (%d of %d total):" % (len(ts_chains), len(chains)))
    for c in ts_chains:
        print("   %-22s %-14s boundaries=%s hops=%s"
              % (c["source_fn"], c["sink_class"], boundaries(c), detail_hops(c)))
    sys.exit(1)

print("PASS: %d TS-rooted chains of %d total" % (len(ts_chains), len(chains)))
print("  (1) %s -> %s  [%s]" % (c1["source_fn"], c1["sink_class"], " -> ".join(boundaries(c1))))
print("  (2) %s -> %s" % (c2["source_fn"], c2["sink_class"]))
print("  (3) %s -> %s" % (c3["source_fn"], c3["sink_class"]))
print("  (4) %s" % m.group(0))
PY

# ===========================================================================
echo
echo "########## e2e-dispatch — narrow resolves, wide stays capped-opaque"
# ===========================================================================
# dispatch must actually change the CGF: off vs vta differing proves the
# resolver wrote targets (a silent no-op would pass every other check).
cgf_differs dispatch-off dispatch-vta || suite_fail "e2e-dispatch (off and vta CGF identical)"
for mode in vta cha off; do taint "dispatch-$mode" --cgf "$CGF/dispatch-$mode"; done
python3 - "$OUT/dispatch-vta.json" "$OUT/dispatch-cha.json" "$OUT/dispatch-off.json" <<'PY' || suite_fail e2e-dispatch
import json, sys
vta, cha, off = (json.load(open(p)) for p in sys.argv[1:4])

def find(chains, src, sink):
    return [c for c in chains if src in c["source_fn"] and c["sink_class"] == sink]

def has(chains, src, sink):
    cs = find(chains, src, sink)
    assert cs, (f"no chain src~{src} sink={sink}: "
                + json.dumps([(c['source_fn'], c['sink_class']) for c in chains], indent=1))
    return cs[0]

# NARROW: sink inside PgRepo.Save — visible only when dispatch enumerates
# targets. VTA and CHA both resolve the 2-impl interface; off cannot.
c = has(vta, "HandleNarrow", "sqli")
assert abs(c["confidence"] - 0.5) < 1e-6, f"narrow vta confidence {c['confidence']}, want 0.5 (2 targets)"
has(cha, "HandleNarrow", "sqli")
assert not find(off, "HandleNarrow", "sqli"), "off mode saw through unresolved dispatch"

# WIDE: capped -> opaque -> default-leaf transparency keeps the local Selectx
# chain alive in every mode, at full confidence (opaque sites don't down-weight).
for name, chains in (("vta", vta), ("cha", cha), ("off", off)):
    c = has(chains, "HandleWide", "sqli")
    assert c["confidence"] == 1.0, f"wide {name} confidence {c['confidence']}, want 1.0"

# The exec sink hidden in Codec07.Encode must never surface: the wide site is
# capped in vta/cha and unresolved in off.
for name, chains in (("vta", vta), ("cha", cha), ("off", off)):
    bad = [c for c in chains if c["sink_class"] == "exec"]
    assert not bad, f"{name}: capped/opaque wide interface leaked exec chain: {bad}"

# Exact counts — a tripwire: a change in either direction is a real change in
# what the tool reports.
assert (len(vta), len(cha), len(off)) == (2, 2, 1), \
    f"chain counts changed: vta={len(vta)} cha={len(cha)} off={len(off)}, want 2/2/1"

# One chain per (source_fn, sink_class, sink_span, route.id) — the dedupe
# invariant itself.
for name, chains in (("vta", vta), ("cha", cha), ("off", off)):
    keys = [(c["source_fn"], c["sink_class"],
             tuple((c["sink_span"] or {}).items()), c["route"]["id"]) for c in chains]
    assert len(keys) == len(set(keys)), f"{name}: duplicate chains survived dedupe"

print(f"PASS: narrow resolved (conf 0.5) in vta+cha, absent in off; "
      f"wide capped everywhere; chains vta={len(vta)} cha={len(cha)} off={len(off)}")
PY

# ===========================================================================
echo
echo "########## e2e-fieldpath — k=2 field paths kill a disjoint-field FP"
# ===========================================================================
cgf_differs fieldpath-on fieldpath-off || suite_fail "e2e-fieldpath (--field-paths=false CGF identical)"
taint fieldpath-on  --cgf "$CGF/fieldpath-on"
taint fieldpath-off --cgf "$CGF/fieldpath-off"
python3 - "$OUT/fieldpath-on.json" "$OUT/fieldpath-off.json" \
          "$FIELDPATH_SINK_LINE_MASKEQ" "$FIELDPATH_SINK_LINE_NOTE" <<'PY' || suite_fail e2e-fieldpath
import json, sys
on, off = (json.load(open(p)) for p in sys.argv[1:3])
sink_line = {"MaskEq": int(sys.argv[3]), "Note": int(sys.argv[4])}
assert len(set(sink_line.values())) == 2, f"pinned sink lines are ambiguous: {sink_line}"

def has(chains, src, sink):
    return any(src in c["source_fn"] and c["sink_class"] == sink for c in chains)

def dump(chains):
    return json.dumps(sorted({(c["source_fn"].split(".")[-1], c["sink_class"])
                              for c in chains}), indent=1)

# whole-request control: both fields' sinks fire from Search
assert has(on, ".Search", "sqli"), f"Search sqli chain lost: {dump(on)}"
assert has(on, ".Search", "exec"), f"Search exec chain lost: {dump(on)}"

# THE FP-KILL: Lookup taints only MaskEq -> the Note-fed exec sink must not fire
assert has(on, ".Lookup", "sqli"), f"Lookup sqli chain lost: {dump(on)}"
assert not has(on, ".Lookup", "exec"), \
    f"field paths failed: Lookup exec FP still present: {dump(on)}"

# escape hatch: opaque json.Marshal coarsens to whole-object -> chain survives
assert has(on, ".Export", "sqli"), f"Export escape-hatch chain lost: {dump(on)}"

# flag off = field-insensitive behavior: the FP is back (proves the kill is
# field-path-driven, and the off mode really disables emission)
assert has(off, ".Lookup", "exec"), \
    f"--field-paths=false should reproduce the whole-struct FP: {dump(off)}"
assert has(off, ".Search", "sqli") and has(off, ".Lookup", "sqli"), \
    f"off-mode recall regressed: {dump(off)}"

# ---- pass-through widening: the ROUTE must land on the right branch ----
# ViaMask/ViaNote both cross store.PassThrough, which reads no field, so the k=2
# path is lost there and FilterTwo's two same-class sinks are both prefix-
# comparable with the widened fact. Asserting BOTH directions makes this
# independent of how the descent's candidate tie-break sorts: before the fix
# exactly one of them lands on the sibling's sink.
def route_of(chains, src, sink):
    got = [c for c in chains if c["source_fn"].endswith("." + src)
           and c["sink_class"] == sink]
    assert len(got) == 1, f"{src}/{sink}: expected 1 chain, got {len(got)}"
    return got[0]["route"]

terminals = {}
for src, want in (("ViaMask", "MaskEq"), ("ViaNote", "Note")):
    r = route_of(on, src, "sqli")
    assert r.get("incomplete") is None, f"{src}: route incomplete: {r['incomplete']}"
    term = r["hops"][-1]
    assert term["kind"] == "sink", f"{src}: route does not end at a sink: {term}"
    terminals[src] = term["line"]
    assert term["line"] == sink_line[want], \
        f"{src}: route landed on the sibling field's sink — pass-through " \
        f"widening: store.go:{term['line']}, want :{sink_line[want]} ({want})"
assert terminals["ViaMask"] != terminals["ViaNote"], \
    f"both routes share a terminal, so one is the sibling's: {terminals}"

print("PASS: field-path assertions OK")
print("  on :", dump(on).replace("\n", " "))
print("  off:", dump(off).replace("\n", " "))
PY

# ===========================================================================
echo
echo "########## e2e-wrappers — synthetic SSA wrappers"
# ===========================================================================
# x/tools/go/ssa auto-generates package-less, Synthetic!="" functions for method
# values ($bound), method expressions ($thunk), and methods promoted from an
# embedded struct. When those are dropped, a call through such a func value
# resolves to ZERO targets -> Opaque -> default leaf -> the entire callee body
# is invisible from that call site. HandleOutOfScope is the scope guard: a
# $bound on strings.Builder must stay dropped.
taint wrappers --cgf "$CGF/wrappers"
cat "$OUT/wrappers.err"
python3 - "$OUT/wrappers.json" <<'PY' || suite_fail e2e-wrappers
import json, sys
chains = json.load(open(sys.argv[1]))

def one(src):
    cs = [c for c in chains if src in c["source_fn"] and c["sink_class"] == "sqli"]
    assert len(cs) == 1, (f"want exactly 1 sqli chain from {src}, got {len(cs)}: "
                          + json.dumps([c["source_fn"] for c in chains], indent=1))
    return cs[0]

def hops(c):
    return c["route"]["hops"]

# ---- the three wrapper kinds each carry request data to the SQL sink ----
# marker: what must appear in the route, proving we went THROUGH the wrapper
# and not around it; wrapped: the real method behind it.
for src, marker, wrapped in (
    ("HandleBound",    "$bound", "query"),    # method value in a struct field
    ("HandleThunk",    "$thunk", "lookup"),   # method expression
    ("HandlePromoted", "Search", "Search"),   # embedded promotion wrapper
):
    c = one(src)
    hs = hops(c)
    assert hs[0]["kind"] == "source" and hs[-1]["kind"] == "sink", \
        f"{src}: malformed route {[h['kind'] for h in hs]}"
    assert "Selectx" in hs[-1]["callee"], f"{src}: must end at the SQL sink, got {hs[-1]}"
    blob = " ".join(h["func"] + " " + h.get("callee", "") for h in hs)
    assert marker in blob, f"{src}: route does not pass through {marker}: {blob}"
    assert wrapped in blob, f"{src}: route never reaches the wrapped method {wrapped}: {blob}"
    assert c["route"].get("incomplete") is None, f"{src}: route incomplete: {c['route']}"
    print(f"PASS: {src:<15} {len(hs)} hops through {marker} -> {wrapped} -> Selectx")

# ---- scope guard: an out-of-scope wrapper must stay dropped ----
# strings.Builder.WriteString$bound resolves to package `strings`, which is not
# in scope, so declaringScopePkg rejects it. Without this, every wrapper in the
# program would be pulled in and the fn-count gate would blow.
oos = [c for c in chains if "HandleOutOfScope" in c["source_fn"]]
assert not oos, f"out-of-scope wrapper leaked a chain: {[c['source_fn'] for c in oos]}"
print("PASS: out-of-scope wrapper (strings.Builder) stays dropped")

assert len(chains) == 3, \
    f"want exactly 3 chains, got {len(chains)}: {[c['source_fn'] for c in chains]}"
print(f"PASS chains: {len(chains)}")
PY

# ===========================================================================
echo
echo "########## e2e-closure — closure free variables"
# ===========================================================================
cgf_differs closureflow-on closureflow-off || suite_fail "e2e-closure (--closure-flow=false CGF identical)"
taint closure-on  --cgf "$CGF/closureflow-on"
taint closure-off --cgf "$CGF/closureflow-off"
cat "$OUT/closure-on.err"
python3 - "$OUT/closure-on.json" "$OUT/closure-off.json" <<'PY' || suite_fail e2e-closure
import json, sys
on, off = (json.load(open(p)) for p in sys.argv[1:3])

def dump(cs):
    return json.dumps(sorted((c["source_fn"].split(".")[-1], c["sink_class"]) for c in cs))

# ---- the whole point: zero before, three after ----
assert not off, f"--closure-flow=false must find nothing here, got {dump(off)}"
print("PASS: 0 chains with the flag off")

def one(src):
    cs = [c for c in on if c["source_fn"].endswith(src) and c["sink_class"] == "sqli"]
    assert len(cs) == 1, f"want exactly 1 sqli chain from {src}, got {len(cs)}: {dump(on)}"
    return cs[0]

def blob(c):
    return " ".join(h["func"] + " " + (h.get("callee") or "") for h in c["route"]["hops"])

for src, through, sink in (
    # the common idiom: query built outside, SQL exec inside
    ("HandleTx",          "HandleTx$1",   "(*example.com/closureflow/store.Tx).Selectx"),
    # $bound wrapper whose single free var is the captured receiver
    ("HandleBoundRecv",   "$bound",       "(*example.com/closureflow/store.MaskDB).Selectx"),
    # ONE closure, TWO captures, two SAME-CLASS sinks — only `m` is tainted, so
    # a shifted binding index would land the fact on `n` and end at NoteDB.
    # No tie-break order makes this pass vacuously.
    ("HandleTwoCaptures", "HandleTwoCaptures$1", "(*example.com/closureflow/store.MaskDB).Selectx"),
):
    c = one(src)
    hs = c["route"]["hops"]
    assert hs[0]["kind"] == "source" and hs[-1]["kind"] == "sink", \
        f"{src}: malformed route {[h['kind'] for h in hs]}"
    assert c["route"].get("incomplete") is None, f"{src}: route incomplete: {c['route']}"
    assert through in blob(c), f"{src}: route does not descend through {through}: {blob(c)}"
    assert hs[-1]["callee"] == sink, f"{src}: route ends at {hs[-1]['callee']}, want {sink}"
    # The BINDING hop (the one right after the source) must be openable against
    # source — a MakeClosure on a func literal carries no position of its own,
    # so the span falls back to the literal's `func` token: a hop you cannot
    # open is worse than no route. Hops inside a synthetic $bound body
    # legitimately have none — that body has no source.
    for h in (hs[1], hs[-1]):
        assert h.get("file") and h.get("line"), f"{src}: hop without a span: {h}"
    print(f"PASS: {src:<18} {len(hs)} hops through {through} -> {sink.split('.')[-2:][0]}")

# the tie-break-proof negative, stated explicitly
tc = one("HandleTwoCaptures")
assert "NoteDB" not in blob(tc), \
    f"HandleTwoCaptures: the UNTAINTED capture's sink is on the route — binding indices are crossed: {blob(tc)}"
print("PASS: HandleTwoCaptures never touches the untainted capture's sink")

# ---- precision negative: a binding that carries nothing must stay silent ----
assert not [c for c in on if "HandleUncaptured" in c["source_fn"]], \
    f"HandleUncaptured leaked a chain — the binding site is smearing whole-object taint: {dump(on)}"
print("PASS: untainted capture produces no chain")

assert len(on) == 3, f"want exactly 3 chains, got {len(on)}: {dump(on)}"
print(f"PASS chains: {len(on)}")
PY

# ===========================================================================
echo
echo "########## e2e-heapslots — abstract heap cells"
# ===========================================================================
# Producer and consumer are reached by DISJOINT call paths from the same pool.
# No call site holds both sides, so no amount of summary composition joins them
# — the join has to be manufactured over an abstract heap cell sym = H(type,
# field), in a phase-2 fixpoint. Four unmodelled edges are exercised separately:
#   HandlePlainSend   bare `ch <- v`  — *ssa.Send is not an ssa.Value
#   HandleSelectSend  the same inside `select` — how most field-sends are written
#   HandleCopyHop     the `copy` builtin — an opaque call site whose default
#                     leaf taints RESULTS, and copy's only result is a count
#   HandleTwoFields   cell identity is (type, FIELD)
cgf_differs heapslots-off    heapslots-on || suite_fail "e2e-heapslots (--heap-slots CGF identical)"
cgf_differs heapslots-narrow heapslots-on || suite_fail "e2e-heapslots (--heap-iface-narrow CGF identical)"
for v in on off chan narrow drop; do taint "heap-$v" --cgf "$CGF/heapslots-$v"; done
if grep '^heap-cells:' "$OUT/heap-on.err"; then :; else suite_fail "e2e-heapslots (no heap-cells line)"; fi
# A new fixpoint that does not converge is a disk-filling failure.
if grep -q "iteration cap" "$OUT/heap-on.err"; then
  suite_fail "e2e-heapslots (heap fixpoint hit its iteration cap)"
else
  echo "PASS: fixpoint converged under the cap"
fi
python3 - "$OUT/heap-on.json" "$OUT/heap-off.json" "$OUT/heap-chan.json" \
          "$OUT/heap-narrow.json" "$OUT/heap-drop.json" <<'PY' || suite_fail e2e-heapslots
import json, sys
on, off, chan, narrow, drop = (json.load(open(p)) for p in sys.argv[1:6])

def names(cs):
    return sorted(c["source_fn"].split(".")[-1] for c in cs)

# ---- the acceptance triple ----
# absent with the flag off, absent with only channel cells, present with all.
assert not off, f"--heap-slots off must find nothing here, got {names(off)}"
print("PASS: 0 chains with --heap-slots off")
assert not chan, (
    "chan-scoped cells must NOT close this — pending.requests is a slice field. "
    f"Got {names(chan)}: either the scope predicate leaked or the fixture stopped "
    "modelling the real pool.")
print("PASS: 0 chains with --heap-slots-scope=chan (needs non-channel fields)")

def one(src):
    cs = [c for c in on if c["source_fn"].endswith(src) and c["sink_class"] == "sqli"]
    assert len(cs) == 1, f"want exactly 1 sqli chain from {src}, got {len(cs)}: {names(on)}"
    return cs[0]

def blob(c):
    return " ".join(h["func"] + " " + (h.get("callee") or "") for h in c["route"]["hops"])

for src, note in (
    ("HandlePlainSend",  "*ssa.Send, dropped entirely before heap cells"),
    ("HandleSelectSend", "send inside select — most real field-sends"),
    ("HandleCopyHop",    "copy builtin: effect is on dst, not on the result"),
    ("HandleTwoFields",  "cell identity is (type, field)"),
):
    c = one(src)
    hs = c["route"]["hops"]
    assert hs[0]["kind"] == "source" and hs[-1]["kind"] == "sink", \
        f"{src}: malformed route {[h['kind'] for h in hs]}"
    # A heap-mediated route that stops at the writer is worse than no route.
    assert c["route"].get("incomplete") is None, \
        f"{src}: route incomplete ({c['route']['incomplete']}) — the crossing is not rendered"
    heap = [h for h in hs if h["kind"] == "heap"]
    assert len(heap) >= 1, f"{src}: no heap hop in the route: {[h['kind'] for h in hs]}"
    for h in heap:
        # a crossing the reviewer cannot open against source is the failure
        assert h.get("file") and h.get("line"), f"{src}: heap hop without a span: {h}"
        assert h["callee"], f"{src}: heap hop does not name its cell: {h}"
        assert h["confidence"] < 1.0, \
            f"{src}: an object-insensitive crossing must not claim full confidence: {h}"
    assert hs[-1]["callee"].endswith("MaskDB).Selectx"), \
        f"{src}: route ends at {hs[-1]['callee']}, want MaskDB.Selectx"
    print(f"PASS: {src:<17} {len(hs)} hops, {len(heap)} crossing(s) — {note}")

# ---- tie-break independence ----
# ONE struct, TWO fields, TWO same-class sinks, only `Eq` tainted. Whichever way
# the witness candidate sort falls, reaching NoteDB is wrong — so this cannot
# pass vacuously, and it is the assertion a type-keyed cell fails.
tf = one("HandleTwoFields")
assert "NoteDB" not in blob(tf), \
    f"HandleTwoFields reached the UNTAINTED field's sink — cells are not field-keyed: {blob(tf)}"
print("PASS: HandleTwoFields never reaches the untainted field's sink")

# ---- precision negative: a cell nothing reads must stay silent ----
assert not [c for c in on if "HandleUnread" in c["source_fn"]], \
    f"HandleUnread leaked a chain — a written-but-unread cell must produce nothing: {names(on)}"
print("PASS: a written-but-unread cell produces no chain")

assert len(on) == 11, f"want exactly 11 chains, got {len(on)}: {names(on)}"
print(f"PASS chains: {len(on)} on / 0 chan / 0 off")

# ---- interface-typed cells: the narrowing ----
# `Evt.Src` is written with two different concrete types and read in ONE place
# behind `.(SBPParam)`. The narrowing must remove the impossible pairing and
# nothing else. Keyed on (handler, sink class) — the dedupe collapses two
# same-class chains from one source, which is why readMixed's two reads land on
# different classes.
def keyed(cs):
    return {(c["source_fn"].split(".")[-1], c["sink_class"]) for c in cs}

kon, knar, kdrop = keyed(on), keyed(narrow), keyed(drop)

removed = kon - knar
assert removed == {("HandleDFAArm", "sqli"), ("HandleMixedDFA", "exec")}, \
    f"--heap-iface-narrow removed the wrong set: {sorted(removed)}"
assert not (knar - kon), f"narrowing must only REMOVE, it added {sorted(knar - kon)}"
print("PASS: narrowing removes exactly the two pairings the assertion rejects")

# the legal pairing survives — the whole reason the cheap filter was rejected
assert ("HandleSBPArm", "sqli") in knar, \
    "the ONE legal writer->reader pairing was removed: the narrowing is not type-precise"
print("PASS: the legal SBPParam pairing survives")

# a reader that does NOT discriminate keeps every writer (recall guard)
assert ("HandleRawIface", "sqli") in knar, \
    "an interface cell whose reader does not assert must keep joining — this is the blunt filter's bug"
print("PASS: an unasserted interface cell is untouched")

# per-READ-SITE, not per-function: readMixed asserts AND uses the raw value.
assert ("HandleMixedDFA", "sqli") in knar, \
    "the RAW read in readMixed lost its writer — the constraint leaked to an unguarded read site"
assert ("HandleMixedSBP", "exec") in knar and ("HandleMixedSBP", "sqli") in knar, \
    "the satisfiable writer lost a read site"
print("PASS: one function, two read sites, only the guarded one is constrained")

# non-interface cells are not in the narrowing's vocabulary at all
for h in ("HandlePlainSend", "HandleSelectSend", "HandleCopyHop", "HandleTwoFields"):
    assert (h, "sqli") in knar, f"{h}: a NON-interface cell changed under --heap-iface-narrow"
print("PASS: non-interface cells unchanged")

# ---- and the argument against the blunt filter, as an assertion ----
# "never open an interface-typed cell" is free on today's corpora and silently
# lossy in general. Here it deletes 5 pairings, 3 of them TRUE.
lost_true = {("HandleSBPArm", "sqli"), ("HandleRawIface", "sqli"), ("HandleMixedSBP", "exec")}
assert lost_true <= (kon - kdrop), \
    f"--heap-iface-drop was expected to delete these true flows: {sorted(lost_true - (kon - kdrop))}"
assert lost_true & kdrop == set(), "blunt filter kept a flow it cannot keep"
assert len(drop) == 4, f"blunt filter: want 4 chains, got {len(drop)}: {names(drop)}"
print(f"PASS: the REJECTED blunt filter costs {len(on) - len(drop)} chains "
      f"({len(lost_true)} of them true) vs the narrowing's {len(on) - len(narrow)} (0 true)")
PY

# ===========================================================================
echo
echo "########## e2e-byrefout — by-ref out params and the receiver"
# ===========================================================================
cgf_differs byrefout-on byrefout-off || suite_fail "e2e-byrefout (--byref-out CGF identical)"
taint byref-on  --cgf "$CGF/byrefout-on"
taint byref-off --cgf "$CGF/byrefout-off"
python3 - "$OUT/byref-on.json" "$OUT/byref-off.json" <<'PY' || suite_fail e2e-byrefout
import json, sys
on, off = (json.load(open(p)) for p in sys.argv[1:3])

def names(cs):
    return sorted(c["source_fn"].split(".")[-1] for c in cs)

assert not off, f"--byref-out off must find nothing here, got {names(off)}"
print("PASS: 0 chains with --byref-out off")

def one(src):
    cs = [c for c in on if c["source_fn"].endswith(src) and c["sink_class"] == "sqli"]
    assert len(cs) == 1, f"want exactly 1 sqli chain from {src}, got {len(cs)}: {names(on)}"
    return cs[0]

def blob(c):
    return " ".join(h["func"] + " " + (h.get("callee") or "") for h in c["route"]["hops"])

for src, callee, note in (
    ("HandleOutParam",    "app.fillWhere", "OUT_PARAM_BYREF on a plain *T out param"),
    ("HandleReceiver",    "Builder).SetSQL", "the RECEIVER — unaddressable as ByRefParam(0)"),
    ("HandlePassThrough", "app.relay",     "pass-through: no local write in the middle frame"),
    ("HandleTwoOuts",     "app.split",     "two out params, one call"),
):
    c = one(src)
    hs = c["route"]["hops"]
    assert hs[0]["kind"] == "source" and hs[-1]["kind"] == "sink", \
        f"{src}: malformed route {[h['kind'] for h in hs]}"
    # A route that stops at the mutating callee is "worse than no route": the
    # reviewer cannot see where the value came back.
    assert c["route"].get("incomplete") is None, \
        f"{src}: route incomplete ({c['route']['incomplete']})"
    assert callee in blob(c), \
        f"{src}: the mutating frame {callee} is missing from the route: {blob(c)}"
    assert hs[-1]["callee"].endswith("MaskDB).Selectx"), \
        f"{src}: route ends at {hs[-1]['callee']}, want MaskDB.Selectx"
    print(f"PASS: {src:<18} {len(hs)} hops via {callee:<16} — {note}")

# ---- the receiver-index guard ----
# `b.SetSQL(v)` passes (receiver, v). Encoded as ByRefParam(0) the callee's
# receiver write lands on arg port 1 — `v` — which is ALREADY tainted here, so
# the recall assertion above would still pass. What it cannot fake is reaching
# the sink through `b.SQL`: that requires the fact on port 0.
rc = one("HandleReceiver")
assert "Builder).SetSQL" in blob(rc), "the receiver-mutating frame vanished"
print("PASS: the receiver write lands on the receiver port, not on arg 1")

# ---- tie-break independence ----
# ONE callee, TWO by-ref out params, TWO same-class sinks, only `eq` tainted.
# Whichever way the witness sort falls, reaching NoteDB is wrong — an out-slot
# keyed on the CALL rather than on the param index fails only here.
to = one("HandleTwoOuts")
assert "NoteDB" not in blob(to), \
    f"HandleTwoOuts reached the UNTAINTED param's sink — out-slots are not param-keyed: {blob(to)}"
assert not [c for c in on if c["source_fn"].endswith("HandleTwoOuts") and "NoteDB" in blob(c)], \
    "an untainted by-ref out param produced a chain"
print("PASS: HandleTwoOuts never reaches the untainted param's sink")

# ---- precision negative ----
assert not [c for c in on if "HandleUnread" in c["source_fn"]], \
    f"HandleUnread leaked a chain — a written-but-unread out param must be silent: {names(on)}"
print("PASS: a written-but-unread out param produces no chain")

assert len(on) == 4, f"want exactly 4 chains, got {len(on)}: {names(on)}"
print(f"PASS chains: {len(on)} on / 0 off")
PY

# ===========================================================================
echo
echo "########## e2e-errorleaf — error-typed result ports"
# ===========================================================================
# The FP: a callsite with no resolvable summary passes taint arg -> ALL results,
# one of which is the `error`, and the error is logged. That was measured at
# roughly a quarter of all findings on one corpus — the largest FP class here.
# Every suppression is paired with the recall guard that must survive it.
cgf_differs errorleaf-on errorleaf-off || suite_fail "e2e-errorleaf (--error-results CGF identical)"
# base:  OFF corpus, no rule            -> the pre-rule behaviour
# inert: OFF corpus + --no-error-leaf   -> the rule has no facts to act on
# onoff: ON corpus, no rule
# fix:   ON corpus + --no-error-leaf    -> the rule
taint err-base  --cgf "$CGF/errorleaf-off"
taint err-inert --cgf "$CGF/errorleaf-off" --no-error-leaf
taint err-onoff --cgf "$CGF/errorleaf-on"
taint err-fix   --cgf "$CGF/errorleaf-on"  --no-error-leaf
grep -q '^error-leaf:' "$OUT/err-fix.err" || suite_fail "e2e-errorleaf (no error-leaf census line)"
grep -q 'WARNING' "$OUT/err-inert.err" \
  || suite_fail "e2e-errorleaf (--no-error-leaf on a corpus without the facts must warn loudly)"
echo "PASS: census line present; the no-facts case warns"
# The flag is an escape hatch: OFF must reproduce today's findings on the SAME
# corpus, or the A/B is not attributable.
if diff -q "$OUT/err-base.json" "$OUT/err-inert.json" > /dev/null; then
  echo "PASS: the rule is inert without the CGF fact"
else
  suite_fail "e2e-errorleaf (--no-error-leaf changed findings on a corpus with no error_results)"
fi
python3 - "$OUT/err-onoff.json" "$OUT/err-fix.json" <<'PY' || suite_fail e2e-errorleaf
import json, sys
off, fix = (json.load(open(p)) for p in sys.argv[1:3])

def keys(cs):
    return {(c["source_fn"].split(".")[-1], c["sink_class"],
             (c["route"]["hops"][-1].get("callee") or "").split("/")[-1]) for c in cs}

koff, kfix = keys(off), keys(fix)
assert not (kfix - koff), f"the rule must only REMOVE, it added {sorted(kfix - koff)}"
print("PASS: the rule only removes")

def gone(handler, why):
    hit = {k for k in koff - kfix if k[0] == handler}
    assert hit, (f"{handler} survived --no-error-leaf; it must not ({why}). "
                 f"still present: {sorted(k for k in kfix if k[0] == handler)}")
    print(f"PASS: {handler:<19} suppressed — {why}")

def kept(handler, why):
    hit = {k for k in kfix if k[0] == handler}
    assert hit, f"{handler} was suppressed but must SURVIVE ({why})"
    print(f"PASS: {handler:<19} survives  — {why}")

# ---- the suppressions ----
gone("HandleSingleErr", "1-result error producer — where the real keys are")
gone("HandleViaHelper", "IN-SCOPE producer, killed transitively at the leaf inside it")

# ---- the recall guards ----
kept("HandleValueSurvives", "same callsite, VALUE port: the rule is per port")
kept("HandleWrapped",       "fmt.Errorf carries request data")
kept("HandleHelperWraps",   "in-scope helper BUILDS its error from the request — "
                            "a summary-side rule would have deleted this")

# ---- the MEASURED LIMITATION ----
# A 2-result leaf still leaks. Result port 0 doubles as the alias for the whole
# Call value, and computeEdges walks each source VALUE, so the tuple's walk
# lands port 0 on the consumers of `err` too — the per-port filter never sees
# it. Two emission fixes were built and BOTH were rejected on measurement: each
# cost real findings elsewhere and bought fewer than it cost.
#
# These assertions pin the limitation so it cannot be forgotten OR silently
# "fixed" without re-measuring: they FAIL the day someone closes the leak, which
# is the correct trigger to re-run the measurement.
kept("HandleErrOnly", "KNOWN LEAK: 2-result leaf, port 0 aliases the tuple "
                      "(the two fixes cost more than they bought)")
tb_off = {k[2] for k in koff if k[0] == "HandleTieBreak"}
tb_fix = {k[2] for k in kfix if k[0] == "HandleTieBreak"}
assert any("MaskDB" in s for s in tb_off) and any("NoteDB" in s for s in tb_off), \
    f"fixture broken: both tie-break sinks must be reachable before the fix, got {sorted(tb_off)}"
assert any("MaskDB" in s for s in tb_fix), "HandleTieBreak lost its TRUE sink (MaskDB)"
assert any("NoteDB" in s for s in tb_fix), \
    "HandleTieBreak's err.Error() sink is gone — the port-0 tuple alias leak is CLOSED. " \
    "That is a real improvement, but it changes every published number for this rule: " \
    "re-measure before updating this test."
print("PASS: HandleTieBreak      keeps the value sink; the err.Error() sink still leaks (pinned)")

print(f"PASS chains: {len(off)} without the rule / {len(fix)} with it "
      f"(the 2 that remain beyond the recall guards are the pinned port-0 leak)")
PY

# ===========================================================================
echo
echo "########## e2e-miniledger — dispatch-induced SCCs and the SCC fixpoint"
# ===========================================================================
# A scaled-down real-service shape — god-object Implementation + one *Storage
# behind many small interfaces + generic pool closures. Asserts per-mode chains
# and confidences AND the trace-level SCC story: dispatch-induced multi-member
# SCCs appear under vta/cha, never under off.
cgf_differs miniledger-off miniledger-vta || suite_fail "e2e-miniledger (off and vta CGF identical)"
# Divergence guard: cap written files at 2GB (SIGXFSZ) and wall-clock at 300s,
# so a non-converging fixpoint fails fast instead of filling the disk.
ml_ok=1
for mode in vta cha off; do
  ( ulimit -f 2097152
    perl -e 'alarm 300; exec @ARGV' "$PC" taint --cgf "$CGF/miniledger-$mode" \
        --catalog "$CATALOG" --trace "$OUT/trace-$mode.log" ) \
    > "$OUT/ml-$mode.json" 2> "$OUT/ml-$mode.err" \
    || { suite_fail "e2e-miniledger (taint --dispatch=$mode killed by the divergence guard)"; ml_ok=0; }
done

if [ "$ml_ok" = 1 ]; then
python3 - "$OUT/ml-vta.json" "$OUT/ml-cha.json" "$OUT/ml-off.json" <<'PY' || suite_fail "e2e-miniledger (chains)"
import json, sys
vta, cha, off = (json.load(open(p)) for p in sys.argv[1:4])

def find(chains, src, sink="sqli"):
    return [c for c in chains if src in c["source_fn"] and c["sink_class"] == sink]

def has(chains, src, sink="sqli"):
    cs = find(chains, src, sink)
    assert cs, (f"no chain src~{src} sink={sink}: "
                + json.dumps([(c['source_fn'], c['sink_class']) for c in chains], indent=1))
    return cs

def conf(chains, src, want, name):
    for c in has(chains, src):
        assert abs(c["confidence"] - want) < 1e-6, \
            f"{name} {src} confidence {c['confidence']}, want {want}"

# Control: the all-static HandleRawQuery chains survive every mode at conf 1.0.
for name, chains in (("vta", vta), ("cha", cha), ("off", off)):
    conf(chains, "HandleRawQuery", 1.0, name)

# Dispatch-only chains: resolved in vta+cha, absent in off.
for name, chains in (("vta", vta), ("cha", cha)):
    conf(chains, "HandleGetAccount", 0.5, name)   # IAccounts, 2 impls
    conf(chains, "HandleReserves", 1.0, name)     # IStore union, 1 impl
    conf(chains, "HandleEndOfDay", 0.25, name)    # IStep, 4 impls
    conf(chains, "HandleRecalc", 1.0, name)       # ICalc 3-member SCC, 1 impl
    has(chains, "HandleEvent")                    # pool-closure 5-member SCC
for src in ("HandleGetAccount", "HandleReserves", "HandleEndOfDay",
            "HandleRecalc", "HandleEvent"):
    assert not find(off, src), f"off mode saw through unresolved dispatch: {src}"

# The exec sink inside Notifier07.Send sits behind a 12-impl (capped) site and
# must never surface in any mode.
for name, chains in (("vta", vta), ("cha", cha), ("off", off)):
    bad = [c for c in chains if c["sink_class"] == "exec"]
    assert not bad, f"{name}: capped INotifier leaked exec chain: {bad}"

# Exact counts — a tripwire against silent chain inflation.
assert (len(vta), len(cha), len(off)) == (7, 7, 2), \
    f"chain counts changed: vta={len(vta)} cha={len(cha)} off={len(off)}, want 7/7/2"

# The dedupe invariant: one chain per (source_fn, sink_class, sink_span, route.id).
for name, chains in (("vta", vta), ("cha", cha), ("off", off)):
    keys = [(c["source_fn"], c["sink_class"],
             tuple((c["sink_span"] or {}).items()), c["route"]["id"]) for c in chains]
    assert len(keys) == len(set(keys)), f"{name}: duplicate chains survived dedupe"

print(f"PASS chains: vta={len(vta)} cha={len(cha)} off={len(off)}")
PY

echo "== trace assertions =="
ml_trace=1
[ -s "$OUT/trace-vta.log" ] || { suite_fail "e2e-miniledger (empty vta trace)"; ml_trace=0; }
for ev in seed sink-hit chain; do
  grep -q "^$ev" "$OUT/trace-vta.log" || { suite_fail "e2e-miniledger (no $ev events in vta trace)"; ml_trace=0; }
done
sccs=$(grep -c '^scc-start' "$OUT/trace-vta.log" || true)
[ "${sccs:-0}" -ge 2 ] || { suite_fail "e2e-miniledger (want >=2 dispatch-induced SCCs in vta trace, got $sccs)"; ml_trace=0; }
grep '^scc-iter' "$OUT/trace-vta.log" | grep -q 'iter=2' \
  || { suite_fail "e2e-miniledger (no SCC reached fixpoint iteration 2 in vta trace)"; ml_trace=0; }

# Generic instantiations must be in the CGF (fqn strings are greppable in the
# protobuf shards) and the pool cycle Add->flush->closure->handleEventsBatch->
# retryEvent->Add must form a large SCC.
grep -aq 'Pool\[string\]).Add' "$CGF/miniledger-vta/example.com_miniledger_pool.pb" \
  || { suite_fail "e2e-miniledger (Pool[string].Add missing from CGF — generic instantiations dropped?)"; ml_trace=0; }
grep '^scc-start' "$OUT/trace-vta.log" | grep -Eq 'size=[5-9]' \
  || { suite_fail "e2e-miniledger (no size>=5 pool SCC in vta trace — generic cycle broken)"; ml_trace=0; }
offsccs=$(grep -c '^scc-start' "$OUT/trace-off.log" || true)
[ "${offsccs:-0}" -eq 0 ] \
  || { suite_fail "e2e-miniledger (off trace has $offsccs scc-start — SCCs must be dispatch-induced)"; ml_trace=0; }

# The iteration-cap backstop must never fire in any taint run of this suite:
# hitting it means the SCC fixpoint regressed to non-convergence and summaries
# are incomplete — a "passing" run with capped SCCs would be a lie.
if grep -q 'SCC fixpoint hit iteration cap' "$OUT"/ml-*.err 2>/dev/null; then
  suite_fail "e2e-miniledger (SCC fixpoint hit the iteration cap — non-convergence regression)"
  ml_trace=0
fi
[ "$ml_trace" = 1 ] && echo "PASS: e2e-miniledger (sccs=$sccs, SCCs are dispatch-induced, generics instantiated)"
fi

# ===========================================================================
echo
echo "########## e2e-backward — sink-seeded verdicts, with and without --backward-unview"
# ===========================================================================
# The three repos cross a GraphQL boundary (webapp -> federation) and a gRPC
# one (federation -> backend). Every GraphQL field here has permuted resolver
# args, so its published view is NOT the resolver's own frame and the backward
# walk used to give up at the crossing. --backward-unview undoes compose's slot
# remap instead.
#
#   flag OFF  must equal the pinned expectation below, exactly — the flag is
#             worthless if it is not free when it is off.
#   flag ON   at least as many `confirmed`, and NOT ONE chain that was
#             confirmed may come back `refuted`. A wrong unview shows up as
#             exactly that inversion, and it is the failure this guards.
taint back-off --cgf "$CGF/webapp" --cgf "$CGF/federation" --cgf "$CGF/backend" --backward
taint back-on  --cgf "$CGF/webapp" --cgf "$CGF/federation" --cgf "$CGF/backend" --backward --backward-unview
grep '^backward:' "$OUT/back-off.err" "$OUT/back-on.err"
python3 - "$OUT/back-off.json" "$OUT/back-on.json" <<'PY' || suite_fail e2e-backward
import json, sys, collections
off = json.load(open(sys.argv[1]))
on  = json.load(open(sys.argv[2]))

def verdicts(chains):
    return collections.Counter(c["backward"]["verdict"] for c in chains)
def key(c):
    return (c["source_fn"], c["sink_class"],
            tuple(sorted((c["sink_span"] or {}).items())), c["route"]["id"])

vo, vn = verdicts(off), verdicts(on)

# --- flag OFF: the pinned expectation (derived 2026-09-05, pre-unview code) --
assert len(off) == 15, f"chain count changed: {len(off)}, want 15"
assert (vo["confirmed"], vo["refuted"], vo["undecided"]) == (8, 0, 7), \
    f"--backward without --backward-unview changed verdicts: {dict(vo)}, want 8/0/7"
assert not any(c["backward"].get("unviewed") for c in off), \
    "flag OFF must never mark a chain `unviewed`"

# --- flag ON: same chains, no lost confirmations, no inverted verdict -------
assert len(on) == len(off), f"the flag changed the chain SET: {len(on)} vs {len(off)}"
assert vn["confirmed"] >= vo["confirmed"], \
    f"--backward-unview lost confirmations: {dict(vn)} vs {dict(vo)}"

bo = {key(c): c["backward"] for c in off}
bn = {key(c): c["backward"] for c in on}
assert set(bo) == set(bn), "the flag changed which chains are reported"
flipped = [k for k in bo
           if bo[k]["verdict"] == "confirmed" and bn[k]["verdict"] == "refuted"]
assert not flipped, f"unview inverted a verified chain to refuted: {flipped}"
# nothing may go the other way either: a verdict may only get SHARPER
regressed = [k for k in bo
             if bo[k]["verdict"] != "undecided" and bo[k]["verdict"] != bn[k]["verdict"]]
assert not regressed, f"unview changed an already-decided verdict: {regressed}"

# --- and it must not be inert on this corpus -------------------------------
gained = vn["confirmed"] - vo["confirmed"]
assert gained > 0, "no crossing was unviewed — the flag is inert on this corpus"
assert sum(1 for c in on if c["backward"].get("unviewed")) >= gained

print(f"PASS: e2e-backward off={dict(vo)} on={dict(vn)} "
      f"(+{gained} confirmed, 0 confirmed->refuted inversions)")
PY

# The summary line must report how many verdicts the unview step moved, and it
# must be 0 when the flag is off.
grep -q 'unview-flips=0 ' "$OUT/back-off.err" \
  || suite_fail "e2e-backward (flag off reported a non-zero unview-flips)"
grep -qE 'unview-flips=[1-9]' "$OUT/back-on.err" \
  || suite_fail "e2e-backward (flag on reported no unview-flips)"

# --backward-prune must not act on a refutation that crossed an unviewed
# contract unless --backward-prune-unviewed says so.
taint back-prune  --cgf "$CGF/webapp" --cgf "$CGF/federation" --cgf "$CGF/backend" --backward-prune --backward-unview
python3 - "$OUT/back-on.json" "$OUT/back-prune.json" <<'PY' || suite_fail e2e-backward-prune
import json, sys
on    = json.load(open(sys.argv[1]))
prune = json.load(open(sys.argv[2]))
kept = {c["backward"]["verdict"] for c in prune}
assert "refuted" not in kept, "a refuted chain survived --backward-prune"
# every chain the unprunable rule protects must still be there
protected = [c for c in on
             if c["backward"]["verdict"] == "refuted" and c["backward"].get("unviewed")]
assert len(prune) == len(on) - (len([c for c in on if c["backward"]["verdict"] == "refuted"])
                                - len(protected)), \
    "the default prune dropped an unviewed refutation"
for c in prune:
    b = c["backward"]
    if b.get("reason") == "unviewed_refutation_not_pruned":
        assert b["verdict"] == "undecided" and b["unviewed"]
print(f"PASS: e2e-backward-prune kept={len(prune)}/{len(on)} "
      f"(protected unviewed refutations: {len(protected)})")
PY

# ===========================================================================
echo
echo "########## e2e-recursion — self-recursive SCC iteration, witness diamond + dispatch retry"
# ===========================================================================
# fixtures/recursion (Go frontend repo). Six handlers, one engine case each:
#   WalkTree        the fact changes SLOT across the recursive call (n -> acc):
#                   without iterating the self-recursive singleton SCC the
#                   chain is missed entirely (recall)
#   RecurseReturn   same shape on the return side (least fixpoint, precision)
#   DirectSink      sink on every frame — exactly one chain, no duplication
#   MutualRecursion two-fn SCC control — unchanged behaviour
#   Diamond         a->shared, b->shared — the second visit is not a cycle
#   PickSecond      2-impl dispatch where the FIRST candidate has no sink —
#                   the witness must fall through to the second
taint rec --cgf "$CGF/recursion" --trace "$OUT/trace-rec.log"
cat "$OUT/rec.err"
python3 - "$OUT/rec.json" <<'PY' || suite_fail e2e-recursion
import json, sys
chains = json.load(open(sys.argv[1]))

def by(src):
    return [c for c in chains if src in c["source_fn"] and c["sink_class"] == "sqli"]

def hops(c):
    return c["route"]["hops"]

def well_formed(c, src):
    hs = hops(c)
    assert "incomplete" not in c["route"], f"{src}: route incomplete: {c['route'].get('incomplete')}"
    assert hs[0]["kind"] == "source" and hs[-1]["kind"] == "sink", \
        f"{src}: malformed route {[h['kind'] for h in hs]}"
    assert hs[-1]["callee"].endswith((".Execx", ".Selectx")), f"{src}: must end at the SQL sink: {hs[-1]}"

# ---- WalkTree: the fact changes SLOT across the recursive call (n -> acc).
# A summary computed without iterating the self-recursive SCC has no row for
# `n` and misses this chain entirely. This is the recall assertion.
ws = by("WalkTree")
assert len(ws) == 1, f"WalkTree: want 1 sqli chain, got {len(ws)}: {[c['source_fn'] for c in chains]}"
well_formed(ws[0], "WalkTree")
rec = [h for h in hops(ws[0]) if h["kind"] == "call" and h.get("callee", "").endswith("app.walk")]
assert len(rec) >= 2, f"WalkTree: route must descend through the recursive call twice, got {rec}"
assert hops(ws[0])[-1]["func"].endswith("app.walk"), "WalkTree: sink must be inside walk"

# ---- RecurseReturn: n reaches the return only as `acc` of the next frame.
rs = by("RecurseReturn")
assert len(rs) == 1, f"RecurseReturn: want 1 sqli chain, got {len(rs)}"
well_formed(rs[0], "RecurseReturn")
assert any(h.get("callee", "").endswith("app.last") for h in hops(rs[0])), "RecurseReturn: route must call last"
assert hops(rs[0])[-1]["callee"].endswith(".Selectx")

# ---- DirectSink: sink on every frame — exactly one chain, no duplication
ds = by("DirectSink")
assert len(ds) == 1, f"DirectSink: want exactly 1 chain, got {len(ds)}"
well_formed(ds[0], "DirectSink")

# ---- MutualRecursion: two-fn SCC, sink in pong — still exactly one chain
ms = by("MutualRecursion")
assert len(ms) == 1, f"MutualRecursion: want exactly 1 chain, got {len(ms)}"
well_formed(ms[0], "MutualRecursion")
assert hops(ms[0])[-1]["func"].endswith("app.pong"), "MutualRecursion: sink must be in pong"

# ---- Diamond: a->shared and b->shared; the second visit of `shared` must
# NOT be reported as a cycle (per-branch visited set in the witness)
dm = by("Diamond")
assert len(dm) == 2, f"Diamond: want 2 chains (via a, via b), got {len(dm)}"
vias = set()
for c in dm:
    well_formed(c, "Diamond")
    assert hops(c)[-1]["func"].endswith("app.shared")
    vias |= {h["callee"].rsplit(".", 1)[-1] for h in hops(c) if h["kind"] == "call"}
assert {"a", "b"} <= vias, f"Diamond: routes must go via a AND b, saw {vias}"

# ---- PickSecond: Runner has two impls, NoopRunner sorts first and has no
# sink. The witness must fall through to SinkRunner (candidate retry).
ps = by("PickSecond")
assert len(ps) == 1, f"PickSecond: want exactly 1 chain, got {len(ps)}"
well_formed(ps[0], "PickSecond")
disp = [h for h in hops(ps[0]) if h["kind"] == "call" and h.get("callee", "").endswith("Runner).Run")]
assert len(disp) == 1 and abs(disp[0]["confidence"] - 0.5) < 1e-6, f"PickSecond: dispatch hop {disp}"
assert hops(ps[0])[-1]["func"].endswith("SinkRunner).Run"), \
    f"PickSecond: route must reproduce through SinkRunner, got {hops(ps[0])[-1]['func']}"
assert ps[0].get("route_confidence", 1.0) <= 0.5 + 1e-6, "PickSecond: route_confidence must carry the 0.5 hop"

total = len([c for c in chains if c["sink_class"] == "sqli"])
assert total == 7, f"want 7 sqli chains total, got {total}: {[c['source_fn'] for c in chains]}"
print(f"PASS: e2e-recursion 7 chains, all routes complete; WalkTree recovered through the self-recursive SCC")
PY
# the self-recursive singleton must actually iterate (visible as size=1 scc-iter)
if [ -s "$OUT/trace-rec.log" ]; then
  grep -Eq '^scc-iter +size=1' "$OUT/trace-rec.log" \
    || suite_fail "e2e-recursion (no size=1 scc-iter in trace — the self-recursive SCC did not iterate)"
else
  suite_fail "e2e-recursion (empty trace)"
fi

# ===========================================================================
echo
echo "########## e2e-libwrites — library calls that write into an argument"
# ===========================================================================
# fixtures/libwrites (Go frontend repo) and fixtures/weblib (TS frontend repo).
# The core has no body for library code; its default leaf sends a call's inputs
# to its RESULTS only, so `sb.WriteString(q)` filling sb, `json.Unmarshal(b, &t)`
# filling t, `parts.push(q)` filling parts were lost. A catalog [[propagators]]
# rule names the port the call writes; the frontend's library write-back edge
# (the -off dirs were extracted without it) carries the write to the caller.
# Every positive case: 0 chains without the rules, 0 without the write-back,
# exactly one with both. thirdparty/ was extracted OUT of scope — a dependency
# the shipped catalog cannot know, which `--unmodeled` must name.
cgf_differs libwrites libwrites-off || suite_fail "e2e-libwrites (Go write-back CGF identical)"
cgf_differs weblib weblib-off       || suite_fail "e2e-libwrites (TS write-back CGF identical)"
python3 - "$CATALOG" "$OUT/cat-norules.toml" "$OUT/cat-plus.toml" <<'PY'
import re, sys
src = open(sys.argv[1]).read()
blocks = re.split(r'\n(?=\[\[)', src)
open(sys.argv[2], "w").write("\n".join(b for b in blocks if not b.startswith("[[propagators]]")) + "\n")
open(sys.argv[3], "w").write(src + '\n[[propagators]]\nselector = "example.com/libwrites/thirdparty.Fill"\nfrom = "1"\nto = "0"\n')
PY
taint lw         --cgf "$CGF/libwrites"
taint lw-back    --cgf "$CGF/libwrites" --backward-prune
taint lw-unmod   --cgf "$CGF/libwrites" --unmodeled "$OUT/lw-unmodeled.json"
taint lw-offwb   --cgf "$CGF/libwrites-off"
taint wl         --cgf "$CGF/weblib"
taint wl-offwb   --cgf "$CGF/weblib-off"
"$PC" taint --catalog "$OUT/cat-norules.toml" --cgf "$CGF/libwrites" > "$OUT/lw-norules.json" 2> "$OUT/lw-norules.err"
"$PC" taint --catalog "$OUT/cat-norules.toml" --cgf "$CGF/weblib"    > "$OUT/wl-norules.json" 2> "$OUT/wl-norules.err"
"$PC" taint --catalog "$OUT/cat-plus.toml" --cgf "$CGF/libwrites" --unmodeled "$OUT/lw-unmodeled-plus.json" \
  > "$OUT/lw-plus.json" 2> "$OUT/lw-plus.err"
grep -h "propagators match" "$OUT/lw.err" "$OUT/wl.err" || suite_fail "e2e-libwrites (no propagator fit line)"
python3 - "$OUT" <<'PY' || suite_fail e2e-libwrites
import json, os, sys
OUT = sys.argv[1]
def load(n): return json.load(open(os.path.join(OUT, n + ".json")))
def srcs(cs): return sorted({c["source_fn"].split(".")[-1].split(":")[-1] for c in cs})

GO = ["Base64", "Buffer", "Builder", "Copy", "Decode", "Fprintf", "MapsCopy", "Template", "Unmarshal", "Values"]
TS = ["viaAssign", "viaMap", "viaParams", "viaPush", "viaSet"]

go = [c for c in load("lw") if c["sink_class"] == "sqli"]
assert srcs(go) == GO, f"Go with the shipped rules: want {GO}, got {srcs(go)}"
for c in go:
    r = c["route"]
    assert r.get("incomplete") is None, f"{c['source_fn']}: route incomplete: {r}"
    assert r["hops"][-1]["callee"].endswith("store.DB).Selectx"), r["hops"][-1]
print(f"PASS: e2e-libwrites Go — all {len(GO)} library shapes, every route complete and ending at Selectx")

assert not [c for c in load("lw-norules") if c["sink_class"] == "sqli"], srcs(load("lw-norules"))
assert not [c for c in load("lw-offwb") if c["sink_class"] == "sqli"], srcs(load("lw-offwb"))
print("PASS: e2e-libwrites Go — 0 chains without the rules, 0 without the write-back edge")

for neg in ("CleanBuilder", "CleanUnmarshal", "ThirdParty"):
    assert neg not in srcs(go), f"{neg} must stay silent with the shipped catalog"
print("PASS: e2e-libwrites Go — CleanBuilder / CleanUnmarshal silent; ThirdParty unknown to the catalog")

um = json.load(open(os.path.join(OUT, "lw-unmodeled.json")))
assert [u["callee"] for u in um] == ["example.com/libwrites/thirdparty.Fill"], f"--unmodeled: {um}"
assert srcs(load("lw-unmod")) == srcs(load("lw")), "--unmodeled must not change the findings on stdout"
assert srcs([c for c in load("lw-plus") if c["sink_class"] == "sqli"]) == sorted(GO + ["ThirdParty"])
assert json.load(open(os.path.join(OUT, "lw-unmodeled-plus.json"))) == []
print("PASS: e2e-libwrites --unmodeled names exactly the uncovered dependency call; one rule finds it and empties the report")

assert srcs([c for c in load("lw-back") if c["sink_class"] == "sqli"]) == GO, "--backward-prune dropped a propagator chain"
print("PASS: e2e-libwrites --backward-prune keeps every propagator chain")

ts = load("wl")
assert srcs(ts) == TS, f"TS with the shipped rules: want {TS}, got {srcs(ts)}"
assert not load("wl-norules") and not load("wl-offwb"), "TS: rules and write-back are both required"
print(f"PASS: e2e-libwrites TS — all {len(TS)} built-ins; cleanPush / untypedPush silent; 0 without rules or write-back")
PY

# ===========================================================================
echo
echo "==========================================================="
if [ ${#FAILED[@]} -eq 0 ]; then
  echo "e2e-core: ALL SUITES PASS"
  exit 0
fi
echo "e2e-core: ${#FAILED[@]} FAILURE(S):"
printf '  - %s\n' "${FAILED[@]}"
exit 1
