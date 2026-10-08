# CLI reference

```
panopticode <COMMAND> [OPTIONS]
panopticode --version
```

| command | what it does | needs |
|---|---|---|
| `taint` | the analysis: load CGF, summarize, compose, print chains as JSON | CGF dirs, a catalog; Postgres only with `--pg` |
| `graph-dump` | counts of what was loaded | CGF dirs |
| `summary` | debug print of computed summaries | CGF dirs, a catalog |
| `extract` | run the Go frontend `pc-fe` | `pc-fe` |
| `impact` | merge-request mode against a warm summary store | a git checkout, `pc-fe`, a store dir |
| `query blast\|reach\|path` | read-only queries over a persisted call graph | Postgres filled by `taint --pg` |

`--cgf <dir>` reads every `*.pb` file directly in that directory (not
recursively). Repeat it to load several repositories into one program. A
directory with no `.pb` files is not an error: it loads zero functions and the
run succeeds with no chains.

`--catalog` defaults to `catalog.example.toml` resolved against the current
directory, so outside the repository root pass it explicitly.

## Exit codes

| code | meaning |
|---|---|
| 0 | success, including a run that found nothing |
| 1 | any runtime error, printed as `Error: ...` on stderr: unreadable catalog, invalid regex or port spec in the catalog, missing `--cgf` directory, undecodable CGF, unreachable Postgres, a failed `pc-fe`, an unknown `--trace-events` kind, a `query` that matches nothing |
| 2 | command-line usage error (from the argument parser) |

## taint

```
panopticode taint --cgf <dir> [--cgf <dir> ...] [--catalog <file>] [flags]
```

stdout is a JSON array of chains, sorted so output is byte-stable across runs.
stderr carries diagnostics and a final stats line. For the README quickstart
(the inert-rule lines, the `opaque:` detail and the `route-stats:` line
elided):

```
normalize: 1 by-name callsite(s), 0 arg port(s) moved into contract position, 0 dangling name(s), 0 unknown contract(s)
catalog-fit: 7/88 rules match at least one call site (47 distinct callees) — inert rules follow; ...
catalog-warn: inert rule <section>[<class|kind>] "<selector>" — no call site matches it (zero recall here)
catalog-fit: 0/23 propagators match at least one call site
opaque: 5 of 75 call sites into a Go module or func value have no loaded body (default leaf: ...) — top modules: ...
functions=56 summaries=63 contracts_linked=7 remote_leaves=0 chains=15 cache_hits=2 cache_misses=54
```

See [catalog.md](catalog.md#diagnostics) for what the `catalog-*` and `opaque`
lines mean.

A corpus with HTTP routes or synthetic HTTP client sites (coverage wave 1)
adds, right after the `normalize:` line:

```
http-link: sites=N linked=K (exact=a suffix=b fanout=f) ambiguous=c unlinked=d routes=R
http-link: top unlinked templates: POST /{}/api/orders ×3, GET /health ×1, …
```

`sites` counts client sites, `routes` the HTTP route contracts loaded. A site
is `exact` when its whole path matched with at least one literal segment in
agreement, `suffix` when only a suffix did (an unresolved base URL or mount
prefix; at least two literal segments must agree),
`fanout` when it was linked to 2 to 4 equally good routes, `ambiguous` when more
than 4 tied (left unlinked), `unlinked` when nothing matched. The second line
lists the commonest templates that were not linked, ambiguous ones marked; it
is where a missing route or an unresolved prefix shows up. Neither line
appears on a corpus without HTTP facts. With `--no-http-link` the census is
replaced by `http-link: off (--no-http-link) — N client site(s) left unlinked`.

| flag | default | effect |
|---|---|---|
| `--cgf <dir>` | required, repeatable | a CGF directory; several compose across contracts |
| `--catalog <file>` | `catalog.example.toml` | the policy file, see [catalog.md](catalog.md) |
| `--endpoint <substr>` | none | keep only chains whose source function fqn contains the substring |
| `--pg <url>` | none | persist the call graph, contracts and summaries to Postgres, and read contract views for contracts no loaded CGF serves (counted as `remote_leaves`). The schema must already exist, see [Postgres](#postgres) |
| `--store <dir>` | none | filesystem summary cache: reuse cached summaries and write new ones. Warms the cache `impact` reads. Independent of Postgres |
| `--trace <file>` | none | write one line per engine event |
| `--trace-fn <substr>` | none | trace only functions whose fqn contains the substring |
| `--trace-events <csv>` | all | trace only these kinds: `seed summary scc-start scc-iter apply leaf propagate sink-hit heap-hit heap-cell heap-narrow chain widen back back-step back-frame`. With `--trace`, an unknown kind is an error; without it the flag has no effect and is not checked |
| `--no-error-leaf` | off | the default leaf stops tainting error-typed results. Needs CGF from `pc-fe --error-results` (warns if absent); catalog `[[error_wrappers]]` are exempt |
| `--backward` | off | add a backward verdict to every chain; removes nothing |
| `--backward-prune` | off | also drop refuted chains (implies `--backward`). The only flag that removes findings. A refutation whose walk crossed an unviewed contract is kept as `undecided` |
| `--backward-unview` | off | let the backward walk cross contracts whose view is not the handler's own frame (streaming gRPC, GraphQL) instead of stopping `undecided` (implies `--backward`) |
| `--backward-prune-unviewed` | off | let `--backward-prune` also drop refutations that crossed such a contract. Does nothing on its own |
| `--pb-getters` | off | treat an out-of-scope protobuf getter as a projection of exactly its field, forward and backward |
| `--unmodeled <file>` | none | write a JSON report of body-less library calls that tainted data reaches, that could write into another argument, and that no `[[propagators]]` rule covers; the top 15 also go to stderr. stdout is unchanged |
| `--no-http-link` | off | do not link synthetic HTTP client sites to the loaded HTTP routes. Unlinked sites are inert, so the chains are those of a corpus without HTTP facts. Not a store namespace flag: linking leaves phase-1 summaries unchanged |

All flags are off by default, so a default run is the plain analysis and any
difference is attributable to the flag you added. HTTP linking is part of the
plain analysis; `--no-http-link` is the one flag that turns something off. `--no-error-leaf`,
`--pb-getters` and `--unmodeled` change results or add pseudo-sinks, so they
also select a separate namespace in the `--store` cache.

### Chain JSON

The finding pictured in the README, from the quickstart run (the [example
system](example.md#one-finding-hop-by-hop) walks through every hop), trimmed to
its first and last route hops:

```json
{
  "source_repo": "webapp",
  "source_fn": "src/routes/search/+page.svelte:$script",
  "sink_class": "sqli",
  "sink_span": {"file": "src/routes/search/+page.svelte", "line": 11},
  "hops": [...],
  "route": {
    "id": "a956a2f72f24",
    "hops": [
      {"repo": "webapp", "func": "src/routes/search/+page.svelte:$script", "kind": "source", "confidence": 1.0},
      ...
      {"repo": "example.com/backend", "func": "(*example.com/backend/store.Storage).findBy",
       "file": ".../backend/store/store.go", "line": 13, "kind": "sink",
       "callee": "(*example.com/backend/store.Storage).Selectx", "confidence": 1.0}
    ],
    "boundaries": 2
  },
  "sanitized": false,
  "confidence": 1.0,
  "route_confidence": 1.0
}
```

- `sink_span` is the call in the source function through which the chain
  reaches its sink: the sink call itself when the sink is local, otherwise the
  first call on the way (here `searchClient.call(...)`). The sink's own
  location is the last entry of `route.hops`.
- `route.hops[]` is the full route: `repo, func, file, line, kind, callee,
  field(s), confidence`, with `kind` one of `source call boundary sink heap`.
- `route.boundaries` counts the contracts the route crosses. A `boundary`
  hop's `callee` is the client's callee name, except across an HTTP route,
  where it names the route actually entered: `http POST /api/users (gin)`
  (method, the path as the server wrote it, the framework). A `heap` hop's
  `callee` names the cell; for a Kafka topic, `kafka topic <name>`.
- `route.incomplete`, when present, says why the route stops early:
  `depth_cap`, `cycle`, `handler_not_loaded`, `callee_body_missing`,
  `not_reproduced`.
- `route.id` is a content hash of the route, stable across runs.
- `route_confidence` is the minimum over the route; the top-level `confidence`
  covers only the source function's own call resolution. Use `route_confidence`.
- `sink_field` / `sink_fields` name the field at the sink, when known.
- The top-level `hops` lists call sites in the source function only; prefer
  `route.hops`. `sanitized` is always `false` (sanitized flows are dropped, not
  reported).

With `--backward` each chain also gets `backward`:
`{"verdict": "confirmed|refuted|undecided", "exact", "source_fields", "terminal", "reason", "unviewed"}`.
For `undecided`, `reason` is `walk_incomplete`, `unview_dropped_slot` or
`unviewed_refutation_not_pruned`; when the walk cannot start it is
`heap_crossing`, `no_route`, `no_terminal` or `route_incomplete:<kind>` (e.g.
`route_incomplete:HandlerNotLoaded`). stderr gets a summary line. On the fixture corpus from the README quickstart:

```
$ panopticode taint ... --backward
backward: confirmed=8 (exact=8, route-terminal-refuted=0) refuted=0 undecided=7 pruned=0 unview-flips=0 in 0.00s
$ panopticode taint ... --backward-unview
backward: confirmed=13 (exact=13, route-terminal-refuted=0) refuted=0 undecided=2 pruned=0 unview-flips=5 in 0.00s
```

## graph-dump

```
panopticode graph-dump --cgf <dir> [--cgf <dir> ...]
```

Prints one line of counts. The quickest check that an extraction produced
contracts. For the three repositories of the README quickstart:

```
$ panopticode graph-dump --cgf testdata/cgf/webapp --cgf testdata/cgf/federation --cgf testdata/cgf/backend
packages=11 functions=56 grpc_methods=4 graphql_fields=3 http_routes=0 endpoints={grpc:4,graphql:3,http:2,message:0} languages={go:8,ts:3}
```

`endpoints` counts `Endpoint` facts by kind; an endpoint kind this core does not
know is added as `unknown:N`. Like `taint`, `graph-dump` links HTTP client sites
first, so its stderr carries the `http-link:` census when there is one.

## summary

```
panopticode summary --cgf <dir> [--cgf <dir> ...] [--catalog <file>] --fn <substr>
```

For every function whose fqn contains the substring, prints its source and sink
call sites, flow pairs and sink hits in Rust debug format. For debugging only:
not JSON, and the order is not stable.

## extract

```
panopticode extract --repo <dir> --out <dir> [--scope <pat>] [--mode main] [--fe pc-fe]
```

Runs `pc-fe build <repo> --out <out> --mode <mode> [--scope <pat>]` and fails if
it fails. It forwards no other flag; call `pc-fe` directly for any extraction
option (see the [panoptife-go](https://github.com/panoptiorg/panoptife-go)
README).

[`scripts/analyze.sh`](../scripts/analyze.sh) is a worked example of a whole
run on real Go repositories: it extracts each one with `pc-fe`, then runs
`taint` over all of them, optionally with `--pg` and `--store`.

## impact

```
panopticode impact --repo <dir> --base <sha> --head <sha> --store <dir> \
  [--scope <pat>] [--cgf <dir> ...] [--catalog <file>] [--out <dir>] [--fe pc-fe] [--pg <url>]
```

Re-extracts `--repo` with `pc-fe build --mode mr --base --head` (the working
tree must be checked out at `--head`), reuses cached summaries for unchanged
functions, and prints a JSON report: `repo, base, head, changed_functions,
taint_chains, blast_radius{repos, endpoints, provenance}, cache{hits, misses,
scc_recomputed, reuse_pct}`. `pc-fe` output goes to stderr.

- Warm the store first with `taint --store <dir>` using the same catalog file
  and none of `--no-error-leaf`, `--pb-getters`, `--unmodeled`; otherwise the
  store namespace differs and every summary is recomputed.
- `--cgf` adds pre-extracted CGF of other repositories so chains compose.
- `--pg` resolves remote contract views from Postgres (making `--cgf`
  optional) and adds an upstream walk of the persisted call graph to the blast
  radius.
- HTTP client sites are linked to the loaded routes as in `taint` (there is no
  `--no-http-link` here). Postgres holds no HTTP routes, so a client of a
  route outside the loaded CGF stays unlinked.

## query

Read-only Postgres queries over the call graph a previous `taint --pg` run
persisted. Dataflow is not persisted, so these answer call-reachability
questions only. Output is JSON.

```
panopticode query blast --pg <url> --repo <module> --file <path> [--file <path> ...]
panopticode query reach --pg <url> --fn <substr> [--repo <module>]
panopticode query path  --pg <url> --from <substr> --to <substr> [--limit 5] [--max-depth 30]
```

| query | answers | fails when |
|---|---|---|
| `blast` | upstream repos and boundary endpoints that reach the changed files (repo-relative) | `--repo` is not in the database |
| `reach` | upstream repos and boundary endpoints that reach functions matching `--fn` | nothing matches `--fn` |
| `path` | shortest forward call paths between two fqn or contract substrings; `--max-depth` bounds the cost | `--from` or `--to` matches no function or contract |

`scripts/blast.sh` wraps `query blast` with a `git diff` of a local checkout.

## Docker

```bash
docker build -t panopticode .
docker run --rm -v "$PWD/testdata/cgf:/cgf" panopticode taint \
  --cgf /cgf/webapp --cgf /cgf/federation --cgf /cgf/backend \
  --catalog /etc/panopticode/catalog.example.toml
```

The image holds the binary and the example catalog at
`/etc/panopticode/catalog.example.toml`. The working directory is `/work`, where
the default `--catalog` path does not exist, so pass `--catalog` explicitly.
`extract` and `impact` need `pc-fe`, which the image does not contain.

## Postgres

Only `taint --pg`, `impact --pg` and `query` use a database. The binary does
not create tables: apply [`deploy/schema.sql`](../deploy/schema.sql) first.
`deploy/docker-compose.yml` starts Postgres 16 with the schema applied on a
fresh volume:

```bash
docker compose -f deploy/docker-compose.yml up -d
# postgres://panopticode:panopticode@localhost:5433/panopticode
```

What is written: functions and contracts as nodes; call, binds-to and
invokes-remote edges; summaries; contract views (`contract_summaries`, which
`--pg` also reads back). The `summaries` table is written but never read.
