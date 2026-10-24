# CLI reference

```
panopticode <COMMAND> [OPTIONS]
panopticode --version
```

| command | what it does | needs |
|---|---|---|
| `taint` | the analysis: load CGF, summarize, compose, print chains as JSON, text or SARIF | CGF dirs; a catalog (the built-in one by default); Postgres only with `--pg` |
| `graph-dump` | counts of what was loaded | CGF dirs |
| `summary` | debug print of computed summaries | CGF dirs; a catalog (optional) |
| `extract` | run the Go frontend `pc-fe` | `pc-fe` |
| `impact` | merge-request mode against a warm summary store | a git checkout, `pc-fe`, a store dir |
| `query blast\|reach\|path` | read-only queries over a persisted call graph | Postgres filled by `taint --pg` |

`--cgf <dir>` reads every `*.pb` file directly in that directory (not
recursively). Repeat it to load several repositories into one program. A
directory with no `.pb` files is an error (`no CGF files (*.pb) in <dir>`):
it is a wrong path or a failed extraction, and a run over it would look like a
clean one.

Without `--catalog`, `taint`, `summary` and `impact` use a copy of
[`catalog.example.toml`](../catalog.example.toml) built into the binary and say
so on stderr (`catalog: built-in example ...`). It is a starting point, not
a policy for your code; see [catalog.md](catalog.md).

## Exit codes

| code | meaning |
|---|---|
| 0 | success, including a run that found nothing |
| 1 | any runtime error, printed as `Error: ...` on stderr: unreadable catalog, invalid regex, port spec or `[severity]` level in the catalog, missing or empty `--cgf` directory, undecodable CGF, unreachable Postgres, a missing or failed `pc-fe`, an unknown `--trace-events` kind, a `query` that matches nothing |
| 2 | command-line usage error (from the argument parser), including a `--fail-on` class the catalog does not define |
| 3 | `taint --fail-on` matched: the output was written, and at least one chain is in a listed class |

## taint

```
panopticode taint --cgf <dir> [--cgf <dir> ...] [--catalog <file>] [flags]
```

stdout is a JSON array of chains, sorted so output is byte-stable across runs
(`--format` selects text or SARIF instead). stderr carries diagnostics and a
final stats line. For the README quickstart (the `opaque:` detail and the
`route-stats:` line elided):

```
normalize: 1 by-name callsite(s), 0 arg port(s) moved into contract position, 0 dangling name(s), 0 unknown contract(s)
catalog-fit: 7/88 rules match at least one call site (47 distinct callees) — inert rules follow; ...
catalog-warn: 81 inert rules match no call site (list them with --verbose)
catalog-fit: 0/23 propagators match at least one call site
opaque: 5 of 75 call sites into a Go module or func value have no loaded body (default leaf: ...) — top modules: ...
functions=56 summaries=63 contracts_linked=7 remote_leaves=0 chains=15 cache_hits=2 cache_misses=54
```

See [catalog.md](catalog.md#diagnostics) for what the `catalog-*` and `opaque`
lines mean.

Since 0.2.0, a corpus with HTTP routes or synthetic HTTP client sites
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
| `--catalog <file>` | built-in example | the policy file, see [catalog.md](catalog.md) |
| `--format <json\|text\|sarif>` | `json` | what stdout holds, see [Output formats](#output-formats). stderr is the same in all three |
| `--fail-on <class,...\|any>` | none | after writing the output, exit 3 if any chain's sink class is listed (any chain at all for `any`). A class the catalog has no sink rule for is a usage error (exit 2), so a typo cannot make CI pass |
| `-v`, `--verbose` | off | list each inert catalog rule on stderr instead of counting them |
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
  "sink_span": {"file": "src/routes/search/+page.svelte", "line": 11, "col": 15},
  "hops": [...],
  "route": {
    "id": "a956a2f72f24",
    "fingerprint": "43f3a5f6b672",
    "hops": [
      {"repo": "webapp", "func": "src/routes/search/+page.svelte:$script",
       "file": "src/routes/search/+page.svelte", "line": 1, "col": 19, "kind": "source", "confidence": 1.0},
      ...
      {"repo": "example.com/backend", "func": "(*example.com/backend/store.Storage).findBy",
       "file": ".../backend/store/store.go", "line": 13, "col": 18, "kind": "sink",
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
- `col`, on `sink_span`, on `hops[].span` and on `route.hops[]`, is the column
  of the call, when the frontend recorded one; it is left out when unknown.
  `file` is whatever the frontend stored: relative to the directory it was run
  on, or absolute in older CGF.
- `route.hops[]` is the full route: `repo, func, file, line, col, kind, callee,
  field(s), confidence`, with `kind` one of `source call boundary sink heap`.
  The `source` hop's location is the source function's own, unless the
  frontend placed the tainted value at a more precise one.
- `route.boundaries` counts the contracts the route crosses. A `boundary`
  hop's `callee` is the client's callee name, except across an HTTP route,
  where it names the route actually entered: `http POST /api/users (gin)`
  (method, the path as the server wrote it, the framework). A `heap` hop's
  `callee` names the cell; for a Kafka topic, `kafka topic <name>`.
- `route.incomplete`, when present, says why the route stops early:
  `depth_cap`, `cycle`, `handler_not_loaded`, `callee_body_missing`,
  `not_reproduced`.
- `route.id` names this exact route: a content hash of its class and of every
  hop's repo, function, callee, kind and line, stable across runs. It changes
  when a hop's line moves.
- `route.fingerprint` is the same hash without lines: the shape of the flow
  (class, and per hop repo, function, callee and kind). It survives edits that
  only move code, so use it to deduplicate and to keep baselines across
  commits.
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

### Output formats

`--format` chooses what stdout holds. The analysis, stderr and exit codes are
the same for all three, and `--fail-on` works with each.

`json` (the default) is the array of chains above. `text` is one block per
chain, in output order, then a summary line; columns are aligned and there is no
colour:

```
sqli  webapp src/routes/search/+page.svelte:$script → example.com/backend (*example.com/backend/store.Storage).Selectx
  route a956a2f72f24 · 2 boundaries · confidence 1.00
  source    webapp                  src/routes/search/+page.svelte:1                            src/routes/search/+page.svelte:$script
  call      webapp                  src/routes/search/+page.svelte:10                           URLSearchParams.get
  ...
  boundary  example.com/federation  .../federation/graph/graph.go:93                            pb.Account/GetAccount
  ...
  sink      example.com/backend     .../backend/store/store.go:13                               (*example.com/backend/store.Storage).Selectx

15 findings: 13 sqli, 1 open_redirect, 1 xss
```

The route line also shows `backward <verdict>` with `--backward`, and
`incomplete: <reason>` for a route that stops early.

#### SARIF

`--format sarif` writes a [SARIF 2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html)
log with one run:

| SARIF | from |
|---|---|
| `rules[]` | one per sink class that appears, with the class as `id` and `name`; `defaultConfiguration.level` is its `[severity]` in the [catalog](catalog.md#format) (default `warning`) |
| `results[]` | one per chain; `ruleId` is the sink class, `level` its severity |
| `message` | `<source_fn> (<source_repo>) reaches <class> sink <callee> in <repo>`, plus the number of service boundaries crossed |
| `locations[0]` | the sink, i.e. the last hop of the route (for an incomplete route, its last hop with a file) |
| `codeFlows[0].threadFlows[0].locations[]` | every hop of `route.hops`, in order; `kinds` is the hop kind and the message is `<kind>: <callee or function>` |
| `partialFingerprints["panopticodeRoute/v1"]` | `route.fingerprint` |
| `properties` | `routeId`, `routeConfidence`, `boundaries`, `sourceRepo`, `sourceFunction`, and `backwardVerdict` / `incomplete` when present |

Paths are written as stored in the CGF, with no rewriting. A relative path gets
`uriBaseId` set to the hop's repo id, and `originalUriBaseIds` lists those repo
ids without a `uri`, because the engine does not know where a checkout is. An
absolute path becomes a `file://` URI. A hop without a file is a location with
only its message.

- **GitHub code scanning**: upload the file with
  `github/codeql-action/upload-sarif`. GitHub annotates locations whose path is
  inside the repository, so it helps to extract with paths relative to the
  checkout; it deduplicates results on `partialFingerprints`.
- **VS Code**: open the log with the SARIF Viewer extension, with the
  repositories in one multi-root workspace, and step through a route in the
  code flow view.

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
it fails. If the binary is not found, the error names it
(`pc-fe not found (install panoptife-go or pass --fe <path>)`); `impact` says
the same. It forwards no other flag; call `pc-fe` directly for any extraction
option (see the [panoptife-go](https://github.com/panoptiorg/panoptife-go)
README).

[`scripts/analyze.sh`](../scripts/analyze.sh) is a worked example of a whole
run on real Go repositories: it extracts each one with `pc-fe`, then runs
`taint` over all of them, optionally with `--pg` and `--store`.

## impact

```
panopticode impact --repo <dir> --base <sha> --head <sha> --store <dir> \
  [--scope <pat>] [--cgf <dir> ...] [--catalog <file>] [--out <dir>] [--fe pc-fe] \
  [--fe-arg <arg> ...] [--pg <url>]
```

Re-extracts `--repo` with `pc-fe build --mode mr --base --head` (the working
tree must be checked out at `--head`), reuses cached summaries for unchanged
functions, and prints a JSON report: `repo, base, head, changed_functions,
taint_chains, blast_radius{repos, endpoints, provenance}, cache{hits, misses,
scc_recomputed, reuse_pct}`. `pc-fe` output goes to stderr.

- Warm the store first with `taint --store <dir>` using the same catalog file
  (or the built-in one in both) and none of `--no-error-leaf`, `--pb-getters`, `--unmodeled`; otherwise the
  store namespace differs and every summary is recomputed.
- `--cgf` adds pre-extracted CGF of other repositories so chains compose.
- `--fe-arg <arg>` (repeatable, order kept) appends arguments to the frontend
  command, after the built-in ones. A TypeScript frontend needs
  `--fe-arg --repo-id <id>` — the CGF repo must match the other CGF dirs of
  the run — and `--fe-arg --adapter <name>`.
- `--pg` resolves remote contract views from Postgres (making `--cgf`
  optional) and adds an upstream walk of the persisted call graph to the blast
  radius.
- HTTP client sites are linked to the loaded routes as in `taint` (there is no
  `--no-http-link` here). Postgres lists HTTP routes in `endpoints`, but holds
  no view for them, so a client of a route outside the loaded CGF stays
  unlinked.

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

`--file` paths are matched against the span files stored in the graph, by
equality or as a suffix after a `/`, so they work for CGF with relative spans
(relative to the directory the frontend was run on) and for older CGF with
absolute ones. `scripts/blast.sh` wraps `query blast` with a `git diff` of a
local checkout; it passes the changed files relative to the checkout directory
it is given, which is the module directory and may be below the git root.

## Docker

```bash
docker build -t panopticode .
docker run --rm -v "$PWD/testdata/cgf:/cgf" panopticode taint \
  --cgf /cgf/webapp --cgf /cgf/federation --cgf /cgf/backend
```

The image holds the binary and, for reference, the example catalog at
`/etc/panopticode/catalog.example.toml`; without `--catalog` the binary uses its
built-in copy of the same file.
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
invokes-remote edges; the entry points of each repo as `endpoints` rows (one
per endpoint and bound handler, every kind — gRPC, GraphQL, HTTP, message
consumers); summaries; contract views (`contract_summaries`, which `--pg`
also reads back). The `summaries` table is written but never read.

A store made by an older version lacks the `endpoints` table; apply
[`deploy/schema.sql`](../deploy/schema.sql) again — every statement is
`CREATE ... IF NOT EXISTS`, so re-applying it adds only what is missing.
