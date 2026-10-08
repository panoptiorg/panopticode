# Architecture

## Components

| component | repo | job |
|---|---|---|
| `pc-fe` | panoptife-go | loads a Go module, builds SSA and a dispatch call graph (VTA or CHA), writes CGF, one file per package |
| `pc-fe-ts` | panoptife-ts | walks a TypeScript/Svelte repo with the TypeScript compiler API, writes the same CGF, one file per directory |
| `panopticode` | this repo | loads any number of CGF directories into one program, computes summaries, composes across contracts, reconstructs routes, prints chains |

The frontends make no security decisions. Every source, sink, sanitizer and
propagator comes from the [catalog](catalog.md), which only the
core reads. CGF files on disk are the only interface between the programs;
the format is described in [cgf.md](cgf.md).

## The rule everything rests on

A frontend never emits a value-flow edge through a call. Taint enters a call at
an argument port vertex and leaves at a result port vertex, and nothing in the
CGF connects the two. The core connects them by applying the callee's summary.
That keeps summaries composable and cacheable, and it is why a remote gRPC or
GraphQL call needs no special algorithm: it is a call site whose callee is a
contract instead of a local function.

## Pipeline of `taint`

1. Load the catalog. A bad regex or port spec stops here.
2. Load every `--cgf` directory into one program, then normalize: TypeScript
   GraphQL calls carry arguments by name, and they are rewritten into the
   contract's positional frame using `GraphqlField.args`. This runs on the
   merged program because the contract may live in another directory.
   Then link synthetic HTTP client sites to the loaded HTTP routes (see
   [HTTP routes](#http-routes)), for the same reason.
3. Print the catalog fit and opacity diagnostics.
4. Phase 1: compute a summary for every function, bottom-up over SCCs.
5. With `--pg`, load stored contract views for contracts no loaded CGF serves.
6. Phase 2a: heap-cell fixpoint (only if the CGF contains heap cells).
7. Phase 2b: cross-repo contract fixpoint.
8. With `--pg`, persist the graph and summaries.
9. Build chains: for each function with source seeds, propagate, then
   reconstruct each route top-down. Deduplicate and sort.
10. With `--backward*`, run backward confirmation on every chain.
11. Print chains as JSON on stdout and a stats line on stderr.

## Summaries

The engine is a bottom-up functional summary analysis in the Sharir–Pnueli
sense. It has no path-edge tables or exploded supergraph, so it is not an IFDS
tabulation solver, though for a distributive boolean domain the results
coincide.

A slot is a place taint can enter or leave a function: `Param(n)`, `Receiver`,
`Global(sym)`, `Return(n)`, `ByRefParam(n)`, `ByRefReceiver`, `Field(n)`, plus
internal `Source`, `StreamIn`, `StreamOut`. A fact is a slot with a field path.
A summary is a set of `(in-fact -> out-fact)` flow pairs plus the sink hits
reachable from each in-fact. Taint is boolean: there are no labels.

`summarize` runs a worklist over one function's LocalFlow once per in-slot,
once for source seeds and once for stream seeds. When taint reaches a call's
argument port, the engine checks in this order:

1. the callee matches a sanitizer: stop;
2. the callee matches a sink (and the `arg` rule, and the port's type is not
   in `sink_ignore_arg_types`): record a sink hit and continue, so taint still
   flows through the call;
3. the callee has a summary: map the argument to the callee's slot and fire
   every row whose in-fact is compatible, tainting the mapped outputs;
4. otherwise, apply matching `[[propagators]]`, then the default leaf: every
   result port becomes tainted (except error results under `--no-error-leaf`).

Source seeds, the only places a chain can start, are `Function.source_params`,
the ports a matching `[[sources]]` rule names in `to` — call results by
default, or argument ports for a bind such as `c.ShouldBindJSON(&req)`, whose
write-back edge carries the seed into `req`; such a seed leaves along that edge
only and is never an input to its own call — and server-side gRPC stream
`Recv` results. Route reconstruction and backward confirmation recognise an
argument-port seed exactly like a result-port one. The same per-port sink
predicate (`Catalog::sink_fires_on`) is used by propagation, route
reconstruction and backward confirmation, so they agree on where a sink fires.

## SCC fixpoint

The call graph of all loaded repos is split into strongly connected components
with an iterative Tarjan pass, callees first. A non-recursive function is
summarized once. A multi-function SCC is recomputed Gauss–Seidel, each member
against the others' latest summaries, until nothing changes; in the first
round a member not yet summarized is a default leaf. A function that calls
only itself starts from an empty summary and iterates the same way, so its
recursive call site uses the least fixpoint rather than the default leaf. The
loop is capped at `4 * |SCC| + 8` iterations and warns `SCC fixpoint hit
iteration cap` if reached; that indicates a bug, and the test suite checks it
never happens.

## Identity and caching

All ids are SHA-256 over parts that are each prefixed with their length as an
8-byte little-endian integer. The frontends compute `iid`, `bid` and contract
ids (`panoptife-go` `internal/hash/hash.go`, `panoptife-ts` `src/hash.ts`);
the core computes `contract_hash`, `summary_key` and route ids the same way
(`core/src/ids.rs`). A contract id, `H("", "", <name>, "grpc")`, is
byte-identical in Go and TypeScript, for GraphQL names too. Function `iid`s
and `bid`s follow each frontend's own recipe and are not comparable across
languages.

| id | hashes | property |
|---|---|---|
| `iid` | repo, package path, fqn, signature (`ts` in TypeScript) | stable across body edits |
| `bid` | the LocalFlow and sorted callee `iid`s; Go hashes a deterministic protobuf encoding without spans, TypeScript a JSON encoding with spans | changes when the body or its call targets change |
| `contract_hash` | a summary's flows and sink hits | same behaviour, same hash |
| `summary_key` | `bid`, `source_params`, sorted callee `contract_hash`es | cache key for one summary |

Because the key uses callee behaviour rather than callee bodies, an edit that
does not change a callee's behaviour does not invalidate its callers. The
`--store` cache is a directory keyed by `summary_key`, namespaced by a hash of
the catalog file and the semantics flags. Functions in recursive SCCs are never
cached.

## Field paths

A fact carries a field path of at most two field indices (`k = 2`; protobuf
field numbers where known). A summary row fires when the slots are equal and
the paths are prefix-compatible. When a shorter row fires for a longer fact,
the forward pass drops the unmatched tail: the result is sound but coarser,
which can move taint onto sibling fields. Route reconstruction and the backward
pass keep the tail. A path that is already two long is never extended, since
the frontend may have truncated it. TypeScript CGF has no field paths.

## Heap cells

Only when the Go CGF was extracted with `pc-fe --heap-slots`. A cell is a
`(type, field)` pair shared by every object of that type (object-insensitive),
written by `OUT_FIELD` vertices and read by `IN_GLOBAL` vertices with the same
`sym`. Phase 1 already summarizes writers (`X -> Global(cell)`) and readers
(`Global(cell) -> sink` or another cell); what it cannot do is join them, since
no call site holds both. After phase 1, a boolean fixpoint over the cell graph
(capped at 64 rounds) computes the sinks reachable from each cell. When
propagation writes taint into a cell, it records hits for those sinks at the
write site, shown in routes as a `heap` hop with confidence 0.5. This lets taint cross goroutine and channel hand-offs the call
graph cannot see, at a precision cost. Optional interface-type narrowing uses
`FlowVertex.iface_type`. Heap state is in memory only.

A Kafka topic (`pc-fe --topic-cells`) is the same mechanism with a different
key: the producer's payload flows into an `OUT_FIELD` vertex whose `sym` is the
contract iid of `msg:kafka:<topic>`, and the consumer reads an `IN_GLOBAL`
vertex with that `sym`. The join is program-wide, and every `--cgf` directory
is merged into one program, so a producer and a consumer in different
repositories join with no engine change; the route's `heap` hop renders the
cell's `sym_name` (`kafka topic orders`). `heap.rs`'s `topic_cell_tests` pin
this through the same phase order `taint` runs.

## Contracts and cross-repo composition

A contract is keyed by a name both sides derive independently from generated
code:

- gRPC: `<Go package of the generated code>.<Service>/<Method>` (e.g.
  `pb.Account/GetAccount`): the Go package name, not the proto package. The
  client side derives it from the generated `<Svc>Client`; the server side from
  an embedded `Unimplemented<Svc>Server` or `Unsafe<Svc>Server`, one of which
  `protoc-gen-go-grpc` requires every server to embed.
- GraphQL: `graphql:<Type>.<field>`, from each side's SDL.
- HTTP: `http:<METHOD> <canonical path>`. The server side names the route; the
  client side is linked to it by the core rather than named, see
  [HTTP routes](#http-routes).

A client call to a contract is an `INVOKES_REMOTE` call site whose callee is the
contract's iid. For each contract with a loaded handler, the engine publishes a
view: the handler's summary remapped into the client's frame (for gRPC,
depending on client and server streaming; for GraphQL, through the resolver's
argument positions; for HTTP, every request parameter onto the client's one
argument port, with every return dropped). The client call resolves through the ordinary summary
lookup. Composition iterates: publish all views, re-summarize callers whose
views changed and their local callers, republish, until stable (capped at
number of contracts + 1, with a warning).

With `--pg`, a contract with no loaded handler can take its view from the
`contract_summaries` table (`remote_leaves` in the stats line); a loaded
handler always wins, and routes stop with `handler_not_loaded` there.

## HTTP routes

A server route is an `HttpRoute` (method, canonical path, handler, the handler
parameters carrying request data). A client request is, in addition to its
ordinary call site, a synthetic site with `http_call` set: one argument port
into which the URL and body flow, no result port. Unlinked it is inert — the
default leaf has nothing to taint.

Right after `normalize`, `httplink.rs` links each such site over the routes of
all loaded packages:

1. **exact**: methods agree (or either side is `*` or unknown), same segment
   count, a route `{}` takes any client segment, a client `{}` only a route
   `{}`, `{*}` takes the tail. At least one literal segment must agree, so
   `/api/users` is no match for `/{owner}/{repo}` and `/` links to nothing.
   Only for a client without an unresolved base.
2. else **suffix**: the client's leading `{}` (an unresolved base URL) is
   dropped and the rest matched against a suffix of the route, or the route
   against a suffix of the client (an unresolved mount or gateway prefix). At
   least two literal segments must agree.
3. Candidates are ranked by kind, then agreeing literal segments, then
   one-for-one segment matches over a `{*}` that swallowed the same segments
   (`/api/users/me` goes to `/api/users/{id}`, not also to `/api/users/{*}`),
   then an exact method match. Every candidate tied for best is linked, up to
   4, each with `dispatch_confidence` 1/n; more is `ambiguous` and stays
   unlinked.

A linked site becomes `INVOKES_REMOTE` with the routes as callees, and from
there it is an ordinary contract call. A route's iid names the route, not the
service, so two loaded services serving the same route would share one view;
in that case each handler gets its own key and the client fans out.

Linking does not change phase 1. The site has no result port, so linked or not
the default leaf taints nothing; no summary exists under a contract key until
compose publishes one; and `summary_key` counts only callees that are loaded
functions. `bid` is the frontend's. `httplink.rs`'s
`phase_one_is_identical_linked_or_not` pins that, so `--no-http-link` is not a
store namespace flag.

The witness renders a crossing as `http <METHOD> <display> (<framework>)` and
re-enters the handler at the first request parameter whose rows carry the
sink. The view is not identity, so `--backward` reports `undecided` across it
unless `--backward-unview` is given. HTTP routes are not persisted to Postgres.

## Routes

The forward pass keeps no predecessor information, so after the fixpoint each
chain's route is re-derived top-down: propagate in the source function, follow
the summary row that produced the sink hit into the callee, and across
contracts into their handlers, until the sink. A route stops early with
`incomplete` set to `depth_cap` (depth 32), `cycle`, `handler_not_loaded`,
`callee_body_missing` (a sink hit in a callee with no body) or
`not_reproduced`. When a dispatch site has several candidates, up to 8 are
tried. If a descent with the precise field path fails it retries with the
coarser one and prints `route-warn: ...`.

`route.id` is a 12-hex content hash over class and, per hop, repo, function,
callee, line and kind (not file paths or confidences), so the same route has
the same id across machines. `route_confidence` is the minimum hop confidence.

## Backward confirmation

`--backward` checks each chain by walking from the sink back towards a source
over reversed LocalFlow edges, descending into callee bodies instead of using
their summaries, and keeping full field paths. Verdicts:

- `confirmed`: the walk reached a source seed; `exact` is false if it crossed
  an over-approximation such as the default leaf;
- `refuted`: the walk finished without reaching a source;
- `undecided`: the walk could not finish (recursion, stream ports, heap cells,
  stored contract views, the depth limit, an incomplete route), or it crossed
  a contract whose view is not the handler's own frame.

That last case covers streaming gRPC, GraphQL (whose resolver arguments are
shifted by the context parameter) and HTTP routes. `--backward-unview` undoes the view remap so
the walk can continue. Nothing is removed unless `--backward-prune` is given,
and a refutation that crossed an unviewed contract is pruned only with
`--backward-prune-unviewed`.

## Library calls that write into an argument

The default leaf only taints results, so `json.Unmarshal(b, &v)` loses the
flow into `v`. Two halves recover it. The frontend emits a write-back edge from
a by-reference argument port to the caller's variable (`pc-fe
--library-writeback`, on by default; `pc-fe-ts` likewise). The core applies
`[[propagators]]` rules at body-less calls, in forward propagation, route
reconstruction and backward confirmation, in addition to the default leaf. A
by-ref `[[sources]]` rule (`to = "1"`) uses the same write-back edge.
Without either half the flow is lost. `--unmodeled` reports calls that look
like they need a rule. Pointers inside a variadic slice (`rows.Scan(&a, &b)`)
and Go's `copy` builtin are not covered; `pc-fe --heap-slots` alone links
`copy`'s source to its destination.

## Other frontend-side modelling

Closures, by-reference out parameters and error-typed results are lowered by
the frontends into ordinary slots and flags; the core has no closure-specific
code. Closure captures become extra parameters, by-ref writes become
`OUT_PARAM_BYREF` / `OUT_RECEIVER_BYREF` vertices (`pc-fe --byref-out`), and
error results are marked in `CallSite.error_results` (`pc-fe --error-results`).

## Adding a protocol

The algorithm has no protocol in it: a remote call is a `CallSite` of kind
`INVOKES_REMOTE` whose `callee_iids` holds a contract id, and a contract's view
is an ordinary summary stored under that id. A protocol has to supply three
things — a **join key** both sides derive identically, a **handler binding**,
and a **shape** (how the handler's parameters map onto the client's call). The
first two are frontend work. The shape, and the contract registry that carries
it, are currently a closed set in the core.

### Frontend

- **Client side** — emit each call that crosses the wire as `INVOKES_REMOTE`
  with `callee_iids = [ContractIID("<key>")]`, `callee_fqn = "<key>"`, and one
  argument port per value the client sends. If the protocol passes arguments by
  name, also fill `arg_names`; `normalize.rs` rewrites them into positions.
- **Server side** — emit a contract record with the same iid and the serving
  function's `handler_iid`, plus `binds_to` on that function and an `Endpoint`,
  as `pc-fe` does for gRPC.
- **The key** — `ContractIID` (`panoptife-go` `internal/hash/hash.go`, mirrored
  byte-for-byte in `panoptife-ts` `src/hash.ts`) hashes a full-name string.
  Prefix it per protocol, as GraphQL does with `graphql:`, so two protocols can
  never collide.

The key decides whether a protocol is worth supporting at all. gRPC's key is a
build condition. A key that only exists at runtime — a URL assembled from config
and path segments, a topic name read from the environment — has to be resolved
statically, and a wrong resolution produces a **false chain**, not a missing
one. Prefer protocols whose two sides take the name from generated code or a
shared schema, and when the key is ambiguous, emit no boundary rather than
guess — the way `pc-fe` refuses a hand-rolled client interface that more than
one `<Svc>Client` satisfies.

### Core

Contract discovery is in one place: `graph.rs` `pkg_contracts` knows which
package fields hold contracts (`grpc_methods`, `graphql_fields`,
`http_routes`) and returns each with its key, handler, kind and
`ContractShape`; `graph::contracts` turns that into the keyed list the analysis
uses. A new contract record is one more block in `pkg_contracts`. Its readers:

| where | uses the contract list for |
|---|---|
| `compose.rs` `fixpoint_with_leaves` | publishing each handler's summary as the contract's view |
| `witness.rs` `contract_handlers` (and so `backward.rs`) | route reconstruction and backward confirmation descending into the handler |
| `httplink.rs` | the routes a client site can link to |
| `storage.rs` `persisted_contracts` | Postgres persistence and `missing_remote_contracts` (gRPC and GraphQL only) |
| `impact.rs` | whether a crossed contract's handler was recomputed |

`cli.rs` `graph-dump` counts each package field itself, for display only.

`Endpoint` plus `Function.binds_to` is not enough to replace them: an `Endpoint`
carries no handler iid and no shape, so endpoints are only counted.

`ContractShape` (`compose.rs`) has three variants, `Grpc(client_streaming,
server_streaming)`, `Graphql(arg → param index)` and `Http { request_params }`.
Every shape is implemented in four places, and they must agree exactly — the
view and unview functions are each other's inverse:

| where | direction |
|---|---|
| `compose.rs` `ContractShape::view` | handler → client frame (forward pass) |
| `witness.rs` `unview_slot` | client → handler frame (route descent) |
| `backward.rs` `view_slot`, `unview_out_slot` | handler → client frame (backward confirmation) |
| `compose.rs` `ContractShape::is_identity` | whether the backward pass may cross without `--backward-unview` |

A unary request/response protocol whose handler takes what the client passes,
in the same order, and returns what the client receives fits the existing
identity shape, `Grpc(false, false)`. A protocol with a different frame needs a
new variant in all four places, with round-trip tests like the existing
`unview_*` ones — as HTTP did: its handler receives `(ResponseWriter,
*Request)` when the client passed a URL and a body. A message consumer that
returns nothing to the producer needs no shape at all if it is modelled as a
heap cell, as Kafka topics are.

### What a new protocol costs

| the protocol | frontend | core |
|---|---|---|
| fits an existing shape | extractor + key | one block in `pkg_contracts` |
| needs its own frame mapping | extractor + key | that block, plus a new `ContractShape` variant in all four places |

There is a shortcut for the first row: emit the protocol as a `GrpcMethod` with
both streaming flags off. The core then links it with no changes, but the
contract is counted, persisted and displayed as gRPC.

## Optional Postgres

[`deploy/schema.sql`](../deploy/schema.sql) stores `repos`, `nodes`, `edges`,
`contracts`, `invokes`, `summaries` and `contract_summaries`. The binary does
not apply the schema. Only the call graph (function and contract nodes; call,
binds-to and invokes-remote edges), summaries and contract views are written;
LocalFlow is not. `summaries` is written but not read back;
`contract_summaries` is read by `--pg` runs. HTTP routes and linked HTTP
client sites are not written at all (`storage.rs` `persisted_contracts`, `is_remote`):
a link is made per run against the loaded routes only. The `query` subcommands
([cli.md](cli.md#query)) read this data.
