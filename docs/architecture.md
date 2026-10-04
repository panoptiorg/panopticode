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
argument port, the engine decides in this order:

1. the callee matches a sanitizer: stop;
2. the callee matches a sink (and the `arg` rule): record a sink hit;
3. the callee has a summary: map the argument to the callee's slot and fire
   every row whose in-fact is compatible, tainting the mapped outputs;
4. otherwise, apply matching `[[propagators]]`, then the default leaf: every
   result port becomes tainted (except error results under `--no-error-leaf`).

Source seeds, the only places a chain can start, are `Function.source_params`,
call results whose callee matches a `[[sources]]` rule, and server-side gRPC
stream `Recv` results.

## SCC fixpoint

The call graph of all loaded repos is split into strongly connected components
with an iterative Tarjan pass, callees first. A non-recursive function is
summarized once. A multi-function SCC, or a function that calls itself, starts
from empty summaries and is recomputed Gauss–Seidel until nothing changes, so a
recursive call site uses the least fixpoint rather than the default leaf. The
loop is capped at `4 * |SCC| + 8` iterations and warns `SCC fixpoint hit
iteration cap` if reached; that indicates a bug, and the test suite checks it
never happens.

## Identity and caching

All ids are SHA-256 and computed the same way in Go, TypeScript and Rust.

| id | hashes | property |
|---|---|---|
| `iid` | repo, package path, fqn, signature | stable across body edits |
| `bid` | canonical LocalFlow (no spans) and sorted callee `iid`s | changes when the body or its call targets change |
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
pass keep the tail. Paths are not extended past length 2. TypeScript CGF has no
field paths.

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

## Contracts and cross-repo composition

A contract is keyed by a name both sides derive independently from generated
code:

- gRPC: `<proto package>.<Service>/<Method>` (e.g. `pb.Account/GetAccount`). The
  client side derives it from the generated `<Svc>Client`; the server side from
  the embedded `Unimplemented<Svc>Server`, which `protoc-gen-go-grpc` requires
  every server to embed.
- GraphQL: `graphql:<Type>.<field>`, from each side's SDL.

A client call to a contract is an `INVOKES_REMOTE` call site whose callee is the
contract's iid. For each contract with a loaded handler, the engine publishes a
view: the handler's summary remapped into the client's frame (for gRPC,
depending on client and server streaming; for GraphQL, through the resolver's
argument positions). The client call resolves through the ordinary summary
lookup. Composition iterates: publish all views, re-summarize callers whose
views changed and their local callers, republish, until stable (capped at
number of contracts + 1, with a warning).

With `--pg`, a contract with no loaded handler can take its view from the
`contract_summaries` table (`remote_leaves` in the stats line); a loaded
handler always wins, and routes stop with `handler_not_loaded` there.

## Routes

The forward pass keeps no predecessor information, so after the fixpoint each
chain's route is re-derived top-down: propagate in the source function, follow
the summary row that produced the sink hit into the callee, and across
contracts into their handlers, until the sink. A route stops early with
`incomplete` set to `depth_cap` (depth 32), `cycle`, `handler_not_loaded`,
`callee_body_missing` (default leaf) or `not_reproduced`. When a dispatch site
has several candidates, up to 8 are tried. If a descent with the precise field
path fails it retries with the coarser one and prints `route-warn: ...`.

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
  stored contract views, depth or demand limits), or it crossed a contract
  whose view is not the handler's own frame.

That last case covers streaming gRPC and GraphQL (whose resolver arguments are
shifted by the context parameter). `--backward-unview` undoes the view remap so
the walk can continue. Nothing is removed unless `--backward-prune` is given,
and a refutation that crossed an unviewed contract is pruned only with
`--backward-prune-unviewed`.

## Library calls that write into an argument

The default leaf only taints results, so `json.Unmarshal(b, &v)` loses the
flow into `v`. Two halves recover it. The frontend emits a write-back edge from
a by-reference argument port to the caller's variable (`pc-fe
--library-writeback`, on by default; `pc-fe-ts` likewise). The core applies
`[[propagators]]` rules at body-less calls, in forward propagation, route
reconstruction and backward confirmation, in addition to the default leaf.
Without either half the flow is lost. `--unmodeled` reports calls that look
like they need a rule. Pointers inside a variadic slice (`rows.Scan(&a, &b)`)
and Go's `copy` builtin are not covered.

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

The core does not read contracts generically. Each of these enumerates
`grpc_methods` and `graphql_fields` by name, so a third contract record is
invisible until all of them are extended:

| where | uses the contract list for |
|---|---|
| `graph.rs` `pkg_contracts` | Postgres persistence and `missing_remote_contracts` |
| `compose.rs` `fixpoint_with_leaves` | publishing each handler's summary as the contract's view |
| `witness.rs` `contract_handlers` | route reconstruction descending into the handler |
| `cli.rs` `graph-dump` | per-kind counts |

`Endpoint` plus `Function.binds_to` is not enough to replace them: an `Endpoint`
carries no handler iid and no shape. That is why the HTTP endpoints `pc-fe-ts`
emits are populated but never read.

`ContractShape` (`compose.rs`) has two variants, `Grpc(client_streaming,
server_streaming)` and `Graphql(arg → param index)`. Every shape is implemented
in four places, and they must agree exactly — the view and unview functions are
each other's inverse:

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
`unview_*` ones. Two examples of a different frame: an HTTP handler that
receives `(ResponseWriter, *Request)` when the client passed a URL and a body,
and a message consumer that returns nothing to the producer.

### What a new protocol costs

| the protocol | frontend | core |
|---|---|---|
| fits an existing shape | extractor + key | extend the four contract enumerations above |
| needs its own frame mapping | extractor + key | the enumerations, plus a new `ContractShape` variant in all four places |

There is a shortcut for the first row: emit the protocol as a `GrpcMethod` with
both streaming flags off. The core then links it with no changes, but the
contract is counted, persisted and displayed as gRPC.

## Optional Postgres

[`deploy/schema.sql`](../deploy/schema.sql) stores `repos`, `nodes`, `edges`,
`contracts`, `invokes`, `summaries` and `contract_summaries`. The binary does
not apply the schema. Only the call graph (function and contract nodes; call,
binds-to and invokes-remote edges) and contract views are written; dataflow is
not. `summaries` is written but not read back; `contract_summaries` is read by
`--pg` runs. The `query` subcommands ([cli.md](cli.md#query)) read this data.
