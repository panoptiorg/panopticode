# Limitations

## Supported stack

The engine sees only what the frontends extract. Which code produces contracts
(handlers, resolvers, remote calls) is decided by each frontend; see
[panoptife-go](https://github.com/panoptiorg/panoptife-go) and
[panoptife-ts](https://github.com/panoptiorg/panoptife-ts).

A repository outside a frontend's stack yields no contracts. The analysis then
has no handler sources and no cross-repo joins, and usually prints few or no
chains, which looks like a clean result. Check the
[`graph-dump`](cli.md#graph-dump) counts before trusting an empty result.

## What a finding means

A sink class means tainted data reached that kind of operation. It does not
mean the code is exploitable: a `sqli` chain into a parameterized query is
expected. Nothing is executed. A chain count is not a vulnerability count.

## The catalog bounds recall

Anything the catalog does not name is not looked for. A rule that matches
nothing, and a misspelled table or key (silently ignored), produce no error and
no findings. Invalid regexes and port specs do fail the load. Read the
`catalog-fit` / `catalog-warn` lines on every new corpus
([catalog.md](catalog.md#diagnostics)).

## Scope is a soundness input

Only code inside the extraction scope has a body. Everything else is a default
leaf. Consequences:

- a sink behind an out-of-scope wrapper is invisible;
- a remote call made through an out-of-scope hand-written client wrapper loses
  its cross-service edge;
- sources read only in out-of-scope code are never seeded;
- a sanitizer called only from out-of-scope code is ignored, which produces
  false positives;
- sinks inside third-party dependencies are always out of reach.

## False negatives

- Goroutine, channel and struct-field hand-offs between call paths that never
  meet in one call site (for example a key queued to a background worker).
  `pc-fe --heap-slots` recovers some of these, at a precision cost.
- Terminal operations inside third-party dependencies.
- Function values passed as parameters and called inside the callee (Go
  "run this in a transaction" helpers; TypeScript `onChange?.(v)` callbacks).
- Library calls that write into an argument (`sb.WriteString(q)`,
  `json.Unmarshal(b, &v)`, `arr.push(q)`) when no `[[propagators]]` rule covers
  the call. Pointers inside a variadic slice (`rows.Scan(&a, &b)`) and Go's
  `copy` are not covered even with a rule; `pc-fe --heap-slots` alone links
  `copy`'s source to its destination.
- A source read inside a helper does not start a chain in the caller: chains
  start only in functions that have source parameters or call a source
  themselves. This mostly affects TypeScript, where URL reads often sit in
  helpers.
- Client-side state stores and dynamically mounted route fragments in
  frontend frameworks.
- Flows through connect, twirp, message queues other than Kafka topic cells,
  caches, cron, or a database round trip.
- HTTP is request-direction only: client data reaches the route's handler,
  but the response does not flow back into the client's variables (the
  synthetic client site has no result port).
- An HTTP client site links only to routes in the same run, by method and
  canonical path. A client whose base URL or a server whose mount prefix the
  frontend could not resolve is matched by suffix, which needs two agreeing
  literal segments: `${API}/users` alone links to nothing. More than four
  equally good routes leave a site unlinked (`ambiguous`). A client path that
  really starts with a dynamic segment (`/${tenant}/users`) reads as an unknown
  base. An exact match needs one agreeing literal segment, so a call to `/`
  never links. The `http-link:` census line lists what stayed unlinked.
- Heap cells are joined before contracts are composed, so a chain that goes
  producer → Kafka topic → consumer → a gRPC or HTTP call → a sink in that
  call's handler is not reported from the producer's side. The same flow
  rooted at the consumer's own catalog source (a consumed message is a source)
  is still reported. This predates HTTP: it holds for gRPC too.
- A `message` event's payload (`window.postMessage`) is not a source: the
  TypeScript frontend has no name for that read.
- Kafka topic cells (`pc-fe --topic-cells`) join a producer and a consumer only
  when both are loaded in one run and the topic name resolves to the same
  string (a constant, or the same `os.Getenv` variable name). They are joined
  by the in-memory heap pass, which `impact` does not run.

## False positives

- The default leaf: a call without a body taints every result from any tainted
  argument. It is necessary for taint to pass through libraries and is the main
  source of false positives.
- Error values: a tainted `error` that is then logged. `pc-fe --error-results`
  with `taint --no-error-leaf` suppresses most of these.
- Field widening: past two field levels, or when a shorter summary row matches,
  taint moves onto sibling fields. Usually this mislabels the field; sometimes
  it creates a false chain.
- Value-destroying transforms (hashing, bucketing) are not modelled.
- Heap cells are shared by every object of a type, so unrelated requests can be
  joined. A Kafka topic cell joins every producer of the topic to every
  consumer.
- An HTTP route shared by two loaded services (`GET /health`) or a suffix
  match against several routes links the client to all of them, each hop with
  `dispatch_confidence` 1/n.
- Canonicalisation drops the scheme and host, so a call to a third-party API
  (`https://api.github.com/users/x`) links to a loaded route with the same
  path shape (`GET /users/{id}`) as if it were a call to that service.
- A linked handler's request parameter is tainted whole. For gin and echo that
  parameter is the framework context, so values middleware stored in it (read
  back with `c.Get`) carry the client's taint too.
- When an HTTP route has more than one request parameter, the route rebuilt
  for a chain can take a heap-cell crossing although a direct path through
  another request parameter also exists. The chain is real; its route is not
  the shortest one.
- Virtual dispatch over-approximation.

## Precision limits

- Field paths are capped at depth 2, and a nested GraphQL input object is one
  opaque value. TypeScript flow has no field sensitivity.
- The analysis is flow-insensitive within a function and taint is boolean
  (no labels such as PII categories).
- The field reported at a sink is named in the sink's frame, not the request's;
  mapping layers rename fields.
- Use `route_confidence`, not `confidence`, which covers only the source
  function's own call resolution.
- `sanitized` is always `false`: sanitized flows are dropped, not reported.
- `FlowEdge.via_alias` edges carry no confidence penalty.

## Backward confirmation

`--backward` leaves chains `undecided` across recursion, stream ports, heap
cells (including Kafka topic cells) and contract views loaded from Postgres.
Streaming gRPC, GraphQL and HTTP route contracts also stay `undecided` unless
`--backward-unview` is given.
`--backward-prune` drops only refuted chains and, by default, keeps any
refutation that crossed such a contract; `--backward-prune-unviewed` removes
that guard. A wrong refutation deletes a real finding, so prune with care.

## Operational notes

- Full `--trace` output grows very large on big programs; restrict it with
  `--trace-events` and `--trace-fn`.
- Editing the catalog or rebuilding `pc-fe` invalidates the respective caches.
- `impact` re-extracts the whole working tree, not only changed files.
- Postgres holds the call graph and contract views, not dataflow; the `query`
  commands answer call-reachability questions only.
- HTTP routes are not persisted: no contract row, node, edge, `invokes` row or
  view goes to Postgres for them, so `--pg` leaves never carry an HTTP view and
  the persisted graph has no edge from an HTTP client to its handler. Topic
  cells are phase-2 and in memory only, like every heap cell.
- The core's cost is dominated by the frontends: whole-program call-graph
  construction in `pc-fe` is the slowest step. On the fixtures in this repo the
  full e2e suite runs in about 3 seconds.
