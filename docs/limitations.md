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
- Flows through HTTP/REST, connect, twirp, message queues, caches, cron, or a
  database round trip.

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
  joined.
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
cells and contract views loaded from Postgres. Streaming gRPC and GraphQL
contracts also stay `undecided` unless `--backward-unview` is given.
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
- The core's cost is dominated by the frontends: whole-program call-graph
  construction in `pc-fe` is the slowest step. On the fixtures in this repo the
  full e2e suite runs in about 3 seconds.
