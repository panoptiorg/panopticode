# The catalog

The catalog is the whole security policy. Frontends emit structural facts only;
everything the tool calls a source, sink, sanitizer or propagator comes from
this TOML file, which only the core reads. Start from
[`catalog.example.toml`](../catalog.example.toml), which the test suite also
runs against.

## Format

Five optional arrays of tables and one top-level key. These are the only keys
the core reads:

| table | keys |
|---|---|
| top level | `sink_ignore_arg_types` (a list of type strings) |
| `[[sources]]` | `kind`, `selector`, `selector_regex`, `to` |
| `[[sinks]]` | `class`, `selector`, `selector_regex`, `arg` |
| `[[sanitizers]]` | `kind`, `selector`, `selector_regex` |
| `[[error_wrappers]]` | `selector`, `selector_regex` |
| `[[propagators]]` | `selector`, `selector_regex`, `from` (required), `to` (required) |

`note` is accepted anywhere and ignored. `to` on anything but a source fails
the load. Any other key or table, including
`schema_version` and misspellings such as `[[sink]]` or `selecter`, is
silently ignored. A misspelled table name therefore removes all its rules
without an error; check the `catalog-fit` line (below) after editing.

```toml
sink_ignore_arg_types = ["context.Context"]

[[sources]]
kind           = "ts_url_query"         # free text, never matched on
selector_regex = '^(URLSearchParams|URL)\.(get|getAll)$'

[[sources]]
kind           = "http_request"
selector_regex = '\(\*github\.com/gin-gonic/gin\.Context\)\.ShouldBind[A-Za-z]*$'
to             = "1"                    # c.ShouldBindJSON(&req) fills req

[[sinks]]
class          = "sqli"                 # any string; lands on the chain as sink_class
selector_regex = '\(\*database/sql\.(DB|Tx|Conn|Stmt)\)\.(Query|QueryRow|Exec)(Context)?$'
arg            = "any"

[[sanitizers]]
kind     = "validation"
selector = "net/url.QueryEscape"

[[error_wrappers]]
selector_regex = '^fmt\.(Errorf|Sprintf|Sprint|Sprintln)$'

[[propagators]]
selector_regex = '^\(\*strings\.Builder\)\.WriteString$'
from           = "1"
to             = "receiver"
```

## Matching

- Every rule matches the callee's fully qualified name as the frontend recorded
  it in `CallSite.callee_fqn` (for example
  `(*example.com/backend/store.Storage).Selectx`, `URLSearchParams.get`). Never
  a type, an import or syntax.
- `selector` matches when the name equals it or ends with it. Suffix matching
  lets one rule cover re-exporting wrappers; it also makes over-broad rules
  easy to write (an empty `selector` matches every call).
- `selector_regex` is a Rust `regex` pattern (no backreferences or lookaround),
  unanchored unless you anchor it. A pattern that does not compile fails the
  load with `[[<section>]] rule "<label>": selector_regex ... does not compile`.
- A rule may have both; either matching fires it. A rule with neither matches
  nothing.
- Sources, sinks and sanitizers: the first matching rule in file order wins.
  Propagators: every matching rule fires.

What each table does:

- `[[sources]]` matches at a call and taints the ports `to` names, in the
  propagator port syntax below: `return` (the default) is the call's result,
  an index, `receiver` or `args` is an argument the call writes into — a bind
  such as `c.ShouldBindJSON(&req)`, which taints `req`. An argument needs the
  frontend's library write-back edge, exactly like a propagator's `to`: the
  seed leaves along that edge only and is not fed into its own call, so the
  bind's `err` stays clean and, without the edge, the rule seeds nothing. `to = "none"` fails the load: a source that seeds nothing is inert
  by construction. Request parameters of gRPC handlers, GraphQL resolvers and
  SvelteKit server endpoints are sources without any rule: frontends mark them
  in `Function.source_params`. Chains start only in functions that have source
  parameters or call a source themselves.
- `[[sinks]]` matches at a tainted argument of the call. `arg` absent, `""` or
  `"any"` accepts any argument; `"args"` any argument except the receiver (for
  a method whose receiver is a handle, such as `(net/http.Header).Set` or
  `(*net/http.Client).Do`); otherwise it is a 0-based argument index, where
  the receiver is index 0 when the call has one. Anything else fails the load.
- `sink_ignore_arg_types` stops every sink from firing on an argument port
  whose vertex type is one of the listed strings, compared exactly. The
  example catalog lists `context.Context`: a tainted context passed to
  `db.QueryContext(ctx, q)` is not a finding about the query. Only the Go
  frontend writes argument types; an untyped port is never filtered. Absent,
  every port is eligible.
- `[[sanitizers]]` matches at a tainted argument and stops the taint there.
  Nothing is recorded, so the chain simply does not appear (and `sanitized` in
  the output is always `false`).
- `[[error_wrappers]]` is read only under `taint --no-error-leaf`: calls that
  build an error from other values (`fmt.Errorf("... %s", id)`) keep tainting
  their error result.
- `[[propagators]]` apply only at calls with no analysable body; see below.

Because matching is by name only, any function can be a sink. To ask "does
input reach function F", add F as a one-off sink in a scratch catalog.

## Propagators

A call with no body (standard library, dependencies, anything outside the
extraction scope) gets the default leaf: taint on any argument taints every
result. That is right for `strings.Join` and wrong for calls that write into
an argument:

```go
sb.WriteString(q)        // q goes into sb
json.Unmarshal(b, &v)    // b goes into v
```

```ts
parts.push(q)            // q goes into parts
```

Without a rule such flows are lost. A propagator describes the movement with
port specs:

| spec | meaning | allowed in |
|---|---|---|
| `0`, `1`, ... | 0-based argument index (receiver is 0 when present) | `from`, `to` |
| `receiver` | port 0, only if the call has a receiver | `from`, `to` |
| `args` | every argument except the receiver | `from`, `to` |
| `any` | every argument | `from`, `to` |
| `return` | every result of the call | `to` |
| `none` | no flow: the call was reviewed and writes nothing | `to` |

Comma lists (`"0,2"`) are allowed. A malformed spec fails the load.
Propagators add to the default leaf, never replace it.

A rule needs the frontend's library write-back edge to have any effect
(`pc-fe --library-writeback` and its `pc-fe-ts` equivalent, both on by
default): the rule says data moves into argument 0, the edge carries argument
0's value back to the caller's variable. Pointers packed into a variadic slice
(`rows.Scan(&a, &b)`) and Go's `copy` builtin are not reachable either way.
TypeScript rules match only receivers whose type the frontend knows
(`Array.push`, `Map.set`); a bare `.push` on an unknown receiver is not matched.

`taint --unmodeled <file>` lists body-less calls that tainted data reaches,
that could write into another argument, and that no propagator covers.

## Worked example

The `libwrites` fixture calls a dependency function, `thirdparty.Fill(&o,
r.Q)`, that was extracted out of scope. With the example catalog the flow
through it is lost, and `--unmodeled` names the call:

```console
$ panopticode taint --cgf testdata/cgf/libwrites --catalog catalog.example.toml --unmodeled um.json > chains.json
catalog-fit: 9/23 propagators match at least one call site
unmodeled: 1 library call(s) receive tainted data and may write into another argument with no [[propagators]] rule -> um.json
      1 routes     1 sites     1 sources  example.com/libwrites/thirdparty.Fill  e.g. .../libwrites/app/app.go:123
functions=19 summaries=32 contracts_linked=13 remote_leaves=0 chains=11 cache_hits=0 cache_misses=19
```

Append a rule saying argument 1 is written into argument 0:

```toml
[[propagators]]
selector = "example.com/libwrites/thirdparty.Fill"
from     = "1"
to       = "0"
```

and rerun with that catalog:

```console
catalog-fit: 10/24 propagators match at least one call site
unmodeled: 0 library call(s) receive tainted data and may write into another argument with no [[propagators]] rule -> um.json
functions=19 summaries=32 contracts_linked=13 remote_leaves=0 chains=12 cache_hits=0 cache_misses=19
```

The new chain is `(*example.com/libwrites/app.Impl).ThirdParty` to a `sqli`
sink at `app.go:124`.

## Diagnostics

Every `taint` run prints, on stderr:

```
catalog-fit: N/M rules match at least one call site (K distinct callees) — inert rules follow; ...
catalog-warn: inert rule <section>[<class or kind>] "<selector>" — no call site matches it (zero recall here)
catalog-warn: sink rule [<class>] "<selector>" arg N never in range (max argc seen M) — it can never fire
catalog-warn: source rule [<kind>] "<selector>" `to` port never in range (max argc seen M) — it can never seed it
catalog-fit: N/M propagators match at least one call site
opaque: X of Y call sites into a Go module or func value have no loaded body (default leaf: ...) — top modules: ...
```

`M` in the first line counts sources, sinks, sanitizers and error wrappers.
An inert rule produces no findings and no other signal, so read these lines on
every new corpus. The arg-range warning covers a sink whose name matches but
whose `arg` index exceeds every matching call's argument count; the `to`
warning is the same for a source whose `to` names argument ports no matching
call has. Inert
propagators are counted but not listed. The `opaque` line names the modules
where calls have no body, which is usually where the next scope change or rule
belongs. `Y` counts every call site; `X` leaves out standard-library, builtin
and remote calls and callees without a module path, which covers most
TypeScript calls.

Against the small fixtures in `testdata/cgf/`, the example catalog prints many
inert-rule warnings because the fixtures do not import most of the libraries it
covers. That is expected.

## Notes on the example catalog

- The `public Go baseline` section covers common Go libraries (database/sql,
  gorm, mongo-driver, go-redis, os/exec, html/template, logging libraries, and
  more). Its rules were written from each library's API shape and are checked
  only by the `example_catalog_shapes` unit test in `core/src/catalog.rs`; they
  have not been measured against a real corpus.
- Coverage wave 1 added, from API shapes and equally unmeasured: `read:`
  sources on `net/http.Request`'s fields (`Body`, `Form`, `PostForm`,
  `MultipartForm`, `Header`, `Trailer`, `URL`, `Host`, `RequestURI`; needs
  `pc-fe --surface-reads`); the gin `Bind*`/`ShouldBind*` family and echo
  `Bind` as by-ref sources (`to = "1"`), with a propagator from the context
  into the bound value so a caller passing the request — a linked HTTP client
  — composes through the bind; Kafka consume sources (kafka-go
  `Reader.ReadMessage`/`FetchMessage`, sarama `ConsumerGroupClaim.Messages` /
  `PartitionConsumer.Messages`, franz-go `Fetches.Records`/`RecordIter`/
  `RecordsAll` and `FetchesRecordIter.Next`); `(*net/http.Request).Context` as
  a `context` sanitizer; `sink_ignore_arg_types = ["context.Context"]`; and
  `arg = "args"` on `(net/http.Header).Set|Add` and the `*http.Client`
  methods. On the TypeScript side: `jsx:html` and `jsx:attr(-unsanitized)?:
  srcDoc` as `xss`; `jsx:attr-unsanitized:<url attribute>` as `xss` (the
  frontend emits it when the repo's React is older than 19 or unknown —
  react-dom 19 neutralises `javascript:` URLs); `jsx:attr:(href|action|
  formAction)` as `open_redirect`; React Router and `next/navigation` hooks as
  sources; and Node server sinks for route
  handlers (`child_process`, `fs`, `pg`/`mysql2` query where the receiver is
  named through its module, Prisma `$queryRawUnsafe`/`$executeRawUnsafe`,
  `next/navigation.redirect`). An untyped `.query` (a `new Pool()` receiver)
  is deliberately not a sink: Apollo's `client.query` has the same name. A
  `postMessage` payload (`event.data`) is not a source yet: the TypeScript
  frontend has no name for that read.
- The `test-only` section holds one `graphql_input` source that exists so
  `scripts/e2e-core.sh` can delete it and show GraphQL sourcing is structural.
  Delete it in your copy.
- Under `pc-fe --field-paths` (the default) trivial protobuf getters become
  field projections, not calls, so getter-based source rules rarely match on
  Go. Go sinks and sanitizers are catalog-only.

## Fitting a catalog to a codebase

1. Run once and read the fit report. Many inert rules means the vocabulary is
   wrong for this codebase.
2. List the real terminal operations (SQL, exec, file, outbound HTTP, logging):
   for each, the exact callee fqn as it appears in the CGF (`summary --fn` or
   a `--trace` run shows them), the sink class, and which argument carries the
   data.
3. Add rules and rerun until the inert list is empty or deliberately kept for
   other repositories.
4. Run with `--unmodeled` and add propagators (or `to = "none"`) for what it
   lists.

Editing the catalog changes its hash, which is part of the `--store` cache
namespace, so the next run recomputes every summary. There is no source-code
annotation for sanitizers; a sanitizer must be a rule naming a function.
