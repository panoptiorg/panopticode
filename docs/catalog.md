# The catalog

The catalog is the whole security policy. Frontends emit structural facts only;
everything the tool calls a source, sink, sanitizer or propagator comes from
this TOML file, which only the core reads. Start from
[`catalog.example.toml`](../catalog.example.toml), which the test suite also
runs against.

## Format

Five optional arrays of tables. These are the only keys the core reads:

| table | keys |
|---|---|
| `[[sources]]` | `kind`, `selector`, `selector_regex` |
| `[[sinks]]` | `class`, `selector`, `selector_regex`, `arg` |
| `[[sanitizers]]` | `kind`, `selector`, `selector_regex` |
| `[[error_wrappers]]` | `selector`, `selector_regex` |
| `[[propagators]]` | `selector`, `selector_regex`, `from` (required), `to` (required) |

`note` is accepted anywhere and ignored. Any other key or table, including
`schema_version` and misspellings such as `[[sink]]` or `selecter`, is
silently ignored. A misspelled table name therefore removes all its rules
without an error; check the `catalog-fit` line (below) after editing.

```toml
[[sources]]
kind           = "ts_url_query"         # free text, never matched on
selector_regex = '^(URLSearchParams|URL)\.(get|getAll)$'

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

- `[[sources]]` matches at a call's result: the value returned by the call is
  tainted. Request parameters of gRPC handlers, GraphQL resolvers and SvelteKit
  server endpoints are sources without any rule: frontends mark them in
  `Function.source_params`. Chains start only in functions that have source
  parameters or call a source themselves.
- `[[sinks]]` matches at a tainted argument of the call. `arg` absent, `""` or
  `"any"` accepts any argument; otherwise it is a 0-based argument index, where
  the receiver is index 0 when the call has one. A non-numeric value fails the
  load.
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
catalog-fit: 9/22 propagators match at least one call site
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
catalog-fit: 10/23 propagators match at least one call site
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
catalog-fit: N/M propagators match at least one call site
opaque: X of Y call sites into a Go module or func value have no loaded body (default leaf: ...) — top modules: ...
```

`M` in the first line counts sources, sinks, sanitizers and error wrappers.
An inert rule produces no findings and no other signal, so read these lines on
every new corpus. The arg-range warning covers a sink whose name matches but
whose `arg` index exceeds every matching call's argument count. Inert
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
