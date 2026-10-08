# CGF: the code graph format

CGF is what frontends write and the core reads. The schema is
[`proto/cgf.proto`](../proto/cgf.proto), the canonical copy; the frontends
vendor it and check for drift. A CGF directory holds one binary
`CgfPackage` message per Go package or TypeScript directory, in files ending
`.pb`. The core reads the `.pb` files directly inside each `--cgf` directory
(not subdirectories).

## Model

```
CgfPackage            repo, language, package_path, commit_sha
├── Function[]        id{iid,bid}, fqn, has_body, span, source_params
│   └── LocalFlow
│       ├── FlowVertex[]   kind, index, field_path, callsite_id, sym, span, ...
│       ├── FlowEdge[]     from -> to (value flow inside the function)
│       └── CallSite[]     kind, callee_iids, callee_fqn, argc, resultc, ...
├── GrpcMethod[]      full_name "<pkg>.<Svc>/<Method>", handler_iid, streaming flags
├── GraphqlField[]    type_field "<Type>.<field>", resolver_iid, args{name,param_idx}
├── HttpRoute[]       method, path (canonical), display, handler_iid, request_params, framework
└── Endpoint[]        kind GRPC | GRAPHQL | HTTP | MESSAGE, name — reporting only
```

- A function's LocalFlow is its value-flow graph. Vertices are the places taint
  can enter (`IN_PARAM`, `IN_RECEIVER`, `IN_GLOBAL`), leave (`OUT_RETURN`,
  `OUT_PARAM_BYREF`, `OUT_RECEIVER_BYREF`, `OUT_FIELD`), or cross a call
  (`CALL_ARG_PORT`, `CALL_RESULT_PORT`, tied to a call site by `callsite_id`
  and to a position by `index`). There is never an edge from an argument port
  to a result port; the core supplies that through the callee's summary.
- `field_path` holds up to two field indices; `field_names` the matching names
  for output.
- `IN_GLOBAL` and `OUT_FIELD` vertices with a `sym` are heap cells (Go, only
  with `pc-fe --heap-slots`).
- A call site's `callee_iids` lists resolved targets (several for virtual
  dispatch); `callee_fqn` is the name catalog rules match; `opaque` marks an
  unresolved call (`pc-fe` sets it on a function-value call with no target and
  on a dispatch site over its fan-out cap, not on other interface calls); the
  core applies the default leaf to any call without a summary either way.
  `INVOKES_REMOTE` sites name a contract's iid.
  `arg0_is_receiver`, `dispatch_confidence`, `stream_op`, `stream_client_side`,
  `error_results` (a bitmask of error-typed results) and `arg_names` (by-name
  GraphQL arguments from TypeScript) refine how the site is handled.
- An `HttpRoute` is a server-side HTTP route: `method` upper-case or `*` for
  any, `path` the canonical template below, `request_params` the handler
  parameters (receiver excluded) that carry request data. Its `iid` is the
  contract iid of `http:<METHOD> <path>`.
- A call site with `http_call` set is a synthetic HTTP client site, emitted in
  addition to the ordinary call: `argc 1`, `resultc 0`, every data-bearing
  argument of the request (URL, body) flowing into arg port 0, `callee_fqn`
  `http:<METHOD> <path>`. Unlinked it is inert. The core links it to the routes
  it matches when it loads the corpus (see
  [architecture.md](architecture.md#http-routes)).
- A `read:<import path>.<Type>.<Field>` call site (Go, `pc-fe
  --surface-reads`) is a field read surfaced as a zero-arg opaque call, so a
  catalog source can name it: `read:net/http.Request.Body`. The TypeScript
  frontend's `read:<path>` sites are the same idea.
- `Function.source_params` lists parameters that are untrusted input (request
  arguments of handlers and resolvers). They seed chains without any catalog
  rule.
- `iid` and `bid` are SHA-256 identities; see
  [architecture.md](architecture.md#identity-and-caching).

### Canonical HTTP path

Routes and client sites carry the same canonical template, so the core
compares strings. [`testdata/http-canon-vectors.json`](../testdata/http-canon-vectors.json)
pins it; both frontends and the core test against every vector.

1. A literal scheme and authority (`https://api.example.com/x`, `//cdn/x`) are
   dropped; so are `?…` and `#…`.
2. Empty segments are dropped. The result is `/` plus the segments joined by
   `/`, or `/` when there are none.
3. A parameter segment is `{}` whatever its syntax (`{id}`, `{id:[0-9]+}`,
   `:id`, `[id]`, a template-literal hole); a partly dynamic segment
   (`v{}.json`) is `{}` as a whole. Go 1.22's `{$}` anchor is dropped.
4. A catch-all is `{*}` (`{path...}`, `*`, `*name`, `[...slug]`,
   `[[...slug]]`) and ends the path.
5. On a client only, an unresolved base URL (`${API}/users`, `os.Getenv(…) +
   "/users"`) is one leading `{}` segment, kept, so the core knows the rest is
   a suffix.

## Live and reserved fields

The schema declares more than the core uses today. The core ignores these:

| element | status |
|---|---|
| `Type`, `Field`, `ProtoMessage`, `ProtoField`, `PiiTag` | not read; taint is boolean, there are no PII labels |
| `CgfPackage.types`, `proto_messages`, `schema_version` | not read |
| `Endpoint` (all kinds, including `untrusted_input`) | counted by kind in `graph-dump`, otherwise not read; contracts come only from `grpc_methods`, `graphql_fields` and `http_routes`, and sources from `source_params` and the catalog |
| `Function.binds_to`, `generator`, `package`, `signature` | not read |
| `GrpcMethod.endpoint_iid`, `GraphqlField.endpoint_iid`, `HttpRoute.endpoint_iid` | not read |
| `HttpRoute.display`, `framework` | reporting only: the route hop of a crossing renders `http <METHOD> <display> (<framework>)` |
| `FlowEdge.via_alias` | read but has no effect |
| `CallSite` kinds `GO`, `DEFER` | treated like ordinary calls; `BUILTIN` only excludes a site from the `opaque:` count |
| `Function.generated`, `origin`, `GrpcMethod.input_msg`, `output_msg`, `CgfPackage.commit_sha` | only written to Postgres |

`CgfPackage.language` is `go` or `ts`; an empty value counts as `go` in
`graph-dump`.

## Other protos

- `proto/summary.proto` is compiled into the core but not used: summaries are
  an internal Rust type, stored as JSON in the `--store` directory and in
  Postgres.
- `proto/cgstore.proto` is the Go frontend's call-graph snapshot cache. The core
  does not compile or read it; it lives here so the schemas stay in one place.
