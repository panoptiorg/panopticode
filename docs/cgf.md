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
└── GraphqlField[]    type_field "<Type>.<field>", resolver_iid, args{name,param_idx}
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
  unresolved call. `INVOKES_REMOTE` sites name a contract's iid.
  `arg0_is_receiver`, `dispatch_confidence`, `stream_op`, `stream_client_side`,
  `error_results` (a bitmask of error-typed results) and `arg_names` (by-name
  GraphQL arguments from TypeScript) refine how the site is handled.
- `Function.source_params` lists parameters that are untrusted input (request
  arguments of handlers and resolvers). They seed chains without any catalog
  rule.
- `iid` and `bid` are SHA-256 identities; see
  [architecture.md](architecture.md#identity-and-caching).

## Live and reserved fields

The schema declares more than the core uses today. The core ignores these:

| element | status |
|---|---|
| `Type`, `Field`, `ProtoMessage`, `ProtoField`, `PiiTag` | not read; taint is boolean, there are no PII labels |
| `CgfPackage.types`, `proto_messages`, `endpoints`, `schema_version` | not read |
| `Endpoint` (all kinds, including `untrusted_input`) | not read; `pc-fe-ts` emits HTTP endpoints, but contracts come only from `grpc_methods` and `graphql_fields`, and sources from `source_params` |
| `Function.binds_to`, `generator`, `package`, `signature` | not read |
| `GrpcMethod.endpoint_iid`, `GraphqlField.endpoint_iid` | not read |
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
