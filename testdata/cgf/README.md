# Golden CGF corpus

Pre-extracted CGF for every analysis fixture. It lets `scripts/e2e-core.sh`
(16 suites) run the whole engine with only a Rust toolchain: no Go, Node,
Postgres, Docker or network. Total size is about 0.9 MB.

The fixture sources live in the frontend repositories
([panoptife-go](https://github.com/panoptiorg/panoptife-go) and
[panoptife-ts](https://github.com/panoptiorg/panoptife-ts), under `fixtures/`).
[`scripts/regen-testdata.sh`](../../scripts/regen-testdata.sh) rebuilds this
directory from them and is the only test script that needs the frontends.

## Provenance

The files were produced by frontends vendoring the same `proto/cgf.proto` as
this repository; every directory was last regenerated from panoptife-go
`02a89e7` and panoptife-ts `ed1d213`. A CGF directory is only meaningful
against a core whose `proto/cgf.proto` matches the one that produced it; each
frontend's `scripts/check-proto.sh` checks that. When you regenerate, record
the frontend commits here.

## Reproducibility

`go/packages` reports absolute file paths and `pc-fe` records them in spans, so
`regen-testdata.sh` first copies the fixture sources to a fixed staging path
(`/tmp/panopticode-fixtures`, override with `STAGE`) and extracts from there.
The committed spans read `/private/tmp/panopticode-fixtures/<fixture>/...`; on
macOS `/tmp` is a symlink to `/private/tmp`, elsewhere set
`STAGE=/private/tmp/panopticode-fixtures`. Re-running the script against the
same frontend commits with the same Go release produces byte-identical output.
A different Go release can change callee ids, which hash standard-library
signatures (go1.27.1 changes the `fmt.Errorf` id in `errorleaf-*`); any other
diff after regeneration is a bug.

## The commands

Every Go directory below is:

```
cd $STAGE/<fixture> && pc-fe build . --scope './...' [flags] --out testdata/cgf/<dir>
```

and `webapp` is:

```
pc-fe-ts build --repo $STAGE/webapp --repo-id webapp --adapter bff-gateway --quiet \
  --out testdata/cgf/webapp
```

| directory | fixture | extra `pc-fe` flags | used by |
|---|---|---|---|
| `backend` | `backend` | — | e2e, e2e-multihop, e2e-route, e2e-graphql, e2e-ts, e2e-backward |
| `federation` | `federation` | — | e2e, e2e-multihop, e2e-route, e2e-graphql, e2e-ts, e2e-backward |
| `downstream` | `downstream` | — | e2e-multihop, e2e-route |
| `dispatch-vta` | `dispatch` | `--dispatch vta` | e2e-dispatch |
| `dispatch-cha` | `dispatch` | `--dispatch cha` | e2e-dispatch |
| `dispatch-off` | `dispatch` | `--dispatch off` | e2e-dispatch |
| `fieldpath-on` | `fieldpath` | `--dispatch vta` | e2e-fieldpath |
| `fieldpath-off` | `fieldpath` | `--dispatch vta --field-paths=false` | e2e-fieldpath |
| `wrappers` | `wrappers` | — | e2e-wrappers |
| `closureflow-on` | `closureflow` | `--dispatch vta` | e2e-closure |
| `closureflow-off` | `closureflow` | `--dispatch vta --closure-flow=false` | e2e-closure |
| `heapslots-on` | `heapslots` | `--dispatch vta --heap-slots --heap-slots-scope=all` | e2e-heapslots |
| `heapslots-off` | `heapslots` | `--dispatch vta` | e2e-heapslots |
| `heapslots-chan` | `heapslots` | `--dispatch vta --heap-slots --heap-slots-scope=chan` | e2e-heapslots |
| `heapslots-narrow` | `heapslots` | `… --heap-slots-scope=all --heap-iface-narrow` | e2e-heapslots |
| `heapslots-drop` | `heapslots` | `… --heap-slots-scope=all --heap-iface-drop` | e2e-heapslots |
| `byrefout-on` | `byrefout` | `--dispatch vta --byref-out` | e2e-byrefout |
| `byrefout-off` | `byrefout` | `--dispatch vta` | e2e-byrefout |
| `errorleaf-on` | `errorleaf` | `--dispatch vta --error-results` | e2e-errorleaf |
| `errorleaf-off` | `errorleaf` | `--dispatch vta` | e2e-errorleaf |
| `miniledger-vta` | `miniledger` | `--dispatch vta` | e2e-miniledger |
| `miniledger-cha` | `miniledger` | `--dispatch cha` | e2e-miniledger |
| `miniledger-off` | `miniledger` | `--dispatch off` | e2e-miniledger |
| `recursion` | `recursion` | defaults | e2e-recursion |
| `libwrites` | `libwrites` | `--scope ./app/...,./pb/...,./store/...` (thirdparty/ out of scope) | e2e-libwrites |
| `libwrites-off` | `libwrites` | same, `--library-writeback=false` | e2e-libwrites |
| `webapp` | `webapp` (TS) | `--adapter bff-gateway` | e2e-ts, e2e-backward |
| `weblib` | `weblib` (TS) | — | e2e-libwrites |
| `weblib-off` | `weblib` (TS) | `--no-library-writeback` | e2e-libwrites |

`-on` / `-off` pairs let a suite compare the same fixture with and without one
frontend flag, so any difference is attributable to that flag.

## What each fixture is for

- **`backend` / `federation` / `downstream`** — a three-service chain. A gqlgen
  resolver in `federation` calls a gRPC method on `backend`, which calls one on
  `downstream`, which runs the SQL. The cross-repo join happens entirely through
  generated `protoc-gen-go-grpc` names; nothing pairs the repos by hand.
- **`dispatch`** — a narrow interface (2 implementations, resolved) next to a
  wide one (12, capped to opaque), to pin what dispatch resolution does and does
  not make visible.
- **`fieldpath`** — two disjoint request fields feeding two different sinks, so
  that k=2 field paths can be shown to kill a false positive rather than just
  changing a number.
- **`wrappers`** — the three synthetic functions `go/ssa` generates (`$bound`,
  `$thunk`, embedded promotion), each carrying request data to a SQL sink.
- **`closureflow`** — closure free variables, including one closure with two
  captures and two same-class sinks so a shifted binding index cannot pass.
- **`heapslots`** — producer and consumer reached by disjoint call paths from
  one pool, plus interface-typed cells written from two concrete types.
- **`byrefout`** — writes through a pointer parameter and through the receiver.
- **`errorleaf`** — error-typed result ports, with the recall guards that any
  error-suppression rule must not break.
- **`recursion`** — six one-handler engine cases: slot-swapping self-recursion (sink and
  return side), a sink-on-every-frame control, a two-function SCC, a witness diamond, and a
  two-implementation dispatch whose first candidate has no sink.
- **`miniledger`** — a scaled-down real service shape: a god-object handler, one
  storage type behind many small interfaces, and a generic pool whose closure
  cycle forms a size-6 SCC.
- **`webapp`** — a SvelteKit app whose GraphQL operation joins by name to
  `federation`'s SDL, giving chains that start in TypeScript and end at a Go
  SQL sink.
- **`libwrites`** (Go) / **`weblib`** (TS) — library calls that write into an
  argument (`strings.Builder`, `json.Unmarshal`, `io.Copy`, … / `Array.push`,
  `Map.set`, `Object.assign`, …), each lost without a catalog `[[propagators]]`
  rule *and* the frontend's library write-back edge; clean cases in each
  language that must stay silent; and (Go) a stand-in dependency, extracted
  out of scope, that only `--unmodeled` can point at.

`webapp`, `federation`, `backend` and `downstream` together form the example
system; [The example system](../../docs/example.md) maps their code to the 18
findings they produce.

## `catalog-warn` noise

Running the suite prints many `catalog-warn: inert rule ...` lines. That is
expected: `catalog.example.toml` covers libraries (`database/sql`, `pgx`, `zap`,
`kafka-go`, ...) these small fixtures do not import. On a real corpus the same
report is worth reading; see [docs/catalog.md](../../docs/catalog.md#diagnostics).
