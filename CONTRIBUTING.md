# Contributing

## Requirements

- Rust stable. CI uses the latest stable; the [Dockerfile](Dockerfile) uses 1.90.
- `protoc`, the Protocol Buffers compiler. [`core/build.rs`](core/build.rs)
  compiles `proto/` with prost-build, and without `protoc` the build fails with
  ``Could not find `protoc`.`` Install it with `apt-get install protobuf-compiler`
  (Debian, Ubuntu) or `brew install protobuf` (macOS), or set `PROTOC` to the
  binary's path.
- `python3` and `perl`, which `scripts/e2e-core.sh` uses for its assertions.

Building and testing need no Go, Node, Postgres or Docker.

## Build and test

```bash
cargo build --manifest-path core/Cargo.toml    # binary: core/target/debug/panopticode
cargo test  --manifest-path core/Cargo.toml
NOBUILD=1 scripts/e2e-core.sh                  # 16 suites on testdata/cgf
```

`scripts/e2e-core.sh` runs `cargo build` first unless `NOBUILD=1` is set. It
runs the engine against the golden CGF in [`testdata/cgf/`](testdata/cgf/README.md),
so it needs no frontend. Run all three before sending a change.

CI ([`.github/workflows/ci.yml`](.github/workflows/ci.yml)) runs the same three
steps on Ubuntu, then `cargo clippy --all-targets`, which does not fail the run.

## Regenerating testdata

`testdata/cgf/` is extracted from fixtures that live in the frontend
repositories. [`scripts/regen-testdata.sh`](scripts/regen-testdata.sh) rebuilds
it and is the only test script that needs them. It expects
[panoptife-go](https://github.com/panoptiorg/panoptife-go) and
[panoptife-ts](https://github.com/panoptiorg/panoptife-ts) checked out next to
this repository, with both frontends built:

```bash
PC_FE=../panoptife-go/bin/pc-fe PC_FE_TS=../panoptife-ts/bin/pc-fe-ts \
  scripts/regen-testdata.sh
```

The script's header shows how to build the frontends and lists the variables
that override these paths. Afterwards, record the frontend commits in
[`testdata/cgf/README.md`](testdata/cgf/README.md#provenance) and rerun
`scripts/e2e-core.sh`.

## Changing the proto

`proto/` here is canonical. Each frontend vendors a copy, records the
panopticode commit it was taken from in `proto/PROTO_VERSION`, and checks for
drift with `scripts/check-proto.sh`. A change to `proto/cgf.proto` must be
re-vendored in both frontends, and `testdata/cgf/` regenerated with them;
`summary.proto` and `cgstore.proto` are vendored only by panoptife-go.
