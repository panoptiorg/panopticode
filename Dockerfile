# Multi-stage build for the panopticode core engine.
#
#   docker build -t panopticode .
#   docker run --rm -v "$PWD/cgf:/cgf" panopticode \
#     taint --cgf /cgf/gateway --cgf /cgf/ledger-svc --catalog /etc/panopticode/catalog.example.toml
#
# NOTE: this image contains the CORE ONLY. Extraction — turning a repo into CGF
# — is done by a separate frontend binary (`pc-fe` for Go, `pc-fe-ts` for
# TypeScript/Svelte), which lives in its own repository and ships as its own
# image. The core never needs a Go or Node toolchain; it reads CGF directories.
# `panopticode extract` shells out to `pc-fe`, so that subcommand does not work
# in this image unless you mount a pc-fe binary onto the PATH.

# --- build ------------------------------------------------------------------
FROM rust:1.90-bookworm AS build
WORKDIR /src

# protoc is a build dependency: build.rs compiles proto/*.proto with prost.
RUN apt-get update \
 && apt-get install -y --no-install-recommends protobuf-compiler \
 && rm -rf /var/lib/apt/lists/*

# Cache the dependency build across source edits.
COPY core/Cargo.toml core/Cargo.lock ./core/
RUN mkdir -p core/src && echo 'fn main() {}' > core/src/main.rs \
 && cargo build --release --manifest-path core/Cargo.toml \
 && rm -rf core/src

COPY proto ./proto
COPY core ./core
# touch so cargo does not reuse the stub main.rs fingerprint
RUN touch core/src/main.rs && cargo build --release --manifest-path core/Cargo.toml

# --- runtime ----------------------------------------------------------------
FROM debian:bookworm-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --create-home --uid 10001 panopticode

COPY --from=build /src/core/target/release/panopticode /usr/local/bin/panopticode
COPY catalog.example.toml /etc/panopticode/catalog.example.toml
COPY proto /usr/share/panopticode/proto

USER panopticode
WORKDIR /work
ENTRYPOINT ["/usr/local/bin/panopticode"]
CMD ["--help"]
