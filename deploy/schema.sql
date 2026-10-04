-- Panopticode graph store + contract registry (doc 06 §8.1).
-- MVP: single Postgres. Serving reads are 1-hop point lookups, not deep traversal.
-- We use a plain repos dimension table + node/edge tables. Partitioning by
-- repo_id (LIST) is documented in doc 06; for MVP we keep it simple (indexed,
-- not physically partitioned) — swap to PARTITION BY LIST(repo_id) at scale.

CREATE TABLE IF NOT EXISTS repos (
  repo_id    SERIAL PRIMARY KEY,
  repo       TEXT UNIQUE NOT NULL,   -- "gitlab.example.com/acme/ledger-svc"
  commit_sha TEXT NOT NULL
);

-- Nodes: functions, types, endpoints, grpc methods, graphql fields.
-- kind: 0 function, 1 type, 2 grpc_method, 3 graphql_field, 4 endpoint, 5 package
CREATE TABLE IF NOT EXISTS nodes (
  node_id BIGSERIAL PRIMARY KEY,
  repo_id INT NOT NULL REFERENCES repos(repo_id),
  kind    SMALLINT NOT NULL,
  iid     BYTEA,
  bid     BYTEA,
  fqn     TEXT NOT NULL,
  generated BOOL NOT NULL DEFAULT FALSE,
  origin  SMALLINT NOT NULL DEFAULT 0,
  span_file TEXT,
  span_line INT
);
CREATE INDEX IF NOT EXISTS nodes_repo_idx ON nodes(repo_id, kind);
CREATE INDEX IF NOT EXISTS nodes_iid_idx  ON nodes(iid);
CREATE UNIQUE INDEX IF NOT EXISTS nodes_repo_fqn_idx ON nodes(repo_id, kind, fqn);

-- Edges: adjacency, both directions materializable via `direction`.
-- rel_type: 0 calls, 1 implements, 2 binds_to, 3 invokes_remote, 4 flows_to, 5 contains
CREATE TABLE IF NOT EXISTS edges (
  from_id   BIGINT NOT NULL,
  to_id     BIGINT NOT NULL,
  rel_type  SMALLINT NOT NULL,
  direction BOOL NOT NULL DEFAULT TRUE,
  repo_id   INT NOT NULL,
  meta      JSONB
);
CREATE INDEX IF NOT EXISTS edges_from_idx ON edges(from_id, rel_type);
CREATE INDEX IF NOT EXISTS edges_to_idx   ON edges(to_id, rel_type);
CREATE INDEX IF NOT EXISTS edges_repo_idx ON edges(repo_id, rel_type);

-- Contract registry: iid -> defining repo. Unique on iid (doc 06 §2).
CREATE TABLE IF NOT EXISTS contracts (
  iid        BYTEA PRIMARY KEY,
  kind       SMALLINT NOT NULL,   -- 0 grpc, 1 graphql
  full_name  TEXT NOT NULL,
  repo       TEXT NOT NULL,
  input_msg  TEXT,
  output_msg TEXT
);

-- Reverse index: which repos/call-sites invoke a given contract iid (doc 05 §4).
CREATE TABLE IF NOT EXISTS invokes (
  iid         BYTEA NOT NULL,
  caller_repo TEXT NOT NULL,
  caller_fn   TEXT NOT NULL,
  span_file   TEXT,
  span_line   INT
);
CREATE INDEX IF NOT EXISTS invokes_iid_idx ON invokes(iid);

-- Contract summary store (durable tier; hot tier is in-process moka LRU).
-- Immutable, content-addressed by summary_key (doc 06 §8.2).
CREATE TABLE IF NOT EXISTS summaries (
  summary_key   BYTEA PRIMARY KEY,
  fn_iid        BYTEA NOT NULL,
  bid           BYTEA NOT NULL,
  contract_hash BYTEA NOT NULL,
  blob          BYTEA NOT NULL,   -- serialized summary.Summary
  repo          TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS summaries_fn_iid_idx ON summaries(fn_iid);

-- Published endpoint summaries keyed by contract iid (Contract Summary Store).
CREATE TABLE IF NOT EXISTS contract_summaries (
  contract_iid  BYTEA PRIMARY KEY,
  contract_hash BYTEA NOT NULL,
  blob          BYTEA NOT NULL,   -- serialized summary.Summary of the handler
  repo          TEXT NOT NULL,
  commit_sha    TEXT NOT NULL
);
