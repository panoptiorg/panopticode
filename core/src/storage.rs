// Postgres persistence (sqlx): graph nodes (functions + grpc-method contract
// nodes), call/binds_to/invokes_remote edges, the contract registry + invokes
// reverse index, and content-addressed summary blobs (doc 06 §8.1). Everything
// runs in one transaction; edges/invokes have no unique key, so they are
// refreshed per analyzed repo (delete + bulk insert) to stay idempotent.
use crate::graph::{hexid, IidHex, Program};
use crate::ids;
use crate::ifds::{slot_parse, slot_str, Engine, SinkHit, Summary};
use crate::proto::cgf;
use crate::summarystore::contract_hash;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::postgres::PgPoolOptions;
use sqlx::{Postgres, Transaction};
use std::collections::{HashMap, HashSet};

// nodes.kind
const KIND_FN: i16 = 0;
const KIND_CONTRACT: i16 = 2;
// edges.rel_type
const REL_CALLS: i16 = 0;
const REL_BINDS_TO: i16 = 2;
const REL_INVOKES_REMOTE: i16 = 3;

/// Versioned summary blob (doc 18 B.1). v1 had no `v` field and tuple-shaped
/// sink_hits; readers treat anything that isn't a decodable v2 as skip-with-
/// warning (v1 blobs age out on the next persist — ON CONFLICT DO UPDATE).
// v3 = field-path slots (`param_1[3,0]`, doc 20 §2): older binaries would
// slot_parse→None new-style strings and silently drop flows (an FN); the
// version gate turns that into the loud skip below. Doc 20 §3.3 reserved v3
// for the transform monoid — that becomes v4 when Part B lands.
const SUMMARYJ_V: u32 = 3;

#[derive(Serialize, Deserialize)]
struct SinkHitJ {
    slot: String,
    class: String,
    span_file: String,
    span_line: u32,
}

#[derive(Serialize, Deserialize)]
struct SummaryJ {
    v: u32,
    flows: Vec<(String, String)>,
    sink_hits: Vec<SinkHitJ>,
    confidence: f32,
}

fn project(s: &Summary) -> SummaryJ {
    SummaryJ {
        v: SUMMARYJ_V,
        flows: s
            .flows
            .iter()
            .map(|(a, b)| (slot_str(a), slot_str(b)))
            .collect(),
        sink_hits: s
            .sink_hits
            .iter()
            .map(|h| SinkHitJ {
                slot: slot_str(&h.in_slot),
                class: h.class.clone(),
                span_file: h.span.as_ref().map(|s| s.file.clone()).unwrap_or_default(),
                span_line: h.span.as_ref().map(|s| s.line as u32).unwrap_or_default(),
            })
            .collect(),
        confidence: s.confidence,
    }
}

/// Inverse of `project` for PG-loaded contract views. Flows/sinks whose slot
/// strings don't parse are skipped (forward compat).
fn unproject(j: &SummaryJ) -> Summary {
    let mut s = Summary {
        confidence: j.confidence,
        ..Default::default()
    };
    for (a, b) in &j.flows {
        if let (Some(a), Some(b)) = (slot_parse(a), slot_parse(b)) {
            s.flows.insert((a, b));
        }
    }
    for h in &j.sink_hits {
        let Some(in_slot) = slot_parse(&h.slot) else { continue };
        let span = (!h.span_file.is_empty()).then(|| cgf::Span {
            file: h.span_file.clone(),
            line: h.span_line as i32,
            col: 0,
        });
        s.sink_hits.push(SinkHit {
            in_slot,
            class: h.class.clone(),
            callsite: 0,
            span,
            via_heap: None, // phase-2 only; never persisted
        });
    }
    s
}

pub struct PersistStats {
    pub nodes: usize,
    pub edges: usize,
    pub invokes: usize,
}

pub fn persist(prog: &Program, eng: &Engine<'_>, pg_url: &str) -> Result<PersistStats> {
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async { persist_async(prog, eng, pg_url).await })
}

fn is_remote(cs: &cgf::CallSite) -> bool {
    cs.kind == cgf::call_site::Kind::InvokesRemote as i32
}

/// Contract iids referenced by invokes_remote callsites but not defined by any
/// loaded package's grpc_methods — the set a PG-backed run resolves from
/// `contract_summaries` (doc 18 B.3) and `persist` materializes foreign
/// contract nodes for.
pub fn missing_remote_contracts(prog: &Program) -> Vec<Vec<u8>> {
    let local: HashSet<IidHex> = prog
        .packages
        .iter()
        .flat_map(|p| crate::graph::pkg_contracts(p).into_iter().map(|c| hexid(c.iid)))
        .collect();
    let mut missing: Vec<Vec<u8>> = Vec::new();
    let mut seen: HashSet<IidHex> = HashSet::new();
    for f in prog.funcs.values() {
        let Some(flow) = &f.flow else { continue };
        for cs in flow.callsites.iter().filter(|cs| is_remote(cs)) {
            for cid in &cs.callee_iids {
                let h = hexid(cid);
                if !local.contains(&h) && seen.insert(h) {
                    missing.push(cid.clone());
                }
            }
        }
    }
    missing
}

async fn persist_async(prog: &Program, eng: &Engine<'_>, pg_url: &str) -> Result<PersistStats> {
    let pool = PgPoolOptions::new()
        .max_connections(4)
        .connect(pg_url)
        .await?;
    let mut tx = pool.begin().await?;

    let repo_ids = upsert_repos(&mut tx, prog).await?;
    upsert_contracts(&mut tx, prog).await?;

    // node rows, deduped on the (repo_id, kind, fqn) unique index
    let mut rows: HashMap<(i32, i16, String), NodeRow> = HashMap::new();
    collect_fn_nodes(prog, &repo_ids, &mut rows);
    // contract nodes for every contract defined in this run (gRPC + GraphQL)
    for p in &prog.packages {
        let rid = *repo_ids.get(&p.repo).unwrap_or(&0);
        for c in crate::graph::pkg_contracts(p) {
            rows.insert(
                (rid, KIND_CONTRACT, c.full_name.to_string()),
                NodeRow {
                    repo_id: rid,
                    kind: KIND_CONTRACT,
                    iid: c.iid.to_vec(),
                    bid: Vec::new(),
                    fqn: c.full_name.to_string(),
                    generated: true,
                    origin: 0,
                    span_file: String::new(),
                    span_line: 0,
                },
            );
        }
    }
    // contracts invoked but defined in repos outside this run: resolve via the
    // registry (populated by an earlier analysis of the defining repo)
    let foreign_repo_ids = resolve_foreign_contracts(&mut tx, prog, &mut rows).await?;

    let node_rows: Vec<NodeRow> = rows.into_values().collect();
    let nodes = node_rows.len();
    upsert_nodes(&mut tx, &node_rows).await?;

    // iid -> node_id maps over every repo we touched
    let mut all_rids: Vec<i32> = repo_ids.values().copied().collect();
    all_rids.extend(foreign_repo_ids);
    all_rids.sort_unstable();
    all_rids.dedup();
    let (fn_node, contract_node) = select_node_ids(&mut tx, &all_rids).await?;

    let analyzed_rids: Vec<i32> = {
        let mut v: Vec<i32> = repo_ids.values().copied().collect();
        v.sort_unstable();
        v.dedup();
        v
    };
    let edges = refresh_edges(&mut tx, prog, &repo_ids, &analyzed_rids, &fn_node, &contract_node)
        .await?;
    let invokes = refresh_invokes(&mut tx, prog).await?;

    persist_summaries(&mut tx, prog, eng).await?;

    tx.commit().await?;
    Ok(PersistStats {
        nodes,
        edges,
        invokes,
    })
}

async fn upsert_repos(
    tx: &mut Transaction<'_, Postgres>,
    prog: &Program,
) -> Result<HashMap<String, i32>> {
    let mut repo_id: HashMap<String, i32> = HashMap::new();
    for p in &prog.packages {
        if repo_id.contains_key(&p.repo) {
            continue;
        }
        let rec: (i32,) = sqlx::query_as(
            "INSERT INTO repos(repo, commit_sha) VALUES($1,$2)
             ON CONFLICT (repo) DO UPDATE SET commit_sha=EXCLUDED.commit_sha
             RETURNING repo_id",
        )
        .bind(&p.repo)
        .bind(&p.commit_sha)
        .fetch_one(&mut **tx)
        .await?;
        repo_id.insert(p.repo.clone(), rec.0);
    }
    Ok(repo_id)
}

async fn upsert_contracts(tx: &mut Transaction<'_, Postgres>, prog: &Program) -> Result<()> {
    for p in &prog.packages {
        // gRPC methods (kind 0) and GraphQL fields (kind 1, doc 36 §3.3) —
        // `kind` is what distinguishes them; a field's full_name is its
        // SDL type_field and it has no input/output message.
        for c in crate::graph::pkg_contracts(p) {
            sqlx::query(
                "INSERT INTO contracts(iid, kind, full_name, repo, input_msg, output_msg)
                 VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT (iid) DO NOTHING",
            )
            .bind(c.iid)
            .bind(c.kind)
            .bind(c.full_name)
            .bind(&p.repo)
            .bind(c.input_msg)
            .bind(c.output_msg)
            .execute(&mut **tx)
            .await?;
        }
    }
    Ok(())
}

struct NodeRow {
    repo_id: i32,
    kind: i16,
    iid: Vec<u8>,
    bid: Vec<u8>,
    fqn: String,
    generated: bool,
    origin: i16,
    span_file: String,
    span_line: i32,
}

fn collect_fn_nodes(
    prog: &Program,
    repo_ids: &HashMap<String, i32>,
    rows: &mut HashMap<(i32, i16, String), NodeRow>,
) {
    for (iid, f) in &prog.funcs {
        let repo = prog.repo_of.get(iid).cloned().unwrap_or_default();
        let rid = *repo_ids.get(&repo).unwrap_or(&0);
        let (span_file, span_line) = f
            .span
            .as_ref()
            .map(|s| (s.file.clone(), s.line))
            .unwrap_or_default();
        rows.insert(
            (rid, KIND_FN, f.fqn.clone()),
            NodeRow {
                repo_id: rid,
                kind: KIND_FN,
                iid: hex::decode(iid).unwrap_or_default(),
                bid: f.id.as_ref().map(|i| i.bid.clone()).unwrap_or_default(),
                fqn: f.fqn.clone(),
                generated: f.generated,
                origin: f.origin as i16,
                span_file,
                span_line,
            },
        );
    }
}

/// Contract iids invoked from this run but defined elsewhere: look them up in
/// the registry and materialize a contract node in the defining repo, so
/// invokes_remote edges can point at it. Unknown contracts (defining repo never
/// analyzed) are skipped — the invokes reverse index still records the call.
async fn resolve_foreign_contracts(
    tx: &mut Transaction<'_, Postgres>,
    prog: &Program,
    rows: &mut HashMap<(i32, i16, String), NodeRow>,
) -> Result<Vec<i32>> {
    let missing = missing_remote_contracts(prog);
    if missing.is_empty() {
        return Ok(Vec::new());
    }
    let found: Vec<(Vec<u8>, String, String)> = sqlx::query_as(
        "SELECT iid, repo, full_name FROM contracts WHERE iid = ANY($1)",
    )
    .bind(&missing)
    .fetch_all(&mut **tx)
    .await?;

    let mut rids = Vec::new();
    for (iid, repo, full_name) in found {
        // ensure a repos row for the defining repo without clobbering the
        // commit_sha a real analysis wrote (no-op update makes RETURNING work)
        let rec: (i32,) = sqlx::query_as(
            "INSERT INTO repos(repo, commit_sha) VALUES($1,'')
             ON CONFLICT (repo) DO UPDATE SET repo=EXCLUDED.repo
             RETURNING repo_id",
        )
        .bind(&repo)
        .fetch_one(&mut **tx)
        .await?;
        rids.push(rec.0);
        rows.insert(
            (rec.0, KIND_CONTRACT, full_name.clone()),
            NodeRow {
                repo_id: rec.0,
                kind: KIND_CONTRACT,
                iid,
                bid: Vec::new(),
                fqn: full_name,
                generated: true,
                origin: 0,
                span_file: String::new(),
                span_line: 0,
            },
        );
    }
    Ok(rids)
}

async fn upsert_nodes(tx: &mut Transaction<'_, Postgres>, rows: &[NodeRow]) -> Result<()> {
    if rows.is_empty() {
        return Ok(());
    }
    let mut rid = Vec::with_capacity(rows.len());
    let mut kind = Vec::with_capacity(rows.len());
    let mut iid = Vec::with_capacity(rows.len());
    let mut bid = Vec::with_capacity(rows.len());
    let mut fqn = Vec::with_capacity(rows.len());
    let mut generated = Vec::with_capacity(rows.len());
    let mut origin = Vec::with_capacity(rows.len());
    let mut span_file = Vec::with_capacity(rows.len());
    let mut span_line = Vec::with_capacity(rows.len());
    for r in rows {
        rid.push(r.repo_id);
        kind.push(r.kind);
        iid.push(r.iid.clone());
        bid.push(r.bid.clone());
        fqn.push(r.fqn.clone());
        generated.push(r.generated);
        origin.push(r.origin);
        span_file.push(r.span_file.clone());
        span_line.push(r.span_line);
    }
    sqlx::query(
        "INSERT INTO nodes(repo_id, kind, iid, bid, fqn, generated, origin, span_file, span_line)
         SELECT * FROM UNNEST($1::int4[], $2::int2[], $3::bytea[], $4::bytea[], $5::text[],
                              $6::bool[], $7::int2[], $8::text[], $9::int4[])
         ON CONFLICT (repo_id, kind, fqn) DO UPDATE
           SET iid=EXCLUDED.iid, bid=EXCLUDED.bid,
               span_file=EXCLUDED.span_file, span_line=EXCLUDED.span_line",
    )
    .bind(&rid)
    .bind(&kind)
    .bind(&iid)
    .bind(&bid)
    .bind(&fqn)
    .bind(&generated)
    .bind(&origin)
    .bind(&span_file)
    .bind(&span_line)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

type NodeIdMap = HashMap<IidHex, i64>;

async fn select_node_ids(
    tx: &mut Transaction<'_, Postgres>,
    repo_ids: &[i32],
) -> Result<(NodeIdMap, NodeIdMap)> {
    let rows: Vec<(i64, i16, Option<Vec<u8>>)> = sqlx::query_as(
        "SELECT node_id, kind, iid FROM nodes
         WHERE repo_id = ANY($1) AND kind = ANY($2) AND iid IS NOT NULL",
    )
    .bind(repo_ids)
    .bind(vec![KIND_FN, KIND_CONTRACT])
    .fetch_all(&mut **tx)
    .await?;
    let mut fn_node = NodeIdMap::new();
    let mut contract_node = NodeIdMap::new();
    for (node_id, kind, iid) in rows {
        let Some(iid) = iid else { continue };
        if iid.is_empty() {
            continue;
        }
        let h = hexid(&iid);
        match kind {
            KIND_FN => {
                fn_node.insert(h, node_id);
            }
            KIND_CONTRACT => {
                contract_node.insert(h, node_id);
            }
            _ => {}
        }
    }
    Ok((fn_node, contract_node))
}

/// Delete-and-reinsert this run's repos' edges (edges have no unique key):
/// rel 0 caller fn -> callee fn, rel 3 caller fn -> contract node, rel 2
/// contract node -> handler fn.
async fn refresh_edges(
    tx: &mut Transaction<'_, Postgres>,
    prog: &Program,
    repo_ids: &HashMap<String, i32>,
    analyzed_rids: &[i32],
    fn_node: &NodeIdMap,
    contract_node: &NodeIdMap,
) -> Result<usize> {
    sqlx::query("DELETE FROM edges WHERE repo_id = ANY($1)")
        .bind(analyzed_rids)
        .execute(&mut **tx)
        .await?;

    struct EdgeRow {
        from: i64,
        to: i64,
        rel: i16,
        repo_id: i32,
        meta: serde_json::Value,
    }
    let mut out: Vec<EdgeRow> = Vec::new();
    let mut seen: HashSet<(i64, i64, i16)> = HashSet::new();

    for (iid, f) in &prog.funcs {
        let Some(&from) = fn_node.get(iid) else { continue };
        let repo = prog.repo_of.get(iid).cloned().unwrap_or_default();
        let rid = *repo_ids.get(&repo).unwrap_or(&0);
        let Some(flow) = &f.flow else { continue };
        for cs in &flow.callsites {
            if is_remote(cs) {
                for cid in &cs.callee_iids {
                    let Some(&to) = contract_node.get(&hexid(cid)) else { continue };
                    if !seen.insert((from, to, REL_INVOKES_REMOTE)) {
                        continue;
                    }
                    let span = cs
                        .span
                        .as_ref()
                        .map(|s| format!("{}:{}", s.file, s.line))
                        .unwrap_or_default();
                    out.push(EdgeRow {
                        from,
                        to,
                        rel: REL_INVOKES_REMOTE,
                        repo_id: rid,
                        meta: json!({
                            "callee_fqn": cs.callee_fqn,
                            "span": span,
                            "stream_op": cs.stream_op,
                        }),
                    });
                }
            } else {
                for cid in &cs.callee_iids {
                    let Some(&to) = fn_node.get(&hexid(cid)) else { continue };
                    if !seen.insert((from, to, REL_CALLS)) {
                        continue;
                    }
                    out.push(EdgeRow {
                        from,
                        to,
                        rel: REL_CALLS,
                        repo_id: rid,
                        meta: json!({ "callee_fqn": cs.callee_fqn }),
                    });
                }
            }
        }
    }

    // contract -> handler (SQL traversal continues into the defining repo)
    for p in &prog.packages {
        let rid = *repo_ids.get(&p.repo).unwrap_or(&0);
        for c in crate::graph::pkg_contracts(p) {
            let (Some(&from), Some(&to)) = (
                contract_node.get(&hexid(c.iid)),
                fn_node.get(&hexid(c.handler_iid)),
            ) else {
                continue;
            };
            if !seen.insert((from, to, REL_BINDS_TO)) {
                continue;
            }
            out.push(EdgeRow {
                from,
                to,
                rel: REL_BINDS_TO,
                repo_id: rid,
                meta: json!({ "full_name": c.full_name }),
            });
        }
    }

    if out.is_empty() {
        return Ok(0);
    }
    let mut from = Vec::with_capacity(out.len());
    let mut to = Vec::with_capacity(out.len());
    let mut rel = Vec::with_capacity(out.len());
    let mut dir = Vec::with_capacity(out.len());
    let mut rid = Vec::with_capacity(out.len());
    let mut meta = Vec::with_capacity(out.len());
    for e in &out {
        from.push(e.from);
        to.push(e.to);
        rel.push(e.rel);
        dir.push(true);
        rid.push(e.repo_id);
        meta.push(e.meta.clone());
    }
    sqlx::query(
        "INSERT INTO edges(from_id, to_id, rel_type, direction, repo_id, meta)
         SELECT * FROM UNNEST($1::int8[], $2::int8[], $3::int2[], $4::bool[], $5::int4[], $6::jsonb[])",
    )
    .bind(&from)
    .bind(&to)
    .bind(&rel)
    .bind(&dir)
    .bind(&rid)
    .bind(&meta)
    .execute(&mut **tx)
    .await?;
    Ok(out.len())
}

/// Reverse index: one row per distinct (contract iid, caller fn, span). Keyed
/// by raw iid bytes, so it records calls to contracts we can't resolve yet.
async fn refresh_invokes(tx: &mut Transaction<'_, Postgres>, prog: &Program) -> Result<usize> {
    let caller_repos: Vec<String> = {
        let mut v: Vec<String> = prog.packages.iter().map(|p| p.repo.clone()).collect();
        v.sort();
        v.dedup();
        v
    };
    sqlx::query("DELETE FROM invokes WHERE caller_repo = ANY($1)")
        .bind(&caller_repos)
        .execute(&mut **tx)
        .await?;

    let mut iid = Vec::new();
    let mut repo = Vec::new();
    let mut caller_fn = Vec::new();
    let mut span_file = Vec::new();
    let mut span_line = Vec::new();
    let mut seen: HashSet<(IidHex, String, String, i32)> = HashSet::new();
    for (fiid, f) in &prog.funcs {
        let r = prog.repo_of.get(fiid).cloned().unwrap_or_default();
        let Some(flow) = &f.flow else { continue };
        for cs in flow.callsites.iter().filter(|cs| is_remote(cs)) {
            let (file, line) = cs
                .span
                .as_ref()
                .map(|s| (s.file.clone(), s.line))
                .unwrap_or_default();
            for cid in &cs.callee_iids {
                let h = hexid(cid);
                if !seen.insert((h, f.fqn.clone(), file.clone(), line)) {
                    continue;
                }
                iid.push(cid.clone());
                repo.push(r.clone());
                caller_fn.push(f.fqn.clone());
                span_file.push(file.clone());
                span_line.push(line);
            }
        }
    }
    if iid.is_empty() {
        return Ok(0);
    }
    sqlx::query(
        "INSERT INTO invokes(iid, caller_repo, caller_fn, span_file, span_line)
         SELECT * FROM UNNEST($1::bytea[], $2::text[], $3::text[], $4::text[], $5::int4[])",
    )
    .bind(&iid)
    .bind(&repo)
    .bind(&caller_fn)
    .bind(&span_file)
    .bind(&span_line)
    .execute(&mut **tx)
    .await?;
    Ok(iid.len())
}

async fn persist_summaries(
    tx: &mut Transaction<'_, Postgres>,
    prog: &Program,
    eng: &Engine<'_>,
) -> Result<()> {
    // content-addressed summaries
    for (iid, sum) in &eng.summaries {
        let f = match prog.funcs.get(iid) {
            Some(f) => f,
            None => continue, // contract-iid alias, skip (published below)
        };
        let bid = f.id.as_ref().map(|i| i.bid.clone()).unwrap_or_default();
        // recorded during run(); fall back for fns the engine skipped (e.g. SCC
        // members have a contract_hash but no cacheable summary_key)
        let ch = eng
            .contract_hashes
            .get(iid)
            .copied()
            .unwrap_or_else(|| contract_hash(sum));
        let sk = eng
            .summary_keys
            .get(iid)
            .copied()
            .unwrap_or_else(|| ids::summary_key(&bid, &f.source_params, vec![ch]));
        let blob = serde_json::to_vec(&project(sum))?;
        let repo = prog.repo_of.get(iid).cloned().unwrap_or_default();
        sqlx::query(
            "INSERT INTO summaries(summary_key, fn_iid, bid, contract_hash, blob, repo)
             VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT (summary_key) DO NOTHING",
        )
        .bind(sk.to_vec())
        .bind(hex::decode(iid).unwrap_or_default())
        .bind(&bid)
        .bind(ch.to_vec())
        .bind(&blob)
        .bind(&repo)
        .execute(&mut **tx)
        .await?;
    }

    // Publish each LOCAL contract's post-fixpoint VIEW (doc 18 B.1):
    // eng.summaries[contract_iid] is the handler summary already remapped into
    // the client frame by compose::publish_view, so a remote reader composes
    // it without needing the streaming flags. Only local grpc_methods are
    // iterated — contracts merely consumed as PG leaves are never re-published
    // (write-back guard, doc 18 B.3).
    for p in &prog.packages {
        for gm in crate::graph::pkg_contracts(p) {
            if gm.handler_iid.is_empty() {
                continue; // consumed-only contract: no local handler, skip
            }
            if let Some(view) = eng.summaries.get(&hexid(gm.iid)) {
                let ch = contract_hash(view);
                let blob = serde_json::to_vec(&project(view))?;
                sqlx::query(
                    "INSERT INTO contract_summaries(contract_iid, contract_hash, blob, repo, commit_sha)
                     VALUES($1,$2,$3,$4,$5) ON CONFLICT (contract_iid) DO UPDATE
                       SET contract_hash=EXCLUDED.contract_hash, blob=EXCLUDED.blob,
                           repo=EXCLUDED.repo, commit_sha=EXCLUDED.commit_sha",
                )
                .bind(&gm.iid)
                .bind(ch.to_vec())
                .bind(&blob)
                .bind(&p.repo)
                .bind(&p.commit_sha)
                .execute(&mut **tx)
                .await?;
            }
        }
    }
    Ok(())
}

/// Load post-fixpoint contract views from PG for the given contract iids
/// (doc 18 B.3). Blocking, like `persist`. Undecodable / non-v2 blobs are
/// skipped with a warning — sound (the callsite stays a default leaf).
pub fn load_contract_views(pg_url: &str, iids: &[Vec<u8>]) -> Result<HashMap<IidHex, Summary>> {
    if iids.is_empty() {
        return Ok(HashMap::new());
    }
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async {
        let pool = PgPoolOptions::new().max_connections(2).connect(pg_url).await?;
        let rows: Vec<(Vec<u8>, Vec<u8>)> = sqlx::query_as(
            "SELECT contract_iid, blob FROM contract_summaries WHERE contract_iid = ANY($1)",
        )
        .bind(iids)
        .fetch_all(&pool)
        .await?;
        let mut out = HashMap::new();
        for (iid, blob) in rows {
            let h = hexid(&iid);
            match serde_json::from_slice::<SummaryJ>(&blob) {
                Ok(j) if j.v == SUMMARYJ_V => {
                    out.insert(h, unproject(&j));
                }
                Ok(j) => eprintln!(
                    "warning: contract_summaries blob for {h} has version {} (want {SUMMARYJ_V}); skipped — re-run analyze on the defining repo",
                    j.v
                ),
                Err(e) => eprintln!(
                    "warning: contract_summaries blob for {h} undecodable ({e}); skipped — re-run analyze on the defining repo"
                ),
            }
        }
        Ok(out)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ifds::Slot;

    #[test]
    fn blob_v2_round_trips_flows_sinks_and_span() {
        let mut s = Summary {
            confidence: 0.5,
            ..Default::default()
        };
        s.flows.insert((Slot::Param(1).into(), Slot::Return(0).into()));
        s.flows.insert((Slot::StreamIn.into(), Slot::StreamOut.into()));
        s.sink_hits.push(SinkHit {
            in_slot: Slot::Param(1).into(),
            class: "sqli".into(),
            callsite: 7,
            span: Some(cgf::Span {
                file: "store/store.go".into(),
                line: 12,
                col: 3,
            }),
            via_heap: None,
        });
        let blob = serde_json::to_vec(&project(&s)).unwrap();
        let j: SummaryJ = serde_json::from_slice(&blob).unwrap();
        assert_eq!(j.v, SUMMARYJ_V);
        let back = unproject(&j);
        assert_eq!(back.flows, s.flows);
        assert_eq!(back.sink_hits.len(), 1);
        let h = &back.sink_hits[0];
        assert_eq!(h.in_slot, Slot::Param(1));
        assert_eq!(h.class, "sqli");
        assert_eq!(h.callsite, 0, "callsite is not persisted");
        assert_eq!(h.span.as_ref().unwrap().file, "store/store.go");
        assert_eq!(h.span.as_ref().unwrap().line, 12);
    }

    #[test]
    fn v1_blob_fails_decode_and_would_be_skipped() {
        // v1 shape: no `v`, tuple sink_hits — must NOT decode as v2
        let v1 = br#"{"flows":[["param_1","return_0"]],"sink_hits":[["param_1","sqli"]],"confidence":1.0}"#;
        assert!(serde_json::from_slice::<SummaryJ>(v1).is_err());
    }

    #[test]
    fn like_escape_makes_metacharacters_literal() {
        assert_eq!(like_escape("do_stuff"), "do\\_stuff");
        assert_eq!(like_escape("100%"), "100\\%");
        assert_eq!(like_escape("a\\b"), "a\\\\b");
        assert_eq!(like_escape("plain"), "plain");
    }

    #[test]
    fn unproject_skips_unparseable_slots() {
        let j = SummaryJ {
            v: SUMMARYJ_V,
            flows: vec![
                ("param_0".into(), "return_0".into()),
                ("future_slot".into(), "return_0".into()),
            ],
            sink_hits: vec![
                SinkHitJ {
                    slot: "future_slot".into(),
                    class: "sqli".into(),
                    span_file: String::new(),
                    span_line: 0,
                },
                SinkHitJ {
                    slot: "param_0".into(),
                    class: "sqli".into(),
                    span_file: String::new(),
                    span_line: 0,
                },
            ],
            confidence: 1.0,
        };
        let s = unproject(&j);
        assert_eq!(s.flows.len(), 1);
        assert_eq!(s.sink_hits.len(), 1);
        assert!(s.sink_hits[0].span.is_none());
    }
}

// Projections over the recursive `up(node_id)` walk: every repo touched, and
// every boundary contract node reached (kind=2, joined to the registry).
const PROJ_REPOS: &str = "
    SELECT DISTINCT r.repo FROM up
    JOIN nodes n USING (node_id)
    JOIN repos r ON r.repo_id = n.repo_id
    ORDER BY 1";
const PROJ_ENDPOINTS: &str = "
    SELECT DISTINCT c.full_name FROM up
    JOIN nodes n USING (node_id)
    JOIN contracts c ON c.iid = n.iid
    WHERE n.kind = 2
    ORDER BY 1";

/// Escape `\`, `%`, `_` so a user substring matches literally under LIKE
/// (PG default ESCAPE is backslash). Go identifiers routinely contain `_`.
fn like_escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('%', "\\%").replace('_', "\\_")
}

pub struct Blast {
    pub repos: Vec<String>,
    pub endpoints: Vec<String>,
    /// repos.commit_sha for the seed repo; None when the repo isn't in PG.
    pub graph_commit_sha: Option<String>,
}

/// Part-A blast radius from PG (doc 18 Part C): seed fn nodes of `repo` whose
/// span_file ends with one of `files` (span_file is absolute, git diff names
/// are repo-relative — suffix match; the `_` LIKE wildcard in file names is
/// pre-existing behavior, kept for parity), then walk edges BACKWARDS over
/// rel 0 (calls) / 2 (binds_to: contract→handler) / 3 (invokes_remote:
/// caller→contract) to a fixpoint.
pub fn pg_blast(pg_url: &str, repo: &str, files: &[String]) -> Result<Blast> {
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async {
        let pool = PgPoolOptions::new().max_connections(2).connect(pg_url).await?;
        let sha: Option<(String,)> =
            sqlx::query_as("SELECT commit_sha FROM repos WHERE repo = $1")
                .bind(repo)
                .fetch_optional(&pool)
                .await?;
        let graph_commit_sha = sha.map(|r| r.0);
        if files.is_empty() {
            return Ok(Blast {
                repos: Vec::new(),
                endpoints: Vec::new(),
                graph_commit_sha,
            });
        }
        const CTE: &str = "
            WITH RECURSIVE up(node_id) AS (
              SELECT n.node_id FROM nodes n
              JOIN repos r ON r.repo_id = n.repo_id
              WHERE r.repo = $1 AND n.kind = 0
                AND EXISTS (SELECT 1 FROM unnest($2::text[]) f
                            WHERE n.span_file = f OR n.span_file LIKE '%/' || f)
              UNION
              SELECT e.from_id FROM edges e JOIN up ON e.to_id = up.node_id
              WHERE e.rel_type IN (0, 2, 3)
            )";
        let repos: Vec<(String,)> = sqlx::query_as(&format!("{CTE}{PROJ_REPOS}"))
            .bind(repo)
            .bind(files)
            .fetch_all(&pool)
            .await?;
        let endpoints: Vec<(String,)> = sqlx::query_as(&format!("{CTE}{PROJ_ENDPOINTS}"))
            .bind(repo)
            .bind(files)
            .fetch_all(&pool)
            .await?;
        Ok(Blast {
            repos: repos.into_iter().map(|r| r.0).collect(),
            endpoints: endpoints.into_iter().map(|r| r.0).collect(),
            graph_commit_sha,
        })
    })
}

/// Returns (upstream repos, boundary endpoint full_names) — see `pg_blast`.
pub fn pg_upstream(
    pg_url: &str,
    repo: &str,
    files: &[String],
) -> Result<(Vec<String>, Vec<String>)> {
    let b = pg_blast(pg_url, repo, files)?;
    Ok((b.repos, b.endpoints))
}

pub struct FnRef {
    pub fqn: String,
    pub repo: String,
    pub span_file: Option<String>,
    pub span_line: Option<i32>,
}

pub struct Reach {
    /// Seed fns the substring matched — makes ambiguity visible to callers.
    pub matches: Vec<FnRef>,
    pub repos: Vec<String>,
    pub endpoints: Vec<String>,
}

/// Same backward walk as `pg_blast`, seeded by fqn substring over fn nodes
/// (optionally repo-filtered) instead of changed files.
pub fn pg_reach(pg_url: &str, fn_substr: &str, repo: Option<&str>) -> Result<Reach> {
    let pat = format!("%{}%", like_escape(fn_substr));
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async {
        let pool = PgPoolOptions::new().max_connections(2).connect(pg_url).await?;
        let seeds: Vec<(String, String, Option<String>, Option<i32>)> = sqlx::query_as(
            "SELECT n.fqn, r.repo, n.span_file, n.span_line
             FROM nodes n JOIN repos r ON r.repo_id = n.repo_id
             WHERE n.kind = 0 AND n.fqn LIKE $1
               AND ($2::text IS NULL OR r.repo = $2)
             ORDER BY r.repo, n.fqn",
        )
        .bind(&pat)
        .bind(repo)
        .fetch_all(&pool)
        .await?;
        let matches: Vec<FnRef> = seeds
            .into_iter()
            .map(|(fqn, repo, span_file, span_line)| FnRef {
                fqn,
                repo,
                span_file,
                span_line,
            })
            .collect();
        if matches.is_empty() {
            return Ok(Reach {
                matches,
                repos: Vec::new(),
                endpoints: Vec::new(),
            });
        }
        const CTE: &str = "
            WITH RECURSIVE up(node_id) AS (
              SELECT n.node_id FROM nodes n
              JOIN repos r ON r.repo_id = n.repo_id
              WHERE n.kind = 0 AND n.fqn LIKE $1
                AND ($2::text IS NULL OR r.repo = $2)
              UNION
              SELECT e.from_id FROM edges e JOIN up ON e.to_id = up.node_id
              WHERE e.rel_type IN (0, 2, 3)
            )";
        let repos: Vec<(String,)> = sqlx::query_as(&format!("{CTE}{PROJ_REPOS}"))
            .bind(&pat)
            .bind(repo)
            .fetch_all(&pool)
            .await?;
        let endpoints: Vec<(String,)> = sqlx::query_as(&format!("{CTE}{PROJ_ENDPOINTS}"))
            .bind(&pat)
            .bind(repo)
            .fetch_all(&pool)
            .await?;
        Ok(Reach {
            matches,
            repos: repos.into_iter().map(|r| r.0).collect(),
            endpoints: endpoints.into_iter().map(|r| r.0).collect(),
        })
    })
}

pub struct PathHop {
    pub fqn: String,
    pub repo: String,
    /// nodes.kind: 0 fn, 2 grpc contract
    pub kind: i16,
    pub span_file: Option<String>,
    pub span_line: Option<i32>,
}

/// Enumerate concrete FORWARD call paths (calls / binds_to / invokes_remote,
/// following edge direction: caller→callee, contract→handler, caller→contract)
/// from nodes matching `from` to nodes matching `to`, shortest first.
/// Seeds include contract nodes (kind=2, fqn = contract full_name) so a
/// `reach`-discovered endpoint composes directly into a path query.
/// Bails when either substring matches no node; no route is Ok(vec![]).
pub fn pg_paths(
    pg_url: &str,
    from: &str,
    to: &str,
    limit: i64,
    max_depth: i32,
) -> Result<Vec<Vec<PathHop>>> {
    let from_pat = format!("%{}%", like_escape(from));
    let to_pat = format!("%{}%", like_escape(to));
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async {
        let pool = PgPoolOptions::new().max_connections(2).connect(pg_url).await?;
        for (pat, flag) in [(&from_pat, "--from"), (&to_pat, "--to")] {
            let n: (i64,) = sqlx::query_as(
                "SELECT count(*) FROM nodes WHERE kind IN (0, 2) AND fqn LIKE $1",
            )
            .bind(pat)
            .fetch_one(&pool)
            .await?;
            if n.0 == 0 {
                anyhow::bail!("{flag} matched no fn/contract nodes");
            }
        }
        // All simple paths up to $3 hops; cycle guard bounds the recursion,
        // the NOT EXISTS stops expansion once a target is reached (paths
        // never pass THROUGH one match to another). ORDER BY materializes
        // the full set before LIMIT — depth is the real cost bound.
        let paths: Vec<(Vec<i64>,)> = sqlx::query_as(
            "WITH RECURSIVE walk(node_id, path) AS (
               SELECT n.node_id, ARRAY[n.node_id]
               FROM nodes n
               WHERE n.kind IN (0, 2) AND n.fqn LIKE $1
               UNION ALL
               SELECT e.to_id, w.path || e.to_id
               FROM walk w
               JOIN edges e ON e.from_id = w.node_id
               WHERE e.rel_type IN (0, 2, 3)
                 AND NOT e.to_id = ANY(w.path)
                 AND array_length(w.path, 1) < $3
                 AND NOT EXISTS (SELECT 1 FROM nodes s
                                 WHERE s.node_id = w.node_id AND s.fqn LIKE $2)
             )
             SELECT w.path FROM walk w
             JOIN nodes t ON t.node_id = w.node_id
             WHERE t.fqn LIKE $2
             ORDER BY array_length(w.path, 1), w.path
             LIMIT $4",
        )
        .bind(&from_pat)
        .bind(&to_pat)
        .bind(max_depth)
        .bind(limit)
        .fetch_all(&pool)
        .await?;
        let mut ids: Vec<i64> = paths.iter().flat_map(|(p,)| p.iter().copied()).collect();
        ids.sort_unstable();
        ids.dedup();
        let rows: Vec<(i64, String, String, i16, Option<String>, Option<i32>)> = sqlx::query_as(
            "SELECT n.node_id, n.fqn, r.repo, n.kind, n.span_file, n.span_line
             FROM nodes n JOIN repos r ON r.repo_id = n.repo_id
             WHERE n.node_id = ANY($1)",
        )
        .bind(&ids)
        .fetch_all(&pool)
        .await?;
        let by_id: HashMap<i64, (String, String, i16, Option<String>, Option<i32>)> = rows
            .into_iter()
            .map(|(id, fqn, repo, kind, sf, sl)| (id, (fqn, repo, kind, sf, sl)))
            .collect();
        Ok(paths
            .into_iter()
            .map(|(p,)| {
                p.into_iter()
                    .filter_map(|id| by_id.get(&id))
                    .map(|(fqn, repo, kind, sf, sl)| PathHop {
                        fqn: fqn.clone(),
                        repo: repo.clone(),
                        kind: *kind,
                        span_file: sf.clone(),
                        span_line: *sl,
                    })
                    .collect()
            })
            .collect())
    })
}
