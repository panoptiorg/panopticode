// MR impact mode (MVP-5, doc 08 §1 shape trimmed to boolean-taint MVP):
// re-extract the MR repo at head (pc-fe --mode mr), reuse cached summaries for
// unchanged functions via the summary store, re-tabulate the rest, and report
// the chains the MR touches. Deferred: pii_categories, reachable_endpoints.
use crate::catalog::Catalog;
use crate::graph::Program;
use crate::ids;
use crate::ifds::{Engine, RunStats};
use crate::report::{self, Chain};
use crate::summarystore::SummaryStore;
use crate::compose;
use crate::normalize::normalize_loaded;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::path::{Path, PathBuf};
use std::process::Command;

/// Go marshals a **nil slice as `null`**, and serde's `default` only fires for
/// an ABSENT field — so a manifest with no changed files aborted the entire run
/// with `invalid type: null, expected a sequence`. That is not a corner case:
/// an MR touching only out-of-scope paths (docs, generated `pb/`, mocks) yields
/// exactly this manifest, and those are common in practice.
fn null_as_empty<'de, D, T>(d: D) -> Result<Vec<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Ok(Option::<Vec<T>>::deserialize(d)?.unwrap_or_default())
}

/// pc-fe's manifest.json (`internal/emit/manifest.go` in panoptife-go).
#[derive(Deserialize)]
pub struct Manifest {
    pub base: String,
    pub head: String,
    #[serde(default, deserialize_with = "null_as_empty")]
    pub changed_files: Vec<String>,
    #[serde(default, deserialize_with = "null_as_empty")]
    pub changed_fns: Vec<ChangedFn>,
}

#[derive(Deserialize, Serialize, Clone)]
pub struct ChangedFn {
    pub iid: String,
    pub bid: String,
    pub fqn: String,
    pub file: String,
}

#[derive(Serialize)]
pub struct BlastRadius {
    pub repos: Vec<String>,
    /// remote contract names on crossed-boundary hops of impacted chains,
    /// plus (with --pg) boundary contracts on the upstream PG walk
    pub endpoints: Vec<String>,
    /// repo -> "chains" | "pg_upstream" | "both" (populated only with --pg)
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub provenance: BTreeMap<String, String>,
}

#[derive(Serialize)]
pub struct CacheStats {
    pub hits: usize,
    pub misses: usize,
    pub scc_recomputed: usize,
    pub reuse_pct: f32,
}

#[derive(Serialize)]
pub struct ImpactReport {
    pub repo: String,
    pub base: String,
    pub head: String,
    pub changed_functions: Vec<ChangedFn>,
    pub taint_chains: Vec<Chain>,
    pub blast_radius: BlastRadius,
    pub cache: CacheStats,
}

pub fn catalog_file_hash(path: &Path) -> Result<ids::Hash> {
    let bytes = std::fs::read(path).with_context(|| format!("read catalog {path:?}"))?;
    Ok(ids::hash_parts(&[&bytes]))
}

fn run_frontend(
    fe: &str,
    repo: &str,
    scope: Option<&str>,
    base: &str,
    head: &str,
    out: &Path,
) -> Result<()> {
    let mut cmd = Command::new(fe);
    cmd.arg("build")
        .arg(repo)
        .arg("--out")
        .arg(out)
        .arg("--mode")
        .arg("mr")
        .arg("--base")
        .arg(base)
        .arg("--head")
        .arg(head);
    if let Some(s) = scope {
        cmd.arg("--scope").arg(s);
    }
    // our stdout is the ImpactReport JSON — route pc-fe's stdout to stderr
    let out = cmd.output().with_context(|| format!("run {fe}"))?;
    eprint!("{}", String::from_utf8_lossy(&out.stderr));
    eprint!("{}", String::from_utf8_lossy(&out.stdout));
    if !out.status.success() {
        anyhow::bail!("pc-fe exited with {}", out.status);
    }
    Ok(())
}

fn read_manifest(out: &Path) -> Result<Manifest> {
    let path = out.join("manifest.json");
    let bytes = std::fs::read(&path).with_context(|| format!("read manifest {path:?}"))?;
    serde_json::from_slice(&bytes).with_context(|| format!("parse manifest {path:?}"))
}

#[allow(clippy::too_many_arguments)]
pub fn impact(
    repo: &str,
    scope: Option<&str>,
    base: &str,
    head: &str,
    other_cgf: &[PathBuf],
    catalog: &PathBuf,
    store_dir: &Path,
    out: Option<&Path>,
    fe: &str,
    pg: Option<&str>,
) -> Result<()> {
    let tmp_out;
    let head_cgf = match out {
        Some(o) => o,
        None => {
            tmp_out = std::env::temp_dir().join(format!(
                "pc-impact-{}",
                Path::new(repo)
                    .file_name()
                    .and_then(|s| s.to_str())
                    .unwrap_or("repo")
            ));
            &tmp_out
        }
    };
    run_frontend(fe, repo, scope, base, head, head_cgf)?;

    let manifest = read_manifest(head_cgf)?;
    let cat = Catalog::load(catalog).with_context(|| format!("load catalog {catalog:?}"))?;
    let mut dirs = vec![head_cgf.to_path_buf()];
    dirs.extend(other_cgf.iter().cloned());
    let mut prog = Program {
        funcs: Default::default(),
        repo_of: Default::default(),
        packages: Default::default(),
    };
    // canonical repo id of the MR repo = the head extraction's package repo
    // (module path), needed for the PG upstream walk
    let mut head_repo = String::new();
    for (i, dir) in dirs.iter().enumerate() {
        let p = Program::load_dir(dir)?;
        if i == 0 {
            head_repo = p
                .packages
                .first()
                .map(|pkg| pkg.repo.clone())
                .unwrap_or_default();
        }
        prog.funcs.extend(p.funcs);
        prog.repo_of.extend(p.repo_of);
        prog.packages.extend(p.packages);
    }
    normalize_loaded(&mut prog);
    // coverage wave 1 §4.3 — as in `taint`: after normalize, before phase 1
    crate::httplink::link_loaded(&mut prog, true);

    let cat_hash = catalog_file_hash(catalog)?;
    let mut store = SummaryStore::open(Some(store_dir), &cat_hash, 1_000_000)?;
    let mut eng = Engine::new(&prog, &cat);
    let stats = eng.run_with_store(&mut store);
    // PG leaves for contracts no loaded CGF defines (doc 18 Part C) — explicit
    // --cgf dirs win automatically (their contracts are local to the run).
    let leaves = match pg {
        Some(url) => {
            let missing = crate::storage::missing_remote_contracts(&prog);
            crate::storage::load_contract_views(url, &missing)?
        }
        None => Default::default(),
    };
    let fx = compose::fixpoint_with_leaves(&mut eng, leaves);

    let mut report = build_report(&prog, &eng, stats, &manifest, repo);
    if let Some(url) = pg {
        merge_pg_blast_radius(&mut report.blast_radius, url, &head_repo, &manifest)?;
    }
    println!("{}", serde_json::to_string_pretty(&report)?);
    eprintln!(
        "functions={} cache_hits={} cache_misses={} scc_recomputed={} contracts_linked={} remote_leaves={} impacted_chains={}",
        prog.funcs.len(),
        stats.hits,
        stats.misses,
        stats.scc_recomputed,
        fx.linked,
        fx.remote_leaves,
        report.taint_chains.len()
    );
    Ok(())
}

/// Merge the PG upstream walk (doc 18 Part A CTE, seeded from the manifest's
/// changed files) into the chain-derived blast radius, tagging provenance.
fn merge_pg_blast_radius(
    br: &mut BlastRadius,
    pg_url: &str,
    head_repo: &str,
    manifest: &Manifest,
) -> Result<()> {
    let (pg_repos, pg_endpoints) =
        crate::storage::pg_upstream(pg_url, head_repo, &manifest.changed_files)?;
    for r in &br.repos {
        br.provenance.insert(r.clone(), "chains".into());
    }
    for r in pg_repos {
        br.provenance
            .entry(r.clone())
            .and_modify(|v| *v = "both".into())
            .or_insert_with(|| "pg_upstream".into());
        if !br.repos.contains(&r) {
            br.repos.push(r);
        }
    }
    br.repos.sort();
    for e in pg_endpoints {
        if !br.endpoints.contains(&e) {
            br.endpoints.push(e);
        }
    }
    br.endpoints.sort();
    Ok(())
}

/// A chain is impacted when it passes through a changed function (manifest) or
/// any function the engine had to re-tabulate this run (changed OR behavior-
/// downstream of a change — by construction of summary_key invalidation).
/// Cross-repo chains report hops only inside the SOURCE function, so a chain is
/// also impacted when a crossed-boundary hop targets a contract whose HANDLER
/// was recomputed (the caller side itself cache-hits — the contract iid is not
/// among its callees' contract_hashes).
/// Cold store ⇒ everything recomputed ⇒ every chain reported; warm the store
/// with a baseline `taint --store` run first.
pub fn build_report(
    prog: &Program,
    eng: &Engine<'_>,
    stats: RunStats,
    manifest: &Manifest,
    repo: &str,
) -> ImpactReport {
    let changed_fqns: HashSet<&str> = manifest.changed_fns.iter().map(|c| c.fqn.as_str()).collect();
    let recomputed_fqns: HashSet<&str> = eng
        .recomputed
        .iter()
        .filter_map(|iid| prog.funcs.get(iid).map(|f| f.fqn.as_str()))
        .collect();
    let touches = |fqn: &str| changed_fqns.contains(fqn) || recomputed_fqns.contains(fqn);

    // contract full_name -> was its handler re-tabulated this run? Covers
    // GraphQL fields too (doc 36 §3.3): their handler is the resolver and
    // their full_name is the SDL type_field, which is what a boundary hop's
    // `detail` carries.
    let mut handler_recomputed: HashSet<String> = HashSet::new();
    for p in &prog.packages {
        for c in crate::graph::pkg_contracts(p) {
            if eng.recomputed.contains(&crate::graph::hexid(c.handler_iid)) {
                handler_recomputed.insert(c.full_name.into_owned());
            }
        }
    }
    // Coverage wave 1 §4.3: a linked HTTP client's boundary hop carries the
    // CLIENT's template (its `callee_fqn`), which need not be the route's name
    // (a suffix match, an unknown method). Map it through the link instead.
    let recomputed_keys: HashSet<String> = crate::graph::contracts(prog)
        .into_iter()
        .filter(|c| c.http.is_some() && eng.recomputed.contains(&c.handler))
        .map(|c| c.key)
        .collect();
    if !recomputed_keys.is_empty() {
        for f in prog.funcs.values() {
            let Some(flow) = &f.flow else { continue };
            for cs in &flow.callsites {
                if cs.http_call.is_some()
                    && cs.callee_iids.iter().any(|k| recomputed_keys.contains(&crate::graph::hexid(k)))
                {
                    handler_recomputed.insert(cs.callee_fqn.clone());
                }
            }
        }
    }

    let all_chains = report::intra_chains(eng, None);
    let taint_chains: Vec<Chain> = all_chains
        .into_iter()
        .filter(|c| {
            touches(&c.source_fn)
                || c.hops.iter().any(|h| {
                    touches(&h.func)
                        || (h.crossed_service_boundary
                            && handler_recomputed.contains(&h.detail))
                })
        })
        .collect();

    let mut repos: BTreeSet<String> = BTreeSet::new();
    let mut endpoints: BTreeSet<String> = BTreeSet::new();
    for c in &taint_chains {
        repos.insert(c.source_repo.clone());
        for h in &c.hops {
            repos.insert(h.repo.clone());
            if h.crossed_service_boundary {
                endpoints.insert(h.detail.clone());
            }
        }
    }

    let total = stats.hits + stats.misses + stats.scc_recomputed;
    ImpactReport {
        repo: repo.to_string(),
        base: manifest.base.clone(),
        head: manifest.head.clone(),
        changed_functions: manifest.changed_fns.clone(),
        taint_chains,
        blast_radius: BlastRadius {
            repos: repos.into_iter().collect(),
            endpoints: endpoints.into_iter().collect(),
            provenance: BTreeMap::new(),
        },
        cache: CacheStats {
            hits: stats.hits,
            misses: stats.misses,
            scc_recomputed: stats.scc_recomputed,
            reuse_pct: if total > 0 {
                stats.hits as f32 / total as f32 * 100.0
            } else {
                0.0
            },
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A manifest for an MR that changed nothing in scope. pc-fe writes Go nil
    /// slices as `null`; this used to abort `impact` outright.
    #[test]
    fn manifest_accepts_null_slices() {
        let m: Manifest = serde_json::from_str(
            r#"{"mode":"mr","base":"a","head":"b","changed_files":null,"changed_fns":null}"#,
        )
        .expect("null slices must parse");
        assert!(m.changed_files.is_empty() && m.changed_fns.is_empty());
    }

    #[test]
    fn manifest_accepts_absent_and_present_slices() {
        let m: Manifest = serde_json::from_str(r#"{"base":"a","head":"b"}"#).unwrap();
        assert!(m.changed_files.is_empty());
        let m: Manifest =
            serde_json::from_str(r#"{"base":"a","head":"b","changed_files":["x.go"]}"#).unwrap();
        assert_eq!(m.changed_files, vec!["x.go"]);
    }
}
