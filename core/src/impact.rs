// MR impact mode (MVP-5, doc 08 §1 shape trimmed to boolean-taint MVP):
// re-extract the MR repo at head (pc-fe --mode mr), reuse cached summaries for
// unchanged functions via the summary store, re-tabulate the rest, and report
// the chains the MR touches. Deferred: pii_categories, reachable_endpoints.
use crate::catalog::Catalog;
use crate::compose;
use crate::graph::Program;
use crate::ifds::{Engine, RunStats};
use crate::normalize::normalize_loaded;
use crate::report::{self, Chain};
use crate::summarystore::SummaryStore;
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

fn run_frontend(
    fe: &str,
    repo: &str,
    scope: Option<&str>,
    base: &str,
    head: &str,
    out: &Path,
    fe_args: &[String],
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
    // caller-supplied frontend arguments, after the built-in ones, in order
    cmd.args(fe_args);
    // our stdout is the ImpactReport JSON — route pc-fe's stdout to stderr
    let out = cmd.output().map_err(|e| crate::cli::fe_err(fe, e))?;
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
    catalog: Option<&Path>,
    store_dir: &Path,
    out: Option<&Path>,
    fe: &str,
    fe_args: &[String],
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
    run_frontend(fe, repo, scope, base, head, head_cgf, fe_args)?;

    let manifest = read_manifest(head_cgf)?;
    let (cat, cat_hash) = Catalog::open(catalog)?;
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
/// Matching is by function identity — the changed manifest iid, the recomputed
/// iid, and for hops the (repo, fqn) pair — never by fqn alone: sibling repos
/// built from one template share fqn paths, and a name match would report
/// their chains for an MR that does not touch them.
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
    // Match changed and recomputed functions by IDENTITY, not by name. A
    // TypeScript fqn is a path inside its repo ("src/api/items.ts:getItems"),
    // and repositories made from one template share these paths — so an MR in
    // repo A must not report the chains of repo B that merely share a path.
    // The manifest records the iid of each changed function (same head
    // extraction as this run), and `recomputed` already holds iids. Hops carry
    // no iid, only (repo, fqn) — so the touched iids resolve to (repo, fqn)
    // pairs in THIS program. For Go the fqn holds the module path and was
    // already unique; the iid match changes nothing there.
    let changed_iids: HashSet<&str> = manifest
        .changed_fns
        .iter()
        .map(|c| c.iid.as_str())
        .collect();
    let touched_hops: HashSet<(&str, &str)> = changed_iids
        .iter()
        .copied()
        .chain(eng.recomputed.iter().map(|iid| iid.as_str()))
        .filter_map(|iid| {
            prog.funcs.get(iid).map(|f| {
                let repo = prog.repo_of.get(iid).map(|s| s.as_str()).unwrap_or("");
                (repo, f.fqn.as_str())
            })
        })
        .collect();
    let touches = |repo: &str, fqn: &str| touched_hops.contains(&(repo, fqn));

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
                    && cs
                        .callee_iids
                        .iter()
                        .any(|k| recomputed_keys.contains(&crate::graph::hexid(k)))
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
            changed_iids.contains(c.source_iid.as_str())
                || eng.recomputed.contains(&c.source_iid)
                || c.hops.iter().any(|h| {
                    touches(&h.repo, &h.func)
                        || (h.crossed_service_boundary && handler_recomputed.contains(&h.detail))
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
    use crate::graph::hexid;
    use crate::ifds::cache_tests::{edge, vertex};
    use crate::proto::cgf;

    /// A TS fqn is a path inside the repo; two repos built from one template
    /// both have this function.
    const TS_FQN: &str = "src/api/items.ts:getItems";
    const REPO_A: &str = "example.com/a";
    const REPO_B: &str = "example.com/b";
    const IID_A: u8 = 0xA1;
    const IID_B: u8 = 0xB2;

    const CAT: &str = r#"
[[sources]]
kind = "http_bind"
selector = "(*github.com/gin-gonic/gin.Context).ShouldBindJSON"
to = "1"
[[sinks]]
class = "sqli"
selector = "db.Exec"
arg = "any"
"#;

    /// `create(c) { err := c.ShouldBindJSON(&req); db.Exec(req) }` — one
    /// source→sink chain per function.
    fn handler(iid: u8, fqn: &str) -> cgf::Function {
        cgf::Function {
            id: Some(cgf::Ident {
                iid: vec![iid; 32],
                bid: vec![iid; 32],
            }),
            fqn: fqn.into(),
            has_body: true,
            flow: Some(cgf::LocalFlow {
                vertices: vec![
                    vertex(1, cgf::VertexKind::InParam, 0, 0),
                    vertex(2, cgf::VertexKind::CallArgPort, 0, 0),
                    vertex(3, cgf::VertexKind::CallArgPort, 1, 0),
                    vertex(4, cgf::VertexKind::CallResultPort, 0, 0),
                    vertex(5, cgf::VertexKind::CallArgPort, 0, 1),
                ],
                edges: vec![edge(1, 2), edge(3, 5)],
                callsites: vec![
                    cgf::CallSite {
                        id: 0,
                        callee_fqn: "(*github.com/gin-gonic/gin.Context).ShouldBindJSON".into(),
                        argc: 2,
                        resultc: 1,
                        arg0_is_receiver: true,
                        ..Default::default()
                    },
                    cgf::CallSite {
                        id: 1,
                        callee_fqn: "db.Exec".into(),
                        argc: 1,
                        resultc: 0,
                        ..Default::default()
                    },
                ],
            }),
            ..Default::default()
        }
    }

    /// Two repos, one function path in each.
    fn two_repo_prog() -> Program {
        let mut prog = Program {
            funcs: Default::default(),
            repo_of: Default::default(),
            packages: Default::default(),
        };
        for (repo, iid) in [(REPO_A, IID_A), (REPO_B, IID_B)] {
            let f = handler(iid, TS_FQN);
            let h = hexid(&f.id.as_ref().unwrap().iid);
            prog.repo_of.insert(h.clone(), repo.into());
            prog.funcs.insert(h, f);
        }
        prog
    }

    /// An MR that changes `TS_FQN` in one repo must report that repo's chain
    /// only. Before, matching went by fqn alone, so the sibling repo's chain
    /// with the same path was reported too.
    #[test]
    fn an_mr_in_one_repo_does_not_report_sibling_repos_with_the_same_fqn() {
        let prog = two_repo_prog();
        let cat = Catalog::load_str(CAT).unwrap();

        for (repo, iid) in [(REPO_A, IID_A), (REPO_B, IID_B)] {
            let manifest = Manifest {
                base: "aaaaaaaa".into(),
                head: "bbbbbbbb".into(),
                changed_files: vec!["src/api/items.ts".into()],
                changed_fns: vec![ChangedFn {
                    iid: hexid(&[iid; 32]),
                    bid: "0000".into(),
                    fqn: TS_FQN.into(),
                    file: "src/api/items.ts".into(),
                }],
            };
            // warm-store shape: only the changed function was re-tabulated.
            // The test pins the matching in build_report, not the cache logic.
            let mut eng = Engine::new(&prog, &cat);
            eng.run();
            eng.recomputed = [hexid(&[iid; 32])].into_iter().collect();

            let report = build_report(&prog, &eng, RunStats::default(), &manifest, repo);
            let repos: HashSet<&str> = report
                .taint_chains
                .iter()
                .map(|c| c.source_repo.as_str())
                .collect();
            assert_eq!(repos, [repo].into_iter().collect());
        }
    }

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
