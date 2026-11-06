// Code graph: load CGF packages (prost), index functions by iid, expose the
// call graph + a reverse-topological SCC order for bottom-up summary building.
use crate::compose::ContractShape;
use crate::proto::cgf;
use anyhow::{Context, Result};
use prost::Message;
use rayon::prelude::*;
use std::borrow::Cow;
use std::collections::HashMap;
use std::path::Path;

pub type IidHex = String;

pub fn hexid(b: &[u8]) -> IidHex {
    hex::encode(b)
}

pub struct Program {
    /// iid(hex) -> function fact
    pub funcs: HashMap<IidHex, cgf::Function>,
    /// iid(hex) -> owning repo
    pub repo_of: HashMap<IidHex, String>,
    /// all loaded packages (for contracts/endpoints)
    pub packages: Vec<cgf::CgfPackage>,
}

/// One cross-repo contract a package DEFINES: a gRPC method, (doc 36 §3.2) a
/// GraphQL field, or (coverage wave 1 §4.4) an HTTP route. All are keyed by a
/// `ContractIID` a client can recompute from the contract's name alone, and all
/// name a local handler — a gRPC handler, a gqlgen resolver, a route handler —
/// so composition, witness, the backward pass, persistence and impact treat
/// them uniformly. `pkg_contracts` is the ONLY place that knows which package
/// fields hold contracts: the next contract kind is one more block there.
pub struct ContractDef<'a> {
    pub iid: &'a [u8],
    /// gRPC full method name, GraphQL `Type.field`, HTTP `http:<METHOD> <path>`
    pub full_name: Cow<'a, str>,
    pub handler_iid: &'a [u8],
    /// `cgf::endpoint::Kind` as i16: 0 = GRPC, 1 = GRAPHQL, 2 = HTTP.
    pub kind: i16,
    /// gRPC only (the registry columns); empty otherwise.
    pub input_msg: &'a str,
    pub output_msg: &'a str,
    /// how compose remaps the handler's slot frame into the client's
    pub shape: ContractShape,
    /// HTTP only: the route as the frontend reported it
    pub http: Option<&'a cgf::HttpRoute>,
}

pub const CONTRACT_KIND_GRPC: i16 = 0;
pub const CONTRACT_KIND_GRAPHQL: i16 = 1;
pub const CONTRACT_KIND_HTTP: i16 = 2;

/// Every contract `p` defines, gRPC first, then GraphQL, then HTTP (stable order).
pub fn pkg_contracts(p: &cgf::CgfPackage) -> Vec<ContractDef<'_>> {
    let mut out =
        Vec::with_capacity(p.grpc_methods.len() + p.graphql_fields.len() + p.http_routes.len());
    for gm in &p.grpc_methods {
        out.push(ContractDef {
            iid: &gm.iid,
            full_name: Cow::Borrowed(&gm.full_name),
            handler_iid: &gm.handler_iid,
            kind: CONTRACT_KIND_GRPC,
            input_msg: &gm.input_msg,
            output_msg: &gm.output_msg,
            shape: ContractShape::Grpc(gm.client_streaming, gm.server_streaming),
            http: None,
        });
    }
    for gf in &p.graphql_fields {
        out.push(ContractDef {
            iid: &gf.iid,
            full_name: Cow::Borrowed(&gf.type_field),
            handler_iid: &gf.resolver_iid,
            kind: CONTRACT_KIND_GRAPHQL,
            input_msg: "",
            output_msg: "",
            shape: ContractShape::Graphql(gf.args.iter().map(|a| a.param_idx).collect()),
            http: None,
        });
    }
    for r in &p.http_routes {
        out.push(ContractDef {
            iid: &r.iid,
            full_name: Cow::Owned(format!("http:{} {}", r.method, r.path)),
            handler_iid: &r.handler_iid,
            kind: CONTRACT_KIND_HTTP,
            input_msg: "",
            output_msg: "",
            shape: ContractShape::Http { request_params: r.request_params.clone() },
            http: Some(r),
        });
    }
    out
}

/// One contract as the ANALYSIS sees it: the key an INVOKES_REMOTE call site
/// names in `callee_iids`, the handler whose summary compose publishes under
/// that key, and the shape of the remap.
#[derive(Clone, Debug)]
pub struct Contract {
    pub key: IidHex,
    pub handler: IidHex,
    pub shape: ContractShape,
    /// HTTP only: (method, canonical path) the linker matches a client on, and
    /// the crossing as a route hop renders it — `http GET /api/users/{id} (chi)`
    pub http: Option<HttpContract>,
}

#[derive(Clone, Debug)]
pub struct HttpContract {
    pub method: String,
    pub path: String,
    pub label: String,
}

/// Every contract of the loaded program that has a local handler, in package
/// order. Compose, witness, the backward pass and the HTTP linker all read
/// this, so a client site, the published view and the descent agree on keys.
///
/// gRPC and GraphQL contracts are keyed by their iid, exactly as before. An
/// HTTP route's iid is `ContractIID("http:" + method + " " + path)` — it names
/// the ROUTE, not the service — so two loaded services that both serve
/// `GET /health` share it, and one view per key would make whichever handler
/// published last win. Only in that case each handler gets its own key,
/// derived from (iid, handler); the linker then fans a client out over both,
/// which is the honest answer (coverage wave 1 §4.3).
pub fn contracts(prog: &Program) -> Vec<Contract> {
    let defs: Vec<ContractDef<'_>> = prog
        .packages
        .iter()
        .flat_map(pkg_contracts)
        .filter(|c| !c.iid.is_empty() && !c.handler_iid.is_empty())
        .collect();
    // HTTP iid -> its distinct handlers
    let mut http_handlers: HashMap<&[u8], Vec<&[u8]>> = HashMap::new();
    for c in defs.iter().filter(|c| c.kind == CONTRACT_KIND_HTTP) {
        let hs = http_handlers.entry(c.iid).or_default();
        if !hs.contains(&c.handler_iid) {
            hs.push(c.handler_iid);
        }
    }
    let mut seen_http: std::collections::HashSet<(IidHex, IidHex)> = Default::default();
    let mut out = Vec::with_capacity(defs.len());
    for c in defs {
        let handler = hexid(c.handler_iid);
        let Some(r) = c.http else {
            out.push(Contract { key: hexid(c.iid), handler, shape: c.shape, http: None });
            continue;
        };
        let key = if http_handlers[c.iid].len() > 1 {
            crate::ids::hex(&crate::ids::hash_parts(&[b"http-route", c.iid, c.handler_iid]))
        } else {
            hexid(c.iid)
        };
        // the same route reported twice (two muxes, one handler) is one contract
        if !seen_http.insert((key.clone(), handler.clone())) {
            continue;
        }
        let label = format!(
            "http {} {}{}",
            if r.method.is_empty() { "*" } else { r.method.as_str() },
            if r.display.is_empty() { r.path.as_str() } else { r.display.as_str() },
            if r.framework.is_empty() { String::new() } else { format!(" ({})", r.framework) }
        );
        out.push(Contract {
            key,
            handler,
            shape: c.shape,
            http: Some(HttpContract { method: r.method.clone(), path: r.path.clone(), label }),
        });
    }
    out
}

// ---- duplicate-iid accounting (load-time) ----

/// One duplicate definition seen at load, for the `load-duplicates` stderr
/// report. Up to MAX_DUP_EXAMPLES of these are shown per run.
#[derive(serde::Serialize)]
pub struct DupExample {
    pub iid: String,
    pub fqn: String,
    /// repo of the copy the program KEEPS
    pub kept_repo: String,
    /// repo of the copy that was dropped
    pub dropped_repo: String,
    /// true when the two copies are byte-identical (a pure re-embed)
    pub identical: bool,
    /// false = a duplicate function iid, true = a duplicate contract iid
    pub is_contract: bool,
}

/// Counts of duplicate iids seen while loading, plus up to
/// [`MAX_DUP_EXAMPLES`] examples. Emitted as one stderr JSON line after load:
/// a duplicate function iid whose copies DIFFER can lose findings the dropped
/// copy would have given — the line makes that loss visible instead of silent.
#[derive(Default)]
pub struct DupStats {
    /// second-and-later copies of an already-loaded function iid
    pub functions: usize,
    /// copies that DIFFER from the copy already loaded
    pub differing_functions: usize,
    /// second-and-later definitions of an already-seen contract iid
    pub contracts: usize,
    /// differing contract definitions for the same iid
    pub differing_contracts: usize,
    pub examples: Vec<DupExample>,
}

/// Examples are unique per iid and split between the two kinds: at most 5
/// function duplicates and 5 contract duplicates. Identical function
/// duplicates can number in the hundreds (one corpus had 858) and would
/// otherwise crowd out the differing contract definitions — the examples a
/// reader actually needs.
pub const MAX_DUP_EXAMPLES_PER_KIND: usize = 5;

/// The merge rule for two packages that define the same function iid:
/// - byte-identical copies are the same fact — keep either (no loss);
/// - differing copies: prefer the one WITH a body (strictly more information
///   — a body-less copy can only produce default-leaf behaviour); equal
///   bodiedness falls to a content order (prost encoding, lexicographic) so
///   the winner does not depend on package order;
/// - every difference is counted, and the example is reported.
///
/// Honest limit: when two DIFFERING bodies exist, the analysis sees only the
/// winner. Taint findings the loser alone would give are lost — that is
/// unavoidable without running both (an extraction bug upstream: two repos
/// claim the same function), and the stderr line surfaces it.
pub fn merge_function(
    prog: &mut Program,
    h: IidHex,
    f: cgf::Function,
    repo: String,
    dups: &mut DupStats,
) {
    use prost::Message;
    let Some(existing) = prog.funcs.get(&h) else {
        prog.funcs.insert(h.clone(), f);
        prog.repo_of.insert(h, repo);
        return;
    };
    dups.functions += 1;
    let identical = *existing == f;
    let keep_new = !identical
        && match (existing.flow.is_some(), f.flow.is_some()) {
            (false, true) => true,
            (true, false) => false,
            // equally (in)formed: content order, not package order
            _ => existing.encode_to_vec() <= f.encode_to_vec(),
        };
    // The repo attribution must be order-independent too: chains carry
    // `source_repo`, so a first-wins repo on byte-identical copies would still
    // make stdout depend on package order. Identical copies report the
    // lexicographically smaller repo; differing ones report the winner's repo.
    let old_repo = prog.repo_of.get(&h).cloned().unwrap_or_default();
    let new_repo = if identical {
        old_repo.clone().min(repo.clone())
    } else {
        repo.clone()
    };
    if !identical {
        dups.differing_functions += 1;
    }
    let kept = if identical { new_repo.clone() } else if keep_new { repo.clone() } else { old_repo.clone() };
    let dropped = if identical {
        old_repo.max(repo.clone())
    } else if keep_new {
        old_repo.clone()
    } else {
        repo.clone()
    };
    let already_shown = dups.examples.iter().any(|e| e.iid == h);
    if !already_shown && dups.examples.iter().filter(|e| !e.is_contract).count() < MAX_DUP_EXAMPLES_PER_KIND {
        dups.examples.push(DupExample {
            iid: h.clone(),
            fqn: f.fqn.clone(),
            kept_repo: kept,
            dropped_repo: dropped,
            identical,
            is_contract: false,
        });
    }
    if keep_new {
        prog.funcs.insert(h.clone(), f);
    }
    if keep_new || identical {
        prog.repo_of.insert(h, new_repo);
    }
}

/// Duplicate CONTRACT iids: two packages that define the same gRPC method /
/// GraphQL field / HTTP route. The graph keeps one body per iid (last-defined
/// in sorted-package order — deterministic; HTTP multi-handler routes already
/// fan out into per-handler keys), and this only COUNTS and reports which body
/// it kept. Linking is NOT narrowed by that choice: compose unions ALL
/// handlers' views for the contract (compose::merged_view), so every handler's
/// behaviour is analyzed. `kept_repo` / `dropped_repo` in the load-duplicates
/// line only name which body the graph kept — they say nothing about which
/// handler views the analysis links.
pub fn contract_duplicates(prog: &Program, dups: &mut DupStats) {
    use std::collections::BTreeMap;
    // contract iid -> (full_name, Vec<(repo, handler hex, shape digest)>)
    let mut seen: BTreeMap<IidHex, (String, Vec<(String, String, Vec<u8>)>)> = BTreeMap::new();
    for p in &prog.packages {
        for c in pkg_contracts(p) {
            if c.iid.is_empty() {
                continue;
            }
            let key = hexid(c.iid);
            // shape participates: same iid, different streaming/params is a
            // differing definition even with the same handler
            let shape = match &c.shape {
                crate::compose::ContractShape::Grpc(cs, ss) => vec![*cs as u8, *ss as u8],
                crate::compose::ContractShape::Graphql(args) => {
                    args.iter().map(|&a| a as u8).collect()
                }
                crate::compose::ContractShape::Http { request_params } => {
                    request_params.iter().map(|&a| a as u8).collect()
                }
            };
            let e = seen.entry(key).or_insert_with(|| (c.full_name.to_string(), Vec::new()));
            let hkey = (p.repo.clone(), hexid(c.handler_iid), shape);
            if !e.1.iter().any(|(r, h, s)| *r == hkey.0 && *h == hkey.1 && *s == hkey.2) {
                e.1.push(hkey);
            }
        }
    }
    for (iid, (name, handlers)) in seen {
        if handlers.len() <= 1 {
            continue;
        }
        dups.contracts += handlers.len() - 1;
        dups.differing_contracts += handlers.len() - 1;
        let already_shown = dups.examples.iter().any(|e| e.iid == iid);
        if !already_shown
            && dups.examples.iter().filter(|e| e.is_contract).count() < MAX_DUP_EXAMPLES_PER_KIND
        {
            // handlers are in package order = sorted-file order; the last one
            // is the winner the analysis keeps
            let last = handlers.last().unwrap();
            dups.examples.push(DupExample {
                iid,
                fqn: name,
                kept_repo: format!("{} ({})", last.0, last.1),
                dropped_repo: handlers[..handlers.len() - 1]
                    .iter()
                    .map(|(r, h, _)| format!("{r} ({h})"))
                    .collect::<Vec<_>>()
                    .join(", "),
                identical: false,
                is_contract: true,
            });
        }
    }
}

/// The one stderr JSON line summarizing what load deduplicated. Silent when
/// nothing was duplicated (the common case).
pub fn report_duplicates(dups: &DupStats) {
    if dups.functions == 0 && dups.contracts == 0 {
        return;
    }
    let examples = serde_json::to_value(&dups.examples).unwrap_or_default();
    eprintln!(
        "{}",
        serde_json::json!({
            "phase": "load-duplicates",
            "functions": dups.functions,
            "differing_functions": dups.differing_functions,
            "contracts": dups.contracts,
            "differing_contracts": dups.differing_contracts,
            "examples": examples,
        })
    );
}

impl Program {
    pub fn load_dir(dir: &Path) -> Result<Program> {
        let mut dups = DupStats::default();
        let p = Self::load_dir_with_dups(dir, &mut dups)?;
        report_duplicates(&dups);
        Ok(p)
    }

    /// `load_dir`, plus duplicate accounting into `dups`. Callers that merge
    /// several --cgf dirs accumulate one stats object across them and emit a
    /// single line (cli::load).
    pub fn load_dir_with_dups(dir: &Path, dups: &mut DupStats) -> Result<Program> {
        let mut prog = Program {
            funcs: HashMap::new(),
            repo_of: HashMap::new(),
            packages: Vec::new(),
        };
        // Collect the file list first and sort it by path. read_dir order is
        // filesystem order, but `prog.packages` order decides which body the
        // graph keeps when two --cgf packages define the same contract iid
        // (the load keeps one; compose unions all handlers' views anyway) —
        // so the load order must not depend on the filesystem. Sorting by
        // full path is by file name within one dir, and stable across runs,
        // machines and thread counts.
        let mut paths: Vec<std::path::PathBuf> = Vec::new();
        for entry in std::fs::read_dir(dir).with_context(|| format!("read_dir {dir:?}"))? {
            let path = entry?.path();
            if path.extension().and_then(|s| s.to_str()) != Some("pb") {
                continue;
            }
            paths.push(path);
        }
        // An empty directory is a wrong path or a failed extraction, and the
        // run over it would look like a clean one.
        if paths.is_empty() {
            anyhow::bail!("no CGF files (*.pb) in {}", dir.display());
        }
        paths.sort();
        // Decode in bounded batches; files are independent, so each batch
        // decodes in parallel (rayon's collect preserves input order) and
        // merges into `prog` before the next batch is read. Batching keeps
        // the decode peak at one batch of raw files + decoded packages
        // instead of the whole directory — a load-time RSS spike would set
        // the process ru_maxrss for every later phase. Merge order is
        // sorted-path order within a batch and batch order overall, so the
        // duplicate-iid last-wins insert is identical at any thread count.
        const DECODE_BATCH: usize = 64;
        for batch in paths.chunks(DECODE_BATCH) {
            let pkgs = batch
                .par_iter()
                .map(|path| -> Result<cgf::CgfPackage> {
                    let bytes = std::fs::read(path).with_context(|| format!("read {path:?}"))?;
                    cgf::CgfPackage::decode(&*bytes).with_context(|| format!("decode {path:?}"))
                })
                .collect::<Result<Vec<_>>>()?;
            for mut pkg in pkgs {
                // Move each function into the `funcs` index instead of cloning
                // it: the packages keep no function bodies afterwards (nothing
                // reads pkg.functions past load), so the program holds ONE
                // copy of every function, not two. Duplicate iids go through
                // merge_function: identical copies keep one, differing copies
                // pick a content-order winner and get reported — see there.
                for f in pkg.functions.drain(..) {
                    if let Some(id) = &f.id {
                        let h = hexid(&id.iid);
                        merge_function(&mut prog, h, f, pkg.repo.clone(), dups);
                    }
                }
                prog.packages.push(pkg);
            }
        }
        // The decode is done; return its freed pages (raw file bytes, batch
        // tables, replaced function storage) to the OS so the analysis phases
        // start from the live program, not the load transient.
        crate::phase::pressure_relief();
        Ok(prog)
    }

    /// Callee iids referenced by f's call sites (that we have bodies for).
    pub fn callees(&self, f: &cgf::Function) -> Vec<IidHex> {
        let mut out = Vec::new();
        if let Some(flow) = &f.flow {
            for cs in &flow.callsites {
                for cid in &cs.callee_iids {
                    let h = hexid(cid);
                    if self.funcs.contains_key(&h) {
                        out.push(h);
                    }
                }
            }
        }
        out
    }

    /// Reverse-topological order over the call graph, condensing SCCs (Tarjan).
    /// Callees precede callers (bottom-up) so summaries compose. Recursive SCCs
    /// are iterated to fixpoint by the tabulator.
    pub fn scc_order(&self) -> Vec<Vec<IidHex>> {
        Tarjan::new(self).run()
    }
}

// ---- Tarjan SCC (iterative) over the function call graph ----
struct Tarjan<'a> {
    prog: &'a Program,
    index: HashMap<IidHex, usize>,
    low: HashMap<IidHex, usize>,
    on_stack: HashMap<IidHex, bool>,
    stack: Vec<IidHex>,
    counter: usize,
    out: Vec<Vec<IidHex>>,
}

impl<'a> Tarjan<'a> {
    fn new(prog: &'a Program) -> Self {
        Tarjan {
            prog,
            index: HashMap::new(),
            low: HashMap::new(),
            on_stack: HashMap::new(),
            stack: Vec::new(),
            counter: 0,
            out: Vec::new(),
        }
    }
    fn run(mut self) -> Vec<Vec<IidHex>> {
        // Sorted start order: HashMap key iteration is randomized per process,
        // which made the SCC order — and the trace, scc-iter counts and store
        // write order built on it — differ from run to run. Sorted keys make
        // the DFS, and so the SCC list, reproducible.
        let mut ids: Vec<IidHex> = self.prog.funcs.keys().cloned().collect();
        ids.sort();
        for v in ids {
            if !self.index.contains_key(&v) {
                self.strongconnect(&v);
            }
        }
        self.out
    }
    fn strongconnect(&mut self, v: &IidHex) {
        // iterative DFS to avoid native-stack overflow on deep graphs
        let mut work: Vec<(IidHex, usize)> = vec![(v.clone(), 0)];
        while let Some((node, mut ci)) = work.pop() {
            if ci == 0 {
                self.index.insert(node.clone(), self.counter);
                self.low.insert(node.clone(), self.counter);
                self.counter += 1;
                self.stack.push(node.clone());
                self.on_stack.insert(node.clone(), true);
            }
            let succ = self
                .prog
                .funcs
                .get(&node)
                .map(|f| self.prog.callees(f))
                .unwrap_or_default();
            let mut recursed = false;
            while ci < succ.len() {
                let w = succ[ci].clone();
                ci += 1;
                if !self.index.contains_key(&w) {
                    work.push((node.clone(), ci));
                    work.push((w, 0));
                    recursed = true;
                    break;
                } else if *self.on_stack.get(&w).unwrap_or(&false) {
                    let lw = self.index[&w];
                    let ln = self.low[&node];
                    self.low.insert(node.clone(), ln.min(lw));
                }
            }
            if recursed {
                continue;
            }
            if self.low[&node] == self.index[&node] {
                let mut comp = Vec::new();
                loop {
                    let w = self.stack.pop().unwrap();
                    self.on_stack.insert(w.clone(), false);
                    comp.push(w.clone());
                    if w == node {
                        break;
                    }
                }
                // Member order within an SCC is stack-pop order, which
                // inherits the DFS order; sorted members make the SCC itself
                // a canonical value (the tabulator iterates it to fixpoint,
                // so member order must not leak into counts or trace).
                comp.sort();
                self.out.push(comp);
            }
            if let Some((parent, _)) = work.last().cloned() {
                let lp = self.low[&parent];
                let ln = self.low[&node];
                self.low.insert(parent, lp.min(ln));
            }
        }
    }
}

#[cfg(test)]
mod dup_tests {
    //! Duplicate-iid merge: identical copies keep one, differing
    //! copies pick the with-body / content-order winner — independent of the
    //! order the packages arrive in, and the finding set follows the winner.

    use super::*;
    use crate::catalog::Catalog;
    use crate::ifds::Engine;
    use crate::proto::cgf;
    use std::collections::HashMap;

    fn vx(id: u32, kind: cgf::VertexKind, cs: u32, path: &[u32], names: &[&str]) -> cgf::FlowVertex {
        cgf::FlowVertex {
            id,
            kind: kind as i32,
            index: 0,
            callsite_id: cs,
            field_path: path.to_vec(),
            field_names: names.iter().map(|s| s.to_string()).collect(),
            ..Default::default()
        }
    }
    fn ed(from: u32, to: u32) -> cgf::FlowEdge {
        cgf::FlowEdge { from, to, via_alias: false }
    }

    /// param 0 is an unconditional source; passes it to db.Exec (a sink).
    fn source_with_body(iid: u8) -> cgf::Function {
        cgf::Function {
            id: Some(cgf::Ident { iid: vec![iid; 32], bid: vec![iid; 32] }),
            fqn: "pkg.S".into(),
            has_body: true,
            source_params: vec![0],
            flow: Some(cgf::LocalFlow {
                vertices: vec![
                    vx(0, cgf::VertexKind::InParam, 0, &[], &[]),
                    vx(1, cgf::VertexKind::CallArgPort, 0, &[], &[]),
                ],
                edges: vec![ed(0, 1)],
                callsites: vec![cgf::CallSite {
                    id: 0,
                    callee_iids: vec![vec![9; 32]],
                    callee_fqn: "db.Exec".into(),
                    argc: 1,
                    ..Default::default()
                }],
            }),
            ..Default::default()
        }
    }

    /// the same identity, but the frontend saw no body — no flow, no source
    fn same_fn_no_body(iid: u8) -> cgf::Function {
        cgf::Function {
            id: Some(cgf::Ident { iid: vec![iid; 32], bid: vec![iid; 32] }),
            fqn: "pkg.S".into(),
            has_body: false,
            ..Default::default()
        }
    }

    fn pkg(repo: &str, fns: Vec<cgf::Function>) -> cgf::CgfPackage {
        cgf::CgfPackage { repo: repo.into(), functions: fns, ..Default::default() }
    }

    fn write_dir(dir: &Path, pkgs: &[(&str, cgf::CgfPackage)]) {
        std::fs::create_dir_all(dir).unwrap();
        for (name, p) in pkgs {
            let path = dir.join(format!("{name}.pb"));
            std::fs::write(&path, p.encode_to_vec()).unwrap();
        }
    }
    use prost::Message;

    const CAT: &str = "[[sinks]]\nclass = \"sqli\"\nselector = \"db.Exec\"\narg = \"any\"\n";

    fn chains_of(prog: &Program) -> String {
        let cat = Catalog::load_str(CAT).unwrap();
        let mut eng = Engine::new(prog, &cat);
        eng.run();
        let mut chains = crate::report::intra_chains(&eng, None, false);
        chains.sort_by(|a, b| a.route.as_ref().map(|r| r.id.clone()).cmp(&b.route.as_ref().map(|r| r.id.clone())));
        serde_json::to_string(&chains).unwrap()
    }

    #[test]
    fn identical_duplicates_merge_to_one_copy_in_both_package_orders() {
        let with = source_with_body(1);
        let (d1, d2) = (std::env::temp_dir().join("pc-dup-t-ident-a"), std::env::temp_dir().join("pc-dup-t-ident-b"));
        // same two packages, file names reversed -> decode order reversed
        write_dir(&d1, &[("a", pkg("repo-a", vec![with.clone()])), ("b", pkg("repo-b", vec![with.clone()]))]);
        write_dir(&d2, &[("a", pkg("repo-b", vec![with.clone()])), ("b", pkg("repo-a", vec![with]))]);

        let mut da = DupStats::default();
        let mut db = DupStats::default();
        let pa = Program::load_dir_with_dups(&d1, &mut da).unwrap();
        let pb = Program::load_dir_with_dups(&d2, &mut db).unwrap();

        assert_eq!(da.functions, 1, "one duplicate function iid");
        assert_eq!(da.differing_functions, 0, "the copies are byte-identical");
        assert_eq!(da.functions, db.functions);
        assert_eq!(da.examples.len(), 1);
        assert!(da.examples[0].identical);
        // same winner, same finding set, either order
        assert_eq!(pa.funcs.len(), pb.funcs.len());
        let fa: Vec<_> = pa.funcs.iter().map(|(k, v)| (k.clone(), format!("{v:?}"))).collect();
        let fb: Vec<_> = pb.funcs.iter().map(|(k, v)| (k.clone(), format!("{v:?}"))).collect();
        assert_eq!(fa, fb, "the merge winner must not depend on package order");
        assert_eq!(chains_of(&pa), chains_of(&pb));
    }

    #[test]
    fn differing_duplicates_keep_the_copy_with_a_body_in_both_orders() {
        // iid 1 defined twice: WITH body (chains) and WITHOUT (no chains).
        // Last-wins would make the finding count depend on package order.
        let (d1, d2) = (std::env::temp_dir().join("pc-dup-t-differ-a"), std::env::temp_dir().join("pc-dup-t-differ-b"));
        write_dir(&d1, &[("a", pkg("repo-body", vec![source_with_body(1)])), ("b", pkg("repo-empty", vec![same_fn_no_body(1)]))]);
        write_dir(&d2, &[("a", pkg("repo-empty", vec![same_fn_no_body(1)])), ("b", pkg("repo-body", vec![source_with_body(1)]))]);

        let mut da = DupStats::default();
        let mut db = DupStats::default();
        let pa = Program::load_dir_with_dups(&d1, &mut da).unwrap();
        let pb = Program::load_dir_with_dups(&d2, &mut db).unwrap();

        for d in [&da, &db] {
            assert_eq!(d.functions, 1);
            assert_eq!(d.differing_functions, 1, "the copies differ");
            assert_eq!(d.examples.len(), 1);
            assert!(!d.examples[0].identical);
        }
        // the winner HAS the body, in both orders: it is the only copy that
        // can produce the finding
        for p in [&pa, &pb] {
            let f = p.funcs.values().next().unwrap();
            assert!(f.flow.is_some(), "the with-body copy must win");
            assert_eq!(f.source_params, vec![0]);
        }
        assert_eq!(chains_of(&pa), chains_of(&pb));
        let cat = Catalog::load_str(CAT).unwrap();
        let mut eng = Engine::new(&pa, &cat);
        eng.run();
        let chains = crate::report::intra_chains(&eng, None, false);
        assert_eq!(chains.len(), 1, "the surviving body gives its chain");
    }

    #[test]
    fn differing_duplicates_fall_to_a_content_order_when_both_have_bodies() {
        // same iid, both with bodies, different source_params: the winner is
        // the lexicographically smaller prost encoding — same either order.
        let f1 = source_with_body(1);
        let mut f2 = source_with_body(1);
        f2.source_params = vec![0, 1];
        let (d1, d2) = (std::env::temp_dir().join("pc-dup-t-tie-a"), std::env::temp_dir().join("pc-dup-t-tie-b"));
        write_dir(&d1, &[("a", pkg("repo-x", vec![f1.clone()])), ("b", pkg("repo-y", vec![f2.clone()]))]);
        write_dir(&d2, &[("a", pkg("repo-y", vec![f2])), ("b", pkg("repo-x", vec![f1.clone()]))]);

        let mut da = DupStats::default();
        let mut db = DupStats::default();
        let pa = Program::load_dir_with_dups(&d1, &mut da).unwrap();
        let pb = Program::load_dir_with_dups(&d2, &mut db).unwrap();

        let fa: Vec<_> = pa.funcs.iter().map(|(k, v)| (k.clone(), format!("{v:?}"))).collect();
        let fb: Vec<_> = pb.funcs.iter().map(|(k, v)| (k.clone(), format!("{v:?}"))).collect();
        assert_eq!(fa, fb, "the content-order winner must not depend on package order");
    }

    #[test]
    fn duplicate_contract_iids_are_counted_and_reported() {
        let gm = |handler: u8| cgf::GrpcMethod {
            iid: vec![7; 32],
            full_name: "led.Ledger/Get".into(),
            input_msg: "led.GetReq".into(),
            output_msg: "led.GetResp".into(),
            handler_iid: vec![handler; 32],
            ..Default::default()
        };
        let mut prog = Program { funcs: HashMap::new(), repo_of: HashMap::new(), packages: Vec::new() };
        prog.packages.push(pkg("repo-a", vec![]));
        prog.packages[0].grpc_methods.push(gm(1));
        prog.packages.push(pkg("repo-b", vec![]));
        prog.packages[1].grpc_methods.push(gm(2));

        let mut d = DupStats::default();
        contract_duplicates(&prog, &mut d);
        assert_eq!(d.contracts, 1, "one contract iid defined twice");
        assert_eq!(d.differing_contracts, 1);
        assert_eq!(d.examples.len(), 1);
        assert_eq!(d.examples[0].fqn, "led.Ledger/Get");
        assert!(d.examples[0].kept_repo.starts_with("repo-b"), "package order decides; it is deterministic");
    }
}

