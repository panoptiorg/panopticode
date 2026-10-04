// panopticode CLI (clap). Shells out to the Go frontend `pc-fe` for extraction,
// then loads CGF, summarizes, composes, and emits JSON.
use crate::catalog::Catalog;
use crate::graph::Program;
use crate::ifds::Engine;
use crate::summarystore::SummaryStore;
use crate::{backward, compose, report};
use crate::normalize::normalize_loaded;
use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use std::process::Command;

#[derive(Parser)]
#[command(name = "panopticode", version, about = "Compositional cross-repo taint analysis")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Extract a repo → CGF via the Go frontend (pc-fe).
    Extract {
        #[arg(long)]
        repo: String,
        #[arg(long)]
        scope: Option<String>,
        #[arg(long, default_value = "main")]
        mode: String,
        #[arg(long)]
        out: PathBuf,
        #[arg(long, default_value = "pc-fe")]
        fe: String,
    },
    /// Load CGF dir(s), run summary-based taint, print chains (JSON).
    /// Multiple --cgf dirs compose cross-repo at invokes_remote sites.
    Taint {
        #[arg(long = "cgf", required = true)]
        cgf: Vec<PathBuf>,
        #[arg(long, default_value = "catalog.example.toml")]
        catalog: PathBuf,
        /// filter chains whose source fn fqn contains this substring
        #[arg(long)]
        endpoint: Option<String>,
        /// persist graph + contracts + summaries to this Postgres URL
        #[arg(long)]
        pg: Option<String>,
        /// summary store dir: probe cached summaries + persist new ones
        /// (warms the cache `impact` reuses)
        #[arg(long)]
        store: Option<PathBuf>,
        /// write step-level trace events (seed/summary/scc-start/scc-iter/
        /// apply/leaf/sink-hit/heap-hit/chain/widen) to this file — inspect
        /// with grep, or narrow with --trace-events
        #[arg(long)]
        trace: Option<PathBuf>,
        /// only trace functions whose fqn contains this substring
        #[arg(long = "trace-fn")]
        trace_fn: Option<String>,
        /// only emit these event kinds (csv, e.g. `chain,widen`). The full
        /// trace does not scale — at --heap-slots-scope=all it extrapolates to
        /// ~50 GB — and fallback attribution reads only chain+widen.
        #[arg(long = "trace-events")]
        trace_events: Option<String>,
        /// Do not let the default leaf taint an `error`-typed
        /// result port (`CallSite.error_results`, needs a corpus extracted with
        /// pc-fe --error-results); catalog `error_wrappers` are exempt because
        /// `fmt.Errorf("… %s", account, err)` really carries request data.
        /// DEFAULT OFF — reproduces today's chains exactly.
        #[arg(long = "no-error-leaf")]
        no_error_leaf: bool,
        /// Sink-seeded backward confirmation. Every chain gets a
        /// `backward` verdict (confirmed / refuted / undecided) and the
        /// source-side field the terminal actually reads. Chains are NOT
        /// removed; counts on stderr. DEFAULT OFF.
        #[arg(long)]
        backward: bool,
        /// Additionally DROP chains the backward pass refuted
        /// (implies --backward). The only flag that removes findings.
        /// A refutation that crossed a contract with a non-identity view is
        /// NOT acted on here unless --backward-prune-unviewed says so.
        #[arg(long = "backward-prune")]
        backward_prune: bool,
        /// Cross contracts whose published view is not the handler's own frame
        /// — streaming gRPC, and GraphQL fields whose resolver arguments are
        /// permuted — by undoing compose's slot remap, instead of giving up on
        /// them (implies --backward). Those boundaries are `undecided` for no
        /// other reason. A slot compose DROPS stays undecided, with reason
        /// `unview_dropped_slot`; the summary line reports how many verdicts
        /// this changed as `unview-flips=`. DEFAULT OFF — with it off every
        /// verdict is exactly the verdict produced without it.
        #[arg(long = "backward-unview")]
        backward_unview: bool,
        /// Let --backward-prune drop chains whose refutation came out of a
        /// walk that crossed such a contract (--backward-unview). OFF by
        /// default: a wrong unview refutes wrongly, and pruning a wrong
        /// refutation DELETES a real finding — worse than leaving it
        /// undecided. Without this flag those chains are reported
        /// `undecided` (reason `unviewed_refutation_not_pruned`) and kept.
        #[arg(long = "backward-prune-unviewed")]
        backward_prune_unviewed: bool,
        /// Treat an out-of-scope protobuf getter leaf as a projection of
        /// exactly its field, in both the forward leaf and the backward pass.
        /// Semantics flag (summary-store namespace). DEFAULT OFF.
        #[arg(long = "pb-getters")]
        pb_getters: bool,
        /// Write the unmodeled-library-call report to this file (JSON): every
        /// body-less library call that tainted data reaches, that could write
        /// into another of its arguments, and that no catalog `[[propagators]]`
        /// rule covers — ranked by how many routes reach it. The engine cannot
        /// follow data through these; each is a candidate propagator (or a
        /// `to = "none"` rule once reviewed). Top entries also go to stderr.
        /// Adds pseudo-sinks, so it is a summary-store namespace flag. The
        /// chains printed on stdout are unchanged.
        #[arg(long)]
        unmodeled: Option<PathBuf>,
    },
    /// Dump the loaded function/contract counts.
    GraphDump {
        #[arg(long = "cgf", required = true)]
        cgf: Vec<PathBuf>,
    },
    /// Debug: print computed summaries for functions matching a substring.
    Summary {
        #[arg(long = "cgf", required = true)]
        cgf: Vec<PathBuf>,
        #[arg(long, default_value = "catalog.example.toml")]
        catalog: PathBuf,
        #[arg(long)]
        fn_: String,
    },
    /// MR impact report: re-extract repo at head (pc-fe --mode mr), reuse the
    /// summary store for unchanged fns, emit ImpactReport JSON.
    Impact {
        /// MR repo working dir, checked out at --head
        #[arg(long)]
        repo: String,
        #[arg(long)]
        scope: Option<String>,
        #[arg(long)]
        base: String,
        #[arg(long)]
        head: String,
        /// pre-extracted CGF dirs of OTHER repos to compose cross-repo
        #[arg(long = "cgf")]
        cgf: Vec<PathBuf>,
        #[arg(long, default_value = "catalog.example.toml")]
        catalog: PathBuf,
        /// summary store dir (warm it with a baseline `taint --store` run)
        #[arg(long)]
        store: PathBuf,
        /// where to write the head CGF extraction (default: temp dir)
        #[arg(long)]
        out: Option<PathBuf>,
        #[arg(long, default_value = "pc-fe")]
        fe: String,
        /// Postgres URL: resolve remote contract views from contract_summaries
        /// (makes --cgf of other repos optional) + PG-walked blast radius
        #[arg(long)]
        pg: Option<String>,
    },
    /// Pure Postgres graph reads (no extraction, no taint) over a graph
    /// persisted by a prior `taint --pg` run.
    Query {
        #[command(subcommand)]
        q: QueryCmd,
    },
}

#[derive(Subcommand)]
enum QueryCmd {
    /// Blast radius: upstream repos + boundary endpoints reaching the given
    /// changed files (repo-relative) of --repo.
    Blast {
        /// Postgres URL
        #[arg(long)]
        pg: String,
        /// repo module path as persisted (go.mod module)
        #[arg(long)]
        repo: String,
        /// changed file, repo-relative (repeatable)
        #[arg(long = "file", required = true)]
        files: Vec<String>,
    },
    /// Which upstream repos + boundary endpoints can reach functions whose
    /// fqn contains SUBSTR.
    Reach {
        /// Postgres URL
        #[arg(long)]
        pg: String,
        /// fqn substring selecting the target function(s)
        #[arg(long = "fn")]
        fn_: String,
        /// only match functions in this repo (module path)
        #[arg(long)]
        repo: Option<String>,
    },
    /// Concrete forward call paths between two fqn substrings (fn or contract
    /// full_name), shortest first.
    Path {
        /// Postgres URL
        #[arg(long)]
        pg: String,
        /// fqn/contract substring for path starts
        #[arg(long)]
        from: String,
        /// fqn/contract substring for path ends
        #[arg(long)]
        to: String,
        /// max paths returned
        #[arg(long, default_value_t = 5)]
        limit: i64,
        /// max hops per path; the real cost bound — lower it if slow
        #[arg(long = "max-depth", default_value_t = 30)]
        max_depth: i32,
    },
}

pub fn run() -> Result<()> {
    match Cli::parse().cmd {
        Cmd::Extract {
            repo,
            scope,
            mode,
            out,
            fe,
        } => extract(&fe, &repo, scope.as_deref(), &mode, &out),
        Cmd::Taint {
            cgf,
            catalog,
            endpoint,
            pg,
            store,
            trace,
            trace_fn,
            trace_events,
            no_error_leaf,
            backward,
            backward_prune,
            backward_unview,
            backward_prune_unviewed,
            pb_getters,
            unmodeled,
        } => taint(
            &cgf,
            &catalog,
            endpoint.as_deref(),
            pg.as_deref(),
            store.as_deref(),
            trace.as_deref(),
            trace_fn,
            trace_events.as_deref(),
            no_error_leaf,
            TaintOpts {
                backward: backward || backward_prune || backward_unview,
                backward_prune,
                backward_unview,
                backward_prune_unviewed,
                pb_getters,
            },
            unmodeled.as_deref(),
        ),
        Cmd::GraphDump { cgf } => graph_dump(&cgf),
        Cmd::Summary { cgf, catalog, fn_ } => summary_dbg(&cgf, &catalog, &fn_),
        Cmd::Impact {
            repo,
            scope,
            base,
            head,
            cgf,
            catalog,
            store,
            out,
            fe,
            pg,
        } => crate::impact::impact(
            &repo,
            scope.as_deref(),
            &base,
            &head,
            &cgf,
            &catalog,
            &store,
            out.as_deref(),
            &fe,
            pg.as_deref(),
        ),
        Cmd::Query { q } => match q {
            QueryCmd::Blast { pg, repo, files } => crate::query::blast(&pg, &repo, &files),
            QueryCmd::Reach { pg, fn_, repo } => {
                crate::query::reach(&pg, &fn_, repo.as_deref())
            }
            QueryCmd::Path {
                pg,
                from,
                to,
                limit,
                max_depth,
            } => crate::query::path(&pg, &from, &to, limit, max_depth),
        },
    }
}

fn extract(fe: &str, repo: &str, scope: Option<&str>, mode: &str, out: &PathBuf) -> Result<()> {
    let mut cmd = Command::new(fe);
    cmd.arg("build").arg(repo).arg("--out").arg(out).arg("--mode").arg(mode);
    if let Some(s) = scope {
        cmd.arg("--scope").arg(s);
    }
    let status = cmd.status().with_context(|| format!("run {fe}"))?;
    if !status.success() {
        anyhow::bail!("pc-fe exited with {status}");
    }
    Ok(())
}

fn load(cgf: &[PathBuf]) -> Result<Program> {
    let mut prog = Program {
        funcs: Default::default(),
        repo_of: Default::default(),
        packages: Default::default(),
    };
    for dir in cgf {
        let p = Program::load_dir(dir)?;
        prog.funcs.extend(p.funcs);
        prog.repo_of.extend(p.repo_of);
        prog.packages.extend(p.packages);
    }
    // doc 36 §3.1. Runs on the MERGED program, not per load_dir: a by-name
    // callsite in one --cgf dir routinely names a contract defined in another.
    normalize_loaded(&mut prog);
    Ok(prog)
}

/// doc 35 taint-side options. Separate struct so the arity of `taint` stops
/// growing by one per flag.
#[derive(Clone, Copy, Default)]
struct TaintOpts {
    backward: bool,
    backward_prune: bool,
    backward_unview: bool,
    backward_prune_unviewed: bool,
    pb_getters: bool,
}

fn taint(
    cgf: &[PathBuf],
    catalog: &PathBuf,
    endpoint: Option<&str>,
    pg: Option<&str>,
    store_dir: Option<&std::path::Path>,
    trace_path: Option<&std::path::Path>,
    trace_fn: Option<String>,
    trace_events: Option<&str>,
    no_error_leaf: bool,
    opts: TaintOpts,
    unmodeled: Option<&std::path::Path>,
) -> Result<()> {
    let cat = Catalog::load(catalog).with_context(|| format!("load catalog {catalog:?}"))?;
    let prog = load(cgf)?;
    // Loud failures (measurements 2026-09-01, 00-report §4): a catalog rule
    // that matches nothing and a callee with no body both used to produce
    // "no finding" indistinguishable from "nothing there". stderr, once per
    // run, before any analysis — a property of the inputs, not of a chain.
    catalog_fit_report(&cat, &prog);
    opacity_report(&prog);
    let tr = match trace_path {
        Some(p) => Some(
            crate::trace::Trace::open(p, trace_fn, trace_events)
                .with_context(|| format!("open trace {p:?}"))?,
        ),
        None => None,
    };
    let mut eng = Engine::new(&prog, &cat);
    eng.trace = tr.as_ref();
    eng.no_error_leaf = no_error_leaf;
    eng.pb_getters = opts.pb_getters;
    eng.report_unmodeled = unmodeled.is_some();
    // Semantics flags, joined into the summary-store namespace: a store warmed
    // under one setting must never serve summaries to a run under another.
    let env_flags = {
        let mut v = Vec::new();
        if no_error_leaf {
            v.push("no_error_leaf=1");
        }
        if opts.pb_getters {
            v.push("pb_getters=1");
        }
        if unmodeled.is_some() {
            v.push("unmodeled=1");
        }
        v.join(",")
    };
    if no_error_leaf {
        // Static population, counted once — never per descent (trap 8c).
        let (sites, wrappers, ports, fns) = eng.error_leaf_census();
        eprintln!(
            "error-leaf: {sites} callsites with an error result ({wrappers} exempt as wrappers), \
             {ports} result ports suppressed, across {fns} functions"
        );
        if sites == 0 {
            eprintln!(
                "error-leaf: WARNING — no CallSite.error_results in this corpus; \
                 re-extract with `pc-fe build --error-results` or the flag does nothing"
            );
        }
    }
    let stats = match store_dir {
        Some(dir) => {
            let cat_hash = crate::summarystore::env_hash(
                &crate::impact::catalog_file_hash(catalog)?,
                &env_flags,
            );
            let mut store = SummaryStore::open(Some(dir), &cat_hash, 1_000_000)?;
            eng.run_with_store(&mut store)
        }
        None => {
            let mut store = SummaryStore::ephemeral();
            eng.run_with_store(&mut store)
        }
    };
    // Remote contract views from PG for contracts no loaded CGF defines
    // (doc 18 B.3) — loaded AFTER phase 1 so cache environments stay identical.
    let leaves = match pg {
        Some(url) => {
            let missing = crate::storage::missing_remote_contracts(&prog);
            crate::storage::load_contract_views(url, &missing)?
        }
        None => Default::default(),
    };
    if let Some(t) = &tr {
        t.flush(); // phase-1 summaries durable even if compose blows up
    }
    // W1F: join heap-cell writers to readers (doc 24 N5). Phase 2, in memory
    // only — see the discipline block in heap.rs. BEFORE compose so a
    // heap-mediated hit still gets a chance to cross a service boundary; a
    // no-op on any CGF extracted without --heap-slots.
    let hs = crate::heap::fixpoint(&mut eng);
    if hs.cells > 0 {
        eprintln!(
            "heap-cells: {} written, {} writers, {} cell-sinks, {} spliced, {} iters, {} resummarized",
            hs.cells, hs.writers, hs.cell_sinks, hs.spliced, hs.iters, hs.resummarized
        );
    }
    // cross-repo composition at invokes_remote, iterated to fixpoint (doc 17)
    let fx = compose::fixpoint_with_leaves(&mut eng, leaves);
    if let Some(url) = pg {
        let st = crate::storage::persist(&prog, &eng, url)?;
        eprintln!(
            "persisted nodes={} edges={} invokes={} to postgres",
            st.nodes, st.edges, st.invokes
        );
    }
    let mut chains = report::intra_chains(&eng, endpoint);
    // --unmodeled pseudo-chains never reach stdout or the backward pass
    let unmodeled_calls = report::take_unmodeled(&mut chains);
    if let Some(path) = unmodeled {
        std::fs::write(path, serde_json::to_string_pretty(&unmodeled_calls)?)
            .with_context(|| format!("write {path:?}"))?;
        eprintln!(
            "unmodeled: {} library call(s) receive tainted data and may write into another argument \
             with no [[propagators]] rule -> {}",
            unmodeled_calls.len(),
            path.display()
        );
        for u in unmodeled_calls.iter().take(15) {
            let ex = u.examples.first();
            eprintln!(
                "  {:>5} routes  {:>4} sites  {:>4} sources  {}  e.g. {}:{}",
                u.chains,
                u.call_sites,
                u.sources,
                u.callee,
                ex.and_then(|e| e.file.as_deref()).unwrap_or("?"),
                ex.and_then(|e| e.line).unwrap_or(0)
            );
        }
    }
    // doc 35: sink-seeded backward confirmation, after every forward pass and
    // after witness (it keys on the route's terminal). Reads summaries only.
    if opts.backward {
        let t0 = std::time::Instant::now();
        // Flag-gated behaviour of the backward pass. Installed here rather
        // than passed through report::backward_check, which several callers
        // share; backward::Back snapshots it at construction.
        backward::set_opts(backward::BackOpts {
            unview: opts.backward_unview,
            prune: opts.backward_prune,
            prune_unviewed: opts.backward_prune_unviewed,
        });
        let bs = report::backward_check(&eng, &mut chains, opts.backward_prune);
        eprintln!(
            "backward: confirmed={} (exact={}, route-terminal-refuted={}) refuted={} undecided={} pruned={} unview-flips={} in {:.2}s",
            bs.confirmed,
            bs.confirmed_exact,
            bs.mislabelled,
            bs.refuted,
            bs.undecided,
            bs.pruned,
            backward::unview_flips(),
            t0.elapsed().as_secs_f32()
        );
    }
    if let Some(t) = &tr {
        t.flush();
    }
    println!("{}", serde_json::to_string_pretty(&chains)?);
    eprintln!(
        "functions={} summaries={} contracts_linked={} remote_leaves={} chains={} cache_hits={} cache_misses={}",
        prog.funcs.len(),
        eng.summaries.len(),
        fx.linked,
        fx.remote_leaves,
        chains.len(),
        stats.hits,
        stats.misses
    );
    Ok(())
}

/// `catalog-fit:` one line always; `catalog-warn:` one line per rule that
/// matches no callee fqn in the loaded CGF. Distinct callee fqns only, so the
/// cost is rules × distinct callees (broker corpus: ~50 × ~60k, well under a
/// second).
fn catalog_fit_report(cat: &Catalog, prog: &Program) {
    let mut fqns: std::collections::HashSet<&str> = std::collections::HashSet::new();
    // (fqn, argc) — the arg-range check needs the width of the call, and
    // distinct pairs are enough for "was the index EVER in range".
    let mut calls: std::collections::HashSet<(&str, u32)> = std::collections::HashSet::new();
    for f in prog.funcs.values() {
        if let Some(fl) = &f.flow {
            for cs in &fl.callsites {
                fqns.insert(cs.callee_fqn.as_str());
                calls.insert((cs.callee_fqn.as_str(), cs.argc));
            }
        }
    }
    let inert = cat.unmatched_rules(fqns.iter().copied());
    let total = cat.rule_count();
    eprintln!(
        "catalog-fit: {}/{} rules match at least one call site ({} distinct callees){}",
        total - inert.len(),
        total,
        fqns.len(),
        if inert.is_empty() { "" } else { " — inert rules follow; scripts/catalog-fit.py shows what IS there" }
    );
    for (section, tag, label) in &inert {
        eprintln!("catalog-warn: inert rule {section}[{tag}] {label:?} — no call site matches it (zero recall here)");
    }
    // The other inertness: the NAME matches, so the rule counts as fitted
    // above, but the arg index is wider than any of those call sites.
    for (class, label, arg, max_argc) in cat.sink_arg_never_in_range(calls.iter().copied()) {
        eprintln!(
            "catalog-warn: sink rule [{class}] {label:?} arg {arg} never in range \
             (max argc seen {max_argc}) — it can never fire"
        );
    }
    if !cat.propagators.is_empty() {
        let (hit, n) = cat.propagator_fit(fqns.iter().copied());
        eprintln!("catalog-fit: {hit}/{n} propagators match at least one call site");
    }
}

/// `opaque:` how many call sites resolve to no body the core can descend
/// into, by owning module. FN-03 (measurements 2026-09-01): terminals inside
/// a Go module dependency are outside every scope, and a chain that stops
/// there looked exactly like a chain with nothing further to find. Stdlib,
/// builtins and remote contracts are excluded — they are opaque by design.
fn opacity_report(prog: &Program) {
    use crate::graph::hexid;
    use std::collections::HashMap;
    let mut by_module: HashMap<String, usize> = HashMap::new();
    let mut total = 0usize;
    let mut sites = 0usize;
    for f in prog.funcs.values() {
        let Some(fl) = &f.flow else { continue };
        for cs in &fl.callsites {
            sites += 1;
            if cs.kind == crate::proto::cgf::call_site::Kind::InvokesRemote as i32
                || cs.kind == crate::proto::cgf::call_site::Kind::Builtin as i32
            {
                continue;
            }
            let bodied = cs
                .callee_iids
                .iter()
                .any(|c| prog.funcs.get(&hexid(c)).map_or(false, |g| g.flow.is_some()));
            if bodied && !cs.opaque {
                continue;
            }
            let Some(module) = module_of(&cs.callee_fqn) else { continue };
            total += 1;
            *by_module.entry(module).or_default() += 1;
        }
    }
    if total == 0 {
        return;
    }
    let mut top: Vec<(String, usize)> = by_module.into_iter().collect();
    top.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    let shown: Vec<String> = top.iter().take(8).map(|(m, n)| format!("{m}={n}")).collect();
    eprintln!(
        "opaque: {total} of {sites} call sites have no analysable body (default leaf; \
         routes through them stop with incomplete=callee_body_missing) — top modules: {}{}",
        shown.join(", "),
        if top.len() > 8 { ", …" } else { "" }
    );
}

/// Owning module of a callee fqn, approximated as the first three path
/// segments of a dotted-host import path (`gitlab.example.com/acme/ledger-svc`,
/// `github.com/x/y`). None for stdlib (`fmt.Sprintf`, `(hash.Hash64).Sum64`)
/// and for anything without an import path.
fn module_of(fqn: &str) -> Option<String> {
    if fqn.starts_with("func(") {
        // dynamic func value with no resolved target — its own bucket
        return Some("<dynamic func value>".into());
    }
    let path = fqn.trim_start_matches('(').trim_start_matches('*');
    let first = path.split('/').next()?;
    if !first.contains('.') || first.contains(' ') {
        return None;
    }
    let mut segs = path.split('/');
    let a = segs.next()?;
    let b = segs.next()?;
    let c = segs.next().map(|s| s.split('.').next().unwrap_or(s));
    Some(match c {
        Some(c) => format!("{a}/{b}/{c}"),
        None => format!("{a}/{b}"),
    })
}

fn summary_dbg(cgf: &[PathBuf], catalog: &PathBuf, fnpat: &str) -> Result<()> {
    let cat = Catalog::load(catalog)?;
    let prog = load(cgf)?;
    let mut eng = Engine::new(&prog, &cat);
    eng.run();
    // same phase-2 order taint uses, so `summary --fn` shows what the report
    // actually sees — without this a heap-mediated hit is invisible to the one
    // tool built for diagnosing summaries.
    let hs = crate::heap::fixpoint(&mut eng);
    if hs.cells > 0 {
        eprintln!(
            "heap-cells: {} written, {} writers, {} cell-sinks, {} spliced, {} iters",
            hs.cells, hs.writers, hs.cell_sinks, hs.spliced, hs.iters
        );
    }
    for (iid, f) in &prog.funcs {
        if !f.fqn.contains(fnpat) {
            continue;
        }
        let s = eng.summaries.get(iid);
        println!("FN {}", f.fqn);
        if let Some(fl) = &f.flow {
            let seeds: Vec<String> = fl
                .callsites
                .iter()
                .filter(|cs| cat.source_of(&cs.callee_fqn).is_some())
                .map(|cs| cs.callee_fqn.clone())
                .collect();
            println!("  source_callsites: {:?}", seeds);
            let sinks: Vec<String> = fl
                .callsites
                .iter()
                .filter(|cs| cat.sink_of(&cs.callee_fqn).is_some())
                .map(|cs| format!("{} [{}]", cs.callee_fqn, cat.sink_of(&cs.callee_fqn).unwrap().class))
                .collect();
            println!("  sink_callsites: {:?}", sinks);
        }
        if let Some(s) = s {
            println!("  flows: {:?}", s.flows);
            println!(
                "  sink_hits: {:?}",
                s.sink_hits
                    .iter()
                    .map(|h| (
                        format!("{:?}", h.in_slot),
                        h.class.clone(),
                        h.via_heap.as_ref().map(|v| v.cell.clone()).unwrap_or_default()
                    ))
                    .collect::<Vec<_>>()
            );
        }
        println!();
    }
    Ok(())
}

fn graph_dump(cgf: &[PathBuf]) -> Result<()> {
    let prog = load(cgf)?;
    let mut grpc = 0;
    let mut gql = 0;
    // packages per CgfPackage.language — the one place a mixed-language corpus
    // is visible at a glance (doc 36 §3.4). "" (pre-doc-36 CGF) reads as go.
    let mut langs: std::collections::BTreeMap<&str, usize> = Default::default();
    for p in &prog.packages {
        grpc += p.grpc_methods.len();
        gql += p.graphql_fields.len();
        let l = if p.language.is_empty() { "go" } else { p.language.as_str() };
        *langs.entry(l).or_default() += 1;
    }
    println!(
        "packages={} functions={} grpc_methods={} graphql_fields={} languages={{{}}}",
        prog.packages.len(),
        prog.funcs.len(),
        grpc,
        gql,
        langs
            .iter()
            .map(|(l, n)| format!("{l}:{n}"))
            .collect::<Vec<_>>()
            .join(","),
    );
    Ok(())
}
