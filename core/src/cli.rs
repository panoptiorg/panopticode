// panopticode CLI (clap). Shells out to the Go frontend `pc-fe` for extraction,
// then loads CGF, summarizes, composes, and emits JSON.
use crate::catalog::Catalog;
use crate::graph::Program;
use crate::ifds::Engine;
use crate::summarystore::SummaryStore;
use crate::{backward, compose, report};
use crate::normalize::normalize_loaded;
use crate::output::{self, FailOn, Format};
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
        /// policy file; default: the example catalog built into the binary
        #[arg(long)]
        catalog: Option<PathBuf>,
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
        /// Do not link synthetic HTTP client sites to the loaded HTTP routes.
        /// Linked, a client request whose method and path
        /// match a route becomes a cross-service call into its handler, like a
        /// gRPC method; unlinked, the site is inert and the chains are exactly
        /// those of a corpus without HTTP facts.
        #[arg(long = "no-http-link")]
        no_http_link: bool,
        /// Output format on stdout: `json` (the chains), `text`, or `sarif`
        /// (SARIF 2.1.0, for code scanning and the VS Code SARIF Viewer).
        #[arg(long, value_enum, default_value = "json")]
        format: Format,
        /// Exit 3 after writing the output if any chain's sink class is in
        /// this comma-separated list, or if there is any chain for `any`.
        /// A class the catalog does not define is a usage error.
        #[arg(long = "fail-on")]
        fail_on: Option<String>,
        /// List every inert catalog rule instead of counting them.
        #[arg(short, long)]
        verbose: bool,
        /// Thread budget for the parallel phases (load decode, summaries,
        /// chains). 0 = all available cores. Default 1, or
        /// PANOPTICODE_THREADS when the flag is absent. Output is
        /// byte-identical at any value.
        #[arg(long)]
        threads: Option<u32>,
        /// Debug: after the summaries phase, recompute every summary
        /// sequentially in SCC order and compare with the parallel result;
        /// report the number of differences on stderr. Costs one extra
        /// sequential pass. Hidden — diagnostics for the parallel scheduler.
        #[arg(long, hide = true)]
        verify_summaries: bool,
        /// Debug: after the chains phase, recompute every chain's route with a
        /// fresh Walk (cold memos) and compare with the shared-Walk route;
        /// report the number of differences on stderr with up to 8 examples.
        /// Catches a memo that serves a visit-context-dependent value. Hidden —
        /// diagnostics for the parallel scheduler.
        #[arg(long, hide = true)]
        verify_routes: bool,
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
        /// policy file; default: the example catalog built into the binary
        #[arg(long)]
        catalog: Option<PathBuf>,
        #[arg(long)]
        fn_: String,
        /// Thread budget (see `taint --threads`).
        #[arg(long)]
        threads: Option<u32>,
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
        /// policy file; default: the example catalog built into the binary
        #[arg(long)]
        catalog: Option<PathBuf>,
        /// summary store dir (warm it with a baseline `taint --store` run)
        #[arg(long)]
        store: PathBuf,
        /// where to write the head CGF extraction (default: temp dir)
        #[arg(long)]
        out: Option<PathBuf>,
        #[arg(long, default_value = "pc-fe")]
        fe: String,
        /// Extra argument passed through to the frontend, after the built-in
        /// arguments, in order (repeatable). A TypeScript frontend needs
        /// `--repo-id <id>` — the CGF repo must match the other CGF dirs of
        /// the run — and `--adapter <name>`.
        #[arg(long = "fe-arg", allow_hyphen_values = true)]
        fe_arg: Vec<String>,
        /// Postgres URL: resolve remote contract views from contract_summaries
        /// (makes --cgf of other repos optional) + PG-walked blast radius
        #[arg(long)]
        pg: Option<String>,
        /// Thread budget (see `taint --threads`).
        #[arg(long)]
        threads: Option<u32>,
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
            no_http_link,
            format,
            fail_on,
            verbose,
            threads,
            verify_summaries,
            verify_routes,
        } => taint(
            &cgf,
            catalog.as_deref(),
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
                http_link: !no_http_link,
            },
            unmodeled.as_deref(),
            Output { format, fail_on, verbose },
            threads,
            verify_summaries,
            verify_routes,
        ),
        Cmd::GraphDump { cgf } => graph_dump(&cgf),
        Cmd::Summary { cgf, catalog, fn_, threads } => {
            summary_dbg(&cgf, catalog.as_deref(), &fn_, threads)
        }
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
            fe_arg,
            pg,
            threads,
        } => crate::impact::impact(
            &repo,
            scope.as_deref(),
            &base,
            &head,
            &cgf,
            catalog.as_deref(),
            &store,
            out.as_deref(),
            &fe,
            &fe_arg,
            pg.as_deref(),
            threads,
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

/// Why `fe` could not be started. A missing binary reads like a missing repo
/// unless it is named.
pub(crate) fn fe_err(fe: &str, e: std::io::Error) -> anyhow::Error {
    if e.kind() == std::io::ErrorKind::NotFound {
        anyhow::anyhow!("{fe} not found (install panoptife-go or pass --fe <path>)")
    } else {
        anyhow::anyhow!("run {fe}: {e}")
    }
}

/// Resolve the thread budget and build the ONE global rayon pool every
/// parallel phase (load decode, summaries, chains) shares. `--threads` wins;
/// absent it, PANOPTICODE_THREADS; default 1. 0 = all available cores
/// (rayon's default). A second build_global call panics, so each subcommand
/// calls this exactly once, before any phase runs.
pub(crate) fn init_threads(flag: Option<u32>) {
    let n = flag
        .or_else(|| {
            std::env::var("PANOPTICODE_THREADS")
                .ok()
                .and_then(|v| v.trim().parse().ok())
        })
        .unwrap_or(1);
    rayon::ThreadPoolBuilder::new()
        .num_threads(n as usize)
        .build_global()
        .expect("build the global rayon thread pool");
}

fn extract(fe: &str, repo: &str, scope: Option<&str>, mode: &str, out: &PathBuf) -> Result<()> {
    let mut cmd = Command::new(fe);
    cmd.arg("build").arg(repo).arg("--out").arg(out).arg("--mode").arg(mode);
    if let Some(s) = scope {
        cmd.arg("--scope").arg(s);
    }
    let status = cmd.status().map_err(|e| fe_err(fe, e))?;
    if !status.success() {
        anyhow::bail!("pc-fe exited with {status}");
    }
    Ok(())
}

fn load(cgf: &[PathBuf], http_link: bool) -> Result<Program> {
    let mut prog = Program {
        funcs: Default::default(),
        repo_of: Default::default(),
        packages: Default::default(),
    };
    let mut dups = crate::graph::DupStats::default();
    for dir in cgf {
        let p = Program::load_dir_with_dups(dir, &mut dups)?;
        // Cross-dir duplicate iids go through the same merge rule as
        // within-dir ones: identical copies keep one, differing copies pick a
        // content-order winner (not "last --cgf dir wins").
        for (h, f) in p.funcs {
            let repo = p.repo_of.get(&h).cloned().unwrap_or_default();
            crate::graph::merge_function(&mut prog, h, f, repo, &mut dups);
        }
        prog.packages.extend(p.packages);
    }
    // Duplicate contract iids: counted and reported, semantics unchanged.
    crate::graph::contract_duplicates(&prog, &mut dups);
    crate::graph::report_duplicates(&dups);
    // doc 36 §3.1. Runs on the MERGED program, not per load_dir: a by-name
    // callsite in one --cgf dir routinely names a contract defined in another.
    normalize_loaded(&mut prog);
    // coverage wave 1 §4.3: same reason — a client in one dir calls a route
    // defined in another. Before any analysis: phase 1 is identical either way
    // (httplink.rs), the link acts in phase 2 through the contract view.
    crate::httplink::link_loaded(&mut prog, http_link);
    Ok(prog)
}

/// What `taint` prints and when it fails.
struct Output {
    format: Format,
    fail_on: Option<String>,
    verbose: bool,
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
    /// `!--no-http-link`
    http_link: bool,
}

fn taint(
    cgf: &[PathBuf],
    catalog: Option<&std::path::Path>,
    endpoint: Option<&str>,
    pg: Option<&str>,
    store_dir: Option<&std::path::Path>,
    trace_path: Option<&std::path::Path>,
    trace_fn: Option<String>,
    trace_events: Option<&str>,
    no_error_leaf: bool,
    opts: TaintOpts,
    unmodeled: Option<&std::path::Path>,
    out: Output,
    threads: Option<u32>,
    verify_summaries: bool,
    verify_routes: bool,
) -> Result<()> {
    init_threads(threads);
    let (cat, cat_hash) = Catalog::open(catalog)?;
    // a typo must not run the whole analysis, nor let CI pass
    let fail_on = match out.fail_on.as_deref().map(|s| FailOn::parse(s, &cat)) {
        Some(Err(e)) => {
            eprintln!("error: {e}");
            std::process::exit(2);
        }
        Some(Ok(f)) => Some(f),
        None => None,
    };
    // Per-phase wall/RSS lines on stderr. One clock read per phase; the counts
    // on each line are the ones that explain that phase's memory.
    let t_load = std::time::Instant::now();
    let prog = load(cgf, opts.http_link)?;
    let callsites: usize = prog.funcs.values().filter_map(|f| f.flow.as_ref()).map(|fl| fl.callsites.len()).sum();
    crate::phase::end(
        "load",
        t_load,
        &[
            ("functions", prog.funcs.len().into()),
            ("packages", prog.packages.len().into()),
            ("callsites", callsites.into()),
        ],
    );
    // Loud failures (measurements 2026-09-01, 00-report §4): a catalog rule
    // that matches nothing and a callee with no body both used to produce
    // "no finding" indistinguishable from "nothing there". stderr, once per
    // run, before any analysis — a property of the inputs, not of a chain.
    catalog_fit_report(&cat, &prog, out.verbose);
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
    let t_summaries = std::time::Instant::now();
    let stats = match store_dir {
        Some(dir) => {
            let cat_hash = crate::summarystore::env_hash(&cat_hash, &env_flags);
            let mut store = SummaryStore::open(Some(dir), &cat_hash, 1_000_000)?;
            let stats = eng.run_with_store(&store);
            // The 1M-entry LRU is a second copy of many summaries. Nothing
            // reads `store` past this point (last use in this function; the
            // FS blobs are durable, hits/misses live in `stats`), so free it
            // BEFORE the phase meter reads RSS — the whole point of the
            // rss_now_bytes on the summaries line.
            store.free_lru();
            stats
        }
        None => {
            let mut store = SummaryStore::ephemeral();
            let stats = eng.run_with_store(&store);
            store.free_lru();
            stats
        }
    };
    if verify_summaries {
        let bad = eng.debug_verify_sequential();
        if bad.is_empty() {
            eprintln!("verify-summaries: 0 differences");
        } else {
            eprintln!("verify-summaries: {} DIFFERENCES", bad.len());
            for iid in bad.iter().take(8) {
                let fqn = prog
                    .funcs
                    .get(iid)
                    .map(|f| f.fqn.clone())
                    .unwrap_or_else(|| iid.clone());
                eprintln!("  {fqn}");
            }
        }
    }
    crate::phase::end(
        "summaries",
        t_summaries,
        &[
            ("functions", prog.funcs.len().into()),
            ("sccs", stats.sccs.into()),
            ("scc_ms", stats.scc_ms.into()),
            ("summaries", eng.summaries.len().into()),
            ("cache_hits", stats.hits.into()),
            ("cache_misses", stats.misses.into()),
        ],
    );
    // Remote contract views from PG for contracts no loaded CGF defines
    // (doc 18 B.3) — loaded AFTER phase 1 so cache environments stay identical.
    let leaves = match pg {
        Some(url) => {
            let t_leaves = std::time::Instant::now();
            let missing = crate::storage::missing_remote_contracts(&prog);
            let leaves = crate::storage::load_contract_views(url, &missing)?;
            crate::phase::end(
                "remote-leaves",
                t_leaves,
                &[("contracts", missing.len().into()), ("leaves", leaves.len().into())],
            );
            leaves
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
    let t_heap = std::time::Instant::now();
    let hs = crate::heap::fixpoint(&mut eng);
    crate::phase::end(
        "heap-fixpoint",
        t_heap,
        &[("cells", hs.cells.into()), ("iters", hs.iters.into())],
    );
    if hs.cells > 0 {
        eprintln!(
            "heap-cells: {} written, {} writers, {} cell-sinks, {} spliced, {} iters, {} resummarized",
            hs.cells, hs.writers, hs.cell_sinks, hs.spliced, hs.iters, hs.resummarized
        );
    }
    // cross-repo composition at invokes_remote, iterated to fixpoint (doc 17)
    let t_compose = std::time::Instant::now();
    let fx = compose::fixpoint_with_leaves(&mut eng, leaves);
    crate::phase::end(
        "compose",
        t_compose,
        &[
            ("summaries", eng.summaries.len().into()),
            ("contracts_linked", fx.linked.into()),
            ("remote_leaves", fx.remote_leaves.into()),
        ],
    );
    if let Some(url) = pg {
        let t_persist = std::time::Instant::now();
        let st = crate::storage::persist(&prog, &eng, url)?;
        crate::phase::end(
            "persist",
            t_persist,
            &[
                ("nodes", st.nodes.into()),
                ("edges", st.edges.into()),
                ("invokes", st.invokes.into()),
                ("endpoints", st.endpoints.into()),
            ],
        );
        eprintln!(
            "persisted nodes={} edges={} invokes={} endpoints={} to postgres",
            st.nodes, st.edges, st.invokes, st.endpoints
        );
    }
    let t_chains = std::time::Instant::now();
    let mut chains = report::intra_chains(&eng, endpoint, verify_routes);
    // --unmodeled pseudo-chains never reach stdout or the backward pass
    let unmodeled_calls = report::take_unmodeled(&mut chains);
    crate::phase::end(
        "chains",
        t_chains,
        &[
            ("chains", chains.len().into()),
            ("unmodeled", unmodeled_calls.len().into()),
        ],
    );
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
        // Flag-gated behaviour of the backward pass, passed through to the
        // pass (the pass stays a pure function of its options, so nothing
        // here touches a global).
        let bs = report::backward_check(
            &eng,
            &mut chains,
            backward::BackOpts {
                unview: opts.backward_unview,
                prune: opts.backward_prune,
                prune_unviewed: opts.backward_prune_unviewed,
            },
        );
        eprintln!(
            "backward: confirmed={} (exact={}, route-terminal-refuted={}) refuted={} undecided={} pruned={} unview-flips={} in {:.2}s",
            bs.confirmed,
            bs.confirmed_exact,
            bs.mislabelled,
            bs.refuted,
            bs.undecided,
            bs.pruned,
            bs.unview_flips,
            t0.elapsed().as_secs_f32()
        );
        crate::phase::end(
            "backward",
            t0,
            &[
                ("chains", chains.len().into()),
                ("confirmed", bs.confirmed.into()),
                ("refuted", bs.refuted.into()),
                ("undecided", bs.undecided.into()),
                ("pruned", bs.pruned.into()),
            ],
        );
    }
    if let Some(t) = &tr {
        t.flush();
    }
    let t_output = std::time::Instant::now();
    let rendered = output::render(out.format, &chains, &cat)?;
    println!("{}", rendered);
    crate::phase::end(
        "output",
        t_output,
        &[
            ("chains", chains.len().into()),
            ("bytes", rendered.len().into()),
        ],
    );
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
    if let Some(f) = fail_on {
        let n = f.count(&chains);
        if n > 0 {
            eprintln!("fail-on: {n} finding(s) in the listed classes");
            std::process::exit(3);
        }
    }
    Ok(())
}

/// `catalog-fit:` one line always; `catalog-warn:` one line per rule that
/// matches no callee fqn in the loaded CGF. Distinct callee fqns only, so the
/// cost is rules × distinct callees (broker corpus: ~50 × ~60k, well under a
/// second).
fn catalog_fit_report(cat: &Catalog, prog: &Program, verbose: bool) {
    let mut fqns: std::collections::HashSet<&str> = std::collections::HashSet::new();
    // (fqn, argc) — the arg-range check needs the width of the call, and
    // distinct pairs are enough for "was the index EVER in range".
    let mut calls: std::collections::HashSet<(&str, u32)> = std::collections::HashSet::new();
    // … and whether port 0 is a receiver, for a by-ref source's `to` ports
    let mut shapes: std::collections::HashSet<(&str, u32, bool)> = std::collections::HashSet::new();
    for f in prog.funcs.values() {
        if let Some(fl) = &f.flow {
            for cs in &fl.callsites {
                fqns.insert(cs.callee_fqn.as_str());
                calls.insert((cs.callee_fqn.as_str(), cs.argc));
                shapes.insert((cs.callee_fqn.as_str(), cs.argc, cs.arg0_is_receiver));
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
        if inert.is_empty() { "" } else { " — inert rules follow; docs/catalog.md explains these lines" }
    );
    if verbose {
        for (section, tag, label) in &inert {
            eprintln!("catalog-warn: inert rule {section}[{tag}] {label:?} — no call site matches it (zero recall here)");
        }
    } else if !inert.is_empty() {
        eprintln!(
            "catalog-warn: {} inert rules match no call site (list them with --verbose)",
            inert.len()
        );
    }
    // The other inertness: the NAME matches, so the rule counts as fitted
    // above, but the arg index is wider than any of those call sites.
    for (class, label, arg, max_argc) in cat.sink_arg_never_in_range(calls.iter().copied()) {
        eprintln!(
            "catalog-warn: sink rule [{class}] {label:?} arg {arg} never in range \
             (max argc seen {max_argc}) — it can never fire"
        );
    }
    // A by-ref source whose `to` ports no matched call has (coverage wave 1
    // §4.1): it can never seed what it claims to.
    for (kind, label, max_argc) in cat.source_to_never_in_range(shapes.iter().copied()) {
        eprintln!(
            "catalog-warn: source rule [{kind}] {label:?} `to` port never in range \
             (max argc seen {max_argc}) — it can never seed it"
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
        "opaque: {total} of {sites} call sites into a Go module or func value have no loaded body \
         (default leaf: taint passes through, sinks inside are not seen) — top modules: {}{}",
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

fn summary_dbg(
    cgf: &[PathBuf],
    catalog: Option<&std::path::Path>,
    fnpat: &str,
    threads: Option<u32>,
) -> Result<()> {
    init_threads(threads);
    let (cat, _) = Catalog::open(catalog)?;
    let prog = load(cgf, true)?;
    let mut eng = Engine::new(&prog, &cat);
    eng.run();
    // same phase-2 order taint uses, so `summary --fn` shows what the report
    // actually sees — without this a heap-mediated hit or a contract view
    // composed at an invokes_remote site is invisible to the one tool built
    // for diagnosing summaries.
    let hs = crate::heap::fixpoint(&mut eng);
    if hs.cells > 0 {
        eprintln!(
            "heap-cells: {} written, {} writers, {} cell-sinks, {} spliced, {} iters",
            hs.cells, hs.writers, hs.cell_sinks, hs.spliced, hs.iters
        );
    }
    // last phase-2 step, exactly like taint: the contract views composed at
    // invokes_remote sites are part of what the report sees
    compose::fixpoint(&mut eng);
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
                        h.via_heap.as_ref().map(|v| v.cell.clone()).unwrap_or_default(),
                        format!(
                            "{}@{}",
                            h.terminal.fn_iid, h.terminal.callsite
                        )
                    ))
                    .collect::<Vec<_>>()
            );
        }
        println!();
    }
    Ok(())
}

fn graph_dump(cgf: &[PathBuf]) -> Result<()> {
    use crate::proto::cgf::endpoint::Kind;
    let prog = load(cgf, true)?;
    let mut grpc = 0;
    let mut gql = 0;
    let mut http = 0;
    // Endpoint.kind census (coverage wave 1 §1: HTTP routes and MESSAGE
    // consumers joined gRPC and GraphQL). An undecodable kind is a newer
    // frontend's — counted, never coerced into a known one.
    let mut ep = [0usize; 5]; // grpc, graphql, http, message, unknown
    // packages per CgfPackage.language — the one place a mixed-language corpus
    // is visible at a glance (doc 36 §3.4). "" (pre-doc-36 CGF) reads as go.
    let mut langs: std::collections::BTreeMap<&str, usize> = Default::default();
    for p in &prog.packages {
        grpc += p.grpc_methods.len();
        gql += p.graphql_fields.len();
        http += p.http_routes.len();
        for e in &p.endpoints {
            ep[match Kind::try_from(e.kind) {
                Ok(Kind::Grpc) => 0,
                Ok(Kind::Graphql) => 1,
                Ok(Kind::Http) => 2,
                Ok(Kind::Message) => 3,
                Err(_) => 4,
            }] += 1;
        }
        let l = if p.language.is_empty() { "go" } else { p.language.as_str() };
        *langs.entry(l).or_default() += 1;
    }
    println!(
        "packages={} functions={} grpc_methods={} graphql_fields={} http_routes={} \
         endpoints={{grpc:{},graphql:{},http:{},message:{}{}}} languages={{{}}}",
        prog.packages.len(),
        prog.funcs.len(),
        grpc,
        gql,
        http,
        ep[0],
        ep[1],
        ep[2],
        ep[3],
        if ep[4] > 0 { format!(",unknown:{}", ep[4]) } else { String::new() },
        langs
            .iter()
            .map(|(l, n)| format!("{l}:{n}"))
            .collect::<Vec<_>>()
            .join(","),
    );
    Ok(())
}
