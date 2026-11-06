// Taint chains (JSON). A chain is a source→…→sink path, possibly spanning repos
// (doc 04 §6, doc 08). MVP: intra-repo chains from unconditional catalog sources;
// cross-repo hops are added by the composer (Phase 4) via invokes_remote.
use crate::graph::IidHex;
use crate::ifds::{Engine, FnCtx};
use crate::proto::cgf;
use crate::witness::{self, Route, Walk};
use rayon::prelude::*;
use serde::Serialize;
use std::collections::HashMap;

#[derive(Serialize, Clone)]
pub struct Span {
    pub file: String,
    pub line: i32,
    #[serde(skip_serializing_if = "is_zero")]
    pub col: i32,
}
fn is_zero(n: &i32) -> bool {
    *n == 0
}
#[derive(Serialize, Clone)]
pub struct Hop {
    pub repo: String,
    pub func: String,
    pub detail: String, // callee fqn at this hop
    pub span: Option<Span>,
    pub crossed_service_boundary: bool,
}
#[derive(Serialize, Clone)]
pub struct Chain {
    pub source_repo: String,
    pub source_fn: String,
    pub sink_class: String,
    pub sink_span: Option<Span>,
    /// field path of the fact arriving at the sink, when narrower than the
    /// whole object (doc 20 §2): names when emitted, else numeric ("3.1")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sink_field: Option<String>,
    /// Every field variant that reaches this sink by this route. Populated only
    /// when dedupe merged more than one (doc 24 N12): `propagate` fires once per
    /// tainted arg-port field variant, so `req.SortBy` and `req.SortOrder`
    /// travelling the identical route used to be two separate chains. They are
    /// one finding; this keeps both field identities.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub sink_fields: Vec<String>,
    /// Boundary-level summary: call sites in the SOURCE function only. Kept for
    /// existing consumers; `route` is the full function-by-function path.
    pub hops: Vec<Hop>,
    /// Complete route from source to sink, descending through callees and
    /// across service boundaries (doc 24 WS-A). None only if reconstruction
    /// could not run at all; a route that stops early carries `incomplete`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub route: Option<Route>,
    pub sanitized: bool,
    /// Product of dispatch confidences over the SOURCE function's call sites
    /// only (`hops` scope). Kept as-is for existing consumers.
    pub confidence: f32,
    /// Weakest hop of the full `route` (min over `route.hops[].confidence`).
    /// BUG-01 (measurements 2026-09-01): `confidence` never sees dispatch
    /// deeper than the source function, so 37 of 849 broker chains carried a
    /// sub-1.0 hop and every one reported 1.0; the one such chain in the
    /// verified sample was the batch's only dispatch FP. New field rather than
    /// a redefinition, so nothing keyed on `confidence` changes meaning. 1.0
    /// when there is no route.
    pub route_confidence: f32,
    /// iid of the source function — internal, so backward.rs can seed from it
    #[serde(skip)]
    pub source_iid: String,
    /// the call site in the source function this chain fired at (`PropSink`
    /// callsite; usize::MAX for a heap crossing) — internal, backward.rs
    #[serde(skip)]
    pub source_callsite: usize,
    /// terminal sink identity (fn iid, callsite in that fn) of the `PropSink`
    /// this chain came from — internal. Distinguishes chains whose routes are
    /// incomplete: those carry no `Route.terminal` (the walk stopped early),
    /// so two terminals that stop at the same partial hops would otherwise
    /// share a `chain_key` and merge.
    #[serde(skip)]
    pub sink_terminal: (String, usize),
    /// the firing vertex of the sink hit (`PropSink::last`) — internal. Two
    /// same-class sinks under one call site share (class, callsite, terminal)
    /// but fire at different vertices; this is what tells them apart.
    #[serde(skip)]
    pub sink_last: u32,
    /// doc 35: the sink-seeded backward confirmation of this chain. None unless
    /// `taint --backward` ran; then confirmed / refuted / undecided plus the
    /// source-side field the terminal actually reads.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub backward: Option<crate::backward::BackReport>,
}

/// One row of the `--unmodeled` report: a body-less library call that tainted
/// data reached and that could write into another of its arguments, with no
/// catalog propagator saying whether it does.
#[derive(Serialize)]
pub struct UnmodeledCall {
    /// the library callee — what a `[[propagators]]` selector should match
    pub callee: String,
    /// source→call routes reaching it (one per source function × call site)
    pub chains: usize,
    /// distinct call sites (file:line)
    pub call_sites: usize,
    /// distinct source functions (endpoints) whose data reaches it
    pub sources: usize,
    /// up to three example routes to open
    pub examples: Vec<UnmodeledExample>,
}
#[derive(Serialize)]
pub struct UnmodeledExample {
    pub source_fn: String,
    pub file: Option<String>,
    pub line: Option<i32>,
}

/// Split the `UNMODELED_CLASS` pseudo-chains out of `chains` and rank them by
/// callee: the ones on the most routes first. These are never findings — a
/// route that stops at an unmodeled call says "data may go somewhere the engine
/// cannot follow", which is a question for the catalog, not a vulnerability.
pub fn take_unmodeled(chains: &mut Vec<Chain>) -> Vec<UnmodeledCall> {
    use std::collections::{BTreeMap, BTreeSet};
    let (unmodeled, rest): (Vec<Chain>, Vec<Chain>) = std::mem::take(chains)
        .into_iter()
        .partition(|c| c.sink_class == crate::ifds::UNMODELED_CLASS);
    *chains = rest;
    #[derive(Default)]
    struct Acc {
        chains: usize,
        sites: BTreeSet<(Option<String>, Option<i32>)>,
        sources: BTreeSet<String>,
        examples: Vec<UnmodeledExample>,
    }
    let mut by: BTreeMap<String, Acc> = BTreeMap::new();
    for c in &unmodeled {
        // the route's terminal hop is the library call itself; a route that
        // could not be rebuilt falls back to the source function's own hop
        let (callee, file, line) = match c.route.as_ref().and_then(|r| r.hops.last()) {
            Some(h) if c.route.as_ref().map_or(false, |r| r.incomplete.is_none()) => {
                (h.callee.clone(), h.file.clone(), h.line)
            }
            _ => match c.hops.last() {
                Some(h) => (h.detail.clone(), h.span.as_ref().map(|s| s.file.clone()), h.span.as_ref().map(|s| s.line)),
                None => ("?".to_string(), None, None),
            },
        };
        let a = by.entry(callee).or_default();
        a.chains += 1;
        a.sites.insert((file.clone(), line));
        a.sources.insert(c.source_fn.clone());
        if a.examples.len() < 3 {
            a.examples.push(UnmodeledExample { source_fn: c.source_fn.clone(), file, line });
        }
    }
    let mut out: Vec<UnmodeledCall> = by
        .into_iter()
        .map(|(callee, a)| UnmodeledCall {
            callee,
            chains: a.chains,
            call_sites: a.sites.len(),
            sources: a.sources.len(),
            examples: a.examples,
        })
        .collect();
    out.sort_by(|x, y| y.chains.cmp(&x.chains).then_with(|| x.callee.cmp(&y.callee)));
    out
}

fn to_span(s: &Option<cgf::Span>) -> Option<Span> {
    s.as_ref().map(|sp| Span {
        file: sp.file.clone(),
        line: sp.line,
        col: sp.col,
    })
}

/// Build intra-repo chains: functions whose body has an unconditional catalog
/// source that reaches a sink.
pub fn intra_chains(engine: &Engine, filter: Option<&str>, verify_routes: bool) -> Vec<Chain> {
    // contract -> handler, so a route can descend across service boundaries.
    // Built once; a scan of the loaded packages.
    let handlers = witness::contract_handlers(engine.prog);
    // Source candidates in a sorted, content-determined order: (fqn, iid) —
    // both are content-derived, so every process and every --threads value
    // walks the same sequence. The parallel path concatenates per-source chain
    // vectors in exactly this order; the dedupe and the final sort below are
    // total orders, so the output would not depend on the order anyway.
    let mut cands: Vec<(&IidHex, &cgf::Function)> = engine
        .prog
        .funcs
        .iter()
        .filter(|(_, f)| f.flow.is_some())
        .filter(|(_, f)| filter.map_or(true, |pat| f.fqn.contains(pat)))
        .collect();
    cands.sort_by(|a, b| {
        (a.1.fqn.as_str(), a.0.as_str()).cmp(&(b.1.fqn.as_str(), b.0.as_str()))
    });
    // Debug: walk the sorted sources in REVERSE (PC_CHAIN_ORDER=reverse). A
    // route must be a pure function of (engine state, source iid, seeds, sink
    // class, SinkTarget) — independent of which routes the same Walk computed
    // before it. Reversal changes exactly that "before" set for every source
    // while leaving chunking alone, so a forward leak the chunk boundaries
    // happen to mask still shows up as a stdout diff between this run and the
    // normal one. Not part of the flag set because it exists to be set by
    // scripts, not typed by hand.
    if std::env::var("PC_CHAIN_ORDER").as_deref() == Ok("reverse") {
        cands.reverse();
    }

    let mut chains: Vec<Chain> = Vec::new();
    let mut wstats = witness::WalkStats::default();
    if rayon::current_num_threads() <= 1 {
        // Sequential fast path (--threads 1): one Walk over every source, so
        // its memos are shared across sources exactly as before.
        let mut walk = Walk::new(engine, &handlers);
        walk.quiet();
        for (iid, f) in &cands {
            chains.extend(chains_for_source(engine, &walk, iid, f));
        }
        wstats = walk.stats();
    } else {
        // One Walk per CHUNK of sources, on the global rayon pool. A Walk's
        // memos are RefCell maps behind `&self`, so a Walk is neither Send nor
        // Sync — each chunk builds its own and drops it with its memos, which
        // bounds the memo memory to ~thread-count live copies instead of the
        // one run-wide map the sequential path keeps. Memo sharing ACROSS
        // chunks is lost on purpose, and that is a cost (re-propagation),
        // never a route difference: the invariant is that a route is a pure
        // function of (engine state, source iid, seeds, sink class, SinkTarget),
        // and the Walk only memoises values that are pure functions of their
        // key — the FnCtx of a function, the PropResult of (iid, seeds). A memo
        // hit therefore always returns exactly what a fresh computation would;
        // what would break the invariant is memoising a CONTEXT-CUT result
        // (one computed under a depth budget, a visited set, or a partial
        // route), and no Walk memo does that.
        let chunk = (cands.len() / (rayon::current_num_threads() * 8)).max(1);
        let parts: Vec<(Vec<Chain>, witness::WalkStats)> = cands
            .par_chunks(chunk)
            .map(|srcs| {
                let mut walk = Walk::new(engine, &handlers);
                walk.quiet();
                let mut out = Vec::new();
                for (iid, f) in srcs {
                    out.extend(chains_for_source(engine, &walk, iid, f));
                }
                (out, walk.stats())
            })
            .collect();
        wstats = parts
            .iter()
            .fold(witness::WalkStats::default(), |mut a, (_, s)| {
                a.widened += s.widened;
                a.ctx_builds += s.ctx_builds;
                a.ctx_hits += s.ctx_hits;
                a.prop_runs += s.prop_runs;
                a.prop_hits += s.prop_hits;
                a.cands_tried += s.cands_tried;
                a.cand_capped += s.cand_capped;
                a
            });
        chains = parts.into_iter().flat_map(|(c, _)| c).collect();
    }
    // A route that could not reproduce its sink from the narrowed fact fell back
    // to the widened one (witness.rs). That only happens when the chain depends
    // on pass-through widening, so the count sizes the residual false-positive
    // population — see doc 25 §3 R1. stderr, not the JSON: it is a property of
    // the run, not of any one chain.
    if wstats.widened > 0 {
        eprintln!(
            "route-warn: {} descent(s) fell back to the widened fact (field-path widening)",
            wstats.widened
        );
    }
    // route-stats, one line, summed over every Walk that ran (per-Walk drops
    // are quiet). Same condition and format as the Walk Drop line.
    if wstats.ctx_builds > 0 || wstats.ctx_hits > 0 {
        eprintln!(
            "route-stats: fnctx {} built / {} memo-hit, propagate {} run / {} memo-hit, \
             dispatch candidates tried {}, fan-outs capped at {} {}",
            wstats.ctx_builds,
            wstats.ctx_hits,
            wstats.prop_runs,
            wstats.prop_hits,
            wstats.cands_tried,
            witness::MAX_DISPATCH_CANDIDATES,
            wstats.cand_capped
        );
    }
    // Debug (--verify-routes): recompute every chain's route with a FRESH Walk
    // (cold memos, nothing shared with the runs above) and compare it with the
    // route the shared/per-chunk Walk produced. A mismatch means some memo
    // served a value that depends on the visit context it was first computed
    // in — exactly the leak this flag exists to catch, since a fresh Walk
    // cannot have inherited any context. stderr, like verify-summaries: a
    // property of the run, not of any one chain.
    if verify_routes {
        // group the shared-Walk chains by source, first-appearance order
        let mut order: Vec<&IidHex> = Vec::new();
        let mut by_src: HashMap<&IidHex, Vec<&Chain>> = HashMap::new();
        for c in &chains {
            if !by_src.contains_key(&c.source_iid) {
                order.push(&c.source_iid);
            }
            by_src.entry(&c.source_iid).or_default().push(c);
        }
        // Pair by INDEX, not by identity: chains_for_source iterates the same
        // pure propagate result both times, so the k-th sink hit produces the
        // k-th chain on both sides — two hits can tie on every stored identity
        // field and still be distinct sink instances (heap rows from two
        // readers), which would break a key-based pairing.
        let mut bad = 0usize;
        let mut shown = 0usize;
        for iid in &order {
            let group = &by_src[*iid];
            let f = &engine.prog.funcs[*iid];
            let mut fresh = Walk::new(engine, &handlers);
            fresh.quiet();
            let fresh_chains = chains_for_source(engine, &fresh, iid, f);
            if fresh_chains.len() != group.len() {
                bad += 1;
                if shown < 8 {
                    eprintln!(
                        "verify-routes:   {} — chain count: shared={} fresh={}",
                        f.fqn,
                        group.len(),
                        fresh_chains.len()
                    );
                    shown += 1;
                }
                continue;
            }
            for (sc, fc) in group.iter().zip(fresh_chains.iter()) {
                if !route_eq(sc.route.as_ref(), fc.route.as_ref()) {
                    bad += 1;
                    if shown < 8 {
                        report_route_diff(sc, fc.route.as_ref());
                        shown += 1;
                    }
                }
            }
        }
        if bad == 0 {
            eprintln!("verify-routes: 0 differences");
        } else {
            eprintln!("verify-routes: {} DIFFERENCES", bad);
        }
    }
    let mut chains = dedupe(chains);
    // prog.funcs is a HashMap — sort so identical runs emit identical JSON.
    // The tail of the key (route id, sink field) makes this a TOTAL order: after
    // dedupe no two chains tie on all of it, so the result never depends on the
    // stable sort falling back to insertion order (which is hash-seed dependent).
    chains.sort_by(|a, b| {
        (&a.source_repo, &a.source_fn, &a.sink_class, a.hops.len())
            .cmp(&(&b.source_repo, &b.source_fn, &b.sink_class, b.hops.len()))
            .then_with(|| {
                let key = |c: &Chain| {
                    let span = c
                        .sink_span
                        .as_ref()
                        .map(|s| (s.file.clone(), s.line))
                        .unwrap_or_default();
                    (
                        span,
                        c.route.as_ref().map(|r| r.id.clone()).unwrap_or_default(),
                        c.sink_field.clone().unwrap_or_default(),
                        // same tail rule as chain_key: two terminals of the
                        // same class never tie, so the order never depends on
                        // the stable sort's insertion-order fallback
                        c.sink_terminal.0.clone(),
                        c.sink_terminal.1,
                    )
                };
                key(a).cmp(&key(b))
            })
    });
    chains
}

/// Full route equality for --verify-routes: every field the JSON carries.
/// Hops compare through their Debug rendering — RouteHop has no PartialEq,
/// and the Debug form covers all of its fields including hop kinds.
fn route_eq(a: Option<&Route>, b: Option<&Route>) -> bool {
    match (a, b) {
        (None, None) => true,
        (Some(a), Some(b)) => {
            a.id == b.id
                && a.fingerprint == b.fingerprint
                && a.boundaries == b.boundaries
                && format!("{:?}", a.incomplete) == format!("{:?}", b.incomplete)
                && a.hops.len() == b.hops.len()
                && a
                    .hops
                    .iter()
                    .zip(b.hops.iter())
                    .all(|(x, y)| format!("{x:?}") == format!("{y:?}"))
        }
        _ => false,
    }
}

/// One verify-routes example on stderr: source, class, and the FIRST place the
/// two routes part ways — a hop index with both renderings, or the ids when
/// only the id (line/col-sensitive) moved.
fn report_route_diff(shared: &Chain, fresh: Option<&Route>) {
    let head = format!("verify-routes:   {} class={}", shared.source_fn, shared.sink_class);
    let Some(sr) = shared.route.as_ref() else {
        eprintln!("{head} — shared route missing");
        return;
    };
    let Some(fr) = fresh else {
        eprintln!("{head} — fresh route missing");
        return;
    };
    for (i, (x, y)) in sr.hops.iter().zip(fr.hops.iter()).enumerate() {
        if format!("{x:?}") != format!("{y:?}") {
            eprintln!("{head} — hop {i}: shared={x:?} fresh={y:?}");
            return;
        }
    }
    if sr.hops.len() != fr.hops.len() {
        eprintln!(
            "{head} — hop count: shared={} fresh={}",
            sr.hops.len(),
            fr.hops.len()
        );
        return;
    }
    eprintln!("{head} — id {} vs {} (hops equal)", sr.id, fr.id);
}

/// Chains from ONE source function — the unit of work of the chains phase,
/// run sequentially or on a rayon worker (`intra_chains`). Pure function of
/// (engine state, handlers, this function), so per-source results are
/// independent of which worker runs them and in what order.
fn chains_for_source<'a, 'e>(
    engine: &'a Engine<'e>,
    walk: &Walk<'a, 'e>,
    iid: &IidHex,
    f: &cgf::Function,
) -> Vec<Chain> {
    let flow = match &f.flow {
        Some(fl) => fl,
        None => return Vec::new(),
    };
    let ctx = FnCtx::build(f, engine.cat);
    if ctx.source_seeds.is_empty() {
        return Vec::new();
    }
    crate::trace_ev!(
        engine.trace,
        "seed",
        &f.fqn,
        "seed      fn={} vertices={:?}",
        f.fqn,
        ctx.source_seeds
    );
    let r = engine.propagate(f, &ctx, &ctx.source_seeds);
    let repo = engine.prog.repo_of.get(iid).cloned().unwrap_or_default();

    // vertex -> callsite id (for hop labelling)
    let mut vcs: HashMap<u32, usize> = HashMap::new();
    for v in &flow.vertices {
        if v.kind == cgf::VertexKind::CallArgPort as i32
            || v.kind == cgf::VertexKind::CallResultPort as i32
        {
            vcs.insert(v.id, v.callsite_id as usize);
        }
    }

    let mut chains = Vec::new();
    for sink in &r.sinks {
        // backtrace vertex path sink.last -> seed via pred
        let mut path = vec![sink.last];
        let mut cur = sink.last;
        let mut guard = 0;
        while let Some(&p) = r.pred.get(&cur) {
            path.push(p);
            cur = p;
            guard += 1;
            if guard > 10_000 {
                break;
            }
        }
        path.reverse();

        let mut hops = Vec::new();
        let mut seen_cs = std::collections::HashSet::new();
        // Product of per-site dispatch confidences over the source-fn call
        // sites on the path (intra_chains labels hops in the source function
        // only). 0.0 = unset (legacy CGF / proto3 default) => treat as 1.0.
        let mut confidence: f32 = 1.0;
        for &v in &path {
            if let Some(&cs_idx) = vcs.get(&v) {
                if seen_cs.insert(cs_idx) {
                    let cs = &flow.callsites[cs_idx];
                    if cs.dispatch_confidence > 0.0 {
                        confidence *= cs.dispatch_confidence;
                    }
                    hops.push(Hop {
                        repo: repo.clone(),
                        func: f.fqn.clone(),
                        detail: cs.callee_fqn.clone(),
                        span: to_span(&cs.span),
                        crossed_service_boundary: cs.kind
                            == cgf::call_site::Kind::InvokesRemote as i32,
                    });
                }
            }
        }
        crate::trace_ev!(
            engine.trace,
            "chain",
            &f.fqn,
            "chain     src={} sink={} hops={} conf={}",
            f.fqn,
            sink.class,
            hops.len(),
            confidence
        );
        let sink_field = flow.vertices.iter().find(|v| v.id == sink.last).and_then(|v| {
            if v.field_path.is_empty() {
                None
            } else if v.field_names.len() == v.field_path.len() {
                Some(v.field_names.join("."))
            } else {
                Some(
                    v.field_path
                        .iter()
                        .map(|i| i.to_string())
                        .collect::<Vec<_>>()
                        .join("."),
                )
            }
        });
        // Full route. The target pins THIS sink instance: the (callsite,
        // firing vertex) pin at the entry frame, and the terminal sink
        // identity at every level below — so two same-class sinks under one
        // call site (even two levels down) get two distinct routes.
        let route = walk.route(
            iid,
            &ctx.source_seeds,
            &sink.class,
            Some(witness::SinkTarget {
                at: Some((sink.callsite, sink.last)),
                terminal: sink.terminal.clone(),
            }),
        );
        // 0.0 = unset (legacy) => 1.0, same convention as the source-fn product.
        let route_confidence = route
            .hops
            .iter()
            .map(|h| h.confidence)
            .filter(|c| *c > 0.0)
            .fold(1.0f32, f32::min);
        chains.push(Chain {
            source_repo: repo.clone(),
            source_fn: f.fqn.clone(),
            sink_class: sink.class.clone(),
            sink_span: to_span(&sink.span),
            sink_field,
            sink_fields: Vec::new(),
            hops,
            route: Some(route),
            sanitized: false,
            confidence,
            route_confidence,
            source_iid: iid.clone(),
            source_callsite: sink.callsite,
            sink_terminal: (sink.terminal.fn_iid.clone(), sink.terminal.callsite),
            sink_last: sink.last,
            backward: None,
        });
    }
    chains
}

/// doc 35: run the sink-seeded backward confirmation over every reported chain
/// and attach its verdict. With `prune` (also `opts.prune`), refuted chains are
/// dropped — the only place this pass ever removes a finding, and only behind
/// its own flag.
///
/// Deliberately SEQUENTIAL at every thread count. A `Back` memoises walks per
/// (function, demand) and (function, sink, terminal), and a memo entry's
/// content depends on the DEPTH BUDGET left when it was first computed
/// (`MAX_DEPTH`) — so a chain's verdict can depend on which chains ran before
/// it in the same `Back`. Sharding chains over threads would change which
/// sub-walk a fresh memo computes first, and 21 of broker-v1's 3007 chains
/// flipped `exact` under a chunked `Back` (verdicts stable, but the JSON is
/// not byte-stable). The memo wins are exactly what would be lost anyway.
pub fn backward_check(
    engine: &Engine,
    chains: &mut Vec<Chain>,
    opts: crate::backward::BackOpts,
) -> crate::backward::BackStats {
    use crate::backward::{Back, BackStats, Verdict};
    let handlers = witness::contract_handlers(engine.prog);
    let back = Back::new(engine, &handlers, opts);
    let mut st = BackStats::default();
    for c in chains.iter_mut() {
        let r = back.check(&c.source_iid, &c.sink_class, c.source_callsite, c.route.as_ref());
        match r.verdict {
            Verdict::Confirmed => {
                st.confirmed += 1;
                if r.exact {
                    st.confirmed_exact += 1;
                }
                if r.terminal == Some(Verdict::Refuted) {
                    st.mislabelled += 1;
                }
            }
            Verdict::Refuted => st.refuted += 1,
            Verdict::Undecided => st.undecided += 1,
        }
        c.backward = Some(r);
    }
    st.unview_flips = back.flips();
    if opts.prune {
        let before = chains.len();
        chains.retain(|c| {
            c.backward
                .as_ref()
                .map_or(true, |b| b.verdict != Verdict::Refuted)
        });
        st.pruned = before - chains.len();
    }
    st
}

/// One entry per (source function, sink, route). `sink_field` is deliberately
/// NOT in the key: `propagate` emits one `PropSink` per tainted arg-port field
/// variant and `intra_chains` emits one chain per `PropSink`, so the same
/// logical flow becomes several chains that differ only in which field of the
/// request travelled — on a large service one route was emitted 20 times
/// N12). Those are one finding, and merging them is lossless: every variant is
/// preserved in `sink_fields` and `RouteHop.fields`.
type ChainKey = (String, String, String, String, i32, String, String, usize);

fn chain_key(c: &Chain) -> ChainKey {
    let (file, line) = c
        .sink_span
        .as_ref()
        .map(|s| (s.file.clone(), s.line))
        .unwrap_or_default();
    // Two chains to different terminals of the same class end in different
    // hops, so their route ids already differ; the terminal is still part of
    // the key so a route-id collision could never merge two chains that end at
    // different sinks. Taken from the chain's own `PropSink`, not the route:
    // an incomplete route carries no terminal, and two terminals that stop at
    // the same partial hops then share a route id.
    let (term_fn, term_cs) = c.sink_terminal.clone();
    (
        c.source_repo.clone(),
        c.source_fn.clone(),
        c.sink_class.clone(),
        file,
        line,
        c.route.as_ref().map(|r| r.id.clone()).unwrap_or_default(),
        term_fn,
        term_cs,
    )
}

/// Ranks the members of a dedupe group; the minimum survives. NARROWEST field
/// variant first (most path segments — precision is not lost to the merge),
/// then a total order over everything else that can differ within a group.
///
/// That tail matters: the order `propagate` produces sinks in derives from a
/// HashSet walk (ifds.rs:624) and Rust reseeds hashes per process, so a
/// representative chosen by "first seen" would make the JSON differ run to run.
/// `e2e-route.sh` gates exactly that.
fn rep_rank(c: &Chain) -> (std::cmp::Reverse<usize>, String, Vec<String>, u32, usize, String) {
    let f = c.sink_field.clone().unwrap_or_default();
    let depth = if f.is_empty() { 0 } else { f.split('.').count() };
    let hop_fields = c
        .route
        .as_ref()
        .map(|r| {
            r.hops
                .iter()
                .map(|h| h.field.clone().unwrap_or_default())
                .collect()
        })
        .unwrap_or_default();
    (
        std::cmp::Reverse(depth),
        f,
        hop_fields,
        c.confidence.to_bits(),
        c.hops.len(),
        // Total-order tail. Everything above can still tie inside a dedupe
        // group: chain_key carries route_id, which deliberately excludes hop
        // `file`/`col`, and it says nothing about sink_span.col, the source-fn
        // `hops` spans, route_confidence or the fingerprint. A tie used to fall
        // to "first seen" — and the chains Vec's order follows the funcs
        // HashMap's per-process iteration, so the surviving JSON differed run
        // to run. Serialize the remaining content to make the choice a total
        // order on the chain itself.
        content_key(c),
    )
}

/// Canonical serialization of every Chain field the earlier rep_rank components
/// do not cover. Any difference inside a dedupe group breaks the tie here.
fn content_key(c: &Chain) -> String {
    let span = |s: &Option<Span>| {
        s.as_ref()
            .map(|s| format!("{}/{}/{}", s.file, s.line, s.col))
            .unwrap_or_default()
    };
    let mut k = String::with_capacity(256);
    k.push_str(&span(&c.sink_span));
    for h in &c.hops {
        k.push('\u{1}');
        k.push_str(&h.repo);
        k.push('\u{1}');
        k.push_str(&h.func);
        k.push('\u{1}');
        k.push_str(&h.detail);
        k.push('\u{1}');
        k.push_str(&span(&h.span));
        k.push('\u{1}');
        k.push_str(if h.crossed_service_boundary { "1" } else { "0" });
    }
    if let Some(r) = &c.route {
        k.push('\u{2}');
        k.push_str(&r.fingerprint);
        k.push('\u{1}');
        k.push_str(&format!("{:?}", r.incomplete));
        for h in &r.hops {
            k.push('\u{1}');
            k.push_str(h.file.as_deref().unwrap_or(""));
            k.push('\u{1}');
            k.push_str(&h.line.unwrap_or(-1).to_string());
            k.push('\u{1}');
            k.push_str(&h.col.unwrap_or(-1).to_string());
            k.push('\u{1}');
            k.push_str(&h.field.clone().unwrap_or_default());
        }
    }
    k.push('\u{2}');
    k.push_str(&c.route_confidence.to_bits().to_string());
    k.push('\u{1}');
    k.push_str(&c.source_iid);
    k.push('\u{1}');
    k.push_str(&c.source_callsite.to_string());
    k.push('\u{1}');
    k.push_str(&format!("{:?}", c.sink_terminal));
    k.push('\u{1}');
    k.push_str(if c.sanitized { "1" } else { "0" });
    k
}

fn dedupe(chains: Vec<Chain>) -> Vec<Chain> {
    use std::collections::BTreeSet;
    // (representative, all sink_field variants, per-hop field variants)
    let mut reps: Vec<(Option<Chain>, BTreeSet<String>, Vec<BTreeSet<String>>)> = Vec::new();
    let mut at: HashMap<ChainKey, usize> = HashMap::new();

    for c in chains {
        let key = chain_key(&c);
        let idx = match at.get(&key) {
            Some(&i) => i,
            None => {
                at.insert(key, reps.len());
                let nhops = c.route.as_ref().map(|r| r.hops.len()).unwrap_or(0);
                reps.push((None, BTreeSet::new(), vec![BTreeSet::new(); nhops]));
                reps.len() - 1
            }
        };
        // Accumulate this member's field identity before deciding who survives,
        // so the merge is independent of which member wins.
        let chf: Vec<Option<String>> = c
            .route
            .as_ref()
            .map(|r| r.hops.iter().map(|h| h.field.clone()).collect())
            .unwrap_or_default();
        let (rep, fields, hop_fields) = &mut reps[idx];
        if let Some(f) = c.sink_field.clone() {
            fields.insert(f);
        }
        // Hop counts agree by construction (same route id ⇒ same hop sequence);
        // a mismatch would mean a route-id collision, so degrade, never panic.
        if chf.len() == hop_fields.len() {
            for (set, f) in hop_fields.iter_mut().zip(chf) {
                if let Some(f) = f {
                    set.insert(f);
                }
            }
        }
        match rep {
            Some(r) if rep_rank(r) <= rep_rank(&c) => {}
            _ => *rep = Some(c),
        }
    }

    reps.into_iter()
        .filter_map(|(rep, fields, hop_fields)| Some((rep?, fields, hop_fields)))
        .map(|(mut rep, fields, hop_fields)| {
            if fields.len() > 1 {
                rep.sink_fields = fields.into_iter().collect();
            }
            if let Some(route) = rep.route.as_mut() {
                if route.hops.len() == hop_fields.len() {
                    for (hop, set) in route.hops.iter_mut().zip(hop_fields) {
                        if set.len() > 1 {
                            hop.fields = set.into_iter().collect();
                        }
                    }
                }
            }
            rep
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::witness::{HopKind, Route, RouteHop};

    fn hop(field: Option<&str>) -> RouteHop {
        RouteHop {
            repo: "r".into(),
            func: "f".into(),
            file: Some("a.go".into()),
            line: Some(10),
            col: None,
            kind: HopKind::Source,
            callee: String::new(),
            field: field.map(|s| s.into()),
            fields: Vec::new(),
            confidence: 1.0,
        }
    }

    /// `route_id` hashes repo/func/callee/line/kind and NOT the field, so field
    /// variants of one flow share an id by construction — that is what makes
    /// them a dedupe group.
    fn chain(sink_field: Option<&str>, route_id: &str, line: i32) -> Chain {
        Chain {
            source_repo: "r".into(),
            source_fn: "f".into(),
            sink_class: "sqli".into(),
            sink_span: Some(Span {
                file: "a.go".into(),
                line,
                col: 0,
            }),
            sink_field: sink_field.map(|s| s.into()),
            sink_fields: Vec::new(),
            hops: Vec::new(),
            route: Some(Route {
                id: route_id.into(),
                fingerprint: String::new(),
                hops: vec![hop(None), hop(sink_field)],
                incomplete: None,
                boundaries: 0,
                terminal: None,
            }),
            sanitized: false,
            confidence: 1.0,
            route_confidence: 1.0,
            source_iid: String::new(),
            source_callsite: 0,
            sink_terminal: (String::new(), 0),
            sink_last: 0,
            backward: None,
        }
    }

    #[test]
    fn field_variants_of_one_route_collapse_to_one_chain() {
        let out = dedupe(vec![
            chain(Some("SortBy"), "aaa", 10),
            chain(Some("SortOrder"), "aaa", 10),
            chain(Some("SortBy"), "aaa", 10), // exact duplicate
        ]);
        assert_eq!(out.len(), 1);
        // Lossless: every variant survives, at the chain AND at the hop that
        // carried it. Dropping one would silently hide a tainted field.
        assert_eq!(out[0].sink_fields, vec!["SortBy", "SortOrder"]);
        assert_eq!(out[0].route.as_ref().unwrap().hops[1].fields,
                   vec!["SortBy", "SortOrder"]);
        // The hop that never carried a field stays clean.
        assert!(out[0].route.as_ref().unwrap().hops[0].fields.is_empty());
    }

    #[test]
    fn single_variant_leaves_the_lists_empty() {
        let out = dedupe(vec![chain(Some("SortBy"), "aaa", 10)]);
        assert_eq!(out.len(), 1);
        assert!(out[0].sink_fields.is_empty(), "no merge => no list to serialize");
        assert!(out[0].route.as_ref().unwrap().hops[1].fields.is_empty());
    }

    #[test]
    fn narrowest_variant_survives() {
        // "a.b" is narrower than "a", which is narrower than the whole object.
        let out = dedupe(vec![
            chain(None, "aaa", 10),
            chain(Some("a.b"), "aaa", 10),
            chain(Some("a"), "aaa", 10),
        ]);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].sink_field.as_deref(), Some("a.b"));
        assert_eq!(out[0].sink_fields, vec!["a", "a.b"]);
    }

    #[test]
    fn distinct_routes_and_distinct_sinks_are_kept() {
        // different route id => a genuinely different path to the same sink
        let out = dedupe(vec![chain(Some("x"), "aaa", 10), chain(Some("x"), "bbb", 10)]);
        assert_eq!(out.len(), 2, "distinct routes must not merge");
        // same route id, different sink span => two sinks in one function
        let out = dedupe(vec![chain(Some("x"), "aaa", 10), chain(Some("x"), "aaa", 20)]);
        assert_eq!(out.len(), 2, "distinct sink spans must not merge");
    }

    #[test]
    fn representative_does_not_depend_on_input_order() {
        // propagate's sink order derives from a HashSet walk and Rust reseeds
        // hashes per process, so a "first seen wins" rule would make the JSON
        // differ run to run. e2e-route.sh gates exactly this.
        let a = chain(Some("SortBy"), "aaa", 10);
        let b = chain(Some("SortOrder"), "aaa", 10);
        let fwd = dedupe(vec![a.clone(), b.clone()]);
        let rev = dedupe(vec![b, a]);
        assert_eq!(
            serde_json::to_string(&fwd).unwrap(),
            serde_json::to_string(&rev).unwrap()
        );
    }

    #[test]
    fn hop_count_mismatch_degrades_instead_of_panicking() {
        // Only reachable via a route-id collision, but a 12-hex id is not a
        // proof, and a panic here would take down the whole run.
        let mut short = chain(Some("y"), "aaa", 10);
        short.route.as_mut().unwrap().hops.truncate(1);
        let out = dedupe(vec![chain(Some("x"), "aaa", 10), short]);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].sink_fields, vec!["x", "y"]);
    }
}
