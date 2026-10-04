// Taint chains (JSON). A chain is a source→…→sink path, possibly spanning repos
// (doc 04 §6, doc 08). MVP: intra-repo chains from unconditional catalog sources;
// cross-repo hops are added by the composer (Phase 4) via invokes_remote.
use crate::ifds::{Engine, FnCtx};
use crate::proto::cgf;
use crate::witness::{self, Route, Walk};
use serde::Serialize;
use std::collections::HashMap;

#[derive(Serialize, Clone)]
pub struct Span {
    pub file: String,
    pub line: i32,
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
    })
}

/// Build intra-repo chains: functions whose body has an unconditional catalog
/// source that reaches a sink.
pub fn intra_chains(engine: &Engine, filter: Option<&str>) -> Vec<Chain> {
    // contract -> handler, so a route can descend across service boundaries.
    // Built once; a scan of the loaded packages.
    let handlers = witness::contract_handlers(engine.prog);
    let walk = Walk::new(engine, &handlers);
    let mut chains = Vec::new();
    for (iid, f) in &engine.prog.funcs {
        let flow = match &f.flow {
            Some(fl) => fl,
            None => continue,
        };
        let ctx = FnCtx::build(f, engine.cat);
        if ctx.source_seeds.is_empty() {
            continue;
        }
        if let Some(pat) = filter {
            if !f.fqn.contains(pat) {
                continue;
            }
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
            // Full route. `target` pins THIS sink, so two same-class sinks in
            // one function get two distinct routes.
            let route = walk.route(
                iid,
                &ctx.source_seeds,
                &sink.class,
                Some((sink.callsite, sink.last)),
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
                backward: None,
            });
        }
    }
    // A route that could not reproduce its sink from the narrowed fact fell back
    // to the widened one (witness.rs). That only happens when the chain depends
    // on pass-through widening, so the count sizes the residual false-positive
    // population — see doc 25 §3 R1. stderr, not the JSON: it is a property of
    // the run, not of any one chain.
    if walk.widened_routes() > 0 {
        eprintln!(
            "route-warn: {} descent(s) fell back to the widened fact (field-path widening)",
            walk.widened_routes()
        );
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
                    )
                };
                key(a).cmp(&key(b))
            })
    });
    chains
}

/// doc 35: run the sink-seeded backward confirmation over every reported chain
/// and attach its verdict. With `prune`, refuted chains are dropped — the only
/// place this pass ever removes a finding, and only behind its own flag.
pub fn backward_check(
    engine: &Engine,
    chains: &mut Vec<Chain>,
    prune: bool,
) -> crate::backward::BackStats {
    use crate::backward::{Back, BackStats, Verdict};
    let handlers = witness::contract_handlers(engine.prog);
    let back = Back::new(engine, &handlers);
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
    if prune {
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
type ChainKey = (String, String, String, String, i32, String);

fn chain_key(c: &Chain) -> ChainKey {
    let (file, line) = c
        .sink_span
        .as_ref()
        .map(|s| (s.file.clone(), s.line))
        .unwrap_or_default();
    (
        c.source_repo.clone(),
        c.source_fn.clone(),
        c.sink_class.clone(),
        file,
        line,
        c.route.as_ref().map(|r| r.id.clone()).unwrap_or_default(),
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
fn rep_rank(c: &Chain) -> (std::cmp::Reverse<usize>, String, Vec<String>, u32, usize) {
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
    )
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
            }),
            sink_field: sink_field.map(|s| s.into()),
            sink_fields: Vec::new(),
            hops: Vec::new(),
            route: Some(Route {
                id: route_id.into(),
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
