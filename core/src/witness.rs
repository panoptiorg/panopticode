// Witness reconstruction (doc 24 §5 WS-A / finding N2).
//
// A summary records "dirty in -> dirty out"; the witness path that justified it
// lives in `propagate`'s local `pred` map and dies when propagate returns. So
// `report::intra_chains` could only ever label hops inside the SOURCE function
// (its `vcs` index is built from that one function's vertices), which made a
// cross-repo chain "there is a chain, it crossed this boundary, there is a sink
// somewhere" — unusable as LLM audit context or for a human reviewer.
//
// This module re-derives the route TOP-DOWN after the fixpoint. The key enabler
// is that `SinkHit` already carries the callee-internal callsite and its span
// (ifds.rs:148-154): at a call site we know the tainted arg, hence the callee's
// in-slot, hence which of the callee's summary rows fired. So we can descend:
//
//   propagate(F, seeds) -> the local vertex path to the arg port that fired
//     |  the fired row is a catalog sink at this call site  => TERMINAL, real span
//     |  the fired row came from a callee summary sink_hit  => descend into the
//     |    callee, seeded by that sink_hit's in_slot, chasing the same class
//     \  at an invokes_remote site the callee iid IS the contract iid, which
//        compose aliased to the handler's summary — map contract -> handler and
//        keep descending, which is what crosses the service boundary
//
// Cost is O(path length x per-function propagation), NOT O(program). Every
// summary is already in memory and LocalFlow edges are pre-closed in the Go
// frontend, so each level is cheap. Nothing is recorded during phase 1, so the
// cache-soundness discipline of ifds.rs:207-215 is untouched.
use crate::compose::ContractShape;
use crate::graph::{hexid, IidHex, Program};
use crate::ifds::{
    arg_to_callee_slot, compose_path, residual_after, slot_compat, slot_str, stream_of, Engine,
    FnCtx, PropResult, Slot, SlotP,
};
use crate::proto::cgf;
use serde::Serialize;
use std::cell::{Cell, RefCell};
use std::collections::{HashMap, HashSet};
use std::rc::Rc;

/// contract iid -> (handler iid, contract shape).
///
/// The inverse of the `handler_of` map compose::fixpoint_with_leaves builds
/// internally (compose.rs). Rebuilt here from the packages rather than
/// threaded out of compose, so witness reconstruction stays independent of the
/// composer's internals — but from the SAME enumeration (`graph::contracts`),
/// so the two agree on every key. Covers gRPC methods, GraphQL fields and HTTP
/// routes alike — the descent has to undo whichever view compose published.
pub type ContractHandlers = HashMap<IidHex, (IidHex, ContractShape)>;

pub fn contract_handlers(prog: &Program) -> ContractHandlers {
    crate::graph::contracts(prog)
        .into_iter()
        .map(|c| (c.key, (c.handler, c.shape)))
        .collect()
}

#[derive(Serialize, Clone, Copy, PartialEq, Eq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum HopKind {
    /// where untrusted data enters (gRPC request param, GraphQL arg, Recv)
    Source,
    /// an intra-repo call the taint passes through
    Call,
    /// an invokes_remote call site — crosses a service boundary
    Boundary,
    /// the sink itself, at its real location
    Sink,
    /// W1F: the value is parked in an abstract heap cell here and picked up by
    /// a function this frame never calls (the epool `Submit` ⇢ `runBatcher`
    /// shape). `func`/`file`/`line` are the WRITE site, `callee` names the cell,
    /// and the next hop is inside the reader. Distinct from Call on purpose: a
    /// consumer must be able to tell "control flows here" from "a goroutine
    /// picks this up later", and an LLM auditing the route must not read it as
    /// a call it can follow in the source.
    Heap,
}

#[derive(Serialize, Clone, Debug)]
pub struct RouteHop {
    pub repo: String,
    pub func: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line: Option<i32>,
    pub kind: HopKind,
    /// callee fqn at this hop (empty for source/sink terminals)
    #[serde(skip_serializing_if = "String::is_empty")]
    pub callee: String,
    /// field path of the fact at this hop — names when the frontend emitted
    /// them, else numeric ("3.1"). This is what lets a consumer classify the
    /// data (doc 24 §5: the LLM labels the field, we only identify it).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub field: Option<String>,
    /// Every field variant seen at this hop across the chains merged into this
    /// one (doc 24 N12 dedupe). Empty unless a merge found more than one — then
    /// `field` is the narrowest of these, and this is the complete set, so
    /// collapsing duplicates never loses field identity.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub fields: Vec<String>,
    pub confidence: f32,
}

/// Why a route stopped before reaching a terminal sink. Never silent — a
/// consumer must be able to tell a complete route from a truncated one.
#[derive(Serialize, Clone, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Incomplete {
    /// hit the depth cap
    DepthCap,
    /// a cycle in the descent (recursive/mutually-recursive functions)
    Cycle,
    /// the boundary's handler is not in this analysis (PG leaf / unanalyzed repo)
    HandlerNotLoaded,
    /// the callee has a summary sink_hit but no body we can descend into
    CalleeBodyMissing,
    /// re-propagation did not reproduce the sink (should not happen; a bug
    /// signal rather than a silent short route)
    NotReproduced,
}

#[derive(Serialize, Clone, Debug)]
pub struct Route {
    /// Content id of the hop sequence — stable across runs for an unchanged
    /// route, so a consumer can cache it, diff two analyses, or let an LLM
    /// reference one route out of many (doc 24 WS-A).
    pub id: String,
    pub hops: Vec<RouteHop>,
    /// None = the route reaches its sink; Some(_) = it stops early, with why
    #[serde(skip_serializing_if = "Option::is_none")]
    pub incomplete: Option<Incomplete>,
    /// how many service boundaries the route crosses
    pub boundaries: usize,
    /// The frame and call site of the terminal Sink hop — the sink INSTANCE
    /// this route ends at. Internal: backward.rs keys its demand walk on it.
    /// None iff the route is incomplete.
    #[serde(skip)]
    pub terminal: Option<(IidHex, usize)>,
}

pub const DEFAULT_MAX_DEPTH: usize = 32;

/// The tail of a caller's field path that the summary row it fired did not
/// consume (`ifds::residual_after`). Carrying it is what stops a fact from
/// reading as whole-object after a pass-through frame — doc 25 §3 R1.
///
/// `names` is reporting-only and follows the proto's own convention: either the
/// same length as `path`, or empty, in which case the path renders numerically.
#[derive(Clone, Default, Debug, PartialEq)]
pub struct Residual {
    path: Vec<u32>,
    names: Vec<String>,
}

impl Residual {
    fn is_empty(&self) -> bool {
        self.path.is_empty()
    }

    /// `declared ++ self`, with names composed only when BOTH sides are fully
    /// named (else the numeric rendering is the honest one).
    fn compose(&self, declared: &[u32], dnames: &[String]) -> (Vec<u32>, Vec<String>) {
        let path = compose_path(declared, &self.path);
        let names = if path.len() == declared.len() {
            dnames.to_vec() // residual dropped (k-guard or empty)
        } else if dnames.len() == declared.len() && self.names.len() == self.path.len() {
            dnames.iter().chain(self.names.iter()).cloned().collect()
        } else {
            Vec::new()
        };
        (path, names)
    }

    /// What is left of `(path, names)` after a row keyed on `matched` fired.
    fn after(matched: &[u32], path: &[u32], names: &[String]) -> Residual {
        let tail = residual_after(matched, path);
        let names = if !tail.is_empty() && names.len() == path.len() {
            names[path.len() - tail.len()..].to_vec()
        } else {
            Vec::new()
        };
        Residual { path: tail, names }
    }
}

/// B3: how many callees of one dispatch fan-out a descent will try before it
/// gives up. Interface sites can carry dozens of implementations and each
/// candidate costs a full sub-descent, so the retry is bounded rather than
/// exhaustive. 8 is well past every fan-out the golden corpus produces; when it
/// bites, `WalkStats::cand_capped` says so instead of the run going quiet.
pub const MAX_DISPATCH_CANDIDATES: usize = 8;

/// Per-run witness counters — cost (memo effectiveness) and reach (how much of
/// a dispatch fan-out the descent had to walk). Printed once when a `Walk` is
/// dropped; also readable programmatically.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct WalkStats {
    /// descents that fell back to the widened fact (see `Walk::widened`)
    pub widened: usize,
    pub ctx_hits: usize,
    pub ctx_builds: usize,
    pub prop_hits: usize,
    pub prop_runs: usize,
    /// dispatch candidates entered (>= routes, == routes when nothing retries)
    pub cands_tried: usize,
    /// call sites whose fan-out exceeded `MAX_DISPATCH_CANDIDATES`
    pub cand_capped: usize,
}

pub struct Walk<'a, 'e> {
    engine: &'a Engine<'e>,
    handlers: &'a ContractHandlers,
    max_depth: usize,
    /// How many descents narrowed by a residual failed to reach their sink and
    /// had to fall back to the widened fact. A fallback means the chain exists
    /// ONLY because of pass-through widening, so this count estimates the
    /// chain-level (false-positive) population without doing that work.
    widened: Cell<usize>,
    /// Set by the descent that emits the Sink hop; read back by `route`.
    terminal: RefCell<Option<(IidHex, usize)>>,
    /// B1 memo: `FnCtx` is a pure function of (function, catalog), both fixed
    /// for the life of a `Walk`, yet every level of every chain rebuilt it.
    /// Same shape as `backward.rs`'s `ctxs`.
    ctxs: RefCell<HashMap<IidHex, Rc<FnCtx>>>,
    /// B1 memo: `propagate` is a pure function of (function, ctx, seeds) plus
    /// the engine's summaries and heap cells, which a `Walk` never mutates.
    ///
    /// Keyed on the seed sequence EXACTLY as given, not on the seed set: seeds
    /// are pushed onto propagate's worklist in order, so two orderings of the
    /// same set can produce different `pred` maps and therefore different local
    /// hops. Every producer (`seeds_for_slot`) already sorts, so this costs no
    /// hits in practice and makes the memo provably route-identical.
    props: RefCell<HashMap<(IidHex, String), Rc<PropResult>>>,
    stats: Cell<WalkStats>,
    /// HTTP contract key -> how its crossing renders (`http GET /x/{id} (chi)`).
    /// The client site's own `callee_fqn` is its TEMPLATE, which after a suffix
    /// or fan-out link is not the route the descent actually enters
    /// (coverage wave 1 §4.4).
    http_labels: HashMap<IidHex, String>,
}

impl<'a, 'e> Walk<'a, 'e> {
    pub fn new(engine: &'a Engine<'e>, handlers: &'a ContractHandlers) -> Self {
        Walk {
            engine,
            handlers,
            max_depth: DEFAULT_MAX_DEPTH,
            widened: Cell::new(0),
            terminal: RefCell::new(None),
            ctxs: RefCell::new(HashMap::new()),
            props: RefCell::new(HashMap::new()),
            stats: Cell::new(WalkStats::default()),
            http_labels: crate::graph::contracts(engine.prog)
                .into_iter()
                .filter_map(|c| Some((c.key, c.http?.label)))
                .collect(),
        }
    }

    /// `unview_slot`, except that an HTTP view folded SEVERAL handler params
    /// onto the client's one port: re-enter at the first request param whose
    /// rows actually carry a `class` sink for this fact, so the descent starts
    /// where the summary says the sink is. `unview_slot` alone takes the first
    /// request param, which is right whenever there is only one.
    fn unview_for(&self, s: &SlotP, shape: &ContractShape, handler: &IidHex, class: &str) -> SlotP {
        if let (ContractShape::Http { request_params }, Slot::Param(0)) = (shape, &s.slot) {
            if let Some(sum) = self.engine.summaries.get(handler) {
                for &p in request_params {
                    let cand = SlotP { slot: Slot::Param(p), path: s.path.clone() };
                    if sum.sink_hits.iter().any(|h| h.class == class && slot_compat(&h.in_slot, &cand)) {
                        return cand;
                    }
                }
            }
        }
        unview_slot(s, shape)
    }

    /// Routes that fell back to the widened fact — see `Walk::widened`.
    pub fn widened_routes(&self) -> usize {
        self.widened.get()
    }

    /// Cost/reach counters for this walk.
    pub fn stats(&self) -> WalkStats {
        let mut s = self.stats.get();
        s.widened = self.widened.get();
        s
    }

    fn bump(&self, f: impl FnOnce(&mut WalkStats)) {
        let mut s = self.stats.get();
        f(&mut s);
        self.stats.set(s);
    }

    /// Memoised `FnCtx::build`.
    fn ctx_of(&self, iid: &IidHex, f: &cgf::Function) -> Rc<FnCtx> {
        if let Some(c) = self.ctxs.borrow().get(iid) {
            self.bump(|s| s.ctx_hits += 1);
            return c.clone();
        }
        let c = Rc::new(FnCtx::build(f, self.engine.cat));
        self.bump(|s| s.ctx_builds += 1);
        self.ctxs.borrow_mut().insert(iid.clone(), c.clone());
        c
    }

    /// Memoised `Engine::propagate`. Carries no `visited` state, so it is safe
    /// to share across branches and across `route()` calls.
    fn prop_of(
        &self,
        iid: &IidHex,
        f: &cgf::Function,
        ctx: &FnCtx,
        seeds: &[u32],
    ) -> Rc<PropResult> {
        let key = (
            iid.clone(),
            seeds.iter().map(|s| s.to_string()).collect::<Vec<_>>().join(","),
        );
        if let Some(r) = self.props.borrow().get(&key) {
            self.bump(|s| s.prop_hits += 1);
            return r.clone();
        }
        let r = Rc::new(self.engine.propagate(f, ctx, seeds));
        self.bump(|s| s.prop_runs += 1);
        self.props.borrow_mut().insert(key, r.clone());
        r
    }

    /// Reconstruct the route from `seeds` in `fn_iid` to a sink of `class`.
    ///
    /// `target` pins which sink to chase as `(callsite, firing vertex)` — a
    /// caller that already propagated (report::intra_chains does) must pass it,
    /// or a function with two same-class sinks would get the same route twice.
    /// None = pick deterministically, for callers without a PropResult.
    pub fn route(
        &self,
        fn_iid: &IidHex,
        seeds: &[u32],
        class: &str,
        target: Option<(usize, u32)>,
    ) -> Route {
        let mut hops = Vec::new();
        let mut visited = HashSet::new();
        self.terminal.replace(None);
        // The entry function's seeds ARE the fact — nothing was coarsened yet.
        let incomplete = self.descend(
            fn_iid,
            seeds,
            class,
            target,
            0,
            &mut visited,
            &mut hops,
            true,
            &Residual::default(),
        );
        let boundaries = hops.iter().filter(|h| h.kind == HopKind::Boundary).count();
        let terminal = if incomplete.is_none() { self.terminal.take() } else { None };
        Route {
            id: route_id(class, &hops),
            hops,
            incomplete,
            boundaries,
            terminal,
        }
    }

    /// Cycle guard + one level of descent.
    ///
    /// B2: `visited` is a PATH stack, not a run-global set — the key is pushed
    /// on entry and popped on every exit. A run-global set made a diamond
    /// (A→B→D and A→C→D within one route) report `Incomplete::Cycle` at D,
    /// because the sibling branch had already "visited" it. Only re-entering a
    /// function that is still on the current descent path is a cycle, and that
    /// is exactly what a stack detects.
    #[allow(clippy::too_many_arguments)]
    fn descend(
        &self,
        fn_iid: &IidHex,
        seeds: &[u32],
        class: &str,
        target: Option<(usize, u32)>,
        depth: usize,
        visited: &mut HashSet<(IidHex, String)>,
        out: &mut Vec<RouteHop>,
        is_entry: bool,
        resid: &Residual,
    ) -> Option<Incomplete> {
        if depth >= self.max_depth {
            return Some(Incomplete::DepthCap);
        }
        let Some(f) = self.engine.prog.funcs.get(fn_iid) else {
            return Some(Incomplete::CalleeBodyMissing);
        };
        if f.flow.is_none() {
            return Some(Incomplete::CalleeBodyMissing);
        }
        // Keyed on (fn, seed set): the same function re-entered on the same
        // path with the same incoming facts can only reproduce the same route.
        let mut seedkey: Vec<String> = seeds.iter().map(|s| s.to_string()).collect();
        seedkey.sort();
        // The residual is part of the incoming fact, so it belongs in the key:
        // the same function re-entered with the same seeds but a DIFFERENT
        // unconsumed path is a different descent, not a cycle.
        let rkey: Vec<String> = resid.path.iter().map(|p| p.to_string()).collect();
        let key = (
            fn_iid.clone(),
            format!("{}|{}", seedkey.join(","), rkey.join(".")),
        );
        if !visited.insert(key.clone()) {
            return Some(Incomplete::Cycle);
        }
        let r = self.descend_at(
            fn_iid, seeds, class, target, depth, visited, out, is_entry, resid,
        );
        visited.remove(&key);
        r
    }

    /// One level: propagate inside `fn_iid`, emit the local hops, then either
    /// terminate at a catalog sink or descend into the callee that carries it.
    #[allow(clippy::too_many_arguments)]
    fn descend_at(
        &self,
        fn_iid: &IidHex,
        seeds: &[u32],
        class: &str,
        target: Option<(usize, u32)>,
        depth: usize,
        visited: &mut HashSet<(IidHex, String)>,
        out: &mut Vec<RouteHop>,
        is_entry: bool,
        resid: &Residual,
    ) -> Option<Incomplete> {
        let f = &self.engine.prog.funcs[fn_iid];
        let flow = f.flow.as_ref().expect("checked by descend");

        let ctx = self.ctx_of(fn_iid, f);
        let r = self.prop_of(fn_iid, f, &ctx, seeds);
        let repo = self.engine.prog.repo_of.get(fn_iid).cloned().unwrap_or_default();

        // Deterministic pick among same-class sinks: HashSet iteration inside
        // propagate makes `sinks` order unstable, so never take sinks[0].
        let Some(ps) = (match target {
            Some((cs, last)) => r
                .sinks
                .iter()
                .find(|s| s.class == class && s.callsite == cs && s.last == last),
            None => r
                .sinks
                .iter()
                .filter(|s| s.class == class)
                .min_by_key(|s| (s.callsite, s.last)),
        }) else {
            return Some(Incomplete::NotReproduced);
        };

        if is_entry {
            out.push(self.source_hop(&repo, f, &ctx, seeds, resid));
        }

        // Local hops: backtrace pred from the firing vertex to a seed, then
        // label each distinct call site along it (report.rs:82-120 did this for
        // the source function only; here it runs at every level).
        let path = backtrace(&r.pred, ps.last);
        let mut vcs: HashMap<u32, usize> = HashMap::new();
        for v in &flow.vertices {
            if v.kind == cgf::VertexKind::CallArgPort as i32
                || v.kind == cgf::VertexKind::CallResultPort as i32
            {
                vcs.insert(v.id, v.callsite_id as usize);
            }
        }
        let mut seen_cs = HashSet::new();
        for &v in &path {
            let Some(&cs_idx) = vcs.get(&v) else { continue };
            if cs_idx == ps.callsite || !seen_cs.insert(cs_idx) {
                continue; // the firing site is emitted below, with its real kind
            }
            let Some(cs) = flow.callsites.get(cs_idx) else { continue };
            out.push(RouteHop {
                repo: repo.clone(),
                func: f.fqn.clone(),
                file: cs.span.as_ref().map(|s| s.file.clone()),
                line: cs.span.as_ref().map(|s| s.line),
                kind: if is_boundary(cs) {
                    HopKind::Boundary
                } else {
                    HopKind::Call
                },
                callee: cs.callee_fqn.clone(),
                field: field_of(flow, v, resid),
                fields: Vec::new(),
                confidence: conf_of(cs),
            });
        }

        // W1F: the fact does not leave this frame through a call — it is written
        // into an abstract heap cell here and picked up by a function this frame
        // never calls (the epool `Submit` ⇢ `runBatcher` shape). Render the
        // crossing at the WRITE site and resume the descent inside the reader.
        // Must precede the callsite lookup: `ps.callsite` is usize::MAX here.
        //
        // The `callsite` test is load-bearing. A caller that composes a callee's
        // heap-mediated sink_hit also carries `via_heap`, but with a REAL call
        // site — and that route must descend into the callee normally so the
        // frame that actually writes the cell appears in the route. Branching on
        // `via_heap` alone renders the crossing at the caller and silently drops
        // the writer's frame (`Submit` vanished from the epool route).
        if let (Some(via), usize::MAX) = (&ps.via_heap, ps.callsite) {
            out.push(RouteHop {
                repo: repo.clone(),
                func: f.fqn.clone(),
                file: ps.span.as_ref().map(|s| s.file.clone()),
                line: ps.span.as_ref().map(|s| s.line),
                kind: HopKind::Heap,
                callee: via.cell.clone(),
                field: field_of(flow, ps.last, resid),
                fields: Vec::new(),
                // A cell join is object-insensitive — every instance of the type
                // shares it — so a crossing is strictly less certain than a call.
                // Same discount `addInject` gives an aliased heap write.
                confidence: 0.5,
            });
            let Some(rf) = self.engine.prog.funcs.get(&via.reader) else {
                return Some(Incomplete::CalleeBodyMissing);
            };
            let rctx = self.ctx_of(&via.reader, rf);
            let rseeds = seeds_for_slot(&rctx, &via.reader_slot);
            if rseeds.is_empty() {
                return Some(Incomplete::NotReproduced);
            }
            return self.descend(
                &via.reader,
                &rseeds,
                class,
                None,
                depth + 1,
                visited,
                out,
                false,
                // whole-object on the far side: nothing of this frame's
                // unconsumed path survives a crossing.
                &Residual::default(),
            );
        }

        let Some(cs) = flow.callsites.get(ps.callsite) else {
            return Some(Incomplete::NotReproduced);
        };
        let Some(&(_, arg_idx, ref arg_path)) = ctx.arg_port.get(&ps.last) else {
            return Some(Incomplete::NotReproduced);
        };

        // Is the sink AT this call site (catalog), or inside the callee?
        if let Some(sink) = self.engine.cat.sink_of(&cs.callee_fqn) {
            let vtype = ctx.vtype.get(&ps.last).map_or("", String::as_str);
            if sink.class == class
                && self.engine.cat.sink_fires_on(sink, arg_idx, cs.arg0_is_receiver, vtype)
            {
                out.push(RouteHop {
                    repo: repo.clone(),
                    func: f.fqn.clone(),
                    file: cs.span.as_ref().map(|s| s.file.clone()),
                    line: cs.span.as_ref().map(|s| s.line),
                    kind: HopKind::Sink,
                    callee: cs.callee_fqn.clone(),
                    field: field_of(flow, ps.last, resid),
                    fields: Vec::new(),
                    confidence: conf_of(cs),
                });
                self.terminal.replace(Some((fn_iid.clone(), ps.callsite)));
                return None; // reached the real sink, with its real span
            }
        }

        // `--unmodeled`: the pseudo-sink sits AT an unmodeled library call —
        // the same test `propagate` used to record it.
        if class == crate::ifds::UNMODELED_CLASS
            && self.engine.unmodeled_write_at(flow, &ctx, ps.callsite, arg_idx)
        {
            out.push(RouteHop {
                repo,
                func: f.fqn.clone(),
                file: cs.span.as_ref().map(|s| s.file.clone()),
                line: cs.span.as_ref().map(|s| s.line),
                kind: HopKind::Sink,
                callee: cs.callee_fqn.clone(),
                field: field_of(flow, ps.last, resid),
                fields: Vec::new(),
                confidence: conf_of(cs),
            });
            self.terminal.replace(Some((fn_iid.clone(), ps.callsite)));
            return None;
        }

        // Otherwise a callee summary carried it. Mirror propagate's own slot
        // derivation, including the client-side Send stream remap.
        //
        // The arg port's own path is only what THIS frame projected; anything
        // the caller's fact still carried unconsumed rides on top of it. That
        // composition is what keeps a k=2 path alive across a pass-through
        // frame, whose only in-slot is the whole-object one (doc 25 §3 R1).
        let (arg_full, arg_names) = resid.compose(arg_path, field_names_of(flow, ps.last));
        let mut callee_slot = arg_to_callee_slot(cs, arg_idx, &arg_full);
        if let Some((cgf::call_site::StreamOp::Send, true)) = stream_of(cs) {
            if arg_idx >= 1 {
                // stream ports are whole-message: the path, residual included,
                // is dropped here exactly as propagate drops it.
                callee_slot = Slot::StreamIn.into();
            }
        }

        // Deterministic pick among candidate callees (dispatch fan-out) and
        // among their matching sink_hits.
        // `heap` first in the key so a callee that reaches the sink through its
        // own call sites always beats one that only gets there through a cell:
        // a route the reviewer can walk in the source is worth more than a
        // crossing, and the crossing is still found when it is the only option.
        let mut cands: Vec<(bool, IidHex, SlotP)> = Vec::new();
        for cid in &cs.callee_iids {
            let h = hexid(cid);
            let Some(sum) = self.engine.summaries.get(&h) else { continue };
            for sh in &sum.sink_hits {
                if sh.class == class && slot_compat(&sh.in_slot, &callee_slot) {
                    cands.push((sh.via_heap.is_some(), h.clone(), sh.in_slot.clone()));
                }
            }
        }
        cands.sort_by(|a, b| (a.0, &a.1, slot_str(&a.2)).cmp(&(b.0, &b.1, slot_str(&b.2))));
        cands.dedup_by(|a, b| a.0 == b.0 && a.1 == b.1 && slot_str(&a.2) == slot_str(&b.2));
        if cands.is_empty() {
            return Some(Incomplete::NotReproduced);
        }
        if cands.len() > MAX_DISPATCH_CANDIDATES {
            self.bump(|s| s.cand_capped += 1);
        }

        // B3: try the candidates in that order and keep the FIRST that
        // reproduces the sink. Taking only `cands[0]` made the whole route
        // incomplete whenever that one callee could not reproduce it, even
        // though a sibling implementation of the same interface could.
        //
        // Stability: the order is unchanged and candidate 0 is still tried
        // first, so every route that completes today completes through the same
        // callee, with the same hops and the same content-addressed id. If NO
        // candidate reproduces, the first candidate's partial hops and its
        // reason are restored, so incomplete routes are byte-identical too.
        // The only new outcomes are completions that used to be failures.
        let boundary = is_boundary(cs);
        let base = out.len();
        let mut first_fail: Option<(Vec<RouteHop>, Option<Incomplete>)> = None;
        for (i, (_, callee_iid, callee_in)) in cands
            .into_iter()
            .take(MAX_DISPATCH_CANDIDATES)
            .enumerate()
        {
            self.bump(|s| s.cands_tried += 1);
            let r = 'cand: {
                out.push(RouteHop {
                    repo: repo.clone(),
                    func: f.fqn.clone(),
                    file: cs.span.as_ref().map(|s| s.file.clone()),
                    line: cs.span.as_ref().map(|s| s.line),
                    kind: if boundary { HopKind::Boundary } else { HopKind::Call },
                    callee: match self.http_labels.get(&callee_iid) {
                        Some(label) if boundary => label.clone(),
                        _ => cs.callee_fqn.clone(),
                    },
                    field: field_of(flow, ps.last, resid),
                    fields: Vec::new(),
                    confidence: conf_of(cs),
                });

                // Resolve the descent target. At a boundary the callee iid IS
                // the contract iid (compose aliased the handler's summary onto
                // it), so we hop to the handler and undo contract_view's slot
                // remap.
                let (target_iid, target_slot) = if boundary {
                    match self.handlers.get(&callee_iid) {
                        Some((h, shape)) => (h.clone(), self.unview_for(&callee_in, shape, h, class)),
                        // No local handler: the summary came from a PG leaf, so
                        // the route legitimately ends at the boundary in THIS
                        // analysis.
                        None => break 'cand Some(Incomplete::HandlerNotLoaded),
                    }
                } else {
                    (callee_iid.clone(), callee_in.clone())
                };

                let Some(tf) = self.engine.prog.funcs.get(&target_iid) else {
                    break 'cand Some(Incomplete::HandlerNotLoaded);
                };
                let tctx = self.ctx_of(&target_iid, tf);

                // What the matched row did NOT consume. Non-empty exactly when
                // the callee coarsened our fact — i.e. it has no in-slot for the
                // field we are actually carrying, because it never projects it.
                let next_resid = if callee_slot.slot == Slot::StreamIn {
                    Residual::default()
                } else {
                    Residual::after(&target_slot.path, &callee_slot.path, &arg_names)
                };
                // Seed the callee with the COMPOSED path, not the row's: that is
                // what stops its propagation from wandering into sibling fields
                // of the same struct, which is where the wrong branches in doc 25
                // §3 R1 come from.
                let seed_slot = SlotP {
                    slot: target_slot.slot.clone(),
                    path: compose_path(&target_slot.path, &next_resid.path),
                };
                // Deeper levels have no caller-supplied target: the sink_hit we
                // matched tells us the class and the in-slot, and the callee's
                // own propagation re-finds the firing site.
                //
                // A narrowed seed set can be EMPTY where the widened one is not,
                // so this shares the fallback below rather than returning early.
                let next_seeds = seeds_for_slot(&tctx, &seed_slot);
                let mark = out.len();
                // No `visited` snapshot is needed any more: `descend` pops its
                // own key on every exit (B2), so a failed sub-descent leaves the
                // path stack exactly as it found it.
                let r = if next_seeds.is_empty() {
                    Some(Incomplete::NotReproduced)
                } else {
                    self.descend(
                        &target_iid,
                        &next_seeds,
                        class,
                        None,
                        depth + 1,
                        visited,
                        out,
                        false,
                        &next_resid,
                    )
                };

                // The narrowed fact could not reach the sink. The sink is real —
                // the summary says so — but it is only reachable from the WIDENED
                // fact, so this chain exists because of pass-through widening.
                // Restore today's behaviour rather than emit a short route: route
                // quality stays monotone, and the counter records how often it
                // happened.
                if r == Some(Incomplete::NotReproduced) && !next_resid.is_empty() {
                    out.truncate(mark);
                    self.widened.set(self.widened.get() + 1);
                    if let Some(t) = self.engine.trace.filter(|t| t.on_ev("widen", &f.fqn)) {
                        t.log(format_args!(
                            "widen     fn={} cs={} callee={} slot={} resid={:?}",
                            f.fqn,
                            ps.callsite,
                            cs.callee_fqn,
                            slot_str(&seed_slot),
                            next_resid.path
                        ));
                    }
                    let wide_seeds = seeds_for_slot(&tctx, &target_slot);
                    if wide_seeds.is_empty() {
                        break 'cand Some(Incomplete::NotReproduced);
                    }
                    break 'cand self.descend(
                        &target_iid,
                        &wide_seeds,
                        class,
                        None,
                        depth + 1,
                        visited,
                        out,
                        false,
                        &Residual::default(),
                    );
                }
                r
            };
            if r.is_none() {
                return None; // this candidate reproduced the sink
            }
            if i == 0 {
                first_fail = Some((out[base..].to_vec(), r));
            }
            out.truncate(base);
        }

        // Nothing reproduced: hand back exactly what the first candidate left,
        // which is what this function returned before B3.
        let (hops, reason) = first_fail.expect("cands is non-empty");
        out.extend(hops);
        reason
    }

    /// The entry hop: where untrusted data enters the source function. IN_PARAM
    /// vertices carry no span (flow.go:157), so file/line may be absent — the
    /// function identity and the field are still the useful part.
    fn source_hop(
        &self,
        repo: &str,
        f: &cgf::Function,
        ctx: &FnCtx,
        seeds: &[u32],
        resid: &Residual,
    ) -> RouteHop {
        let flow = f.flow.as_ref();
        let seed = seeds.iter().min().copied();
        let span = seed.and_then(|s| ctx.vspan.get(&s).cloned().flatten());
        RouteHop {
            repo: repo.to_string(),
            func: f.fqn.clone(),
            file: span.as_ref().map(|s| s.file.clone()),
            line: span.as_ref().map(|s| s.line),
            kind: HopKind::Source,
            callee: String::new(),
            field: flow.zip(seed).and_then(|(fl, s)| field_of(fl, s, resid)),
            fields: Vec::new(),
            confidence: 1.0,
        }
    }
}

/// B4: one line per run, on stderr, next to `report.rs`'s `route-warn:`.
/// Emitted from `Drop` because the counters are only final once every route of
/// the walk has been built, and a `Walk` is created once per reporting pass.
/// Silent when the walk did nothing (no routes, e.g. the unit tests that only
/// exercise helpers).
impl Drop for Walk<'_, '_> {
    fn drop(&mut self) {
        let s = self.stats();
        if s.ctx_builds == 0 && s.ctx_hits == 0 {
            return;
        }
        eprintln!(
            "route-stats: fnctx {} built / {} memo-hit, propagate {} run / {} memo-hit, \
             dispatch candidates tried {}, fan-outs capped at {} {}",
            s.ctx_builds,
            s.ctx_hits,
            s.prop_runs,
            s.prop_hits,
            s.cands_tried,
            MAX_DISPATCH_CANDIDATES,
            s.cand_capped
        );
    }
}

fn is_boundary(cs: &cgf::CallSite) -> bool {
    cs.kind == cgf::call_site::Kind::InvokesRemote as i32
}

fn conf_of(cs: &cgf::CallSite) -> f32 {
    // 0.0 = unset (legacy CGF / proto3 default) => treat as certain, as
    // report.rs:107 does.
    if cs.dispatch_confidence > 0.0 {
        cs.dispatch_confidence
    } else {
        1.0
    }
}

/// Reporting names declared on vertex `v` (empty when absent or truncated —
/// the proto's own convention, which `Residual::compose` mirrors).
fn field_names_of(flow: &cgf::LocalFlow, v: u32) -> &[String] {
    match flow.vertices.iter().find(|x| x.id == v) {
        Some(vx) if vx.field_names.len() == vx.field_path.len() => &vx.field_names,
        _ => &[],
    }
}

/// Field path of the fact at vertex `v`, rendered like report.rs:130-144:
/// names when the frontend emitted a full set, else numeric.
///
/// `resid` is what the caller's fact still carried unconsumed, so the rendered
/// field is the fact's TRUE path here, not just what this frame projected — a
/// hop through a pass-through frame reports the caller's field instead of
/// nothing.
fn field_of(flow: &cgf::LocalFlow, v: u32, resid: &Residual) -> Option<String> {
    let vx = flow.vertices.iter().find(|x| x.id == v)?;
    let dnames = field_names_of(flow, v);
    let (path, names) = resid.compose(&vx.field_path, dnames);
    if path.is_empty() {
        return None;
    }
    if names.len() == path.len() {
        Some(names.join("."))
    } else {
        Some(
            path.iter()
                .map(|i| i.to_string())
                .collect::<Vec<_>>()
                .join("."),
        )
    }
}

/// Content id over the hop sequence. Deliberately excludes `confidence` (a
/// dispatch-precision artifact, not route identity) and `file` (absolute paths
/// differ per checkout), so the same route in two analyses gets the same id.
fn route_id(class: &str, hops: &[RouteHop]) -> String {
    let mut parts: Vec<Vec<u8>> = vec![class.as_bytes().to_vec()];
    for h in hops {
        parts.push(h.repo.as_bytes().to_vec());
        parts.push(h.func.as_bytes().to_vec());
        parts.push(h.callee.as_bytes().to_vec());
        parts.push(h.line.unwrap_or(-1).to_le_bytes().to_vec());
        parts.push(format!("{:?}", h.kind).into_bytes());
    }
    let refs: Vec<&[u8]> = parts.iter().map(|p| p.as_slice()).collect();
    crate::ids::hex(&crate::ids::hash_parts(&refs))[..12].to_string()
}

fn backtrace(pred: &HashMap<u32, u32>, last: u32) -> Vec<u32> {
    let mut path = vec![last];
    let mut cur = last;
    let mut guard = 0;
    while let Some(&p) = pred.get(&cur) {
        path.push(p);
        cur = p;
        guard += 1;
        if guard > 10_000 {
            break; // pred is acyclic by construction; this is belt-and-braces
        }
    }
    path.reverse();
    path
}

/// Undo `compose::contract_view*`'s in-slot remap: client frame -> handler frame.
/// Unary gRPC is identity; a server-streaming handler's req is Param(0)
/// server-side but was published as Param(1) (compose.rs). A GraphQL client's
/// arg port j is the resolver's Param(args[j]).
pub(crate) fn unview_slot(s: &SlotP, shape: &ContractShape) -> SlotP {
    match shape {
        ContractShape::Grpc(client_streaming, server_streaming) => {
            if !client_streaming && !server_streaming {
                return s.clone();
            }
            match &s.slot {
                Slot::Param(1) if *server_streaming && !*client_streaming => SlotP {
                    slot: Slot::Param(0),
                    path: s.path.clone(),
                },
                _ => s.clone(),
            }
        }
        ContractShape::Graphql(args) => match &s.slot {
            Slot::Param(j) => match args.get(*j as usize) {
                Some(&p) => SlotP {
                    slot: Slot::Param(p),
                    path: s.path.clone(),
                },
                None => s.clone(),
            },
            _ => s.clone(),
        },
        // The client's one port is the first request param (`Walk::unview_for`
        // picks a later one when only that one carries the sink).
        ContractShape::Http { request_params } => match (&s.slot, request_params.first()) {
            (Slot::Param(0), Some(&p)) => SlotP {
                slot: Slot::Param(p),
                path: s.path.clone(),
            },
            _ => s.clone(),
        },
    }
}

/// Vertices in `ctx` that carry `slot` — the seeds for descending into it.
/// Source/StreamIn are not positional in-slots; they have their own seed lists.
fn seeds_for_slot(ctx: &FnCtx, slot: &SlotP) -> Vec<u32> {
    match slot.slot {
        Slot::Source => return ctx.source_seeds.clone(),
        Slot::StreamIn => return ctx.stream_in_seeds.clone(),
        _ => {}
    }
    let mut v: Vec<u32> = ctx
        .in_slots
        .iter()
        .filter(|(_, s)| slot_compat(s, slot))
        .map(|(id, _)| *id)
        .collect();
    v.sort();
    v.dedup();
    v
}

#[cfg(test)]
mod descent_tests {
    use super::*;
    use crate::catalog::Catalog;
    use crate::ifds::cache_tests::{edge, vertex};
    use crate::ifds::{SinkHit, Summary};

    const CAT: &str = r#"
[[sinks]]
class = "sqli"
selector = "db.Exec"
arg = "any"
"#;

    fn func(iid: u8, flow: cgf::LocalFlow) -> cgf::Function {
        cgf::Function {
            id: Some(cgf::Ident {
                iid: vec![iid; 32],
                bid: vec![iid; 32],
            }),
            fqn: format!("pkg.F{iid:02x}"),
            has_body: true,
            flow: Some(flow),
            ..Default::default()
        }
    }

    /// `F(p) { callee(p) }` — one call site, arg 0 = the whole param. Several
    /// `callees` model a dispatch fan-out on one site.
    fn relay(iid: u8, callees: &[u8], fqn: &str) -> cgf::Function {
        func(
            iid,
            cgf::LocalFlow {
                vertices: vec![
                    vertex(1, cgf::VertexKind::InParam, 0, 0),
                    vertex(2, cgf::VertexKind::CallArgPort, 0, 0),
                ],
                edges: vec![edge(1, 2)],
                callsites: vec![cgf::CallSite {
                    id: 0,
                    callee_iids: callees.iter().map(|c| vec![*c; 32]).collect(),
                    callee_fqn: fqn.into(),
                    argc: 1,
                    ..Default::default()
                }],
            },
        )
    }

    /// `F(p) { db.Exec(p) }` — the catalog sink itself.
    fn sink_leaf(iid: u8) -> cgf::Function {
        relay(iid, &[], "db.Exec")
    }

    fn prog_of(fns: Vec<cgf::Function>) -> Program {
        let mut prog = Program {
            funcs: HashMap::new(),
            repo_of: HashMap::new(),
            packages: Vec::new(),
        };
        for f in fns {
            let h = hexid(&f.id.as_ref().unwrap().iid);
            prog.repo_of.insert(h.clone(), "test".into());
            prog.funcs.insert(h, f);
        }
        prog
    }

    fn iid(b: u8) -> IidHex {
        hexid(&[b; 32])
    }

    /// A ──iface.M──> B1 -> C -> X -> Y(sink)      (too deep: DepthCap)
    ///   └─iface.M──> B2 -------> X -> Y(sink)      (reaches it)
    ///
    /// Both dispatch candidates descend through the SAME X with the SAME seeds:
    /// a diamond inside one route. With a run-global `visited` the first
    /// branch left X marked, so the second reported `Cycle` at X and the route
    /// stayed incomplete. X is not on the second branch''s path, so it is not a
    /// cycle — the path stack must let it through.
    #[test]
    fn a_diamond_is_not_a_cycle() {
        let cat = Catalog::load_str(CAT).unwrap();
        let prog = prog_of(vec![
            relay(0xA0, &[0xB1, 0xB2], "iface.M"),
            relay(0xB1, &[0xC0], "pkg.C"),
            relay(0xC0, &[0x0E], "pkg.X"),
            relay(0xB2, &[0x0E], "pkg.X"),
            relay(0x0E, &[0x0F], "pkg.Y"),
            sink_leaf(0x0F),
        ]);
        let mut eng = Engine::new(&prog, &cat);
        eng.run();
        let handlers = ContractHandlers::new();
        let mut w = Walk::new(&eng, &handlers);
        // Budget: A(0) B1(1) C(2) X(3) Y(4) is one level too deep, while
        // A(0) B2(1) X(2) Y(3) fits. That asymmetry is what makes the second
        // branch''s outcome differ from the first''s.
        w.max_depth = 4;

        let route = w.route(&iid(0xA0), &[1], "sqli", None);
        assert_eq!(
            route.incomplete, None,
            "the short branch reaches the sink: {:?}",
            route.hops.iter().map(|h| (&h.func, &h.callee)).collect::<Vec<_>>()
        );
        assert_eq!(route.hops.last().unwrap().kind, HopKind::Sink);
        assert_eq!(route.hops.last().unwrap().callee, "db.Exec");
        // it went through B2, not B1
        assert!(route.hops.iter().any(|h| h.func.ends_with("b2")), "{:?}",
            route.hops.iter().map(|h| h.func.clone()).collect::<Vec<_>>());
    }

    /// The path stack must be exactly as it was found: every key pushed on
    /// entry is popped on every exit. This is what makes sibling branches
    /// independent (and what the diamond above relies on).
    #[test]
    fn a_finished_descent_leaves_the_path_stack_empty() {
        let cat = Catalog::load_str(CAT).unwrap();
        let prog = prog_of(vec![relay(0xA0, &[0x0F], "pkg.Y"), sink_leaf(0x0F)]);
        let mut eng = Engine::new(&prog, &cat);
        eng.run();
        let handlers = ContractHandlers::new();
        let w = Walk::new(&eng, &handlers);

        let mut visited = HashSet::new();
        let mut hops = Vec::new();
        let inc = w.descend(
            &iid(0xA0),
            &[1],
            "sqli",
            None,
            0,
            &mut visited,
            &mut hops,
            true,
            &Residual::default(),
        );
        assert_eq!(inc, None);
        assert!(visited.is_empty(), "keys left on the stack: {visited:?}");
    }

    /// A real cycle is still a cycle: F -> G -> F with the same fact.
    /// G''s first call site is the recursive one, so the deterministic sink pick
    /// chases it and re-enters F, which IS on the current path.
    #[test]
    fn a_real_cycle_still_reports_cycle() {
        let cat = Catalog::load_str(CAT).unwrap();
        // G(p) { F(p); db.Exec(p) } — cs0 recursive, cs1 the sink
        let g = func(
            0x2B,
            cgf::LocalFlow {
                vertices: vec![
                    vertex(1, cgf::VertexKind::InParam, 0, 0),
                    vertex(2, cgf::VertexKind::CallArgPort, 0, 0),
                    vertex(3, cgf::VertexKind::CallArgPort, 0, 1),
                ],
                edges: vec![edge(1, 2), edge(1, 3)],
                callsites: vec![
                    cgf::CallSite {
                        id: 0,
                        callee_iids: vec![vec![0x1A; 32]],
                        callee_fqn: "pkg.F1a".into(),
                        argc: 1,
                        ..Default::default()
                    },
                    cgf::CallSite {
                        id: 1,
                        callee_fqn: "db.Exec".into(),
                        argc: 1,
                        ..Default::default()
                    },
                ],
            },
        );
        let prog = prog_of(vec![relay(0x1A, &[0x2B], "pkg.F2b"), g]);
        let mut eng = Engine::new(&prog, &cat);
        eng.run();
        let handlers = ContractHandlers::new();
        let w = Walk::new(&eng, &handlers);

        let route = w.route(&iid(0x1A), &[1], "sqli", None);
        assert_eq!(route.incomplete, Some(Incomplete::Cycle), "{:?}", route.hops);
    }

    /// Dispatch fan-out with two candidates where the FIRST cannot be
    /// descended into — a summary loaded for a callee whose body is not in this
    /// analysis, which is exactly what `HandlerNotLoaded` names. Before B3 the
    /// route stopped there; now the sibling implementation is tried and the
    /// route completes.
    #[test]
    fn a_dispatch_site_falls_through_to_the_candidate_that_reproduces() {
        let cat = Catalog::load_str(CAT).unwrap();
        // callee iids 0x11.. and 0x22.. — 0x11 sorts first, so it is tried
        // first, exactly as before this change.
        let prog = prog_of(vec![relay(0xA0, &[0x11, 0x22], "iface.M"), sink_leaf(0x22)]);
        let mut eng = Engine::new(&prog, &cat);
        eng.run();
        // 0x11 has a summary but no body (cross-repo / stored summary).
        eng.summaries.insert(
            iid(0x11),
            Summary {
                flows: HashSet::new(),
                sink_hits: vec![SinkHit {
                    in_slot: Slot::Param(0).into(),
                    class: "sqli".into(),
                    callsite: 0,
                    span: None,
                    via_heap: None,
                }],
                confidence: 1.0,
            },
        );
        let handlers = ContractHandlers::new();
        let w = Walk::new(&eng, &handlers);

        let route = w.route(&iid(0xA0), &[1], "sqli", None);
        assert_eq!(
            route.incomplete, None,
            "candidate 2 reproduces the sink: {:?}",
            route.hops.iter().map(|h| (&h.func, &h.callee, h.kind)).collect::<Vec<_>>()
        );
        assert_eq!(route.hops.last().unwrap().callee, "db.Exec");
        assert_eq!(w.stats().cands_tried, 2, "both candidates must be entered");
    }

    /// The memo survives across `route()` calls: `visited` is per-route, the
    /// FnCtx / propagate memos are per-Walk. Two chains through the same
    /// function pay for it once.
    #[test]
    fn a_second_route_through_the_same_function_hits_the_memo() {
        let cat = Catalog::load_str(CAT).unwrap();
        let prog = prog_of(vec![relay(0xA0, &[0x0F], "pkg.Y"), sink_leaf(0x0F)]);
        let mut eng = Engine::new(&prog, &cat);
        eng.run();
        let handlers = ContractHandlers::new();
        let w = Walk::new(&eng, &handlers);

        let first = w.route(&iid(0xA0), &[1], "sqli", None);
        assert_eq!(first.incomplete, None);
        let s1 = w.stats();
        // one build + one propagate per level, cold
        assert_eq!((s1.ctx_builds, s1.prop_runs), (2, 2), "{s1:?}");
        assert_eq!(s1.prop_hits, 0, "nothing to hit yet: {s1:?}");

        let second = w.route(&iid(0xA0), &[1], "sqli", None);
        assert_eq!(second.id, first.id, "the same route, and the same id");
        let s2 = w.stats();
        assert_eq!(s2.ctx_builds, s1.ctx_builds, "nothing was rebuilt");
        assert_eq!(s2.prop_runs, s1.prop_runs, "nothing was re-propagated");
        assert_eq!(s2.prop_hits, s1.prop_hits + 2, "both levels came from the memo");
        assert!(s2.ctx_hits > s1.ctx_hits, "{s1:?} -> {s2:?}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sp(slot: Slot, path: &[u32]) -> SlotP {
        SlotP {
            slot,
            path: path.to_vec(),
        }
    }

    fn vertex(id: u32, path: &[u32], names: &[&str]) -> cgf::FlowVertex {
        cgf::FlowVertex {
            id,
            field_path: path.to_vec(),
            field_names: names.iter().map(|s| s.to_string()).collect(),
            ..Default::default()
        }
    }

    // --- unview_slot: the inverse of compose::contract_view's in-slot remap.
    // No fixture covers a STREAMING chain that continues past the boundary, so
    // this is the only guard on the streaming descent.

    /// Coverage wave 1 §4.4: the client's one port re-enters the handler at
    /// its first request param.
    #[test]
    fn unview_http_maps_the_port_to_the_first_request_param() {
        let shape = ContractShape::Http { request_params: vec![1, 2] };
        assert_eq!(unview_slot(&sp(Slot::Param(0), &[4]), &shape), sp(Slot::Param(1), &[4]));
        assert_eq!(unview_slot(&sp(Slot::Source, &[]), &shape), sp(Slot::Source, &[]));
    }

    #[test]
    fn unview_unary_is_identity() {
        for s in [
            sp(Slot::Param(0), &[]),
            sp(Slot::Param(1), &[3]),
            sp(Slot::Receiver, &[]),
            sp(Slot::StreamIn, &[]),
        ] {
            assert_eq!(slot_str(&unview_slot(&s, &ContractShape::Grpc(false, false))), slot_str(&s));
        }
    }

    #[test]
    fn unview_server_stream_undoes_the_param_shift() {
        // contract_view maps handler Param(0) -> client Param(1) (compose.rs:30).
        // Descending must map it back, or we would seed the handler's ctx param.
        let got = unview_slot(&sp(Slot::Param(1), &[7]), &ContractShape::Grpc(false, true));
        assert_eq!(got.slot, Slot::Param(0));
        assert_eq!(got.path, vec![7], "field path must ride through the remap");
    }

    #[test]
    fn unview_leaves_client_and_bidi_streams_alone() {
        // client-stream/bidi handlers take only the stream object, so
        // contract_view drops positional params entirely — nothing to undo.
        for (c, s) in [(true, false), (true, true)] {
            let got = unview_slot(&sp(Slot::Param(1), &[]), &ContractShape::Grpc(c, s));
            assert_eq!(got.slot, Slot::Param(1));
        }
        // StreamIn is contract-level, never positional.
        assert_eq!(
            unview_slot(&sp(Slot::StreamIn, &[]), &ContractShape::Grpc(true, true)).slot,
            Slot::StreamIn
        );
    }

    // --- seeds_for_slot

    #[test]
    fn seeds_use_the_dedicated_lists_for_non_positional_slots() {
        let ctx = FnCtx {
            source_seeds: vec![9, 4],
            stream_in_seeds: vec![7],
            in_slots: vec![(1, sp(Slot::Param(0), &[]))],
            ..Default::default()
        };
        assert_eq!(seeds_for_slot(&ctx, &sp(Slot::Source, &[])), vec![9, 4]);
        assert_eq!(seeds_for_slot(&ctx, &sp(Slot::StreamIn, &[])), vec![7]);
    }

    #[test]
    fn seeds_match_positionally_and_by_comparable_path() {
        let ctx = FnCtx {
            in_slots: vec![
                (5, sp(Slot::Param(0), &[])),
                (3, sp(Slot::Param(0), &[3])),
                (4, sp(Slot::Param(0), &[7])),
                (8, sp(Slot::Param(1), &[])),
                (2, sp(Slot::Receiver, &[])),
            ],
            ..Default::default()
        };
        // whole-object fact: every Param(0) variant is comparable (mutual prefix)
        assert_eq!(seeds_for_slot(&ctx, &sp(Slot::Param(0), &[])), vec![3, 4, 5]);
        // field-specific fact: the disjoint sibling [7] must NOT be seeded —
        // this is the field-path precision doc 20 buys, preserved in descent.
        assert_eq!(seeds_for_slot(&ctx, &sp(Slot::Param(0), &[3])), vec![3, 5]);
        assert_eq!(seeds_for_slot(&ctx, &sp(Slot::Param(1), &[])), vec![8]);
        assert_eq!(seeds_for_slot(&ctx, &sp(Slot::Receiver, &[])), vec![2]);
        // sorted+deduped so the descent is order-stable
        assert!(seeds_for_slot(&ctx, &sp(Slot::Param(0), &[])).windows(2).all(|w| w[0] < w[1]));
    }

    #[test]
    fn seeds_empty_when_nothing_carries_the_slot() {
        let ctx = FnCtx {
            in_slots: vec![(1, sp(Slot::Param(0), &[]))],
            ..Default::default()
        };
        assert!(seeds_for_slot(&ctx, &sp(Slot::Param(9), &[])).is_empty());
    }

    // --- backtrace

    #[test]
    fn backtrace_returns_seed_to_sink_order() {
        // 1 -> 2 -> 3 recorded as pred{3:2, 2:1}
        let pred: HashMap<u32, u32> = [(3, 2), (2, 1)].into_iter().collect();
        assert_eq!(backtrace(&pred, 3), vec![1, 2, 3]);
        assert_eq!(backtrace(&HashMap::new(), 5), vec![5], "seed itself");
    }

    #[test]
    fn backtrace_survives_a_cyclic_pred_map() {
        // pred is acyclic by construction; if that ever breaks we must not hang.
        let pred: HashMap<u32, u32> = [(1, 2), (2, 1)].into_iter().collect();
        let p = backtrace(&pred, 1);
        assert!(p.len() <= 10_002, "guard must bound the walk, got {}", p.len());
    }

    // --- field_of

    #[test]
    fn field_of_prefers_names_and_falls_back_to_numbers() {
        let flow = cgf::LocalFlow {
            vertices: vec![
                vertex(1, &[], &[]),
                vertex(2, &[3, 1], &["Client", "Id"]),
                vertex(3, &[3, 1], &["Client"]), // names incomplete => numeric
            ],
            ..Default::default()
        };
        let none = Residual::default();
        assert_eq!(field_of(&flow, 1, &none), None, "whole object => no field");
        assert_eq!(field_of(&flow, 2, &none), Some("Client.Id".to_string()));
        assert_eq!(field_of(&flow, 3, &none), Some("3.1".to_string()));
        assert_eq!(field_of(&flow, 99, &none), None, "unknown vertex");
    }

    /// A hop inside a pass-through frame declares no path of its own; the fact
    /// it carries is entirely the caller's residual, and that is what a reader
    /// of the route needs to see.
    #[test]
    fn field_of_renders_the_residual_when_the_frame_projects_nothing() {
        let flow = cgf::LocalFlow {
            vertices: vec![
                vertex(1, &[], &[]),
                vertex(2, &[3], &["Client"]),
                vertex(3, &[3, 1], &["Client", "Id"]),
            ],
            ..Default::default()
        };
        let r = Residual {
            path: vec![1],
            names: vec!["Id".into()],
        };
        assert_eq!(
            field_of(&flow, 1, &r),
            Some("Id".to_string()),
            "whole-object vertex + residual => the residual IS the field"
        );
        assert_eq!(
            field_of(&flow, 2, &r),
            Some("Client.Id".to_string()),
            "declared path and residual compose"
        );
        // k-guard: vertex 3 is already at MAX_FIELD_PATH, so it may be a
        // frontend truncation and the residual must be dropped.
        assert_eq!(
            field_of(&flow, 3, &r),
            Some("Client.Id".to_string()),
            "a full-length declared path must not be extended"
        );
        // names unavailable on one side => numeric rendering, never a mix
        let unnamed = Residual {
            path: vec![1],
            names: vec![],
        };
        assert_eq!(field_of(&flow, 2, &unnamed), Some("3.1".to_string()));
    }

    // --- contract_handlers

    #[test]
    fn contract_handlers_indexes_by_contract_and_keeps_streaming_flags() {
        let prog = Program {
            funcs: HashMap::new(),
            repo_of: HashMap::new(),
            packages: vec![cgf::CgfPackage {
                grpc_methods: vec![
                    cgf::GrpcMethod {
                        iid: vec![0xC1; 32],
                        handler_iid: vec![0x1A; 32],
                        server_streaming: true,
                        ..Default::default()
                    },
                    // no handler in this repo => not indexable
                    cgf::GrpcMethod {
                        iid: vec![0xC2; 32],
                        handler_iid: vec![],
                        ..Default::default()
                    },
                ],
                ..Default::default()
            }],
        };
        let h = contract_handlers(&prog);
        assert_eq!(h.len(), 1, "handler-less contracts must be skipped");
        let (handler, shape) = h.get(&hexid(&[0xC1; 32])).unwrap();
        assert_eq!(*handler, hexid(&[0x1A; 32]));
        assert_eq!(*shape, ContractShape::Grpc(false, true));
    }

    // --- GraphQL contracts (doc 36 §3.2)

    #[test]
    fn contract_handlers_indexes_graphql_fields_with_their_arg_frame() {
        let prog = Program {
            funcs: HashMap::new(),
            repo_of: HashMap::new(),
            packages: vec![cgf::CgfPackage {
                graphql_fields: vec![
                    cgf::GraphqlField {
                        iid: vec![0xC3; 32],
                        type_field: "Query.searchByToken".into(),
                        resolver_iid: vec![0x2B; 32],
                        args: vec![cgf::GraphqlArg { name: "token".into(), param_idx: 1 }],
                        ..Default::default()
                    },
                    // resolver not in this repo => not indexable
                    cgf::GraphqlField {
                        iid: vec![0xC4; 32],
                        resolver_iid: vec![],
                        ..Default::default()
                    },
                ],
                ..Default::default()
            }],
        };
        let h = contract_handlers(&prog);
        assert_eq!(h.len(), 1, "resolver-less fields must be skipped");
        let (handler, shape) = h.get(&hexid(&[0xC3; 32])).unwrap();
        assert_eq!(*handler, hexid(&[0x2B; 32]));
        assert_eq!(*shape, ContractShape::Graphql(vec![1]));
    }

    /// The client's arg port j must land on the resolver's real param, not on
    /// ctx (Param(0)) — the whole point of the GraphQL contract view.
    #[test]
    fn unview_graphql_maps_arg_port_to_the_resolver_param() {
        let shape = ContractShape::Graphql(vec![2, 3]); // field resolver: ctx, obj, a, b
        assert_eq!(unview_slot(&sp(Slot::Param(0), &[5]), &shape).slot, Slot::Param(2));
        assert_eq!(unview_slot(&sp(Slot::Param(0), &[5]), &shape).path, vec![5]);
        assert_eq!(unview_slot(&sp(Slot::Param(1), &[]), &shape).slot, Slot::Param(3));
        // a dangling port (normalize.rs pushes unknown names past the end)
        assert_eq!(unview_slot(&sp(Slot::Param(9), &[]), &shape).slot, Slot::Param(9));
    }
}
