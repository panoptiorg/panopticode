// Sink-seeded backward demand analysis — the bidirectional confirmation pass
// (doc 35).
//
// Phase 1 (ifds.rs) is FORWARD and compositional: every function is summarised
// once, per in-slot, in its own local vocabulary — the field paths its body
// happens to project. That vocabulary is the root of the dominant route defect
// on two corpora (doc 25 §3 R1, measurements FP-02): a pass-through frame has
// only the whole-object in-slot, `slot_compat` fires it for a caller fact
// `req.Amount` and the unconsumed tail is dropped, so two frames later every
// SIBLING field reads as tainted. Stage W (witness.rs) repairs the ROUTE by
// carrying the residual through the descent; Stage C (doc 26) would carry it
// through `propagate`, at the price of a new summary format and a whole-corpus
// re-baseline.
//
// This module takes the other end. For a chain the forward engine reported it
// asks, on demand: *which in-facts of the source function reach THIS terminal,
// exactly?* The walk starts at the terminal sink's argument ports and follows
// LocalFlow edges BACKWARD (the sidecar is a symmetric relation, bipartite
// source-kind -> sink-kind, so reversal is exact at the edge level). At a
// result port it descends into the callee's body with the demanded out-slot
// instead of consulting the callee's summary rows, and it carries the part of
// the demand the frame does not spell out as a RESIDUAL — state is
// `(vertex, residual)`, exactly the model doc 26 §7 prescribes for Stage C, but
// on a per-chain demand instead of on every summary. A pass-through frame with
// only whole-object vertices therefore rides the demand intact, and a mapper
// that fills `ClientId` from the session and `Amount` from the request tells the
// two apart, because backward from `req.ClientId` the only predecessor is the
// session call.
//
// The meet is at the source: a chain is
//   confirmed   a demand landed on one of the forward pass's source seeds;
//   refuted     the walk completed and no demand did;
//   undecided   the walk was INCOMPLETE — a construct this pass does not model
//               (recursion, stream ports, heap cells, PG-leaf contracts, a
//               truncated route) — so absence of a demand proves nothing.
// Over-approximations (a default leaf, a k-truncated vertex, a body-less summary
// row) only ever ADD demands, so they can never turn a real chain into a
// refutation; they are tracked as `exact=false` on the confirmation instead.
// Under-approximations are the only way to refute wrongly, and every one of
// them sets `incomplete`, which downgrades the verdict to undecided. That
// asymmetry is the whole soundness argument: a refuted chain is a chain no
// residual-carrying path can explain.
//
// Nothing here touches summaries, the summary store, or phase 1's cache
// environment. Cost is memoised per (function, demand) and per (function, sink
// class, terminal), so a cone is walked once however many chains share it.
use crate::compose::ContractShape;
use crate::graph::{hexid, IidHex};
use crate::ifds::{leaf_getter_field, stream_of, Engine, FieldPath, FnCtx, Slot, SlotP, MAX_FIELD_PATH};
use crate::proto::cgf;
use crate::witness::{ContractHandlers, HopKind, Route};
use serde::Serialize;
use std::cell::{Cell, RefCell};
use std::collections::{HashMap, HashSet};
use std::rc::Rc;

/// A residual element known only by NAME: the core-side protobuf getter rule
/// (`leaf_getter_field`) learns the field's Go name from the callee fqn but not
/// its proto number, which is what vertex paths carry. Such an element matches
/// a vertex element by name when both sides have names, and is otherwise
/// treated as comparable-but-inexact (the sound direction).
pub const NAME_ID: u32 = u32::MAX;
/// Bound on a full demand path (declared ++ residual). Beyond it the residual is
/// dropped — a widening, recorded as such.
pub const MAX_DEMAND: usize = 8;
const MAX_DEPTH: usize = 64;

/// Flag-gated behaviour for this pass.
///
/// Held in a thread-local rather than threaded through `Back::new`, so that
/// `report::backward_check`'s signature — and every one of its callers — is
/// untouched by a flag that only this module reads. `Back::new` snapshots it
/// once, so a walk never sees the options change under it. Thread-local and
/// not a global because `Back` is single-threaded anyway (RefCell throughout)
/// and the unit tests below would otherwise leak one test's flags into
/// another's walk.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct BackOpts {
    /// Cross a contract whose published view is NOT the handler's own frame
    /// (streaming gRPC, a GraphQL field whose resolver args are permuted) by
    /// undoing `compose`'s slot remap, instead of declaring the walk
    /// incomplete there. DEFAULT OFF: with it off every verdict is exactly
    /// the verdict this pass produced before the unview step existed.
    pub unview: bool,
    /// `--backward-prune` is active. Known here, not only in report.rs,
    /// because a refutation that crossed an unviewed contract must SURVIVE the
    /// prune: a wrong unview refutes wrongly, and a pruned chain is gone.
    pub prune: bool,
    /// …unless this says unviewed refutations are trusted for pruning too.
    pub prune_unviewed: bool,
}

thread_local! {
    static OPTS: Cell<BackOpts> = Cell::new(BackOpts { unview: false, prune: false, prune_unviewed: false });
    /// chains whose verdict differs from the one the same walk would have
    /// returned with `unview` off
    static FLIPS: Cell<usize> = Cell::new(0);
}

/// Install the options for the next `report::backward_check` (same thread) and
/// reset the flip counter.
pub fn set_opts(o: BackOpts) {
    OPTS.with(|c| c.set(o));
    FLIPS.with(|c| c.set(0));
}

pub fn opts() -> BackOpts {
    OPTS.with(|c| c.get())
}

/// How many chains the unview step moved off the verdict they would have got
/// without it. Printed in the backward summary line.
pub fn unview_flips() -> usize {
    FLIPS.with(|c| c.get())
}

fn is_false(b: &bool) -> bool {
    !*b
}

/// Handler frame -> client frame for an IN-slot: exactly the `map_in` of
/// `compose::contract_view` / `compose::contract_view_graphql`, on the slot
/// alone (a field path rides a contract untouched, doc 20 §2.4).
///
/// This is the direction the BACKWARD pass needs. Demand travels sink ->
/// source: a walk that descended into the handler comes back carrying demands
/// in the HANDLER's frame, and they must be re-expressed in the CLIENT's frame
/// before `land` can put them on the call site's arg ports. It is the exact
/// inverse of `witness::unview_slot`, which the FORWARD descent uses to go the
/// other way (client -> handler); the round trip is asserted in the tests.
///
/// `None` means `compose` DROPS the slot: no client-frame port carries it, so
/// the demand cannot be expressed at the call site at all. That is an
/// under-approximation, so the caller keeps `incomplete` — it never guesses a
/// port, because a guessed port is how a wrong `refuted` is manufactured.
///
/// ```text
///   shape                          handler in-slot          client in-slot
///   ------------------------------ ------------------------ ----------------
///   gRPC unary (false,false)       every slot               itself (identity)
///   gRPC server-stream (false,true) Param(0)  (the request) Param(1)
///                                  Param(n>0), Receiver     DROPPED
///                                  StreamIn/Source/Global   itself
///   gRPC client-stream (true,false) Param(_), Receiver      DROPPED — the
///   gRPC bidi          (true,true)                          handler takes only
///                                                           the stream object
///                                  StreamIn/Source/Global   itself
///   GraphQL(args)                  Param(args[j])           Param(j)
///                                  Param(p) not in args     DROPPED (ctx, obj)
///                                  Receiver, ByRef*         DROPPED
///                                  Source/Global/Stream*    itself
/// ```
///
/// Note the one asymmetry with `ContractShape::is_identity`: `Graphql(vec![])`
/// (a field with no SDL arguments) is VACUOUSLY identity, yet maps every
/// `Param` to `None`. The crossing sites take the identity branch for it —
/// i.e. today's behaviour, unchanged — and never consult this function, which
/// is why the debug_assert in `land_viewed` allows a drop but not a remap.
fn view_slot(s: &Slot, shape: &ContractShape) -> Option<Slot> {
    match shape {
        ContractShape::Grpc(client_streaming, server_streaming) => {
            if !client_streaming && !server_streaming {
                return Some(s.clone());
            }
            match s {
                Slot::Param(0) if *server_streaming && !*client_streaming => Some(Slot::Param(1)),
                Slot::Param(_) | Slot::Receiver => None,
                _ => Some(s.clone()),
            }
        }
        ContractShape::Graphql(args) => match s {
            Slot::Param(p) => args
                .iter()
                .position(|a| a == p)
                .map(|j| Slot::Param(j as u32)),
            Slot::Receiver | Slot::ByRefParam(_) | Slot::ByRefReceiver => None,
            _ => Some(s.clone()),
        },
    }
}

/// Client frame -> handler frame for an OUT-slot: the inverse of the same two
/// views' `map_out`. Backward hands a demanded callee OUT-slot DOWN into the
/// handler's body, so this one runs on the way in — `view_slot` runs on the
/// way back out.
///
/// ```text
///   gRPC unary      every out-slot -> itself
///   gRPC streaming  Return(_)              -> DROPPED (compose drops the
///                                             handler's error return so it
///                                             cannot land, index-mismatched,
///                                             on the client's (stream, err))
///                   StreamOut/Source/…     -> itself
///   GraphQL         Return(0)              -> Return(0)
///                   Return(n>0)            -> DROPPED (the resolver's error)
///                   ByRefParam/ByRefReceiver -> DROPPED
///                   everything else        -> itself
/// ```
///
/// `None` again means the demand is inexpressible on the other side of the
/// contract: keep `incomplete`, do not guess.
fn unview_out_slot(s: &Slot, shape: &ContractShape) -> Option<Slot> {
    match shape {
        ContractShape::Grpc(client_streaming, server_streaming) => {
            if !client_streaming && !server_streaming {
                return Some(s.clone());
            }
            match s {
                Slot::Return(_) => None,
                _ => Some(s.clone()),
            }
        }
        ContractShape::Graphql(_) => match s {
            Slot::Return(0) => Some(Slot::Return(0)),
            Slot::Return(_) | Slot::ByRefParam(_) | Slot::ByRefReceiver => None,
            _ => Some(s.clone()),
        },
    }
}

#[derive(Serialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    Confirmed,
    Refuted,
    Undecided,
}

#[derive(Serialize, Clone, Debug)]
pub struct BackReport {
    pub verdict: Verdict,
    /// true iff some confirming demand never crossed an over-approximation
    /// (default leaf, k-truncation, body-less summary row). A confirmed but
    /// inexact chain is one this pass cannot discriminate either — typically a
    /// value that went through an opaque callee.
    pub exact: bool,
    /// The source-side field(s) the terminal actually reads, as the demand
    /// arrived at the source seed. Names when the frontend emitted them, else
    /// numeric; `?` for a name-only element.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub source_fields: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Verdict for the route's OWN terminal sink instance (the chain verdict
    /// above admits any same-class terminal below the chain's source call
    /// site, because that is what one forward chain stands for). A chain that
    /// is confirmed while its terminal is refuted has a real flow and a wrong
    /// route label — the witness picked a sibling sink that a session value,
    /// not the request, reaches (measurements FP-02 / idx 11).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub terminal: Option<Verdict>,
    /// The walk crossed a contract whose published view is not the handler's
    /// own frame, and got through it by undoing compose's slot remap
    /// (`--backward-unview`). Always false without that flag. A refutation
    /// carrying this bit is the one kind the default `--backward-prune`
    /// refuses to act on.
    #[serde(skip_serializing_if = "is_false")]
    pub unviewed: bool,
}

#[derive(Default, Debug, Clone, Copy, Serialize)]
pub struct BackStats {
    pub confirmed: usize,
    pub confirmed_exact: usize,
    pub refuted: usize,
    pub undecided: usize,
    pub pruned: usize,
    /// confirmed chains whose route terminal is refuted: real finding, wrong
    /// route label
    pub mislabelled: usize,
}

/// A field path with optional reporting names (`names.len() == ids.len()` or
/// empty — the proto's own convention).
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
struct Path {
    ids: Vec<u32>,
    names: Vec<String>,
}

impl Path {
    fn from_vertex(v: &cgf::FlowVertex) -> Path {
        let names = if v.field_names.len() == v.field_path.len() {
            v.field_names.clone()
        } else {
            Vec::new()
        };
        Path { ids: v.field_path.clone(), names }
    }
    fn from_ids(ids: &[u32]) -> Path {
        Path { ids: ids.to_vec(), names: Vec::new() }
    }
    fn is_empty(&self) -> bool {
        self.ids.is_empty()
    }
    fn len(&self) -> usize {
        self.ids.len()
    }
    fn name(&self, i: usize) -> Option<&str> {
        self.names.get(i).map(|s| s.as_str()).filter(|s| !s.is_empty())
    }
    fn concat(&self, tail: &Path) -> Path {
        let ids: Vec<u32> = self.ids.iter().chain(tail.ids.iter()).copied().collect();
        let names = if (self.names.len() == self.ids.len() || self.ids.is_empty())
            && (tail.names.len() == tail.ids.len() || tail.ids.is_empty())
        {
            self.names.iter().chain(tail.names.iter()).cloned().collect()
        } else {
            Vec::new()
        };
        Path { ids, names }
    }
    /// `self[from..]`
    fn tail(&self, from: usize) -> Path {
        Path {
            ids: self.ids[from..].to_vec(),
            names: if self.names.len() == self.ids.len() {
                self.names[from..].to_vec()
            } else {
                Vec::new()
            },
        }
    }
    fn render(&self) -> String {
        if self.ids.is_empty() {
            return String::new();
        }
        if self.names.len() == self.ids.len() {
            self.names.join(".")
        } else {
            self.ids
                .iter()
                .map(|i| if *i == NAME_ID { "?".to_string() } else { i.to_string() })
                .collect::<Vec<_>>()
                .join(".")
        }
    }
}

/// Are two paths prefix-comparable (`ifds::paths_comparable`, name-aware)?
/// Some(exact): comparable, and whether every compared element matched by
/// identity rather than by the sound fallback. None: disjoint.
fn comparable(a: &Path, b: &Path) -> Option<bool> {
    let n = a.len().min(b.len());
    let mut exact = true;
    for i in 0..n {
        let (x, y) = (a.ids[i], b.ids[i]);
        if x != NAME_ID && y != NAME_ID {
            if x != y {
                return None;
            }
            continue;
        }
        match (a.name(i), b.name(i)) {
            (Some(p), Some(q)) => {
                if p != q {
                    return None;
                }
            }
            _ => exact = false,
        }
    }
    Some(exact)
}

/// What a demand `full` still carries below a vertex declared at `declared`
/// (both already known comparable).
fn residual_of(full: &Path, declared: &Path) -> Path {
    if full.len() > declared.len() {
        full.tail(declared.len())
    } else {
        Path::default()
    }
}

/// One backward state: a vertex plus the part of the demand the vertex's own
/// path does not spell out. `exact` is false once an over-approximation was
/// crossed on the way here.
#[derive(Clone, Debug)]
struct St {
    v: u32,
    resid: Path,
    exact: bool,
    /// this state was reached through a contract whose view had to be
    /// un-remapped (`--backward-unview`); without the flag it would not exist
    uv: bool,
}

/// A demand on a callee-side in-slot (or, after `land`, a caller-side port).
#[derive(Clone, Debug)]
struct Demand {
    slot: Slot,
    path: Path,
    exact: bool,
    /// see `St::uv`
    uv: bool,
}

#[derive(Default, Debug)]
struct FrameOut {
    ins: Vec<Demand>,
    /// (full path at the seed, exact, reached-through-an-unview) for every
    /// forward source seed a demand landed on
    seeds: Vec<(Path, bool, bool)>,
    /// an under-approximation happened: absence of a demand proves nothing
    incomplete: bool,
    /// an over-approximation happened
    widened: bool,
    /// a contract with a non-identity view was crossed by undoing the remap
    unviewed: bool,
    /// …and somewhere a demanded slot had no counterpart on the other side of
    /// such a contract, so `incomplete` is set for that specific reason
    unview_dropped: bool,
}

#[derive(Default, Debug)]
struct FlowSum {
    ins: Vec<Demand>,
    incomplete: bool,
    widened: bool,
    unviewed: bool,
    unview_dropped: bool,
}

#[derive(Default, Debug)]
struct SinkSum {
    ins: Vec<Demand>,
    seeds: Vec<(Path, bool, bool)>,
    incomplete: bool,
    widened: bool,
    unviewed: bool,
    unview_dropped: bool,
}

/// Per-function reverse view of the LocalFlow sidecar.
struct BCtx<'p> {
    flow: &'p cgf::LocalFlow,
    verts: HashMap<u32, &'p cgf::FlowVertex>,
    radj: HashMap<u32, Vec<u32>>,
    /// vertices that are the `from` of some edge (an arg port here is a by-ref
    /// source: the callee wrote through it)
    has_out: HashSet<u32>,
    arg_ports: HashMap<(usize, u32), Vec<u32>>,
    out_verts: Vec<u32>,
    source_seeds: HashSet<u32>,
    arg0_recv: Vec<bool>,
    fqn: String,
}

impl<'p> BCtx<'p> {
    fn build(f: &'p cgf::Function, ctx: &FnCtx) -> Option<BCtx<'p>> {
        let flow = f.flow.as_ref()?;
        let mut b = BCtx {
            flow,
            verts: HashMap::new(),
            radj: HashMap::new(),
            has_out: HashSet::new(),
            arg_ports: HashMap::new(),
            out_verts: Vec::new(),
            source_seeds: ctx.source_seeds.iter().copied().collect(),
            arg0_recv: flow.callsites.iter().map(|c| c.arg0_is_receiver).collect(),
            fqn: f.fqn.clone(),
        };
        for v in &flow.vertices {
            b.verts.insert(v.id, v);
            let Ok(kind) = cgf::VertexKind::try_from(v.kind) else { continue };
            match kind {
                cgf::VertexKind::CallArgPort => b
                    .arg_ports
                    .entry((v.callsite_id as usize, v.index))
                    .or_default()
                    .push(v.id),
                cgf::VertexKind::OutReturn
                | cgf::VertexKind::OutParamByref
                | cgf::VertexKind::OutReceiverByref => b.out_verts.push(v.id),
                _ => {}
            }
        }
        for e in &flow.edges {
            b.radj.entry(e.to).or_default().push(e.from);
            b.has_out.insert(e.from);
        }
        Some(b)
    }
}

/// Which sink instance a chain ends at: the frame and call site of its
/// terminal hop. Keys the sink-demand memo so two chains of one source
/// function and class that end at different sinks get different verdicts.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Terminal {
    pub fn_iid: IidHex,
    pub callsite: usize,
}

pub struct Back<'a, 'e> {
    engine: &'a Engine<'e>,
    handlers: &'a ContractHandlers,
    ctxs: RefCell<HashMap<IidHex, Option<Rc<BCtx<'e>>>>>,
    flow_memo: RefCell<HashMap<(IidHex, String), Rc<FlowSum>>>,
    sink_memo: RefCell<HashMap<(IidHex, String, Option<Terminal>), Rc<SinkSum>>>,
    in_progress: RefCell<HashSet<String>>,
    /// snapshot of the thread-local flags, taken once so a walk cannot see
    /// them change (and so the memo tables stay coherent with them)
    opts: BackOpts,
}

impl<'a, 'e> Back<'a, 'e> {
    pub fn new(engine: &'a Engine<'e>, handlers: &'a ContractHandlers) -> Self {
        Back {
            engine,
            handlers,
            ctxs: RefCell::new(HashMap::new()),
            flow_memo: RefCell::new(HashMap::new()),
            sink_memo: RefCell::new(HashMap::new()),
            in_progress: RefCell::new(HashSet::new()),
            opts: opts(),
        }
    }

    fn ctx(&self, iid: &IidHex) -> Option<Rc<BCtx<'e>>> {
        if let Some(c) = self.ctxs.borrow().get(iid) {
            return c.clone();
        }
        let built = self
            .engine
            .prog
            .funcs
            .get(iid)
            .and_then(|f| BCtx::build(f, &FnCtx::build(f, self.engine.cat)).map(Rc::new));
        self.ctxs.borrow_mut().insert(iid.clone(), built.clone());
        built
    }

    /// Verdict for one reported chain: source function `src`, sink `class`,
    /// the call site in `src` the forward chain fired at (`cs0`), and the
    /// route the witness reconstructed (its terminal names the sink instance
    /// the route shows).
    ///
    /// The chain verdict admits ANY same-class terminal below `cs0`: one
    /// forward chain is one `PropSink`, i.e. one (class, call site, variant),
    /// and the witness merely picked one of the sinks it stands for. The
    /// route's own terminal gets its separate verdict in `terminal`.
    pub fn check(&self, src: &IidHex, class: &str, cs0: usize, route: Option<&Route>) -> BackReport {
        let undecided = |why: &str| BackReport {
            verdict: Verdict::Undecided,
            exact: false,
            source_fields: Vec::new(),
            reason: Some(why.to_string()),
            terminal: None,
            unviewed: false,
        };
        let Some(route) = route else {
            return undecided("no_route");
        };
        if let Some(inc) = &route.incomplete {
            return undecided(&format!("route_incomplete:{inc:?}"));
        }
        if route.hops.iter().any(|h| h.kind == HopKind::Heap) || cs0 == usize::MAX {
            return undecided("heap_crossing");
        }
        let Some((leaf, cs)) = &route.terminal else {
            return undecided("no_terminal");
        };
        let term = Terminal { fn_iid: leaf.clone(), callsite: *cs };
        let any = self.top_frame(src, class, cs0, None);
        let own = self.top_frame(src, class, cs0, Some(&term));
        let verdict_of = |ss: &SinkSum| {
            if !ss.seeds.is_empty() {
                Verdict::Confirmed
            } else if ss.incomplete {
                Verdict::Undecided
            } else {
                Verdict::Refuted
            }
        };
        let (v_any, v_own) = (verdict_of(&any), verdict_of(&own));
        // What the SAME walk would have returned with --backward-unview off:
        // every remapped crossing would have set `incomplete` there, and no
        // demand — hence no seed — would have come back through it. Exact,
        // because `uv`/`unviewed` mark precisely the states that only exist
        // because of the unview step.
        let v_off = if any.seeds.iter().any(|(_, _, uv)| !*uv) {
            Verdict::Confirmed
        } else if any.incomplete || any.unviewed {
            Verdict::Undecided
        } else {
            Verdict::Refuted
        };
        if v_off != v_any {
            FLIPS.with(|c| c.set(c.get() + 1));
        }
        // Doc 35 §safety, restated for the unview step: a wrong unview yields a
        // wrong REFUTATION, and under --backward-prune a refutation deletes a
        // finding. So the default prune never acts on one that crossed a
        // remapped contract — it is reported undecided instead, which `retain`
        // keeps. --backward-prune-unviewed opts back in.
        let (v_any, unviewed_refutation) = if v_any == Verdict::Refuted
            && any.unviewed
            && self.opts.prune
            && !self.opts.prune_unviewed
        {
            (Verdict::Undecided, true)
        } else {
            (v_any, false)
        };
        if let Some(t) = self.engine.trace.filter(|t| t.wants("back")) {
            let fqn = self.engine.prog.funcs.get(src).map(|f| f.fqn.as_str()).unwrap_or("?");
            t.log(format_args!(
                "back      fn={} class={} cs0={} term={}:{} any={:?} own={:?} ins={} seeds={} incomplete={} widened={}",
                fqn,
                class,
                cs0,
                &leaf[..leaf.len().min(12)],
                cs,
                v_any,
                v_own,
                any.ins.len(),
                any.seeds.len(),
                any.incomplete,
                any.widened
            ));
        }
        match v_any {
            Verdict::Confirmed => {
                let exact = any.seeds.iter().any(|(_, e, _)| *e);
                let mut fields: Vec<String> = any
                    .seeds
                    .iter()
                    .map(|(p, _, _)| p.render())
                    .filter(|s| !s.is_empty())
                    .collect();
                fields.sort();
                fields.dedup();
                BackReport {
                    verdict: Verdict::Confirmed,
                    exact,
                    source_fields: fields,
                    reason: None,
                    terminal: Some(v_own),
                    unviewed: any.unviewed,
                }
            }
            Verdict::Undecided => {
                let why = if unviewed_refutation {
                    "unviewed_refutation_not_pruned"
                } else if any.unview_dropped {
                    "unview_dropped_slot"
                } else {
                    "walk_incomplete"
                };
                BackReport {
                    terminal: Some(v_own),
                    unviewed: any.unviewed,
                    ..undecided(why)
                }
            }
            Verdict::Refuted => BackReport {
                verdict: Verdict::Refuted,
                exact: !any.widened,
                source_fields: Vec::new(),
                reason: None,
                terminal: Some(v_own),
                unviewed: any.unviewed,
            },
        }
    }

    /// The source frame, entered only through call site `cs0` (the one the
    /// forward chain fired at). Not memoised: one walk per chain.
    fn top_frame(&self, src: &IidHex, class: &str, cs0: usize, term: Option<&Terminal>) -> SinkSum {
        self.back_sink_inner(src, class, term, 0, Some(cs0))
    }

    /// Demands on `iid`'s in-slots that reach a `class` sink at `term`
    /// (through any callee), plus the forward source seeds they land on.
    fn back_sink(&self, iid: &IidHex, class: &str, term: Option<&Terminal>, depth: usize) -> Rc<SinkSum> {
        let key = (iid.clone(), class.to_string(), term.cloned());
        if let Some(s) = self.sink_memo.borrow().get(&key) {
            return s.clone();
        }
        let guard = format!(
            "S|{}|{}|{}",
            iid,
            class,
            term.map(|t| format!("{}:{}", t.fn_iid, t.callsite)).unwrap_or_default()
        );
        if depth > MAX_DEPTH || !self.in_progress.borrow_mut().insert(guard.clone()) {
            // recursion (or the depth cap): the demands below this point are
            // unknown, so nothing derived from here may refute
            return Rc::new(SinkSum { incomplete: true, ..Default::default() });
        }
        let out = self.back_sink_inner(iid, class, term, depth, None);
        self.in_progress.borrow_mut().remove(&guard);
        let rc = Rc::new(out);
        self.sink_memo.borrow_mut().insert(key, rc.clone());
        rc
    }

    /// `only_cs`: restrict the frame's entry points to one call site (the
    /// chain's source call site); None = every call site in the frame.
    fn back_sink_inner(&self, iid: &IidHex, class: &str, term: Option<&Terminal>, depth: usize, only_cs: Option<usize>) -> SinkSum {
        let Some(b) = self.ctx(iid) else {
            return SinkSum { incomplete: true, ..Default::default() };
        };
        let cat = self.engine.cat;
        let mut fo = FrameOut::default();
        let mut starts: Vec<St> = Vec::new();
        // W1F: a heap-mediated sink inside this cone is invisible to a
        // positional walk; only relevant once heap::fixpoint populated cells.
        if !self.engine.heap_cells.is_empty()
            && b.flow.vertices.iter().any(|v| {
                v.kind == cgf::VertexKind::OutField as i32 && !v.sym.is_empty()
            })
        {
            fo.incomplete = true;
        }
        for (cs_idx, cs) in b.flow.callsites.iter().enumerate() {
            if only_cs.map_or(false, |c| c != cs_idx) {
                continue;
            }
            // propagate: a sanitizer call site kills the fact before the sink
            // check and before composition, so nothing starts here
            if cat.sanitizer_of(&cs.callee_fqn).is_some() {
                continue;
            }
            // (a) a catalog sink at this call site: the terminal itself, or
            // any of the class when no terminal is pinned
            if term.map_or(true, |t| *iid == t.fn_iid && cs_idx == t.callsite) {
                if let Some(sink) = cat.sink_of(&cs.callee_fqn) {
                    if sink.class == class {
                        let ports: Vec<u32> = match sink.arg {
                            crate::catalog::SinkArg::Any => (0..cs.argc).collect(),
                            crate::catalog::SinkArg::Index(i) => vec![i],
                        };
                        for p in ports {
                            for &v in b.arg_ports.get(&(cs_idx, p)).into_iter().flatten() {
                                starts.push(St { v, resid: Path::default(), exact: true, uv: false });
                            }
                        }
                    }
                }
            }
            // (b) callees that reach the terminal
            if stream_of(cs).is_some() {
                // stream data ports are whole-message and routed structurally
                // (StreamIn/StreamOut); not modelled here
                if cs.callee_iids.iter().any(|c| {
                    self.engine
                        .summaries
                        .get(&hexid(c))
                        .map_or(false, |s| s.sink_hits.iter().any(|h| h.class == class))
                }) {
                    fo.incomplete = true;
                }
                continue;
            }
            for cid in &cs.callee_iids {
                let h = hexid(cid);
                let Some(sum) = self.engine.summaries.get(&h) else { continue };
                if !sum.sink_hits.iter().any(|s| s.class == class) {
                    continue; // cheap prune: nothing of this class below
                }
                // `remapped` means "the published view is not the handler's
                // own frame" (streaming gRPC, a permuted-arg GraphQL field).
                // Descending into such a handler needs compose's slot remap
                // undone on the way back out (`view_slot`, in `land_viewed`);
                // without --backward-unview there is no unview step here, so
                // the crossing is reported incomplete rather than followed
                // into the wrong slot — the pre-flag behaviour, byte for byte.
                let (target, shape) = match self.handlers.get(&h) {
                    Some((hh, sh)) => (hh.clone(), Some(sh.clone())),
                    None => (h.clone(), None),
                };
                let remapped = shape.as_ref().map_or(false, |sh| !sh.is_identity());
                if remapped && !self.opts.unview {
                    fo.incomplete = true;
                    continue;
                }
                let has_body = self
                    .engine
                    .prog
                    .funcs
                    .get(&target)
                    .map_or(false, |f| f.flow.is_some());
                if has_body {
                    let sub = self.back_sink(&target, class, term, depth + 1);
                    fo.incomplete |= sub.incomplete;
                    fo.widened |= sub.widened;
                    fo.unviewed |= sub.unviewed | remapped;
                    fo.unview_dropped |= sub.unview_dropped;
                    for d in &sub.ins {
                        self.land_viewed(&b, cs_idx, d, shape.as_ref(), &mut fo, &mut starts);
                    }
                } else {
                    // body-less (PG leaf contract): only its rows are known,
                    // in its own vocabulary and with no terminal identity
                    fo.widened = true;
                    if remapped {
                        // the rows ARE the client-frame view, so they land
                        // as-is, no remap to undo — but that view is a LOSSY
                        // projection of a body we cannot see (compose drops
                        // the handler's non-stream params, its returns, ctx,
                        // obj), so the rows may confirm and must never refute.
                        fo.incomplete = true;
                        fo.unviewed = true;
                    }
                    for sh in &sum.sink_hits {
                        if sh.class != class {
                            continue;
                        }
                        let d = Demand {
                            slot: sh.in_slot.slot.clone(),
                            path: Path::from_ids(&sh.in_slot.path),
                            exact: false,
                            uv: remapped,
                        };
                        self.land(&b, cs_idx, &d, &mut starts);
                    }
                }
            }
        }
        let nstarts = starts.len();
        self.walk(&b, starts, depth, &mut fo);
        if let Some(t) = self.engine.trace.filter(|t| t.on_ev("back-frame", &b.fqn)) {
            let ins: Vec<String> = fo
                .ins
                .iter()
                .map(|d| format!("{:?}.{}{}", d.slot, d.path.render(), if d.exact { "" } else { "~" }))
                .collect();
            t.log(format_args!(
                "back-frame fn={} class={} term={} only_cs={:?} starts={} ins=[{}] seeds={} incomplete={} widened={}",
                b.fqn,
                class,
                term.map(|t| format!("{}:{}", &t.fn_iid[..12], t.callsite)).unwrap_or_else(|| "any".into()),
                only_cs,
                nstarts,
                ins.join(" "),
                fo.seeds.len(),
                fo.incomplete,
                fo.widened
            ));
        }
        SinkSum {
            ins: fo.ins,
            seeds: fo.seeds,
            incomplete: fo.incomplete,
            widened: fo.widened,
            unviewed: fo.unviewed,
            unview_dropped: fo.unview_dropped,
        }
    }

    /// Demands on `iid`'s in-slots that reach its out-slot `out` (a backward
    /// transfer row, computed from the body rather than read from the summary).
    fn back_flow(&self, iid: &IidHex, out: &Demand, depth: usize) -> Rc<FlowSum> {
        let key = (iid.clone(), format!("{}|{}", crate::ifds::slot_str(&SlotP {
            slot: out.slot.clone(),
            path: out.path.ids.clone(),
        }), out.path.render()));
        if let Some(s) = self.flow_memo.borrow().get(&key) {
            return s.clone();
        }
        let guard = format!("F|{}|{}", key.0, key.1);
        if depth > MAX_DEPTH || !self.in_progress.borrow_mut().insert(guard.clone()) {
            return Rc::new(FlowSum { incomplete: true, ..Default::default() });
        }
        let sum = match self.ctx(iid) {
            None => FlowSum { incomplete: true, ..Default::default() },
            Some(b) => {
                let mut fo = FrameOut::default();
                let mut starts = Vec::new();
                for &v in &b.out_verts {
                    let vx = b.verts[&v];
                    let Ok(kind) = cgf::VertexKind::try_from(vx.kind) else { continue };
                    let slot = match kind {
                        cgf::VertexKind::OutReturn => Slot::Return(vx.index),
                        cgf::VertexKind::OutParamByref => Slot::ByRefParam(vx.index),
                        cgf::VertexKind::OutReceiverByref => Slot::ByRefReceiver,
                        _ => continue,
                    };
                    if slot != out.slot {
                        continue;
                    }
                    let vp = Path::from_vertex(vx);
                    let Some(ex) = comparable(&vp, &out.path) else { continue };
                    // uv starts false inside a sub-frame: the memo key does
                    // not carry it, and whether a remap was crossed on the way
                    // in is the CALLER's fact, OR-ed back in at `land_viewed`.
                    starts.push(St { v, resid: residual_of(&out.path, &vp), exact: out.exact && ex, uv: false });
                }
                self.walk(&b, starts, depth, &mut fo);
                FlowSum {
                    ins: fo.ins,
                    incomplete: fo.incomplete,
                    widened: fo.widened,
                    unviewed: fo.unviewed,
                    unview_dropped: fo.unview_dropped,
                }
            }
        };
        self.in_progress.borrow_mut().remove(&guard);
        let rc = Rc::new(sum);
        self.flow_memo.borrow_mut().insert(key, rc.clone());
        rc
    }

    /// Map a callee-side in-demand onto this frame's arg-port variants at
    /// `cs_idx` — the inverse of `ifds::arg_to_callee_slot`, receiver shift
    /// included.
    fn land(&self, b: &BCtx<'e>, cs_idx: usize, d: &Demand, out: &mut Vec<St>) {
        let recv = *b.arg0_recv.get(cs_idx).unwrap_or(&false);
        let port = match &d.slot {
            Slot::Param(i) => {
                if recv {
                    i + 1
                } else {
                    *i
                }
            }
            Slot::Receiver => {
                if recv {
                    0
                } else {
                    return;
                }
            }
            // Global/Field/Stream/Source in-facts never compose positionally
            _ => return,
        };
        self.land_port(b, cs_idx, port, &d.path, d.exact, d.uv, out);
    }

    /// `land`, with `compose`'s in-slot remap undone first. `shape` is the
    /// contract shape when this call site crossed a contract boundary, None
    /// for an ordinary callee. An IDENTITY shape lands exactly as `land`
    /// would — which is what makes --backward-unview a no-op on unary gRPC and
    /// on GraphQL fields whose resolver args are already in SDL order.
    fn land_viewed(
        &self,
        b: &BCtx<'e>,
        cs_idx: usize,
        d: &Demand,
        shape: Option<&ContractShape>,
        fo: &mut FrameOut,
        out: &mut Vec<St>,
    ) {
        match shape {
            Some(sh) if !sh.is_identity() => match view_slot(&d.slot, sh) {
                Some(slot) => self.land(
                    b,
                    cs_idx,
                    &Demand { slot, path: d.path.clone(), exact: d.exact, uv: true },
                    out,
                ),
                // compose drops this handler slot, so no client-frame port
                // carries the demand: absence of it downstream proves nothing.
                None => {
                    fo.incomplete = true;
                    fo.unview_dropped = true;
                }
            },
            // Safety net for the flag (doc 35): `is_identity()` is exactly what
            // the flag-OFF path trusts when it descends without a remap, so it
            // had better agree with the map. A drop is allowed — `Graphql([])`
            // is vacuously identity and has no params to map — a REMAP is not.
            Some(sh) => {
                debug_assert!(
                    view_slot(&d.slot, sh).map_or(true, |m| m == d.slot),
                    "identity shape {sh:?} remapped {:?}",
                    d.slot
                );
                self.land(b, cs_idx, d, out)
            }
            None => self.land(b, cs_idx, d, out),
        }
    }

    fn land_port(&self, b: &BCtx<'e>, cs_idx: usize, port: u32, path: &Path, exact: bool, uv: bool, out: &mut Vec<St>) {
        for &v in b.arg_ports.get(&(cs_idx, port)).into_iter().flatten() {
            let vp = Path::from_vertex(b.verts[&v]);
            let Some(ex) = comparable(&vp, path) else { continue };
            out.push(St { v, resid: residual_of(path, &vp), exact: exact && ex, uv });
        }
    }

    /// Backward crossing of a call site from a demanded callee OUT-slot to this
    /// frame's arg ports. Mirrors `propagate`'s call-site cases one by one.
    fn cross(&self, b: &BCtx<'e>, cs_idx: usize, out: &Demand, depth: usize, fo: &mut FrameOut, states: &mut Vec<St>) {
        let cs = &b.flow.callsites[cs_idx];
        let mut have = false;
        for cid in &cs.callee_iids {
            let h = hexid(cid);
            let Some(sum) = self.engine.summaries.get(&h) else { continue };
            have = true;
            // see back_sink. A remapped contract is crossed only with
            // --backward-unview, and then in BOTH directions: the demanded
            // out-slot goes client -> handler on the way down
            // (`unview_out_slot`), the demands that come back go handler ->
            // client (`view_slot`, in `land_viewed`).
            let (target, shape) = match self.handlers.get(&h) {
                Some((hh, sh)) => (hh.clone(), Some(sh.clone())),
                None => (h.clone(), None),
            };
            let remapped = shape.as_ref().map_or(false, |sh| !sh.is_identity());
            if remapped && !self.opts.unview {
                fo.incomplete = true;
                continue;
            }
            let has_body = self
                .engine
                .prog
                .funcs
                .get(&target)
                .map_or(false, |f| f.flow.is_some());
            if has_body {
                let want;
                let want = if remapped {
                    let sh = shape.as_ref().expect("remapped implies a shape");
                    match unview_out_slot(&out.slot, sh) {
                        Some(slot) => {
                            want = Demand { slot, path: out.path.clone(), exact: out.exact, uv: out.uv };
                            &want
                        }
                        // compose publishes no client-frame out-slot that this
                        // handler out-slot could be: the demand cannot be
                        // stated on the far side, so nothing below may refute.
                        None => {
                            fo.incomplete = true;
                            fo.unview_dropped = true;
                            fo.unviewed = true;
                            continue;
                        }
                    }
                } else {
                    out
                };
                let sub = self.back_flow(&target, want, depth + 1);
                fo.incomplete |= sub.incomplete;
                fo.widened |= sub.widened;
                fo.unviewed |= sub.unviewed | remapped;
                fo.unview_dropped |= sub.unview_dropped;
                for d in &sub.ins {
                    self.land_viewed(b, cs_idx, d, shape.as_ref(), fo, states);
                }
            } else {
                fo.widened = true;
                if remapped {
                    // as in back_sink: the rows are the lossy client-frame
                    // view of a body we cannot see — confirm, never refute
                    fo.incomplete = true;
                    fo.unviewed = true;
                }
                for (isl, osl) in &sum.flows {
                    if osl.slot != out.slot {
                        continue;
                    }
                    if comparable(&Path::from_ids(&osl.path), &out.path).is_none() {
                        continue;
                    }
                    let d = Demand { slot: isl.slot.clone(), path: Path::from_ids(&isl.path), exact: false, uv: remapped };
                    self.land(b, cs_idx, &d, states);
                }
            }
        }
        if have {
            return;
        }
        // Catalog propagators (propagate's library branch, run BEFORE the
        // leaf): a rule whose `to` names the demanded port was fed by its
        // `from` ports. Without this a write-back through `sb.WriteString(s)`
        // or `json.Unmarshal(b, &v)` would find no predecessor here and refute
        // a real chain — the one thing this pass must never do.
        let recv = cs.arg0_is_receiver;
        let demanded_port = match out.slot {
            Slot::ByRefReceiver if recv => Some(0),
            Slot::ByRefParam(k) => Some(if recv { k + 1 } else { k }),
            _ => None,
        };
        for rule in self.engine.cat.propagators_for(&cs.callee_fqn) {
            let hit = rule.to.iter().any(|spec| match (spec, demanded_port, &out.slot) {
                (crate::catalog::PortSpec::Return, _, Slot::Return(_)) => true,
                (_, Some(p), _) => spec.ports(cs.argc, recv).contains(&p),
                _ => false,
            });
            if !hit {
                continue;
            }
            fo.widened = true;
            for spec in &rule.from {
                for port in spec.ports(cs.argc, recv) {
                    for &v in b.arg_ports.get(&(cs_idx, port)).into_iter().flatten() {
                        states.push(St { v, resid: Path::default(), exact: false, uv: out.uv });
                    }
                }
            }
        }
        // Default leaf (propagate: any tainted arg taints every result port;
        // by-ref outs are never produced by a leaf).
        let Slot::Return(j) = out.slot else { return };
        if let Some(field) = leaf_getter_field(cs, self.engine.pb_getters) {
            // protobuf getter: result 0 is exactly receiver.<field>
            if j != 0 {
                return;
            }
            let head = Path { ids: vec![NAME_ID], names: vec![field.to_string()] };
            let want = head.concat(&out.path);
            self.land_port(b, cs_idx, 0, &want, out.exact, out.uv, states);
            return;
        }
        if self.engine.no_error_leaf
            && cs.error_results != 0
            && j < 63
            && (cs.error_results >> j) & 1 == 1
            && !self.engine.cat.is_error_wrapper(&cs.callee_fqn)
        {
            return;
        }
        fo.widened = true;
        for port in 0..cs.argc {
            for &v in b.arg_ports.get(&(cs_idx, port)).into_iter().flatten() {
                states.push(St { v, resid: Path::default(), exact: false, uv: out.uv });
            }
        }
    }

    /// The intra-frame backward walk. Bipartite sidecar: a sink-kind vertex's
    /// predecessors are source-kind vertices; a source-kind vertex is either an
    /// in-slot (record the demand) or a result port (cross the callee).
    fn walk(&self, b: &BCtx<'e>, starts: Vec<St>, depth: usize, fo: &mut FrameOut) {
        // Keyed on the FULL residual (ids and names): two name-only residuals
        // share the NAME_ID sentinel and differ only by name.
        let mut seen: HashSet<(u32, Path, bool, bool)> = HashSet::new();
        let mut work = starts;
        let tr = self.engine.trace.filter(|t| t.on_ev("back-step", &b.fqn));
        while let Some(st) = work.pop() {
            if !seen.insert((st.v, st.resid.clone(), st.exact, st.uv)) {
                continue;
            }
            let Some(vx) = b.verts.get(&st.v).copied() else { continue };
            let Ok(kind) = cgf::VertexKind::try_from(vx.kind) else { continue };
            let declared = Path::from_vertex(vx);
            // k-guard (doc 26 §7 / ifds::compose_path): a declared path of
            // length k may be a frontend truncation, so a residual below it
            // cannot be placed. Dropping it demands the whole subtree — wider.
            let (resid, exact) = if !st.resid.is_empty()
                && (declared.len() >= MAX_FIELD_PATH || declared.len() + st.resid.len() > MAX_DEMAND)
            {
                fo.widened = true;
                (Path::default(), false)
            } else {
                (st.resid.clone(), st.exact)
            };
            // `uv` rides the whole walk: a state reached from one that only
            // exists because of an unview is itself only there because of it.
            let uv = st.uv;
            if let Some(t) = tr {
                t.log(format_args!(
                    "back-step fn={} v={} kind={:?} cs={} idx={} declared={:?}/{:?} resid={:?}/{:?} exact={}",
                    b.fqn,
                    st.v,
                    kind,
                    vx.callsite_id,
                    vx.index,
                    declared.ids,
                    declared.names,
                    resid.ids,
                    resid.names,
                    exact
                ));
            }
            match kind {
                cgf::VertexKind::CallArgPort
                | cgf::VertexKind::OutReturn
                | cgf::VertexKind::OutParamByref
                | cgf::VertexKind::OutReceiverByref
                | cgf::VertexKind::OutField => {
                    for &u in b.radj.get(&st.v).into_iter().flatten() {
                        work.push(St { v: u, resid: resid.clone(), exact, uv });
                    }
                    // W1a: an arg port with out-edges is a by-ref SOURCE — the
                    // callee wrote through it. Demand the callee's by-ref out.
                    if kind == cgf::VertexKind::CallArgPort && b.has_out.contains(&st.v) {
                        let cs_idx = vx.callsite_id as usize;
                        let recv = *b.arg0_recv.get(cs_idx).unwrap_or(&false);
                        let slot = if vx.index == 0 && recv {
                            Slot::ByRefReceiver
                        } else {
                            Slot::ByRefParam(if recv { vx.index - 1 } else { vx.index })
                        };
                        let d = Demand { slot, path: declared.concat(&resid), exact, uv };
                        let mut more = Vec::new();
                        self.cross(b, cs_idx, &d, depth, fo, &mut more);
                        work.extend(more.into_iter().map(|s| St { uv: s.uv | uv, ..s }));
                    }
                }
                cgf::VertexKind::InParam | cgf::VertexKind::InReceiver => {
                    let full = declared.concat(&resid);
                    let slot = if kind == cgf::VertexKind::InParam {
                        Slot::Param(vx.index)
                    } else {
                        Slot::Receiver
                    };
                    fo.ins.push(Demand { slot, path: full.clone(), exact, uv });
                    if b.source_seeds.contains(&st.v) {
                        fo.seeds.push((full, exact, uv));
                    }
                }
                // heap cells never compose positionally (ifds.rs
                // callee_out_to_vertices / propagate row matching), so a
                // demand on one cannot be met by any caller either
                cgf::VertexKind::InGlobal => {}
                cgf::VertexKind::CallResultPort => {
                    let full = declared.concat(&resid);
                    if b.source_seeds.contains(&st.v) {
                        fo.seeds.push((full.clone(), exact, uv));
                    }
                    let cs_idx = vx.callsite_id as usize;
                    let cs = &b.flow.callsites[cs_idx];
                    if self.engine.cat.sanitizer_of(&cs.callee_fqn).is_some() {
                        continue; // propagate never composes through a sanitizer
                    }
                    if stream_of(cs).is_some() {
                        fo.incomplete = true;
                        continue;
                    }
                    let d = Demand { slot: Slot::Return(vx.index), path: full, exact, uv };
                    let mut more = Vec::new();
                    self.cross(b, cs_idx, &d, depth, fo, &mut more);
                    work.extend(more.into_iter().map(|s| St { uv: s.uv | uv, ..s }));
                }
            }
        }
    }
}

/// Convenience for report.rs: the seed-side `FieldPath` of a demand.
#[allow(dead_code)]
pub fn demand_ids(p: &[u32]) -> FieldPath {
    p.to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(ids: &[u32], names: &[&str]) -> Path {
        Path { ids: ids.to_vec(), names: names.iter().map(|s| s.to_string()).collect() }
    }

    #[test]
    fn comparable_is_prefix_based_and_name_aware() {
        assert_eq!(comparable(&p(&[], &[]), &p(&[1, 2], &[])), Some(true));
        assert_eq!(comparable(&p(&[1], &[]), &p(&[1, 2], &[])), Some(true));
        assert_eq!(comparable(&p(&[3], &[]), &p(&[1, 2], &[])), None);
        // name-only element matches by name when both sides are named
        assert_eq!(comparable(&p(&[NAME_ID], &["ClientId"]), &p(&[2], &["ClientId"])), Some(true));
        assert_eq!(comparable(&p(&[NAME_ID], &["ClientId"]), &p(&[2], &["Amount"])), None);
        // ... and is comparable-but-inexact when a name is missing
        assert_eq!(comparable(&p(&[NAME_ID], &["ClientId"]), &p(&[2], &[])), Some(false));
    }

    #[test]
    fn residual_is_the_unspelled_tail() {
        assert_eq!(residual_of(&p(&[1, 2, 3], &["a", "b", "c"]), &p(&[1], &["a"])), p(&[2, 3], &["b", "c"]));
        assert!(residual_of(&p(&[1], &["a"]), &p(&[1, 2], &["a", "b"])).is_empty());
    }

    #[test]
    fn concat_keeps_names_only_when_both_sides_are_complete() {
        assert_eq!(p(&[1], &["a"]).concat(&p(&[2], &["b"])), p(&[1, 2], &["a", "b"]));
        assert_eq!(p(&[1], &[]).concat(&p(&[2], &["b"])).names, Vec::<String>::new());
        assert_eq!(p(&[], &[]).concat(&p(&[2], &["b"])), p(&[2], &["b"]));
        assert_eq!(p(&[1, NAME_ID], &["a", "x"]).render(), "a.x");
        assert_eq!(p(&[1, NAME_ID], &[]).render(), "1.?");
    }

    // ---- end-to-end: the FP-02 shape (measurements dossier, idx 6) ----------
    //
    //   S(req)            source_params=[0]; passes req whole to M
    //   M(p)              mapper: dto.Amount = p.Amount, dto.ClientId = sess.Get()
    //   P(x)              pass-through: only the whole-object vertex, calls L(x)
    //   L(x)              reads ONE field of x into db.Exec
    //
    // Forward widening reports S -> sqli either way: P's row is keyed on its
    // whole-object vocabulary, so M's `Amount` fact fires it. The backward pass
    // tells the two cases apart.
    use crate::catalog::Catalog;
    use crate::graph::{hexid, Program};
    use crate::ifds::Engine;
    use std::collections::HashMap;

    const CAT: &str = "[[sinks]]\nclass = \"sqli\"\nselector = \"db.Exec\"\narg = \"any\"\n";

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
    fn site(id: u32, callee: Option<u8>, fqn: &str, argc: u32, resultc: u32) -> cgf::CallSite {
        cgf::CallSite {
            id,
            callee_iids: callee.map(|c| vec![vec![c; 32]]).unwrap_or_default(),
            callee_fqn: fqn.into(),
            argc,
            resultc,
            ..Default::default()
        }
    }
    fn func(iid: u8, source_params: Vec<u32>, flow: cgf::LocalFlow) -> cgf::Function {
        cgf::Function {
            id: Some(cgf::Ident { iid: vec![iid; 32], bid: vec![iid; 32] }),
            fqn: format!("pkg.F{iid}"),
            has_body: true,
            source_params,
            flow: Some(flow),
            ..Default::default()
        }
    }
    fn program(leaf_reads: (u32, &str)) -> Program {
        use cgf::VertexKind::*;
        let s = func(1, vec![0], cgf::LocalFlow {
            vertices: vec![vx(0, InParam, 0, &[], &[]), vx(1, CallArgPort, 0, &[], &[])],
            edges: vec![ed(0, 1)],
            callsites: vec![site(0, Some(2), "pkg.F2", 1, 0)],
        });
        let m = func(2, vec![], cgf::LocalFlow {
            vertices: vec![
                vx(0, InParam, 0, &[], &[]),
                vx(1, InParam, 0, &[1], &["Amount"]),
                vx(2, CallResultPort, 0, &[], &[]),
                vx(3, CallArgPort, 1, &[1], &["Amount"]),
                vx(4, CallArgPort, 1, &[2], &["ClientId"]),
            ],
            edges: vec![ed(1, 3), ed(2, 4)],
            callsites: vec![site(0, None, "sess.Get", 0, 1), site(1, Some(3), "pkg.F3", 1, 0)],
        });
        let p = func(3, vec![], cgf::LocalFlow {
            vertices: vec![vx(0, InParam, 0, &[], &[]), vx(1, CallArgPort, 0, &[], &[])],
            edges: vec![ed(0, 1)],
            callsites: vec![site(0, Some(4), "pkg.F4", 1, 0)],
        });
        let l = func(4, vec![], cgf::LocalFlow {
            vertices: vec![
                vx(0, InParam, 0, &[], &[]),
                vx(1, InParam, 0, &[leaf_reads.0], &[leaf_reads.1]),
                vx(2, CallArgPort, 0, &[], &[]),
            ],
            edges: vec![ed(1, 2)],
            callsites: vec![site(0, None, "db.Exec", 1, 0)],
        });
        let mut prog = Program { funcs: HashMap::new(), repo_of: HashMap::new(), packages: Vec::new() };
        for f in [s, m, p, l] {
            let h = hexid(&f.id.as_ref().unwrap().iid);
            prog.repo_of.insert(h.clone(), "test".into());
            prog.funcs.insert(h, f);
        }
        prog
    }

    fn run(leaf_reads: (u32, &str)) -> (crate::backward::BackStats, Vec<crate::report::Chain>) {
        set_opts(BackOpts::default());
        let cat = Catalog::load_str(CAT).unwrap();
        let prog = program(leaf_reads);
        let mut eng = Engine::new(&prog, &cat);
        eng.run();
        let mut chains = crate::report::intra_chains(&eng, None);
        assert_eq!(chains.len(), 1, "forward widening reports the chain in both cases");
        let st = crate::report::backward_check(&eng, &mut chains, false);
        (st, chains)
    }

    #[test]
    fn a_session_field_behind_a_pass_through_frame_is_refuted() {
        let (st, chains) = run((2, "ClientId"));
        let b = chains[0].backward.as_ref().unwrap();
        assert_eq!(b.verdict, Verdict::Refuted, "{b:?}");
        assert_eq!(b.terminal, Some(Verdict::Refuted));
        assert_eq!((st.refuted, st.confirmed, st.undecided), (1, 0, 0));
    }

    #[test]
    fn a_request_field_behind_a_pass_through_frame_is_confirmed_with_its_field() {
        let (st, chains) = run((1, "Amount"));
        let b = chains[0].backward.as_ref().unwrap();
        assert_eq!(b.verdict, Verdict::Confirmed, "{b:?}");
        assert!(b.exact, "no over-approximation on the confirming path: {b:?}");
        assert_eq!(b.source_fields, vec!["Amount".to_string()]);
        assert_eq!((st.refuted, st.confirmed), (0, 1));
    }


    // ---- the contract slot maps (--backward-unview) ------------------------
    //
    // Direction discipline, because getting it backwards is how an unview
    // manufactures a wrong refutation:
    //   witness::unview_slot  client -> handler  (forward descent, and the
    //                         backward pass's OUT-slot on the way down)
    //   view_slot             handler -> client  (the backward pass's IN-slot
    //                         demands on the way back out)
    // They are inverses on every slot both keep; `view_slot` returns None
    // exactly where compose drops the slot.
    use crate::ifds::slot_str;
    use crate::witness::unview_slot;

    fn sp(slot: Slot) -> SlotP {
        SlotP { slot, path: vec![] }
    }

    #[test]
    fn graphql_inverse_swaps_permuted_args() {
        // SDL arg 0 is the resolver's Param(1), SDL arg 1 is its Param(0).
        let shape = ContractShape::Graphql(vec![1, 0]);
        assert!(!shape.is_identity());
        // handler -> client
        assert_eq!(view_slot(&Slot::Param(0), &shape), Some(Slot::Param(1)));
        assert_eq!(view_slot(&Slot::Param(1), &shape), Some(Slot::Param(0)));
        // ctx / obj / receiver / by-refs are not client-addressable at all
        assert_eq!(view_slot(&Slot::Param(2), &shape), None);
        assert_eq!(view_slot(&Slot::Receiver, &shape), None);
        assert_eq!(view_slot(&Slot::ByRefParam(0), &shape), None);
        // …and it really is the inverse of the forward descent's remap
        for p in [0u32, 1] {
            let client = Slot::Param(p);
            let handler = unview_slot(&sp(client.clone()), &shape).slot;
            assert_eq!(view_slot(&handler, &shape), Some(client));
        }
        // out-slots: only the resolver's value return survives the view
        assert_eq!(unview_out_slot(&Slot::Return(0), &shape), Some(Slot::Return(0)));
        assert_eq!(unview_out_slot(&Slot::Return(1), &shape), None); // the error
        assert_eq!(unview_out_slot(&Slot::ByRefReceiver, &shape), None);
        assert_eq!(unview_out_slot(&Slot::StreamOut, &shape), Some(Slot::StreamOut));
    }

    #[test]
    fn server_stream_shape_shifts_the_request_and_drops_the_returns() {
        let shape = ContractShape::Grpc(false, true);
        assert!(!shape.is_identity());
        // handler (req, stream) -> client [iface, ctx, req]: Param(0) -> Param(1)
        assert_eq!(view_slot(&Slot::Param(0), &shape), Some(Slot::Param(1)));
        // the stream param and the receiver have no client-frame port
        assert_eq!(view_slot(&Slot::Param(1), &shape), None);
        assert_eq!(view_slot(&Slot::Receiver, &shape), None);
        // contract-level slots ride through untouched
        assert_eq!(view_slot(&Slot::StreamIn, &shape), Some(Slot::StreamIn));
        assert_eq!(view_slot(&Slot::Source, &shape), Some(Slot::Source));
        // the forward remap is the mirror image: Param(1) -> Param(0)
        assert_eq!(unview_slot(&sp(Slot::Param(1)), &shape).slot, Slot::Param(0));
        assert_eq!(view_slot(&unview_slot(&sp(Slot::Param(1)), &shape).slot, &shape), Some(Slot::Param(1)));
        // every return is dropped by the view, so no out-demand crosses
        for j in 0..3 {
            assert_eq!(unview_out_slot(&Slot::Return(j), &shape), None);
        }
        assert_eq!(unview_out_slot(&Slot::StreamOut, &shape), Some(Slot::StreamOut));
        // client-stream / bidi: the handler takes only the stream object
        for shape in [ContractShape::Grpc(true, false), ContractShape::Grpc(true, true)] {
            assert_eq!(view_slot(&Slot::Param(0), &shape), None);
            assert_eq!(view_slot(&Slot::Param(1), &shape), None);
            assert_eq!(view_slot(&Slot::StreamIn, &shape), Some(Slot::StreamIn));
        }
    }

    #[test]
    fn identity_shapes_map_identically() {
        let slots = [
            Slot::Param(0),
            Slot::Param(1),
            Slot::Param(7),
            Slot::Receiver,
            Slot::StreamIn,
            Slot::StreamOut,
            Slot::Source,
            Slot::Global("g".into()),
            Slot::Return(0),
            Slot::Return(1),
            Slot::ByRefParam(0),
            Slot::ByRefReceiver,
        ];
        let unary = ContractShape::Grpc(false, false);
        assert!(unary.is_identity());
        for s in &slots {
            assert_eq!(view_slot(s, &unary).as_ref(), Some(s), "in {}", slot_str(&sp(s.clone())));
            assert_eq!(unview_out_slot(s, &unary).as_ref(), Some(s), "out {}", slot_str(&sp(s.clone())));
            assert_eq!(slot_str(&unview_slot(&sp(s.clone()), &unary)), slot_str(&sp(s.clone())));
        }
        // a GraphQL field whose resolver args are already in SDL order
        let gql = ContractShape::Graphql(vec![0, 1, 2]);
        assert!(gql.is_identity());
        for p in 0..3u32 {
            assert_eq!(view_slot(&Slot::Param(p), &gql), Some(Slot::Param(p)));
        }
        // The one asymmetry, documented on `view_slot`: no-arg GraphQL fields
        // are VACUOUSLY identity, and there the map drops rather than remaps.
        // `land_viewed`'s debug_assert allows exactly that and no more.
        let empty = ContractShape::Graphql(vec![]);
        assert!(empty.is_identity());
        assert_eq!(view_slot(&Slot::Param(0), &empty), None);
        assert_eq!(view_slot(&Slot::Source, &empty), Some(Slot::Source));
    }

    // ---- end-to-end across a permuted-arg GraphQL contract -----------------
    //
    //   S(req)  --invokes_remote--> contract 9  ==published view==  M (resolver)
    //   M(ctx, obj, _, arg)   dto.Amount = arg.Amount; dto.ClientId = sess.Get()
    //   P(x)                  pass-through
    //   L(x)                  reads ONE field of x into db.Exec
    //
    // SDL arg 0 is the resolver's InParam 3, so the published view is
    // `Param(3) -> Param(0)` — as non-identity as it gets, and today's walk
    // refuses the crossing outright. With --backward-unview the demand is
    // re-expressed in the client's frame and the FP-02 discrimination works
    // ACROSS the boundary.
    fn vxi(id: u32, kind: cgf::VertexKind, index: u32, cs: u32, path: &[u32], names: &[&str]) -> cgf::FlowVertex {
        cgf::FlowVertex { index, ..vx(id, kind, cs, path, names) }
    }
    fn remote_site(id: u32, contract: u8, fqn: &str, argc: u32, resultc: u32) -> cgf::CallSite {
        cgf::CallSite {
            kind: cgf::call_site::Kind::InvokesRemote as i32,
            ..site(id, Some(contract), fqn, argc, resultc)
        }
    }

    fn program_gql(leaf_reads: (u32, &str)) -> Program {
        use cgf::VertexKind::*;
        // the GraphQL client: the whole request rides arg port 0 of the
        // operation call site, whose callee iid IS the contract
        let s = func(1, vec![0], cgf::LocalFlow {
            vertices: vec![vx(0, InParam, 0, &[], &[]), vx(1, CallArgPort, 0, &[], &[])],
            edges: vec![ed(0, 1)],
            callsites: vec![remote_site(0, 9, "graph.Query.details", 1, 1)],
        });
        // the resolver `(ctx, obj, _, arg)`: SDL arg 0 is InParam 3
        let m = func(2, vec![], cgf::LocalFlow {
            vertices: vec![
                vxi(0, InParam, 3, 0, &[], &[]),
                vxi(1, InParam, 3, 0, &[1], &["Amount"]),
                vx(2, CallResultPort, 0, &[], &[]),
                vx(3, CallArgPort, 1, &[1], &["Amount"]),
                vx(4, CallArgPort, 1, &[2], &["ClientId"]),
            ],
            edges: vec![ed(1, 3), ed(2, 4)],
            callsites: vec![site(0, None, "sess.Get", 0, 1), site(1, Some(3), "pkg.F3", 1, 0)],
        });
        let p = func(3, vec![], cgf::LocalFlow {
            vertices: vec![vx(0, InParam, 0, &[], &[]), vx(1, CallArgPort, 0, &[], &[])],
            edges: vec![ed(0, 1)],
            callsites: vec![site(0, Some(4), "pkg.F4", 1, 0)],
        });
        let l = func(4, vec![], cgf::LocalFlow {
            vertices: vec![
                vx(0, InParam, 0, &[], &[]),
                vx(1, InParam, 0, &[leaf_reads.0], &[leaf_reads.1]),
                vx(2, CallArgPort, 0, &[], &[]),
            ],
            edges: vec![ed(1, 2)],
            callsites: vec![site(0, None, "db.Exec", 1, 0)],
        });
        let mut prog = Program { funcs: HashMap::new(), repo_of: HashMap::new(), packages: Vec::new() };
        for f in [s, m, p, l] {
            let h = hexid(&f.id.as_ref().unwrap().iid);
            prog.repo_of.insert(h.clone(), "test".into());
            prog.funcs.insert(h, f);
        }
        prog.packages.push(cgf::CgfPackage {
            repo: "test".into(),
            graphql_fields: vec![cgf::GraphqlField {
                iid: vec![9; 32],
                type_field: "Query.details".into(),
                resolver_iid: vec![2; 32],
                args: vec![cgf::GraphqlArg { name: "req".into(), param_idx: 3 }],
                ..Default::default()
            }],
            ..Default::default()
        });
        prog
    }

    fn run_gql(leaf_reads: (u32, &str), o: BackOpts) -> (crate::backward::BackStats, Vec<crate::report::Chain>) {
        set_opts(o);
        let cat = Catalog::load_str(CAT).unwrap();
        let prog = program_gql(leaf_reads);
        let mut eng = Engine::new(&prog, &cat);
        eng.run();
        crate::compose::fixpoint(&mut eng);
        let mut chains = crate::report::intra_chains(&eng, None);
        assert_eq!(chains.len(), 1, "forward widening reports the cross-contract chain either way");
        let st = crate::report::backward_check(&eng, &mut chains, o.prune);
        (st, chains)
    }

    #[test]
    fn a_permuted_graphql_contract_is_undecided_without_the_flag() {
        for leaf in [(1u32, "Amount"), (2, "ClientId")] {
            let (st, chains) = run_gql(leaf, BackOpts::default());
            let b = chains[0].backward.as_ref().unwrap();
            assert_eq!(b.verdict, Verdict::Undecided, "{leaf:?}: {b:?}");
            assert!(!b.unviewed, "no crossing happened: {b:?}");
            assert_eq!(st.undecided, 1);
            assert_eq!(unview_flips(), 0);
        }
    }

    #[test]
    fn unview_confirms_the_request_field_across_the_contract() {
        let (st, chains) = run_gql((1, "Amount"), BackOpts { unview: true, ..Default::default() });
        let b = chains[0].backward.as_ref().unwrap();
        assert_eq!(b.verdict, Verdict::Confirmed, "{b:?}");
        assert!(b.unviewed, "the verdict rests on an unviewed crossing: {b:?}");
        assert_eq!(b.source_fields, vec!["Amount".to_string()]);
        assert_eq!((st.confirmed, st.refuted, st.undecided), (1, 0, 0));
        assert_eq!(unview_flips(), 1, "undecided -> confirmed is a flip");
    }

    #[test]
    fn unview_refutes_the_session_field_across_the_contract() {
        let (st, chains) = run_gql((2, "ClientId"), BackOpts { unview: true, ..Default::default() });
        let b = chains[0].backward.as_ref().unwrap();
        assert_eq!(b.verdict, Verdict::Refuted, "{b:?}");
        assert!(b.unviewed);
        assert_eq!((st.confirmed, st.refuted, st.undecided), (0, 1, 0));
        assert_eq!(unview_flips(), 1);
    }

    #[test]
    fn the_default_prune_never_acts_on_an_unviewed_refutation() {
        // …it is reported undecided, with its own reason, and KEPT
        let (st, chains) = run_gql((2, "ClientId"), BackOpts { unview: true, prune: true, prune_unviewed: false });
        let b = chains[0].backward.as_ref().unwrap();
        assert_eq!(b.verdict, Verdict::Undecided, "{b:?}");
        assert_eq!(b.reason.as_deref(), Some("unviewed_refutation_not_pruned"));
        assert!(b.unviewed);
        assert_eq!(st.pruned, 0);
        assert_eq!(chains.len(), 1);

        // …and --backward-prune-unviewed opts back in
        let (st, chains) = run_gql((2, "ClientId"), BackOpts { unview: true, prune: true, prune_unviewed: true });
        assert_eq!(st.pruned, 1);
        assert!(chains.is_empty());
    }

    #[test]
    fn prune_drops_only_refuted_chains() {
        set_opts(BackOpts::default());
        let cat = Catalog::load_str(CAT).unwrap();
        let prog = program((2, "ClientId"));
        let mut eng = Engine::new(&prog, &cat);
        eng.run();
        let mut chains = crate::report::intra_chains(&eng, None);
        let st = crate::report::backward_check(&eng, &mut chains, true);
        assert_eq!(st.pruned, 1);
        assert!(chains.is_empty());
    }
}

#[cfg(test)]
mod propagator_tests {
    use super::*;
    use crate::catalog::Catalog;
    use crate::graph::Program;

    const CAT: &str = r#"
[[sinks]]
class = "sqli"
selector = "db.Exec"
arg = "any"

[[propagators]]
selector_regex = '\(\*strings\.Builder\)\.WriteString$'
from = "1"
to   = "receiver"
"#;

    fn v(id: u32, kind: cgf::VertexKind, index: u32, cs: u32) -> cgf::FlowVertex {
        cgf::FlowVertex { id, kind: kind as i32, index, callsite_id: cs, ..Default::default() }
    }

    /// Handler(req): var sb strings.Builder; sb.WriteString(req); db.Exec(sb.String())
    /// — the only path from the source to the sink is the propagator's write
    /// into `sb` (port 2 → port 4 is the frontend's write-back edge).
    fn handler_prog() -> Program {
        use cgf::VertexKind::*;
        let call = |id: u32, fqn: &str, argc: u32, resultc: u32, recv: bool| cgf::CallSite {
            id,
            callee_fqn: fqn.into(),
            argc,
            resultc,
            arg0_is_receiver: recv,
            ..Default::default()
        };
        let f = cgf::Function {
            id: Some(cgf::Ident { iid: vec![7; 32], bid: vec![7; 32] }),
            fqn: "pkg.Handler".into(),
            has_body: true,
            source_params: vec![0],
            flow: Some(cgf::LocalFlow {
                vertices: vec![
                    v(1, InParam, 0, 0),
                    v(2, CallArgPort, 0, 0),
                    v(3, CallArgPort, 1, 0),
                    v(4, CallArgPort, 0, 1),
                    v(5, CallResultPort, 0, 1),
                    v(6, CallArgPort, 0, 2),
                ],
                edges: vec![
                    cgf::FlowEdge { from: 1, to: 3, via_alias: false },
                    cgf::FlowEdge { from: 2, to: 4, via_alias: false },
                    cgf::FlowEdge { from: 5, to: 6, via_alias: false },
                ],
                callsites: vec![
                    call(0, "(*strings.Builder).WriteString", 2, 2, true),
                    call(1, "(*strings.Builder).String", 1, 1, true),
                    call(2, "db.Exec", 1, 0, false),
                ],
            }),
            ..Default::default()
        };
        let mut prog = Program { funcs: HashMap::new(), repo_of: HashMap::new(), packages: Vec::new() };
        let h = hexid(&f.id.as_ref().unwrap().iid);
        prog.repo_of.insert(h.clone(), "test".into());
        prog.funcs.insert(h, f);
        prog
    }

    #[test]
    fn a_chain_through_a_propagator_is_confirmed_not_refuted() {
        let cat = Catalog::load_str(CAT).unwrap();
        let prog = handler_prog();
        let mut eng = Engine::new(&prog, &cat);
        eng.run();
        let mut chains = crate::report::intra_chains(&eng, None);
        assert_eq!(chains.len(), 1, "forward: the propagator carries req into the SQL sink");
        let route = chains[0].route.as_ref().expect("route");
        assert!(route.incomplete.is_none(), "route must reach the sink: {:?}", route.incomplete);
        assert!(
            route.hops.iter().any(|h| h.callee.ends_with("WriteString")),
            "the propagator call is a visible hop"
        );
        let st = crate::report::backward_check(&eng, &mut chains, true);
        let b = chains.first().and_then(|c| c.backward.as_ref()).expect("chain kept, with a verdict");
        assert_eq!(b.verdict, Verdict::Confirmed, "{b:?}");
        assert_eq!(st.pruned, 0, "--backward-prune must not drop a propagator chain");
    }

    /// Without the rule, `--unmodeled` reports WriteString as the place the
    /// route stops — with a complete route to open — and the report never
    /// leaks into the findings.
    #[test]
    fn unmodeled_report_names_the_call_and_stays_out_of_the_findings() {
        let sink_only = "[[sinks]]\nclass = \"sqli\"\nselector = \"db.Exec\"\narg = \"any\"\n";
        let cat = Catalog::load_str(sink_only).unwrap();
        let prog = handler_prog();
        let mut eng = Engine::new(&prog, &cat);
        eng.report_unmodeled = true;
        eng.run();
        let mut chains = crate::report::intra_chains(&eng, None);
        assert_eq!(chains.len(), 1);
        let r = chains[0].route.as_ref().expect("route");
        assert!(r.incomplete.is_none(), "witness must end the route at the unmodeled call: {:?}", r.incomplete);
        assert!(r.hops.last().map_or(false, |h| h.callee.ends_with("WriteString")));
        let calls = crate::report::take_unmodeled(&mut chains);
        assert!(chains.is_empty(), "no rule: no SQL finding, and the pseudo-chain is not a finding");
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].callee, "(*strings.Builder).WriteString");
        assert_eq!((calls[0].chains, calls[0].sources), (1, 1));
    }
}
