// IFDS-style boolean taint. Per-function procedure summaries are computed
// bottom-up over the call graph (callees before callers) by walking each
// function's LocalFlow (calls as barriers) with callee summaries composed at
// call sites; there is no exploded supergraph. Recursive SCCs iterate to a
// fixpoint.
//
// Boolean taint is distributive, so this summary-composition reachability equals
// the IFDS tabulation fixpoint at slot granularity.
use crate::catalog::Catalog;
use crate::graph::{hexid, IidHex, Program};
use crate::ids;
use crate::proto::cgf;
use crate::shard::ShardMap;
use crate::summarystore::{self, SummaryStore};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Slot {
    Param(u32),
    Receiver,
    Global(String),
    Return(u32),
    ByRefParam(u32),
    /// W1a: the RECEIVER mutated by-ref. Distinct from `ByRefParam`
    /// because that index is IN_PARAM-relative and the caller shifts it past
    /// the receiver (N3), leaving arg port 0 unaddressable. Mirrors the IN
    /// direction, where port 0 is `Receiver`.
    ByRefReceiver,
    Field(u32),
    Source,    // synthetic: an unconditional catalog source inside the body
    StreamIn,  // gRPC stream data arriving from the peer (contract in-port)
    StreamOut, // gRPC stream data sent to the peer (contract out-port)
}

/// Pseudo-sink class for `--unmodeled`: tainted data entered a body-less library
/// call that could write into one of its other arguments, and no catalog
/// propagator says whether it does. Never a finding — cli.rs moves these chains
/// into the unmodeled-call report.
pub const UNMODELED_CLASS: &str = "unmodeled-write";

/// k≤2 field path (doc 20 §2), truncated by the frontend; empty = whole object.
pub type FieldPath = Vec<u32>;

/// The frontend's k (flow.go `maxFieldPath`). A declared path of exactly this
/// length may be a TRUNCATION of a longer real path: `step`'s opInject drops
/// the tail once the path is full, and its opProj traverses without recording
/// once srcDepth has reached k. Both are invisible in the emitted vertex, so a
/// path of length k is the one place composition must not be trusted.
pub const MAX_FIELD_PATH: usize = 2;

/// The suffix of `full` that the row keyed on `matched` did not consume.
///
/// `slot_compat` fires a row whose path is a PREFIX of the caller's fact — a
/// sound coarsening, but the unconsumed tail is then dropped and the fact reads
/// as whole-object from there on. Every sibling field of the struct becomes
/// tainted, which is the single root cause behind 5 of the 6 defects in doc 25
/// (§3 R1). This returns that tail so a caller can carry it forward.
pub fn residual_after(matched: &[u32], full: &[u32]) -> FieldPath {
    if full.len() > matched.len() && full.starts_with(matched) {
        full[matched.len()..].to_vec()
    } else {
        // `matched` is the longer (exact//deeper) row, or the two are disjoint:
        // nothing left over either way.
        Vec::new()
    }
}

/// `declared ++ residual` — the true path of a fact sitting at a vertex whose
/// own declared path is `declared`, reached by a caller fact that had `residual`
/// left over.
///
/// Drops the residual when `declared` is already k long, because such a path may
/// itself be a frontend truncation (see `MAX_FIELD_PATH`) and appending to a
/// truncated prefix would fabricate a path that addresses the wrong field.
/// Dropping is always the widening — i.e. exactly today's behaviour — so the
/// fallback direction is the sound one.
pub fn compose_path(declared: &[u32], residual: &[u32]) -> FieldPath {
    if residual.is_empty() || declared.len() >= MAX_FIELD_PATH {
        return declared.to_vec();
    }
    let mut out = declared.to_vec();
    out.extend_from_slice(residual);
    out
}

/// The taint fact: a slot plus an accessed field path (doc 20 §2.3). `Slot`
/// stays the catalog/contract vocabulary; paths ride alongside, never inside
/// the enum. Empty path ⇒ exactly the pre-fieldpath fact.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SlotP {
    pub slot: Slot,
    pub path: FieldPath,
}

impl From<Slot> for SlotP {
    fn from(slot: Slot) -> Self {
        SlotP { slot, path: Vec::new() }
    }
}

/// A fact equals a bare `Slot` iff it is whole-object (empty path).
impl PartialEq<Slot> for SlotP {
    fn eq(&self, other: &Slot) -> bool {
        self.path.is_empty() && self.slot == *other
    }
}

/// Two field paths address overlapping regions iff one is a prefix of the
/// other (a fact taints its whole subtree; a longer path is inside it, a
/// shorter one contains it). Incomparable paths are disjoint fields.
pub fn paths_comparable(a: &[u32], b: &[u32]) -> bool {
    a.starts_with(b) || b.starts_with(a)
}

/// Does a summary row keyed on `row` fire for the caller fact `fact`?
/// Same base slot + prefix-comparable paths. Firing shorter (coarser) rows is
/// required for soundness (whole-object rows must see field-level taint);
/// firing longer rows is the exact accessed-path match.
pub fn slot_compat(row: &SlotP, fact: &SlotP) -> bool {
    row.slot == fact.slot && paths_comparable(&row.path, &fact.path)
}

/// The `Slot::Global` payload for an IN_GLOBAL vertex: the cell sym, plus the
/// A16 reader constraint when the frontend tagged one.
fn cell_of(v: &cgf::FlowVertex) -> String {
    if v.iface_type.is_empty() {
        hex::encode(&v.sym)
    } else {
        format!("{}@{}", hex::encode(&v.sym), hex::encode(&v.iface_type))
    }
}

/// A16 (doc 30 §6.1). An interface-typed cell's READ slot carries the concrete
/// type the reader asserts, appended to the cell sym as `<cell>@<typetag>`; both
/// halves are hex, so this is unambiguous and `slot_str`'s `[` path syntax is
/// untouched. Splits a `Slot::Global` payload into (cell, that constraint).
///
/// Writes are NOT tagged this way — a write's concrete type is filtered per
/// write SITE, off the OUT_FIELD vertex in `propagate`, next to the path filter.
pub fn cell_split(g: &str) -> (&str, Option<&str>) {
    match g.split_once('@') {
        Some((cell, ty)) => (cell, Some(ty)),
        None => (g, None),
    }
}

pub fn slot_str(s: &SlotP) -> String {
    let base = match &s.slot {
        Slot::Param(i) => format!("param_{i}"),
        Slot::Receiver => "receiver".into(),
        Slot::Global(g) => format!("global_{g}"),
        Slot::Return(i) => format!("return_{i}"),
        Slot::ByRefParam(i) => format!("byref_{i}"),
        Slot::ByRefReceiver => "byref_recv".into(),
        Slot::Field(i) => format!("field_{i}"),
        Slot::Source => "source".into(),
        Slot::StreamIn => "stream_in".into(),
        Slot::StreamOut => "stream_out".into(),
    };
    if s.path.is_empty() {
        // bare legacy form: path-free facts hash/serialize exactly as before
        // (contract_hash stability outside affected cones)
        base
    } else {
        let p: Vec<String> = s.path.iter().map(|i| i.to_string()).collect();
        format!("{base}[{}]", p.join(","))
    }
}

/// Exact inverse of `slot_str`. Unknown strings → None (forward compat: a
/// reader skips flows/sinks it can't parse instead of failing the load).
/// `Global` payloads are hex-encoded, so '[' unambiguously starts the path.
pub fn slot_parse(s: &str) -> Option<SlotP> {
    let (base, path) = match s.find('[') {
        None => (s, Vec::new()),
        Some(i) => {
            let inner = s[i..].strip_prefix('[')?.strip_suffix(']')?;
            let mut path = Vec::new();
            for part in inner.split(',') {
                path.push(part.parse::<u32>().ok()?);
            }
            if path.is_empty() {
                return None;
            }
            (&s[..i], path)
        }
    };
    let slot = base_slot_parse(base)?;
    Some(SlotP { slot, path })
}

fn base_slot_parse(s: &str) -> Option<Slot> {
    match s {
        "receiver" => return Some(Slot::Receiver),
        // before the `byref_` numeric arm below, which would parse-fail on it
        "byref_recv" => return Some(Slot::ByRefReceiver),
        "source" => return Some(Slot::Source),
        "stream_in" => return Some(Slot::StreamIn),
        "stream_out" => return Some(Slot::StreamOut),
        _ => {}
    }
    if let Some(g) = s.strip_prefix("global_") {
        return Some(Slot::Global(g.to_string()));
    }
    let idx = |rest: &str| rest.parse::<u32>().ok();
    if let Some(r) = s.strip_prefix("param_") {
        return idx(r).map(Slot::Param);
    }
    if let Some(r) = s.strip_prefix("return_") {
        return idx(r).map(Slot::Return);
    }
    if let Some(r) = s.strip_prefix("byref_") {
        return idx(r).map(Slot::ByRefParam);
    }
    if let Some(r) = s.strip_prefix("field_") {
        return idx(r).map(Slot::Field);
    }
    None
}

/// (op, client_side) for a stream data-port callsite, None otherwise.
pub fn stream_of(cs: &cgf::CallSite) -> Option<(cgf::call_site::StreamOp, bool)> {
    match cs.stream_op() {
        cgf::call_site::StreamOp::None => None,
        op => Some((op, cs.stream_client_side)),
    }
}

/// Provenance of a sink hit that `heap::fixpoint` spliced in: the chain leaves
/// this frame through an abstract heap cell, NOT through `callsite`. Everything
/// witness needs to render the crossing and keep descending on the far side.
#[derive(Clone, Debug, PartialEq)]
pub struct HeapVia {
    /// human name of the cell, e.g. "epool.Pool.incoming"
    pub cell: String,
    /// the function that READS the cell and owns the rest of the route
    pub reader: IidHex,
    /// the reader's own in-slot for the cell — where descent resumes
    pub reader_slot: SlotP,
}

/// One sink a heap cell carries, as `heap::fixpoint` computed it. `assert` is
/// the A16 constraint the READER imposes: the concrete type its type assertion
/// demands. A write whose own concrete type is known and different cannot
/// possibly be the value that reader saw, so `propagate` drops the pairing.
#[derive(Clone, Debug, PartialEq)]
pub struct HeapEntry {
    pub class: String,
    pub via: HeapVia,
    pub assert: Option<String>,
    /// The terminal sink inside the READER this entry stands for — copied from
    /// the reader's own `SinkHit::terminal`, so a heap-mediated hit stays
    /// distinct from any other same-class terminal below the same call site.
    /// (The heap hit itself has no call site: `callsite` is usize::MAX.)
    pub terminal: SinkOrigin,
}

impl HeapEntry {
    /// Can a write whose concrete type is `write_ty` (empty = unknown) be the
    /// value this reader asserted? Unknown on either side ⇒ yes, the sound
    /// direction: A16 removes pairings it can PROVE impossible, nothing else.
    pub fn admits(&self, write_ty: &[u8]) -> bool {
        match (&self.assert, write_ty.is_empty()) {
            (Some(a), false) => *a == hex::encode(write_ty),
            _ => true,
        }
    }
}

#[derive(Clone, Debug)]
pub struct SinkHit {
    pub in_slot: SlotP,
    pub class: String,
    /// Index into THIS frame's callsites. Meaningless when `via_heap` is set —
    /// a heap crossing has no call site — so witness must test `via_heap` first.
    pub callsite: usize,
    pub span: Option<cgf::Span>,
    /// Some(..) iff spliced by heap::fixpoint (phase 2, never persisted).
    pub via_heap: Option<HeapVia>,
    /// Identity of the TERMINAL sink this hit stands for: the leaf function's
    /// iid and the call-site index of the sink call inside that leaf. A direct
    /// sink in this frame sets its own; composition copies the callee row's
    /// terminal unchanged, so two same-class sinks below one call site stay
    /// distinct at every level above, while two paths to the same terminal
    /// still merge (dedup keys include the terminal, not the path).
    pub terminal: SinkOrigin,
}

/// Where a sink chain actually ends (see `SinkHit::terminal`).
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SinkOrigin {
    pub fn_iid: IidHex,
    pub callsite: usize,
}

#[derive(Clone, Default, Debug)]
pub struct Summary {
    pub flows: HashSet<(SlotP, SlotP)>,
    pub sink_hits: Vec<SinkHit>,
    pub confidence: f32,
}

pub struct Engine<'a> {
    pub prog: &'a Program,
    pub cat: &'a Catalog,
    /// Concurrent because the parallel tabulation shares `&self` across the
    /// rayon pool: workers read callee rows and publish completed ones. Values
    /// are `Arc` so a lookup is an atomic increment, not a summary copy; the
    /// map is written only by the SCC that owns an fn (readiness rule) and is
    /// read-only afterwards (heap, compose, witness, persist).
    pub summaries: ShardMap<Arc<Summary>>,
    /// behavior-only hash per summarized fn (feeds callers' summary_keys);
    /// concurrent for the same reason as `summaries`.
    pub contract_hashes: ShardMap<ids::Hash>,
    /// summary_key per cacheable fn (persisted by storage.rs)
    pub summary_keys: HashMap<IidHex, ids::Hash>,
    /// fns actually (re)tabulated this run — cache misses + SCC members
    pub recomputed: HashSet<IidHex>,
    /// W1F phase-2 side table: cell (hex sym) -> the sinks reachable from it.
    /// `propagate` consults it when a fact reaches an OUT_FIELD write, so a heap
    /// hit is DERIVED on every summarize rather than spliced into a summary that
    /// `resummarize` would recompute away — and, because it is derived at a real
    /// vertex, the local hops before the crossing backtrace normally and a
    /// function that writes a cell itself gets a chain, not just its callers.
    /// Populated ONLY by heap::fixpoint, after phase 1. Never persisted.
    pub heap_cells: HashMap<String, Vec<HeapEntry>>,
    /// step-level event log (--trace); None = off
    pub trace: Option<&'a crate::trace::Trace>,
    /// B1 / doc 31: the default leaf does not taint an `error`-typed result port
    /// (`CallSite.error_results`) unless the callee is a catalog error wrapper.
    /// Default false = today's behaviour exactly. A semantics flag, so it is part
    /// of the summary-store namespace (`summarystore.rs`) — a store warmed with
    /// it off must not serve those summaries to a run with it on.
    pub no_error_leaf: bool,
    /// doc 35: an out-of-scope protobuf getter (`(*pb.T).GetX`, receiver only,
    /// one result) is a PROJECTION, not a default leaf — only the receiver's
    /// whole-object variant or its `X` variant reaches the result. The frontend
    /// canonicalises the same getters when their body is in scope
    /// (flow.go:1419-1495); this is the core-side rule for the vendored ones
    /// it cannot see. Semantics flag ⇒ part of the summary-store namespace.
    /// Default false = today's behaviour exactly.
    pub pb_getters: bool,
    /// `--unmodeled`: record an `UNMODELED_CLASS` pseudo-sink wherever tainted
    /// data enters a library call that could write into another argument and
    /// no propagator covers it. It adds sink hits, so it is a semantics flag
    /// (summary-store namespace). Default false.
    pub report_unmodeled: bool,
}

#[derive(Debug, Default, Clone, Copy, Serialize)]
pub struct RunStats {
    pub hits: usize,
    pub misses: usize,
    pub scc_recomputed: usize,
    /// SCCs in the call graph (Tarjan, run once here) — phase-line count
    pub sccs: usize,
    /// wall ms Tarjan took inside this run — phase-line count
    pub scc_ms: u64,
}

/// Per-run collection for the outputs that stay plain engine maps: worker
/// tasks append under a mutex; `run_with_store` merges them into
/// `self.summary_keys` / `self.recomputed` after the phase. Every value is
/// keyed by iid and deterministic, so the merge order cannot change content.
/// (summaries / contract_hashes go straight into their concurrent ShardMaps —
/// no merge needed, the map IS the result.)
struct TabOut {
    summary_keys: Mutex<HashMap<IidHex, ids::Hash>>,
    recomputed: Mutex<HashSet<IidHex>>,
    scc_recomputed: AtomicUsize,
    /// SCCs not yet completed; only read back in a debug assert.
    remaining: AtomicUsize,
}

impl Default for TabOut {
    fn default() -> Self {
        TabOut {
            summary_keys: Mutex::new(HashMap::new()),
            recomputed: Mutex::new(HashSet::new()),
            scc_recomputed: AtomicUsize::new(0),
            remaining: AtomicUsize::new(0),
        }
    }
}

/// Everything the spawned SCC tasks share, all immutable once the scope runs.
struct TabCtx<'c> {
    eng: &'c Engine<'c>,
    store: &'c SummaryStore,
    sccs: &'c [Vec<IidHex>],
    deps: &'c [AtomicUsize],
    dependents: &'c [Vec<usize>],
    started: &'c [AtomicBool],
    out: &'c TabOut,
}

/// Claim SCC `i` for a one-time spawn: the initial ready-scan and a callee's
/// release can both observe "ready" for the same SCC (a counter that was 1 at
/// scan time may hit 0 while the scan is still walking the list), so both
/// sites must atomically claim before spawning. Without the claim an SCC is
/// tabulated twice and releases its dependents twice: a dependent counter can
/// reach zero before all of its callees are complete, and the dependent then
/// composes partial callee summaries (a subset of the sequential result).
fn claim_scc(ctx: &TabCtx<'_>, i: usize) -> bool {
    !ctx.started[i].swap(true, Ordering::SeqCst)
}

/// Schedule one SCC on the pool: tabulate it, then release its dependents —
/// a counter reaching zero spawns the SCC it belongs to. Recursion here only
/// *queues* (spawn returns immediately), so the call depth stays flat; the
/// work happens on pool threads in readiness order.
fn spawn_scc<'c>(scope: &rayon::Scope<'c>, ctx: &'c TabCtx<'c>, i: usize) {
    scope.spawn(move |s| {
        if std::env::var("PC_SCHED_SHUFFLE").is_ok() {
            // Debug stress only: widen the interleaving windows by parking this
            // worker a random sub-millisecond instant before it tabulates, so
            // other ready SCCs run (and release their dependents) mid-flight.
            let mut seed = (i as u64)
                .wrapping_mul(0x9E3779B97F4A7C15)
                ^ std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.subsec_nanos() as u64)
                    .unwrap_or(0);
            seed ^= seed >> 12;
            seed = seed.wrapping_mul(0x2545F4914F6CDD1D);
            let spins = (seed % 64) * 4096;
            for _ in 0..spins {
                std::hint::spin_loop();
            }
        }
        ctx.eng.tabulate_scc(&ctx.sccs[i], ctx.store, ctx.out);
        ctx.out.remaining.fetch_sub(1, Ordering::SeqCst);
        for &d in &ctx.dependents[i] {
            if ctx.deps[d].fetch_sub(1, Ordering::SeqCst) == 1 && claim_scc(ctx, d) {
                spawn_scc(s, ctx, d);
            }
        }
    });
}

impl<'a> Engine<'a> {
    pub fn new(prog: &'a Program, cat: &'a Catalog) -> Self {
        Engine {
            prog,
            cat,
            summaries: ShardMap::new(),
            contract_hashes: ShardMap::new(),
            summary_keys: HashMap::new(),
            recomputed: HashSet::new(),
            heap_cells: HashMap::new(),
            trace: None,
            no_error_leaf: false,
            pb_getters: false,
            report_unmodeled: false,
        }
    }

    /// Does this call site need the default leaf and the catalog propagators?
    /// True when the site has no resolved target, or when at least one target
    /// has no summary (a library call, or a dispatch target whose code is not
    /// loaded in this run). Targets that do have a summary are composed as
    /// usual, in addition. `propagate`, witness and the backward pass all ask
    /// this one question, so they agree on where the leaf applies.
    pub fn site_has_unsummarized_target(&self, cs: &cgf::CallSite) -> bool {
        cs.callee_iids.is_empty()
            || cs.callee_iids.iter().any(|c| !self.summaries.contains_key(&hexid(c)))
    }


    /// Is arg port `arg_idx` of call site `cs_idx` a place `--unmodeled`
    /// reports? True when the report is on, the call has a body-less library
    /// target (no summary), no propagator names it, and some OTHER port of the
    /// call can carry a write back into this frame — the frontend marks such a
    /// port by giving it out-edges (Go: a by-ref argument, `--library-writeback`;
    /// TS: an identifier). Shared by `propagate` and witness, which must agree on
    /// where an unmodeled route ends.
    pub fn unmodeled_write_at(&self, flow: &cgf::LocalFlow, ctx: &FnCtx, cs_idx: usize, arg_idx: u32) -> bool {
        if !self.report_unmodeled {
            return false;
        }
        let Some(cs) = flow.callsites.get(cs_idx) else { return false };
        if stream_of(cs).is_some() || cs.kind == cgf::call_site::Kind::InvokesRemote as i32 {
            return false;
        }
        if !self.site_has_unsummarized_target(cs) {
            return false;
        }
        if self.cat.propagators_for(&cs.callee_fqn).next().is_some() {
            return false;
        }
        // A by-ref source (`[[sources]] to = "1"`, coverage wave 1 §4.1) IS the
        // model of what this call writes into its other arguments — reviewed.
        if self.cat.source_of(&cs.callee_fqn).is_some_and(|s| s.writes_args()) {
            return false;
        }
        (0..cs.argc).filter(|&q| q != arg_idx).any(|q| {
            ctx.arg_port_of
                .get(&(cs_idx, q))
                .into_iter()
                .flatten()
                .any(|(_, w)| ctx.adj.contains_key(w))
        })
    }

    /// B1 / doc 31: how much of the corpus the `--no-error-leaf` rule can see.
    /// Computed ONCE over the static callsite population — never from
    /// `propagate`, which re-derives every leaf on every summarize (trap 8c).
    /// Returns (callsites with an error result, of those exempt as wrappers,
    /// error result ports, functions touched).
    pub fn error_leaf_census(&self) -> (usize, usize, usize, usize) {
        let (mut sites, mut wrappers, mut ports, mut fns) = (0, 0, 0, 0);
        for f in self.prog.funcs.values() {
            let Some(flow) = f.flow.as_ref() else { continue };
            let mut touched = false;
            for cs in &flow.callsites {
                if cs.error_results == 0 {
                    continue;
                }
                sites += 1;
                touched = true;
                if self.cat.is_error_wrapper(&cs.callee_fqn) {
                    wrappers += 1;
                    continue;
                }
                ports += (0..cs.resultc.min(63))
                    .filter(|j| (cs.error_results >> j) & 1 == 1)
                    .count();
            }
            if touched {
                fns += 1;
            }
        }
        (sites, wrappers, ports, fns)
    }

    /// Compute all summaries bottom-up; recursive SCCs iterate to fixpoint.
    pub fn run(&mut self) {
        let store = SummaryStore::ephemeral();
        self.run_with_store(&store);
    }

    /// Same as run() but probes/populates a summary store: unchanged fns
    /// (same summary_key = H(bid ++ sorted callee contract_hashes)) reuse
    /// cached summaries instead of re-tabulating. Callee contract_hashes are
    /// always known when the caller's key is built — sequentially because SCC
    /// order is bottom-up, in parallel because of the readiness rule below.
    /// NOTE cache soundness: compose::fixpoint (contract aliasing + phase-2
    /// re-summarize) runs AFTER this, so invokes_remote callees (incl. stream
    /// data ports) are default-leaf during summarize in every run — cached and
    /// fresh summaries see identical callee environments. Phase-2 summaries
    /// are in-memory only and never written back to the store. Stream-port structure (stream_op,
    /// stream_client_side) is bid-covered, so it invalidates correctly.
    ///
    /// Parallel bottom-up tabulation. The SCCs of `prog.scc_order()` form a
    /// condensation DAG; a readiness counter per SCC (its unfinished
    /// body-bearing callee SCCs) schedules each component onto the global rayon
    /// pool the moment its last callee completes — a ready-queue with
    /// dependency counters, never level-synchronous barriers. This preserves
    /// the one invariant the sequential order guarantees:
    /// `site_has_unsummarized_target` must see exactly the summaries the
    /// sequential run sees when an SCC tabulates (callees WITH a body are
    /// complete; callees WITHOUT a body never get one, in either order), or a
    /// call site would silently take the default leaf instead of composing.
    /// Inside one SCC the fixpoint is unchanged and sequential: its rounds
    /// must observe their own writes.
    ///
    /// Determinism: a summary is a pure function of the body, the catalog and
    /// the callees' completed summaries — the least fixpoint over a monotone
    /// lattice does not depend on SCC processing order — so the maps built
    /// here have exactly the sequential run's content for any thread count.
    /// The per-worker outputs (summary_keys, recomputed, counters) are merged
    /// after the phase; every insert is keyed by iid and every value is
    /// deterministic, so the merge order cannot change the result.
    pub fn run_with_store(&mut self, store: &SummaryStore) -> RunStats {
        let mut stats = RunStats::default();
        let t_scc = std::time::Instant::now();
        let sccs = self.prog.scc_order();
        stats.sccs = sccs.len();
        stats.scc_ms = t_scc.elapsed().as_millis() as u64;

        // ---- condensation readiness ----
        // For each SCC: the set of DISTINCT callee SCCs that have bodies and
        // are not itself (a self-recursive singleton depends on its own
        // fixpoint, not on a callee). `prog.callees` is exactly the population
        // `site_has_unsummarized_target` is answered from — call-site callee
        // iids that have bodies — so a zero counter means the SCC sees the
        // same callee summaries the sequential order produced.
        let n = sccs.len();
        let mut scc_of: HashMap<&IidHex, usize> = HashMap::with_capacity(n * 2);
        for (i, scc) in sccs.iter().enumerate() {
            for iid in scc {
                scc_of.insert(iid, i);
            }
        }
        let mut dep_sets: Vec<HashSet<usize>> = vec![HashSet::new(); n];
        for (i, scc) in sccs.iter().enumerate() {
            for iid in scc {
                if let Some(f) = self.prog.funcs.get(iid) {
                    for c in self.prog.callees(f) {
                        if let Some(&j) = scc_of.get(&c) {
                            if j != i {
                                dep_sets[i].insert(j);
                            }
                        }
                    }
                }
            }
        }
        drop(scc_of);
        let deps: Vec<AtomicUsize> = dep_sets
            .iter()
            .map(|s| AtomicUsize::new(s.len()))
            .collect();
        let mut dependents: Vec<Vec<usize>> = vec![Vec::new(); n];
        for (i, ds) in dep_sets.iter().enumerate() {
            for &j in ds {
                dependents[j].push(i);
            }
        }
        drop(dep_sets);
        let started: Vec<AtomicBool> = (0..n).map(|_| AtomicBool::new(false)).collect();

        let out = TabOut::default();
        out.remaining.store(n, Ordering::SeqCst);
        let eng: &Engine<'_> = &*self;
        let ctx = TabCtx {
            eng,
            store,
            sccs: &sccs,
            deps: &deps,
            dependents: &dependents,
            started: &started,
            out: &out,
        };
        if rayon::current_num_threads() <= 1 {
            // Sequential fast path (--threads 1): the old sequential loop over
            // the SCC order, no scheduler overhead. Same per-SCC code and the
            // same result as the parallel path — only the spawn layer differs.
            for scc in &sccs {
                self.tabulate_scc(scc, store, &out);
                out.remaining.fetch_sub(1, Ordering::SeqCst);
            }
        } else {
            // PC_SCHED_SHUFFLE=1 (debug stress): walk the ready scan in a
            // random order and let each task spin a random instant before
            // tabulating. The ready scan and a concurrent release can then
            // race for the same SCC far more often than the sorted walk
            // allows. Only the schedule changes — the result must not, which
            // is exactly what --verify-summaries (or a cmp of two runs)
            // checks.
            let mut scan: Vec<usize> = (0..n).collect();
            let stress = std::env::var("PC_SCHED_SHUFFLE").is_ok();
            if stress {
                let mut seed = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.subsec_nanos() as u64)
                    .unwrap_or(0x9E3779B97F4A7C15)
                    | 1;
                for i in (1..scan.len()).rev() {
                    seed ^= seed << 13;
                    seed ^= seed >> 7;
                    seed ^= seed << 17;
                    scan.swap(i, (seed % (i as u64 + 1)) as usize);
                }
            }
            rayon::scope(|scope| {
                for i in scan {
                    if deps[i].load(Ordering::SeqCst) == 0 && claim_scc(&ctx, i) {
                        spawn_scc(scope, &ctx, i);
                    }
                }
            });
        }
        debug_assert_eq!(out.remaining.load(Ordering::SeqCst), 0);

        // Merge the per-worker output. Everything is keyed by iid and every
        // value is deterministic, so insertion order cannot change these maps
        // — they equal the sequential run's by construction.
        self.summary_keys.extend(out.summary_keys.into_inner().unwrap());
        self.recomputed.extend(out.recomputed.into_inner().unwrap());
        stats.scc_recomputed = out.scc_recomputed.load(Ordering::SeqCst);
        stats.hits = store.hits.load(Ordering::SeqCst) as usize;
        stats.misses = store.misses.load(Ordering::SeqCst) as usize;
        // Tabulation transients (propagate sets, per-fn contexts, the store
        // LRU's evicted tail) are freed here; hand their pages back before
        // compose and the chain walk allocate.
        crate::phase::pressure_relief();
        stats
    }

    /// Debug check for the parallel tabulation (`--verify-summaries`): recompute
    /// every summary SEQUENTIALLY in SCC order into fresh maps and compare with
    /// the phase's result by content — summaries, contract_hashes and
    /// summary_keys. Returns the iids whose parallel result differs from, or is
    /// missing against, the sequential one; empty means the readiness scheduler
    /// covered every callee edge the tabulation reads, at this thread count, on
    /// this input. The engine's maps are restored before returning, so the rest
    /// of the run stays exactly the parallel run's.
    /// Debug-only: one extra sequential pass over the program plus an `Arc` per
    /// summary held twice.
    pub fn debug_verify_sequential(&mut self) -> Vec<IidHex> {
        let sccs = self.prog.scc_order();
        let par_s: ShardMap<Arc<Summary>> = std::mem::take(&mut self.summaries);
        let par_ch: ShardMap<ids::Hash> = std::mem::take(&mut self.contract_hashes);
        let par_keys = std::mem::take(&mut self.summary_keys);
        // tabulate_scc in SCC order IS the old sequential run: bottom-up order,
        // so every callee summary is complete when a caller summarizes.
        self.summaries = ShardMap::new();
        self.contract_hashes = ShardMap::new();
        let store = SummaryStore::ephemeral();
        let out = TabOut::default();
        for scc in &sccs {
            self.tabulate_scc(scc, &store, &out);
        }
        let seq_keys = out.summary_keys.into_inner().unwrap();
        // Same predicate the SCC fixpoint uses for "changed": flows as a set,
        // sink_hits as a set (order-insensitive — the Vec order is a run artifact).
        let mut bad: Vec<IidHex> = Vec::new();
        for (iid, p) in par_s.iter() {
            match self.summaries.get(&iid) {
                Some(s) => {
                    if summary_changed(&p, &s) {
                        bad.push(iid.clone());
                    }
                }
                None => bad.push(iid.clone()),
            }
        }
        if self.summaries.len() != par_s.len() {
            // a summary the parallel phase never produced (or dropped): name
            // the extras too, they are equally a scheduler defect
            for (iid, _) in self.summaries.iter() {
                if par_s.get(&iid).is_none() && !bad.contains(&iid) {
                    bad.push(iid);
                }
            }
        }
        // contract_hashes: same key set, same per-fn hash. The hash is a pure
        // function of the summary, so a hash diff implies a summary diff — but
        // the parallel phase can also miss or drop a hash entry on its own.
        for (iid, h) in par_ch.iter() {
            if !bad.contains(&iid) {
                match self.contract_hashes.get(&iid) {
                    Some(sh) if sh == h => {}
                    _ => bad.push(iid.clone()),
                }
            }
        }
        for (iid, _) in self.contract_hashes.iter() {
            if par_ch.get(&iid).is_none() && !bad.contains(&iid) {
                bad.push(iid);
            }
        }
        // summary_keys: both runs record one per cacheable fn (cache hit or
        // miss — the key is recorded before the store lookup), and the key is
        // a pure function of (bid, callee contract_hashes), so the sets must
        // match exactly.
        for (iid, k) in par_keys.iter() {
            if !bad.contains(iid) {
                match seq_keys.get(iid) {
                    Some(sk) if *sk == *k => {}
                    _ => bad.push(iid.clone()),
                }
            }
        }
        for iid in seq_keys.keys() {
            if !par_keys.contains_key(iid) && !bad.contains(iid) {
                bad.push(iid.clone());
            }
        }
        self.summaries = par_s;
        self.contract_hashes = par_ch;
        self.summary_keys = par_keys;
        bad
    }

    /// Tabulate ONE SCC to fixpoint. Runs entirely on the calling worker: the
    /// fixpoint rounds must observe their own writes, and running the SCC
    /// sequentially is what makes a parallel SCC identical to a sequential
    /// one. The body is the per-SCC loop of the old sequential `run_with_store`
    /// verbatim, modulo where the results land.
    fn tabulate_scc(&self, scc: &[IidHex], store: &SummaryStore, out: &TabOut) {
        // A singleton SCC that calls ITSELF is a recursive SCC too — Tarjan
        // just has no second member to prove it with. It must iterate to
        // fixpoint like any other, or the recursive call site never sees a
        // summary and the default leaf fires there: every result tainted,
        // and NO sink hit, so any sink reachable only at depth >= 1 is
        // silently lost.
        let self_rec = scc.len() == 1 && self.is_self_recursive(&scc[0]);
        let cacheable = scc.len() == 1 && !self_rec;
        if cacheable {
            let iid = &scc[0];
            let f = &self.prog.funcs[iid];
            let key = self.key_of(iid, f);
            if let Some(key) = key {
                out.summary_keys.lock().unwrap().insert(iid.clone(), key);
                if let Some(c) = store.get(&key) {
                    crate::trace_ev!(self.trace, "summary", &f.fqn, "summary   fn={} CACHE-HIT", f.fqn);
                    self.contract_hashes.insert(iid.clone(), c.contract_hash);
                    self.summaries.insert(iid.clone(), Arc::new(c.summary.clone()));
                    return;
                }
                let s = self.summarize(f);
                crate::trace_ev!(
                    self.trace,
                    "summary",
                    &f.fqn,
                    "summary   fn={} computed flows={} sink_hits={}",
                    f.fqn,
                    s.flows.len(),
                    s.sink_hits.len()
                );
                let ch = summarystore::contract_hash(&s);
                let _ = store.put(key, &s, ch); // store write failure ≠ run failure
                self.contract_hashes.insert(iid.clone(), ch);
                out.recomputed.lock().unwrap().insert(iid.clone());
                self.summaries.insert(iid.clone(), Arc::new(s));
                return;
            }
            // no bid (shouldn't happen with pc-fe output): fall through
        }
        // recursive SCC (or keyless fn): fixpoint, never cached (MVP)
        // `iterate` is the real predicate: a multi-fn SCC, or a singleton
        // that is its own callee. A NON-recursive singleton still runs
        // exactly one round below and never calls summarize twice, so its
        // cost is unchanged.
        let iterate = scc.len() > 1 || self_rec;
        // `scc-start` deliberately stays multi-member: it announces a
        // CONDENSED component, and existing recipes count it to separate
        // dispatch-induced cycles from direct recursion (e2e-miniledger
        // asserts zero of them with dispatch off, where `walkDepth` is
        // still self-recursive). The rounds below are emitted for both, so
        // a singleton's iteration is still visible — as `scc-iter size=1`,
        // which also names the function.
        if scc.len() > 1 {
            if let Some(f) = self.prog.funcs.get(&scc[0]) {
                crate::trace_ev!(
                    self.trace,
                    "scc-start",
                    &f.fqn,
                    "scc-start size={} first={}",
                    scc.len(),
                    f.fqn
                );
            }
        }
        if self_rec {
            // Start the ascent at ⊥ (bottom), not at the default leaf's ⊤.
            // With an EMPTY summary present, every target of the recursive
            // call site has a summary, so `propagate` applies no default
            // leaf there and round 1 composes against "nothing flows,
            // nothing sinks" and each round can
            // only add. The result is the LEAST fixpoint: every real flow
            // and sink hit is found, and the recursive site contributes no
            // taint it cannot justify. (Seeding ⊤ instead would be sound
            // but strictly coarser.) `summary_changed` sees this differ
            // from the first real summary, so it is always replaced.
            self.summaries.get_or_insert(scc[0].clone(), || {
                Arc::new(Summary {
                    confidence: 1.0,
                    ..Default::default()
                })
            });
        }
        let mut iters = 0usize;
        loop {
            let mut changed = false;
            let mut n_changed = 0usize;
            for iid in scc {
                if let Some(f) = self.prog.funcs.get(iid) {
                    let s = self.summarize(f);
                    let differs = self
                        .summaries
                        .get(iid)
                        .map(|p| summary_changed(&p, &s))
                        .unwrap_or(true);
                    if differs {
                        self.summaries.insert(iid.clone(), Arc::new(s));
                        changed = true;
                        n_changed += 1;
                    }
                }
            }
            iters += 1;
            if iterate {
                if let Some(f) = self.prog.funcs.get(&scc[0]) {
                    crate::trace_ev!(
                        self.trace,
                        "scc-iter",
                        &f.fqn,
                        "scc-iter  size={} iter={} changed={}",
                        scc.len(),
                        iters,
                        n_changed
                    );
                }
            }
            if !changed || !iterate {
                break;
            }
            // Backstop: with set semantics the boolean lattice converges in
            // O(SCC diameter) rounds; hitting this cap means a regression
            // to non-monotone/multiset behavior. Warn loudly, keep the
            // current (sound-so-far) summaries, and move on.
            if iters >= 4 * scc.len() + 8 {
                let first = self
                    .prog
                    .funcs
                    .get(&scc[0])
                    .map(|f| f.fqn.as_str())
                    .unwrap_or("?");
                eprintln!(
                    "warning: SCC fixpoint hit iteration cap ({iters}) without converging: size={} first={first} — summaries may be incomplete",
                    scc.len(),
                );
                break;
            }
        }
        // members' contract_hashes still recorded so CALLERS of the SCC can hit
        for iid in scc {
            if let Some(s) = self.summaries.get(iid) {
                self.contract_hashes
                    .insert(iid.clone(), summarystore::contract_hash(&s));
            }
            out.recomputed.lock().unwrap().insert(iid.clone());
            out.scc_recomputed.fetch_add(1, Ordering::SeqCst);
        }
    }

    /// Phase-2 re-tabulation (compose::fixpoint): recompute summaries for
    /// `dirty` fns bottom-up over `order`, propagating through `local_callers`
    /// within the pass (order is reverse-topological, so a changed callee's
    /// callers are always visited later in the same pass). Returns the fns
    /// whose summary changed. In-memory only: must NOT touch summary_keys /
    /// contract_hashes / recomputed / the store — post-fixpoint summaries see
    /// remote callee summaries and would poison phase-1 cache keys (see the
    /// run_with_store NOTE).
    pub fn resummarize(
        &mut self,
        dirty: &HashSet<IidHex>,
        order: &[Vec<IidHex>],
        local_callers: &HashMap<IidHex, Vec<IidHex>>,
    ) -> HashSet<IidHex> {
        let mut changed: HashSet<IidHex> = HashSet::new();
        if dirty.is_empty() {
            return changed;
        }
        let mut work: HashSet<IidHex> = dirty.clone();
        for scc in order {
            if !scc.iter().any(|iid| work.contains(iid)) {
                continue;
            }
            // Same defect as phase 1: a self-recursive singleton is a recursive
            // SCC, so one round is not a fixpoint — a summary that grew this
            // round must be fed back through its OWN recursive call site. No ⊥
            // seeding here: phase 1 already left the least fixpoint in
            // `summaries`, and phase 2 only ever adds (remote callees resolve),
            // so the ascent continues from there.
            let iterate = scc.len() > 1 || (scc.len() == 1 && self.is_self_recursive(&scc[0]));
            let mut iters = 0usize;
            loop {
                // summarize is &self and reads self.summaries: collect the
                // round's results before applying (same shape as run_with_store).
                let mut round: Vec<(IidHex, Summary)> = Vec::new();
                for iid in scc {
                    if let Some(f) = self.prog.funcs.get(iid) {
                        let s = self.summarize(f);
                        let differs = self
                            .summaries
                            .get(iid)
                            .map(|p| summary_changed(&p, &s))
                            .unwrap_or(true);
                        if differs {
                            round.push((iid.clone(), s));
                        }
                    }
                }
                if round.is_empty() {
                    break;
                }
                for (iid, s) in round {
                    self.summaries.insert(iid.clone(), Arc::new(s));
                    changed.insert(iid.clone());
                    if let Some(callers) = local_callers.get(&iid) {
                        work.extend(callers.iter().cloned());
                    }
                }
                iters += 1;
                if !iterate {
                    break;
                }
                // Same backstop as phase 1 (this loop had none): monotone set
                // semantics converges in O(SCC diameter) rounds, so reaching
                // the cap is a non-monotonicity regression, not a deep graph.
                if iters >= 4 * scc.len() + 8 {
                    let first = self
                        .prog
                        .funcs
                        .get(&scc[0])
                        .map(|f| f.fqn.as_str())
                        .unwrap_or("?");
                    eprintln!(
                        "warning: SCC fixpoint hit iteration cap ({iters}) without converging: size={} first={first} — summaries may be incomplete",
                        scc.len(),
                    );
                    break;
                }
            }
        }
        changed
    }

    fn is_self_recursive(&self, iid: &IidHex) -> bool {
        self.prog
            .funcs
            .get(iid)
            .map(|f| self.prog.callees(f).iter().any(|c| c == iid))
            .unwrap_or(false)
    }

    /// summary_key = H(own_iid ++ bid ++ sorted callee contract_hashes).
    /// Callees without a recorded hash (out-of-scope / invokes_remote)
    /// contribute nothing — their default-leaf treatment depends only on
    /// callsite structure already in bid. own_iid is mixed in because a
    /// summary names its own fn in terminal sink origins: two same-body
    /// functions have different summaries and must not share a cache entry.
    fn key_of(&self, iid: &IidHex, f: &cgf::Function) -> Option<ids::Hash> {
        let bid = f.id.as_ref().map(|i| i.bid.as_slice()).unwrap_or_default();
        if bid.is_empty() {
            return None;
        }
        let mut seen: HashSet<&IidHex> = HashSet::new();
        let mut hashes: Vec<ids::Hash> = Vec::new();
        let callees = self.prog.callees(f);
        for c in &callees {
            if seen.insert(c) {
                if let Some(h) = self.contract_hashes.get(c) {
                    hashes.push(h);
                }
            }
        }
        Some(ids::summary_key(iid, bid, &f.source_params, hashes))
    }

    /// Derive the summary of one function.
    pub fn summarize(&self, f: &cgf::Function) -> Summary {
        let ctx = FnCtx::build(f, self.cat);
        let mut out = Summary {
            confidence: 1.0,
            ..Default::default()
        };

        for (vid, slot) in &ctx.in_slots {
            let r = self.propagate(f, &ctx, &[*vid]);
            for oid in &r.tainted {
                if let Some(os) = ctx.out_slot(*oid) {
                    out.flows.insert((slot.clone(), os));
                }
            }
            if r.stream_out {
                out.flows.insert((slot.clone(), Slot::StreamOut.into()));
            }
            for sh in r.sinks {
                out.sink_hits.push(SinkHit {
                    in_slot: slot.clone(),
                    class: sh.class,
                    callsite: sh.callsite,
                    span: sh.span,
                    via_heap: sh.via_heap,
                    terminal: sh.terminal,
                });
            }
        }

        if !ctx.source_seeds.is_empty() {
            let r = self.propagate(f, &ctx, &ctx.source_seeds);
            for oid in &r.tainted {
                if let Some(os) = ctx.out_slot(*oid) {
                    out.flows.insert((Slot::Source.into(), os));
                }
            }
            if r.stream_out {
                out.flows.insert((Slot::Source.into(), Slot::StreamOut.into()));
            }
            for sh in r.sinks {
                out.sink_hits.push(SinkHit {
                    in_slot: Slot::Source.into(),
                    class: sh.class,
                    callsite: sh.callsite,
                    span: sh.span,
                    via_heap: sh.via_heap,
                    terminal: sh.terminal,
                });
            }
        }

        // StreamIn pass: server-side Recv results, plus StreamIn entries
        // surfaced by same-repo helpers that were handed the stream object
        // (bottom-up order ⇒ their summaries already exist).
        let mut stream_seeds = ctx.stream_in_seeds.clone();
        let mut stream_verts: Vec<u32> = Vec::new();
        if let Some(flow) = &f.flow {
            for (cs_idx, cs) in flow.callsites.iter().enumerate() {
                if stream_of(cs).is_some()
                    || cs.kind == cgf::call_site::Kind::InvokesRemote as i32
                {
                    continue;
                }
                for cid in &cs.callee_iids {
                    let Some(sum) = self.summaries.get(&hexid(cid)) else {
                        continue;
                    };
                    for sh in &sum.sink_hits {
                        if sh.in_slot.slot == Slot::StreamIn {
                            out.sink_hits.push(SinkHit {
                                in_slot: Slot::StreamIn.into(),
                                class: sh.class.clone(),
                                callsite: cs_idx,
                                span: cs.span.clone(),
                                via_heap: None,
                                // the terminal is the callee row's — the sink
                                // deep inside the callee, unchanged
                                terminal: sh.terminal.clone(),
                            });
                        }
                    }
                    for (isl, osl) in &sum.flows {
                        if isl.slot != Slot::StreamIn {
                            continue;
                        }
                        if osl.slot == Slot::StreamOut {
                            out.flows.insert((Slot::StreamIn.into(), Slot::StreamOut.into()));
                        } else {
                            // Collect, don't extend: sum.flows iterates in
                            // per-process HashSet order, and stream_seeds seeds
                            // the propagate worklist (same route-order hazard as
                            // the apply loop). Sorted+deduped before use below.
                            stream_verts.extend(ctx.callee_out_to_vertices(cs_idx, osl));
                        }
                    }
                }
            }
        }
        if !stream_verts.is_empty() {
            stream_seeds.extend(stream_verts);
            stream_seeds.sort_unstable();
            stream_seeds.dedup();
        }
        if !stream_seeds.is_empty() {
            let r = self.propagate(f, &ctx, &stream_seeds);
            for oid in &r.tainted {
                if let Some(os) = ctx.out_slot(*oid) {
                    out.flows.insert((Slot::StreamIn.into(), os));
                }
            }
            if r.stream_out {
                out.flows.insert((Slot::StreamIn.into(), Slot::StreamOut.into()));
            }
            for sh in r.sinks {
                out.sink_hits.push(SinkHit {
                    in_slot: Slot::StreamIn.into(),
                    class: sh.class,
                    callsite: sh.callsite,
                    span: sh.span,
                    via_heap: sh.via_heap,
                    terminal: sh.terminal,
                });
            }
        }
        // Set semantics: composing a callee summary with k identical sinks (or
        // re-summarizing inside an SCC whose members' summaries grew last
        // iteration) pushes duplicate SinkHits. Without dedup the multiset
        // grows every SCC iteration and the fixpoint never converges (54GB
        // trace / 80GB RAM on real repos).
        dedup_sink_hits(&mut out.sink_hits);
        out
    }

    /// Boolean forward propagation over LocalFlow + composed callee summaries.
    pub fn propagate(&self, f: &cgf::Function, ctx: &FnCtx, seeds: &[u32]) -> PropResult {
        let flow = f.flow.as_ref().unwrap();
        // trace gate resolved once per fn: None unless tracing AND fqn matches
        let tr = self.trace.filter(|t| t.on(&f.fqn));
        let mut tainted: HashSet<u32> = HashSet::new();
        let mut work: Vec<u32> = Vec::new();
        let mut sinks: Vec<PropSink> = Vec::new();
        let mut pred: HashMap<u32, u32> = HashMap::new();
        let mut stream_out = false;
        // Own identity, for terminal assignment on direct hits: a sink this
        // frame calls directly IS the terminal.
        let own_iid = f
            .id
            .as_ref()
            .map(|i| hexid(&i.iid))
            .unwrap_or_default();

        for s in seeds {
            if tainted.insert(*s) {
                work.push(*s);
            }
        }
        // Coverage wave 1 §4.1: a by-ref source seed is data the call WROTE
        // through its arg port. It leaves along the port's write-back edges
        // only — it is not an input to its own call, so no sink check, no
        // callee summary and no default leaf (which would taint the bind's
        // `err`) at that call. Only when it was seeded in THIS run: the same
        // port reached by ordinary taint is an input like any other.
        let writeback: HashSet<u32> = if ctx.writeback_seeds.is_empty() {
            HashSet::new()
        } else {
            seeds.iter().copied().filter(|s| ctx.writeback_seeds.contains(s)).collect()
        };
        while let Some(v) = work.pop() {
            if let Some(adj) = ctx.adj.get(&v) {
                for &(w, _alias) in adj {
                    if tainted.insert(w) {
                        pred.entry(w).or_insert(v);
                        work.push(w);
                    }
                }
            }
            if writeback.contains(&v) {
                continue;
            }
            if let Some(&(cs_idx, arg_idx, ref arg_path)) = ctx.arg_port.get(&v) {
                let cs = &flow.callsites[cs_idx];
                let stream = stream_of(cs);
                let mut callee_slot = arg_to_callee_slot(cs, arg_idx, arg_path);

                if self.cat.sanitizer_of(&cs.callee_fqn).is_some() {
                    continue;
                }
                if let Some(sink) = self.cat.sink_of(&cs.callee_fqn) {
                    let vtype = ctx.vtype.get(&v).map_or("", String::as_str);
                    if self.cat.sink_fires_on(sink, arg_idx, cs.arg0_is_receiver, vtype) {
                        if let Some(t) = tr.filter(|t| t.wants("sink-hit")) {
                            t.log(format_args!(
                                "sink-hit  fn={} cs={} class={} arg={} callee={} via=catalog",
                                f.fqn, cs_idx, sink.class, arg_idx, cs.callee_fqn
                            ));
                        }
                        sinks.push(PropSink {
                            class: sink.class.clone(),
                            callsite: cs_idx,
                            span: cs.span.clone(),
                            last: v,
                            via_heap: None,
                            terminal: SinkOrigin {
                                fn_iid: own_iid.clone(),
                                callsite: cs_idx,
                            },
                        });
                    }
                }
                // Server-side stream port: semantics are fully structural —
                // Send args are StreamOut out-slots (out_of), Recv results are
                // seeds. Skip composition (callee_iids is our OWN contract,
                // which post-link aliases this very handler) and the default
                // leaf (a Send's error result is not data).
                if let Some((_, false)) = stream {
                    continue;
                }
                // Client-side Send: the message flows into the contract.
                // Stream ports are whole-message (path dropped — sound).
                if let Some((cgf::call_site::StreamOp::Send, true)) = stream {
                    if arg_idx >= 1 {
                        callee_slot = Slot::StreamIn.into();
                    }
                }
                for cid in &cs.callee_iids {
                    let h = hexid(cid);
                    if let Some(sum) = self.summaries.get(&h) {
                        if let Some(t) = tr.filter(|t| t.wants("apply")) {
                            t.log(format_args!(
                                "apply     fn={} cs={} callee={} slot={} flows={} sink_hits={}",
                                f.fqn,
                                cs_idx,
                                cs.callee_fqn,
                                slot_str(&callee_slot),
                                sum.flows.len(),
                                sum.sink_hits.len()
                            ));
                        }
                        for sh in &sum.sink_hits {
                            if slot_compat(&sh.in_slot, &callee_slot) {
                                if let Some(t) = tr.filter(|t| t.wants("sink-hit")) {
                                    t.log(format_args!(
                                        "sink-hit  fn={} cs={} class={} callee={} via=summary",
                                        f.fqn, cs_idx, sh.class, cs.callee_fqn
                                    ));
                                }
                                sinks.push(PropSink {
                                    class: sh.class.clone(),
                                    callsite: cs_idx,
                                    span: cs.span.clone(),
                                    last: v,
                                    via_heap: sh.via_heap.clone(),
                                    // unchanged from the callee row: the sink
                                    // is where the CALLEE (or deeper) put it,
                                    // not here
                                    terminal: sh.terminal.clone(),
                                });
                            }
                        }
                        // sum.flows is a HashSet whose iteration order is
                        // randomized per process (SipHash seed). The rows all
                        // get applied either way, but the ORDER they taint
                        // vertices in sets the worklist order, which sets the
                        // `pred.entry(w).or_insert(v)` winners — and the pred
                        // tree is what a witness backtrace walks. So the route
                        // (hops, fingerprint) differed run to run with identical
                        // findings. Apply the rows in sorted (content) order to
                        // make the whole worklist deterministic. Keys are built
                        // once, not per comparison — slot_str allocates.
                        let mut rows: Vec<((String, String), (SlotP, SlotP))> = sum
                            .flows
                            .iter()
                            .filter(|(isl, _)| slot_compat(isl, &callee_slot))
                            .map(|(isl, osl)| ((slot_str(isl), slot_str(osl)), (isl.clone(), osl.clone())))
                            .collect();
                        rows.sort_unstable_by(|a, b| a.0.cmp(&b.0));
                        for (_, (_isl, osl)) in rows {
                            if osl.slot == Slot::StreamOut {
                                if cs.kind == cgf::call_site::Kind::InvokesRemote as i32 {
                                    // contract sends our data back over the
                                    // stream: taint this fn's Recv results on
                                    // the same contract.
                                    for &w in ctx.stream_recv.get(&h).into_iter().flatten() {
                                        if tainted.insert(w) {
                                            pred.entry(w).or_insert(v);
                                            work.push(w);
                                        }
                                    }
                                } else {
                                    // same-repo helper Sends our data on a
                                    // server stream: surfaces as this fn's own
                                    // StreamOut flow.
                                    stream_out = true;
                                }
                                continue;
                            }
                            for w in ctx.callee_out_to_vertices(cs_idx, &osl) {
                                if tainted.insert(w) {
                                    pred.entry(w).or_insert(v);
                                    work.push(w);
                                }
                            }
                        }
                    }
                }
                // Conservative default leaf (refinement E): an out-of-scope /
                // unresolved callee with no summary is treated taint-transparent
                // — any tainted arg (incl. receiver, for builder chains) taints
                // all result ports. Over-approximate, lower confidence. Keeps
                // taint flowing through squirrel builders, mappers, wrappers.
                // The test is per target: a dispatch site with one summarized
                // target and one target that is not loaded gets the summary of
                // the first AND the leaf for the second.
                if self.site_has_unsummarized_target(cs) {
                    // Catalog propagators: the data movement the default leaf
                    // cannot see (`sb.WriteString(s)` fills sb, `json.Unmarshal(
                    // b, &v)` fills v). Additive — the leaf below still runs.
                    // The written port's out-edges are the frontend's
                    // write-back into this frame's variable.
                    for rule in self.cat.propagators_for(&cs.callee_fqn) {
                        if !rule.fires_from(arg_idx, cs.argc, cs.arg0_is_receiver) {
                            continue;
                        }
                        for spec in &rule.to {
                            let targets: Vec<u32> = if *spec == crate::catalog::PortSpec::Return {
                                (0..cs.resultc)
                                    .flat_map(|j| ctx.result_port.get(&(cs_idx, j)).into_iter().flatten())
                                    .map(|&(_, w)| w)
                                    .collect()
                            } else {
                                spec.ports(cs.argc, cs.arg0_is_receiver)
                                    .into_iter()
                                    .flat_map(|q| ctx.arg_port_of.get(&(cs_idx, q)).into_iter().flatten())
                                    .map(|&(_, w)| w)
                                    .collect()
                            };
                            for w in targets {
                                if tainted.insert(w) {
                                    if let Some(t) = tr.filter(|t| t.wants("propagate")) {
                                        t.log(format_args!(
                                            "propagate fn={} cs={} callee={} from=arg{} to=v{}",
                                            f.fqn, cs_idx, cs.callee_fqn, arg_idx, w
                                        ));
                                    }
                                    pred.entry(w).or_insert(v);
                                    work.push(w);
                                }
                            }
                        }
                    }
                    if self.unmodeled_write_at(flow, ctx, cs_idx, arg_idx) {
                        sinks.push(PropSink {
                            class: UNMODELED_CLASS.to_string(),
                            callsite: cs_idx,
                            span: cs.span.clone(),
                            last: v,
                            via_heap: None,
                            // the unmodeled call here IS the terminal
                            terminal: SinkOrigin {
                                fn_iid: own_iid.clone(),
                                callsite: cs_idx,
                            },
                        });
                    }
                    if let Some(t) = tr.filter(|t| t.wants("leaf")) {
                        t.log(format_args!(
                            "leaf      fn={} cs={} callee={} default-leaf arg{}→{}results{}",
                            f.fqn,
                            cs_idx,
                            cs.callee_fqn,
                            arg_idx,
                            cs.resultc,
                            if cs.opaque { " (opaque)" } else { "" }
                        ));
                    }
                    // B1 / doc 31 §4: an `error`-typed result is not request
                    // data. Skipping it is the largest measured FP reduction in
                    // this tree (doc 30 §6.2 / doc 31 §3: 214-278 keys, ~25%).
                    // Two things make it safe:
                    //   - the mask is EXACT (types.Implements in the frontend),
                    //     not "the last result" — that proxy was measured at 21
                    //     of 278 keys (doc 31 §3a) and rejected;
                    //   - error WRAPPERS are exempt, because
                    //     `fmt.Errorf("… %s", account, err)` really does carry
                    //     request data (doc 25 R3). An in-scope producer needs no
                    //     rule of its own: its error return is tainted only if
                    //     something inside it tainted it — a leaf (killed here)
                    //     or a wrapper (kept here), so this composes transitively.
                    // error_results is 0 on every pre-B1 CGF, so this is inert
                    // unless the corpus was extracted with --error-results.
                    let skip_err = self.no_error_leaf
                        && cs.error_results != 0
                        && !self.cat.is_error_wrapper(&cs.callee_fqn);
                    // doc 35: a protobuf getter projects ONE field. A receiver
                    // variant that carries a different field (`req.Amount`
                    // reaching `GetClientId`) cannot reach the result; the
                    // whole-object variant and the matching variant can.
                    // Unknown names keep the leaf's old behaviour (sound).
                    if let Some(field) = leaf_getter_field(cs, self.pb_getters) {
                        let head_ok = arg_idx == 0
                            && (arg_path.is_empty()
                                || ctx
                                    .vnames
                                    .get(&v)
                                    .and_then(|n| n.first())
                                    .map_or(true, |n| n == field));
                        if !head_ok {
                            continue;
                        }
                    }
                    for j in 0..cs.resultc {
                        // No trace event here on purpose (HANDOFF trap 8c):
                        // `propagate` re-derives every leaf on every summarize,
                        // so a per-drop log counts DESCENT WORK — A16's version
                        // of it produced 7.8 M lines / 2 GB. The population is a
                        // static property of the corpus, so `error_leaf_census`
                        // counts it once instead.
                        if skip_err && j < 63 && (cs.error_results >> j) & 1 == 1 {
                            continue;
                        }
                        for &(_, w) in ctx.result_port.get(&(cs_idx, j)).into_iter().flatten() {
                            if tainted.insert(w) {
                                pred.entry(w).or_insert(v);
                                work.push(w);
                            }
                        }
                    }
                }
            }
        }
        // W1F: a fact that reached an OUT_FIELD write has entered an abstract
        // heap cell, and heap::fixpoint already knows which sinks that cell
        // reaches. Emitting it here rather than splicing it into the summary
        // afterwards means (a) `last` is a real vertex, so the local hops
        // backtrace and the route opens against source, (b) it is re-derived on
        // every summarize, so nothing can recompute it away, and (c) a function
        // that writes the cell ITSELF gets the sink, not only its callers —
        // which a splice keyed on callers silently misses.
        //
        // Empty for the whole of phase 1 (heap::fixpoint has not run), so the
        // summary-store cache environment is untouched. See heap.rs' discipline.
        if !self.heap_cells.is_empty() {
            // vertex id order, never `tainted`'s HashSet order: sinks feed
            // witness's deterministic pick and report's chain list.
            for vtx in &flow.vertices {
                if !tainted.contains(&vtx.id) {
                    continue;
                }
                let Some(SlotP { slot: Slot::Global(cell), .. }) = ctx.out_slot(vtx.id) else {
                    continue;
                };
                let Some(reach) = self.heap_cells.get(&cell) else { continue };
                for e in reach {
                    // A16: this WRITE's concrete type against the reader's
                    // assertion. Per write site, exactly like the path filter —
                    // one arm of a type switch cannot be the value a different
                    // arm's type assertion accepted (doc 30 §6.1).
                    // Deliberately NOT logged here. `propagate` re-derives every
                    // heap hit on every summarize, so a per-drop line counts
                    // descent WORK, not drops: the first run of this filter
                    // emitted 7.8 M lines / 2 GB on a large internal corpus, past the 2 GB
                    // `ulimit -f` guard. The `heap-narrow` instrument computes
                    // the same set once, statically, in heap.rs.
                    if !e.admits(&vtx.iface_type) {
                        continue;
                    }
                    let (class, via) = (&e.class, &e.via);
                    if let Some(t) = tr.filter(|t| t.wants("heap-hit")) {
                        t.log(format_args!(
                            "heap-hit  fn={} cell={} class={} reader={}",
                            f.fqn, via.cell, class, via.reader
                        ));
                    }
                    sinks.push(PropSink {
                        class: class.clone(),
                        // no call site is involved; witness must branch on
                        // via_heap before it touches this.
                        callsite: usize::MAX,
                        span: vtx.span.clone(),
                        last: vtx.id,
                        via_heap: Some(via.clone()),
                        // the sink lives inside the READER; HeapEntry carries
                        // the reader sink_hit's terminal unchanged
                        terminal: e.terminal.clone(),
                    });
                }
            }
        }
        PropResult {
            tainted,
            sinks,
            pred,
            stream_out,
        }
    }
}

pub struct PropResult {
    pub tainted: HashSet<u32>,
    pub sinks: Vec<PropSink>,
    pub pred: HashMap<u32, u32>,
    /// seeds reached a server-stream Send in a (transitive) callee
    pub stream_out: bool,
}
pub struct PropSink {
    pub class: String,
    pub callsite: usize,
    pub span: Option<cgf::Span>,
    pub last: u32,
    /// W1F: the sink is not at `callsite` — the fact was written into a heap
    /// cell here and some function this frame never calls picks it up. `last` is
    /// still a real vertex (the OUT_FIELD write), so the local backtrace and
    /// every hop before the crossing render normally.
    pub via_heap: Option<HeapVia>,
    /// Identity of the terminal sink this hit stands for (see
    /// `SinkHit::terminal`): direct and unmodeled hits set their own
    /// (fn, callsite); composed and heap-mediated hits carry the callee row's
    /// / reader row's terminal unchanged. witness follows it when descending,
    /// and `Route::terminal` must equal it when a route completes.
    pub terminal: SinkOrigin,
}

/// Per-function precomputed indices over LocalFlow. Path-variant vertices
/// (doc 20 §2): a vertex's `field_path` makes it one (slot, path) fact; the
/// per-(callsite, index) ports are therefore multi-valued.
#[derive(Default)]
pub struct FnCtx {
    pub adj: HashMap<u32, Vec<(u32, bool)>>,
    pub in_slots: Vec<(u32, SlotP)>,
    pub out_of: HashMap<u32, SlotP>,
    pub arg_port: HashMap<u32, (usize, u32, FieldPath)>,
    pub result_port: HashMap<(usize, u32), Vec<(FieldPath, u32)>>,
    pub arg_port_of: HashMap<(usize, u32), Vec<(FieldPath, u32)>>,
    pub source_seeds: Vec<u32>,
    /// the subset of `source_seeds` that are arg ports a by-ref source
    /// (`[[sources]] to = "1"`) writes through: they contribute their
    /// write-back out-edges only (see `propagate`)
    pub writeback_seeds: HashSet<u32>,
    /// server-side stream Recv result-port vertices (contract StreamIn)
    pub stream_in_seeds: Vec<u32>,
    /// contract iid -> client-side stream Recv result-port vertices
    pub stream_recv: HashMap<IidHex, Vec<u32>>,
    pub vspan: HashMap<u32, Option<cgf::Span>>,
    pub vtype: HashMap<u32, String>,
    /// reporting names of a vertex's field path, only when complete (doc 35:
    /// the pb-getter rule matches the receiver variant's head by name)
    pub vnames: HashMap<u32, Vec<String>>,
    /// `arg0_is_receiver` per callsite index. Needed by
    /// `callee_out_to_vertices`, which maps a CALLEE-side slot back onto this
    /// frame's arg ports and must therefore invert `arg_to_callee_slot`'s
    /// receiver shift (N3).
    pub arg0_receiver: Vec<bool>,
}

impl FnCtx {
    pub fn build(f: &cgf::Function, cat: &Catalog) -> FnCtx {
        let mut ctx = FnCtx {
            adj: HashMap::new(),
            in_slots: Vec::new(),
            out_of: HashMap::new(),
            arg_port: HashMap::new(),
            result_port: HashMap::new(),
            arg_port_of: HashMap::new(),
            source_seeds: Vec::new(),
            writeback_seeds: HashSet::new(),
            stream_in_seeds: Vec::new(),
            stream_recv: HashMap::new(),
            vspan: HashMap::new(),
            vtype: HashMap::new(),
            vnames: HashMap::new(),
            arg0_receiver: Vec::new(),
        };
        let flow = match &f.flow {
            Some(fl) => fl,
            None => return ctx,
        };
        ctx.arg0_receiver = flow.callsites.iter().map(|cs| cs.arg0_is_receiver).collect();
        for v in &flow.vertices {
            ctx.vspan.insert(v.id, v.span.clone());
            ctx.vtype.insert(v.id, v.r#type.clone());
            if !v.field_path.is_empty() && v.field_names.len() == v.field_path.len() {
                ctx.vnames.insert(v.id, v.field_names.clone());
            }
            let vpath = || v.field_path.clone();
            // N6 (doc 24 §3): an UNRECOGNISED kind must be skipped, not coerced.
            // `unwrap_or(InParam)` used to fabricate an in-slot `Param(v.index)`
            // out of it — garbage facts rather than a missing one, and the exact
            // opposite of the reader policy stated above (skip what you cannot
            // parse). Span/type are already recorded, so a future kind stays
            // renderable while contributing no facts.
            let Ok(kind) = cgf::VertexKind::try_from(v.kind) else {
                continue;
            };
            match kind {
                cgf::VertexKind::InParam => {
                    ctx.in_slots
                        .push((v.id, SlotP { slot: Slot::Param(v.index), path: vpath() }));
                    // endpoint-driven sourcing (doc 19): untrusted endpoint args
                    // (e.g. GraphQL resolver fc.Args) are unconditional sources.
                    // Whole-object seeding: every path variant of the param is
                    // its own vertex, so each gets seeded here.
                    if f.source_params.contains(&v.index) {
                        ctx.source_seeds.push(v.id);
                    }
                }
                cgf::VertexKind::InReceiver => ctx
                    .in_slots
                    .push((v.id, SlotP { slot: Slot::Receiver, path: vpath() })),
                cgf::VertexKind::InGlobal => ctx.in_slots.push((
                    v.id,
                    // A16: a set `iface_type` here is the reader's type
                    // assertion. It has to ride the SLOT (not the vertex),
                    // because the join in heap.rs sees only summaries — and two
                    // reads of the same field in one function, one guarded and
                    // one raw, must not collapse to the same in-slot.
                    SlotP { slot: Slot::Global(cell_of(v)), path: vpath() },
                )),
                cgf::VertexKind::OutReturn => {
                    ctx.out_of
                        .insert(v.id, SlotP { slot: Slot::Return(v.index), path: vpath() });
                }
                cgf::VertexKind::OutParamByref => {
                    ctx.out_of
                        .insert(v.id, SlotP { slot: Slot::ByRefParam(v.index), path: vpath() });
                }
                cgf::VertexKind::OutReceiverByref => {
                    ctx.out_of
                        .insert(v.id, SlotP { slot: Slot::ByRefReceiver, path: vpath() });
                }
                cgf::VertexKind::OutField => {
                    // W1F: a set `sym` makes this a WRITE to an abstract heap
                    // cell, whose identity is program-wide — so it must be
                    // Global(sym), not Field(index). Field indices are only
                    // meaningful relative to the frame's receiver/return
                    // aggregate (doc 24 N4), which is why the cell needs its own
                    // vocabulary rather than a reuse of Field.
                    let slot = if v.sym.is_empty() {
                        Slot::Field(v.index)
                    } else {
                        Slot::Global(hex::encode(&v.sym))
                    };
                    ctx.out_of.insert(v.id, SlotP { slot, path: vpath() });
                }
                cgf::VertexKind::CallArgPort => {
                    ctx.arg_port
                        .insert(v.id, (v.callsite_id as usize, v.index, vpath()));
                    ctx.arg_port_of
                        .entry((v.callsite_id as usize, v.index))
                        .or_default()
                        .push((vpath(), v.id));
                    let cs = &flow.callsites[v.callsite_id as usize];
                    // Coverage wave 1 §4.1 (E1): a by-ref source writes the
                    // untrusted data THROUGH this port (`c.ShouldBindJSON(&req)`).
                    // The frontend's library write-back gives the port out-edges
                    // into the caller's variable — the same vertices a
                    // propagator's `to` reaches — so the port is the seed.
                    if cat
                        .source_of(&cs.callee_fqn)
                        .is_some_and(|s| s.seeds_arg(v.index, cs.argc, cs.arg0_is_receiver))
                    {
                        ctx.source_seeds.push(v.id);
                        ctx.writeback_seeds.insert(v.id);
                    }
                    // server-side stream Send data arg = contract StreamOut
                    // (whole-message: stream ports never carry paths)
                    if let Some((cgf::call_site::StreamOp::Send, false)) = stream_of(cs) {
                        if v.index >= 1 {
                            ctx.out_of.insert(v.id, Slot::StreamOut.into());
                        }
                    }
                }
                cgf::VertexKind::CallResultPort => {
                    ctx.result_port
                        .entry((v.callsite_id as usize, v.index))
                        .or_default()
                        .push((vpath(), v.id));
                    let cs = &flow.callsites[v.callsite_id as usize];
                    // catalog source getter => unconditional source seed
                    if cat.source_of(&cs.callee_fqn).is_some_and(|s| s.seeds_results()) {
                        ctx.source_seeds.push(v.id);
                    }
                    // stream Recv message (result 0): server side = untrusted
                    // input (Source + StreamIn); client side = tainted iff the
                    // contract flows to StreamOut (composed in propagate).
                    if let Some((cgf::call_site::StreamOp::Recv, client)) = stream_of(cs) {
                        if v.index == 0 {
                            if client {
                                if let Some(cid) = cs.callee_iids.first() {
                                    ctx.stream_recv.entry(hexid(cid)).or_default().push(v.id);
                                }
                            } else {
                                ctx.source_seeds.push(v.id);
                                ctx.stream_in_seeds.push(v.id);
                            }
                        }
                    }
                }
            }
        }
        for e in &flow.edges {
            ctx.adj.entry(e.from).or_default().push((e.to, e.via_alias));
        }
        ctx
    }

    pub fn out_slot(&self, vid: u32) -> Option<SlotP> {
        self.out_of.get(&vid).cloned()
    }

    /// All local variant vertices a callee out-fact lands on: variants of the
    /// port whose declared path overlaps the fact's path (`paths_comparable` —
    /// includes the whole-object `[]` variant, a sound coarsening).
    pub fn callee_out_to_vertices(&self, cs_idx: usize, out: &SlotP) -> Vec<u32> {
        let pick = |list: Option<&Vec<(FieldPath, u32)>>| -> Vec<u32> {
            list.into_iter()
                .flatten()
                .filter(|(p, _)| paths_comparable(p, &out.path))
                .map(|&(_, w)| w)
                .collect()
        };
        match &out.slot {
            Slot::Return(j) => pick(self.result_port.get(&(cs_idx, *j))),
            // N3 (doc 24 §3): the EXACT inverse of `arg_to_callee_slot`. The
            // frontend emits an arg port for every argument INCLUDING the
            // receiver (flow.go:251,302), so port `k` always exists and the old
            // presence-keyed `k` -> `k+1` fallback was dead code: for
            // `x.M(a, b)` a callee `ByRefParam(1)` (= `b`) landed on port 1
            // (= `a`), an FP on `a` and an FN on `b` at once. The IN direction
            // was already right, which is what made the asymmetry the proof.
            Slot::ByRefParam(k) => {
                let port = if *self.arg0_receiver.get(cs_idx).unwrap_or(&false) {
                    k + 1
                } else {
                    *k
                };
                pick(self.arg_port_of.get(&(cs_idx, port)))
            }
            // W1a. Port 0, and ONLY when this call site actually passes a
            // receiver — a callee that mutates its receiver reached through a
            // plain function value has no receiver port here, and port 0 would
            // be an ordinary argument.
            Slot::ByRefReceiver => {
                if *self.arg0_receiver.get(cs_idx).unwrap_or(&false) {
                    pick(self.arg_port_of.get(&(cs_idx, 0)))
                } else {
                    Vec::new()
                }
            }
            // stream ports never map to a local vertex of THIS callsite —
            // StreamOut is routed to sibling Recv results (propagate) and
            // StreamIn only ever appears as an in-slot.
            Slot::StreamIn | Slot::StreamOut => Vec::new(),
            // Everything else is `Global`/`Field` (plus in-slot-only kinds that
            // can never be an out-slot). Routing those to result port 0 was
            // simply wrong — a package global or a heap field written by the
            // callee is not this call's first result. Neither is emitted today
            // (N4), so returning nothing is behaviour-neutral now and correct
            // when they land; heap facts get their own propagation then.
            _ => Vec::new(),
        }
    }
}

/// The frontend's pb/api package heuristic (flow.go `isPbPackage`), mirrored
/// so the core-side getter rule fires on exactly the packages the frontend
/// would have canonicalised had they been in scope.
pub fn is_pb_package(path: &str) -> bool {
    path.contains("/pb/") || path.ends_with("/pb") || path.contains("/api/") || path.ends_with("/api")
}

/// doc 35: the Go field a protobuf getter leaf projects, or None. Fires only
/// for the generated shape — `(*pkg/path.T).GetX` with a receiver-only arg list
/// and one result, `T` in a pb/api package — and only when the rule is
/// enabled (`Engine::pb_getters`). The frontend applies the same
/// canonicalisation, body-verified, to in-scope getters (flow.go:1419-1495);
/// this is the name-convention fallback for the vendored ones.
pub fn leaf_getter_field(cs: &cgf::CallSite, enabled: bool) -> Option<&str> {
    if !enabled || cs.argc != 1 || !cs.arg0_is_receiver || cs.resultc != 1 {
        return None;
    }
    let rest = cs.callee_fqn.strip_prefix('(')?;
    let (ty, meth) = rest.split_once(").")?;
    let ty = ty.trim_start_matches('*');
    let (pkg, _tyname) = ty.rsplit_once('.')?;
    if !is_pb_package(pkg) {
        return None;
    }
    let field = meth.strip_prefix("Get")?;
    if field.chars().next().map_or(false, |c| c.is_ascii_uppercase()) && !field.contains('(') {
        Some(field)
    } else {
        None
    }
}

/// The callee-side fact for a tainted arg-port variant: positional remap of
/// the base slot; the field path is carried through verbatim (the core only
/// matches paths, it never composes them — doc 20 §2.3).
pub fn arg_to_callee_slot(cs: &cgf::CallSite, arg_idx: u32, path: &[u32]) -> SlotP {
    let slot = if cs.arg0_is_receiver {
        if arg_idx == 0 {
            Slot::Receiver
        } else {
            Slot::Param(arg_idx - 1)
        }
    } else {
        Slot::Param(arg_idx)
    };
    SlotP { slot, path: path.to_vec() }
}

/// Canonicalize a summary's sink_hits: sort into a content order, then drop
/// exact duplicates (which are adjacent after the sort). Set semantics with a
/// deterministic order — summaries built in this run and the same summaries
/// served back from the store (summarystore sorts the blobs the same way)
/// then agree element for element, so a warm cache cannot change which
/// duplicate a downstream keep-first consumer keeps. Debug-format keying
/// mirrors summary_changed; SinkHit holds a prost Span, which has no Hash/Ord.
pub(crate) fn dedup_sink_hits(hits: &mut Vec<SinkHit>) {
    hits.sort_by(|a, b| {
        slot_str(&a.in_slot)
            .cmp(&slot_str(&b.in_slot))
            .then(a.class.cmp(&b.class))
            .then(a.callsite.cmp(&b.callsite))
            .then(a
                .span
                .as_ref()
                .map(|s| (s.file.clone(), s.line, s.col))
                .cmp(&b.span.as_ref().map(|sp| (sp.file.clone(), sp.line, sp.col))))
            .then(a.via_heap.as_ref().map(|v| (v.cell.clone(), v.reader.clone(), slot_str(&v.reader_slot))).cmp(&b.via_heap.as_ref().map(|v| (v.cell.clone(), v.reader.clone(), slot_str(&v.reader_slot)))))
            .then(a.terminal.fn_iid.cmp(&b.terminal.fn_iid))
            .then(a.terminal.callsite.cmp(&b.terminal.callsite))
    });
    let mut seen = std::collections::HashSet::new();
    hits.retain(|h| seen.insert(format!("{h:?}")));
}

/// Change detection for both the phase-1 SCC loop and the cross-repo fixpoint.
/// Compares sink_hits as a SET: a same-length reshape registers as a change,
/// while duplicate hits (composing a callee view with k identical sinks pushes
/// k identical SinkHits) do not — set semantics is the boolean lattice the
/// fixpoint termination argument needs; multiset growth would never converge
/// on cycles (count-based comparison here is exactly what made vta taint
/// diverge on interface-dispatch SCCs).
pub fn summary_changed(a: &Summary, b: &Summary) -> bool {
    if a.flows != b.flows {
        return true;
    }
    let key = |s: &Summary| -> std::collections::BTreeSet<String> {
        s.sink_hits.iter().map(|h| format!("{h:?}")).collect()
    };
    key(a) != key(b)
}

#[cfg(test)]
mod slot_tests {
    use super::*;

    #[test]
    fn residual_is_what_a_coarser_row_left_unconsumed() {
        // the pass-through case: a whole-object row fires for a field fact
        assert_eq!(residual_after(&[], &[9]), vec![9]);
        assert_eq!(residual_after(&[3], &[3, 1]), vec![1]);
        // exact match, deeper row, and disjoint fields all leave nothing
        assert_eq!(residual_after(&[3], &[3]), Vec::<u32>::new());
        assert_eq!(residual_after(&[3, 1], &[3]), Vec::<u32>::new());
        assert_eq!(residual_after(&[7], &[3, 1]), Vec::<u32>::new());
    }

    #[test]
    fn compose_appends_but_never_extends_a_possibly_truncated_path() {
        assert_eq!(compose_path(&[], &[9]), vec![9]);
        assert_eq!(compose_path(&[3], &[1]), vec![3, 1]);
        assert_eq!(compose_path(&[3], &[]), vec![3]);
        // at k the declared path may itself be a frontend truncation, so the
        // residual is dropped — the widening, i.e. the pre-fix behaviour
        assert_eq!(compose_path(&[3, 1], &[9]), vec![3, 1]);
    }

    #[test]
    fn composing_a_residual_makes_a_disjoint_sibling_stop_matching() {
        let ids = SlotP { slot: Slot::Param(1), path: compose_path(&[], &[9]) };
        let keysets = SlotP { slot: Slot::Param(1), path: vec![8] };
        let whole = SlotP { slot: Slot::Param(1), path: vec![] };
        // this is the doc 25 §3 R1 defect in one assertion: before composition
        // the fact is `whole`, which fires the sibling's row; after, it does not
        assert!(slot_compat(&keysets, &whole));
        assert!(!slot_compat(&keysets, &ids));
        assert!(slot_compat(&whole, &ids), "coarser rows must still fire");
    }

    #[test]
    fn slot_parse_round_trips_every_variant() {
        let all = vec![
            Slot::Param(0),
            Slot::Param(7),
            Slot::Receiver,
            Slot::Global("pkg.Var".into()),
            Slot::Return(0),
            Slot::Return(3),
            Slot::ByRefParam(2),
            Slot::Field(5),
            Slot::Source,
            Slot::StreamIn,
            Slot::StreamOut,
        ];
        for base in all {
            for path in [vec![], vec![3], vec![3, 0]] {
                let s = SlotP { slot: base.clone(), path };
                assert_eq!(slot_parse(&slot_str(&s)), Some(s.clone()), "{s:?}");
            }
        }
        // path-free facts render in the bare legacy form (hash stability)
        assert_eq!(slot_str(&Slot::Param(1).into()), "param_1");
        assert_eq!(slot_str(&SlotP { slot: Slot::Param(1), path: vec![3, 7] }), "param_1[3,7]");
        assert_eq!(slot_parse("param_x"), None);
        assert_eq!(slot_parse("unknown_9"), None);
        assert_eq!(slot_parse(""), None);
        assert_eq!(slot_parse("param_1[]"), None);
        assert_eq!(slot_parse("param_1[3"), None);
        assert_eq!(slot_parse("param_1[a]"), None);
    }

    #[test]
    fn path_compat_semantics() {
        let p = |path: Vec<u32>| SlotP { slot: Slot::Param(0), path };
        // exact + prefix in both directions fire
        assert!(slot_compat(&p(vec![3]), &p(vec![3])));
        assert!(slot_compat(&p(vec![]), &p(vec![3]))); // whole-object row sees field taint
        assert!(slot_compat(&p(vec![3]), &p(vec![]))); // whole-tainted fact fires field row
        assert!(slot_compat(&p(vec![3]), &p(vec![3, 1])));
        // disjoint fields never fire
        assert!(!slot_compat(&p(vec![3]), &p(vec![7])));
        assert!(!slot_compat(&p(vec![3, 1]), &p(vec![3, 2])));
        // base slot must match
        assert!(!slot_compat(
            &SlotP { slot: Slot::Param(1), path: vec![] },
            &p(vec![])
        ));
    }
}

#[cfg(test)]
pub(crate) mod cache_tests {
    use super::*;
    use crate::graph::Program;

    const CAT: &str = r#"
[[sinks]]
class = "sqli"
selector = "db.Exec"
arg = "any"
"#;

    pub(crate) fn vertex(id: u32, kind: cgf::VertexKind, index: u32, cs: u32) -> cgf::FlowVertex {
        cgf::FlowVertex {
            id,
            kind: kind as i32,
            index,
            callsite_id: cs,
            ..Default::default()
        }
    }

    pub(crate) fn edge(from: u32, to: u32) -> cgf::FlowEdge {
        cgf::FlowEdge {
            from,
            to,
            via_alias: false,
        }
    }

    /// B(p0): db.Exec(p0)  [+ optional p0 -> return0 flow]
    fn fn_b(bid: u8, flows_to_return: bool) -> cgf::Function {
        let mut vertices = vec![
            vertex(1, cgf::VertexKind::InParam, 0, 0),
            vertex(2, cgf::VertexKind::CallArgPort, 0, 0),
        ];
        let mut edges = vec![edge(1, 2)];
        if flows_to_return {
            vertices.push(vertex(3, cgf::VertexKind::OutReturn, 0, 0));
            edges.push(edge(1, 3));
        }
        cgf::Function {
            id: Some(cgf::Ident {
                iid: vec![0xBB; 32],
                bid: vec![bid; 32],
            }),
            fqn: "pkg.B".into(),
            has_body: true,
            flow: Some(cgf::LocalFlow {
                vertices,
                edges,
                callsites: vec![cgf::CallSite {
                    id: 0,
                    callee_fqn: "db.Exec".into(),
                    argc: 1,
                    resultc: 0,
                    ..Default::default()
                }],
            }),
            ..Default::default()
        }
    }

    /// A(p0): r := B(p0); return r
    fn fn_a(bid: u8) -> cgf::Function {
        cgf::Function {
            id: Some(cgf::Ident {
                iid: vec![0xAA; 32],
                bid: vec![bid; 32],
            }),
            fqn: "pkg.A".into(),
            has_body: true,
            flow: Some(cgf::LocalFlow {
                vertices: vec![
                    vertex(1, cgf::VertexKind::InParam, 0, 0),
                    vertex(2, cgf::VertexKind::CallArgPort, 0, 0),
                    vertex(3, cgf::VertexKind::CallResultPort, 0, 0),
                    vertex(4, cgf::VertexKind::OutReturn, 0, 0),
                ],
                edges: vec![edge(1, 2), edge(3, 4)],
                callsites: vec![cgf::CallSite {
                    id: 0,
                    callee_iids: vec![vec![0xBB; 32]],
                    callee_fqn: "pkg.B".into(),
                    argc: 1,
                    resultc: 1,
                    ..Default::default()
                }],
            }),
            ..Default::default()
        }
    }

    fn program(a: cgf::Function, b: cgf::Function) -> Program {
        let mut prog = Program {
            funcs: HashMap::new(),
            repo_of: HashMap::new(),
            packages: Vec::new(),
        };
        for f in [a, b] {
            let h = hexid(&f.id.as_ref().unwrap().iid);
            prog.repo_of.insert(h.clone(), "test".into());
            prog.funcs.insert(h, f);
        }
        prog
    }

    fn store_dir(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("pc-ifds-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        d
    }

    #[test]
    fn cold_then_warm_run_hits_everything() {
        let cat = Catalog::load_str(CAT).unwrap();
        let dir = store_dir("warm");
        let prog = program(fn_a(1), fn_b(2, false));

        let mut s1 = SummaryStore::open(Some(&dir), &[0u8; 32], 1024).unwrap();
        let mut e1 = Engine::new(&prog, &cat);
        let r1 = e1.run_with_store(&mut s1);
        assert_eq!((r1.hits, r1.misses), (0, 2));
        let a_hex = hexid(&[0xAA; 32]);
        assert_eq!(e1.summaries.get(&a_hex).unwrap().sink_hits.len(), 1, "sink through callee");

        // fresh engine + fresh store instance over the same dir
        let mut s2 = SummaryStore::open(Some(&dir), &[0u8; 32], 1024).unwrap();
        let mut e2 = Engine::new(&prog, &cat);
        let r2 = e2.run_with_store(&mut s2);
        assert_eq!((r2.hits, r2.misses), (2, 0));
        assert!(e2.recomputed.is_empty());
        assert_eq!(e2.summaries.get(&a_hex).unwrap().flows, e1.summaries.get(&a_hex).unwrap().flows);
        assert_eq!(e2.summaries.get(&a_hex).unwrap().sink_hits.len(), 1);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    // doc 05 mechanism B: body edit with unchanged behavior must not cascade.
    #[test]
    fn early_cutoff_callee_bid_change_same_behavior() {
        let cat = Catalog::load_str(CAT).unwrap();
        let dir = store_dir("cutoff");

        let prog1 = program(fn_a(1), fn_b(2, false));
        let mut s = SummaryStore::open(Some(&dir), &[0u8; 32], 1024).unwrap();
        Engine::new(&prog1, &cat).run_with_store(&mut s);

        // B edited (bid flips) but behavior identical -> B misses, A hits
        let prog2 = program(fn_a(1), fn_b(9, false));
        let mut s2 = SummaryStore::open(Some(&dir), &[0u8; 32], 1024).unwrap();
        let mut e = Engine::new(&prog2, &cat);
        let r = e.run_with_store(&mut s2);
        assert_eq!((r.hits, r.misses), (1, 1));
        let b_hex = hexid(&[0xBB; 32]);
        assert!(e.recomputed.contains(&b_hex));
        assert!(!e.recomputed.contains(&hexid(&[0xAA; 32])));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn behavior_change_invalidates_caller() {
        let cat = Catalog::load_str(CAT).unwrap();
        let dir = store_dir("invalidate");

        let prog1 = program(fn_a(1), fn_b(2, false));
        let mut s = SummaryStore::open(Some(&dir), &[0u8; 32], 1024).unwrap();
        Engine::new(&prog1, &cat).run_with_store(&mut s);

        // B now also flows p0 -> return0: contract_hash changes -> A must recompute
        let prog2 = program(fn_a(1), fn_b(9, true));
        let mut s2 = SummaryStore::open(Some(&dir), &[0u8; 32], 1024).unwrap();
        let mut e = Engine::new(&prog2, &cat);
        let r = e.run_with_store(&mut s2);
        assert_eq!((r.hits, r.misses), (0, 2));
        let a_hex = hexid(&[0xAA; 32]);
        assert!(
            e.summaries.get(&a_hex).unwrap()
                .flows
                .contains(&(Slot::Param(0).into(), Slot::Return(0).into())),
            "new callee flow must surface in caller summary"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }
}

/// N6 + N3: how a vertex kind becomes a fact, and how a CALLEE-side out-fact is
/// mapped back onto this frame's ports. Both bugs are latent on today's corpus
/// (no unknown kinds, no `OUT_PARAM_BYREF` emitted — N4), so only a synthetic
/// CGF can hold them still.
#[cfg(test)]
mod slot_mapping_tests {
    use super::*;
    use cache_tests::vertex;

    const CAT: &str = r#"
[[sinks]]
class = "sqli"
selector = "db.Exec"
arg = "any"
"#;

    fn fn_with(vertices: Vec<cgf::FlowVertex>, callsites: Vec<cgf::CallSite>) -> cgf::Function {
        cgf::Function {
            id: Some(cgf::Ident { iid: vec![0xCC; 32], bid: vec![1; 32] }),
            fqn: "pkg.C".into(),
            has_body: true,
            flow: Some(cgf::LocalFlow { vertices, edges: Vec::new(), callsites }),
            ..Default::default()
        }
    }

    /// N6. A kind this build does not know must contribute NOTHING. It used to
    /// be coerced to `InParam`, inventing an in-slot `Param(index)` that no
    /// frontend ever emitted — and in-slots are what `summarize` iterates, so
    /// the fabrication would propagate into every caller's summary.
    #[test]
    fn an_unknown_vertex_kind_is_skipped_not_coerced_to_a_param() {
        let cat = Catalog::load_str(CAT).unwrap();
        let mut unknown = vertex(2, cgf::VertexKind::InParam, 5, 0);
        unknown.kind = 99; // not in the enum: a kind from a newer frontend
        let f = fn_with(
            vec![vertex(1, cgf::VertexKind::InParam, 0, 0), unknown],
            Vec::new(),
        );

        let ctx = FnCtx::build(&f, &cat);

        let slots: Vec<&SlotP> = ctx.in_slots.iter().map(|(_, s)| s).collect();
        assert!(
            slots.iter().any(|s| **s == Slot::Param(0)),
            "the real IN_PARAM must still be an in-slot: {slots:?}"
        );
        assert!(
            !slots.iter().any(|s| **s == Slot::Param(5)),
            "unknown kind fabricated an in-slot: {slots:?}"
        );
        assert!(
            ctx.vspan.contains_key(&2) && ctx.vtype.contains_key(&2),
            "a skipped vertex must stay renderable (span/type recorded)"
        );
    }

    /// N3. `x.M(a, b)` with `arg0_is_receiver`: the callee's `ByRefParam(1)` is
    /// its second non-receiver param, i.e. `b` = arg port 2. Landing it on port
    /// 1 taints `a` (FP) and leaves `b` clean (FN) in one step.
    #[test]
    fn a_byref_out_param_inverts_the_receiver_shift() {
        let cat = Catalog::load_str(CAT).unwrap();
        let ports = || {
            vec![
                vertex(10, cgf::VertexKind::CallArgPort, 0, 0), // receiver x
                vertex(11, cgf::VertexKind::CallArgPort, 1, 0), // a
                vertex(12, cgf::VertexKind::CallArgPort, 2, 0), // b
            ]
        };
        let cs = |recv: bool| {
            vec![cgf::CallSite {
                id: 0,
                callee_fqn: "pkg.M".into(),
                argc: 3,
                resultc: 1,
                arg0_is_receiver: recv,
                ..Default::default()
            }]
        };
        let byref1 = SlotP { slot: Slot::ByRefParam(1), path: Vec::new() };

        let with_recv = FnCtx::build(&fn_with(ports(), cs(true)), &cat);
        assert_eq!(
            with_recv.callee_out_to_vertices(0, &byref1),
            vec![12],
            "arg0_is_receiver: callee param 1 is caller arg 2"
        );

        // Same callee slot, plain function call: no shift.
        let no_recv = FnCtx::build(&fn_with(ports(), cs(false)), &cat);
        assert_eq!(
            no_recv.callee_out_to_vertices(0, &byref1),
            vec![11],
            "no receiver: callee param 1 is caller arg 1"
        );
    }

    // ---- W1a: by-ref RECEIVER out-slots (doc 29 §1b).
    //
    // Every one of these fails on the pre-W1a tree, where the only way to
    // express "the callee mutated its receiver" was `ByRefParam(0)`. Test 1 is
    // the defect itself: that encoding lands the receiver's write on the first
    // real ARGUMENT, which is the N3 bug arriving from the other direction.

    fn recv_ports() -> Vec<cgf::FlowVertex> {
        vec![
            vertex(10, cgf::VertexKind::CallArgPort, 0, 0), // receiver x
            vertex(11, cgf::VertexKind::CallArgPort, 1, 0), // a
            vertex(12, cgf::VertexKind::CallArgPort, 2, 0), // b
        ]
    }
    fn recv_cs(recv: bool) -> Vec<cgf::CallSite> {
        vec![cgf::CallSite {
            id: 0,
            callee_fqn: "pkg.M".into(),
            argc: 3,
            resultc: 1,
            arg0_is_receiver: recv,
            ..Default::default()
        }]
    }
    fn sp0(slot: Slot) -> SlotP {
        SlotP { slot, path: Vec::new() }
    }

    /// 1. THE DEFECT. `x.M(a, b)` where `M` writes through its receiver: with
    /// `ByRefParam(0)` the fact lands on port 1 (= `a`), tainting an argument
    /// the callee never touched and leaving `x` clean. `ByRefReceiver` is the
    /// only encoding that reaches port 0.
    #[test]
    fn a_receiver_write_encoded_as_byref_param_zero_lands_on_the_wrong_arg() {
        let cat = Catalog::load_str(CAT).unwrap();
        let ctx = FnCtx::build(&fn_with(recv_ports(), recv_cs(true)), &cat);

        assert_eq!(
            ctx.callee_out_to_vertices(0, &sp0(Slot::ByRefParam(0))),
            vec![11],
            "ByRefParam(0) is the callee's FIRST NON-RECEIVER param — port 1"
        );
        assert_eq!(
            ctx.callee_out_to_vertices(0, &sp0(Slot::ByRefReceiver)),
            vec![10],
            "only ByRefReceiver reaches the receiver port"
        );
    }

    /// 2. A plain function call has no receiver port, so a `ByRefReceiver` fact
    /// has nowhere to land. Port 0 there is an ordinary argument — returning it
    /// would taint an unrelated value.
    #[test]
    fn a_receiver_out_fact_lands_nowhere_when_the_call_passes_no_receiver() {
        let cat = Catalog::load_str(CAT).unwrap();
        let ctx = FnCtx::build(&fn_with(recv_ports(), recv_cs(false)), &cat);
        assert!(
            ctx.callee_out_to_vertices(0, &sp0(Slot::ByRefReceiver)).is_empty(),
            "no arg0_is_receiver: the fact must be dropped, not aimed at arg 0"
        );
    }

    /// 3. The vertex kind maps to the slot, and — unlike an in-slot — lands in
    /// `out_of`. A kind that produced an IN-slot would make the callee appear to
    /// *read* its receiver as a fresh source.
    #[test]
    fn out_receiver_byref_becomes_an_out_slot() {
        let cat = Catalog::load_str(CAT).unwrap();
        let f = fn_with(
            vec![
                vertex(1, cgf::VertexKind::InReceiver, 0, 0),
                vertex(2, cgf::VertexKind::OutReceiverByref, 0, 0),
            ],
            Vec::new(),
        );
        let ctx = FnCtx::build(&f, &cat);

        assert_eq!(ctx.out_slot(2).map(|s| s.slot), Some(Slot::ByRefReceiver));
        assert!(
            !ctx.in_slots.iter().any(|(id, _)| *id == 2),
            "an out-slot must not also be seeded as an in-slot"
        );
        assert!(
            ctx.in_slots.iter().any(|(_, s)| s.slot == Slot::Receiver),
            "the IN_RECEIVER in-slot is untouched"
        );
    }

    /// 4. `slot_str`/parse round-trip. The summary store keys on these strings,
    /// so a lossy round-trip silently drops the fact from every cached summary —
    /// and `byref_recv` sits under the `byref_` prefix the numeric arm claims.
    #[test]
    fn byref_recv_round_trips_and_does_not_collide_with_byref_n() {
        for s in [
            sp0(Slot::ByRefReceiver),
            SlotP { slot: Slot::ByRefReceiver, path: vec![3, 7] },
            sp0(Slot::ByRefParam(0)),
        ] {
            let txt = slot_str(&s);
            assert_eq!(slot_parse(&txt), Some(s.clone()), "round-trip of {txt}");
        }
        assert_eq!(slot_str(&sp0(Slot::ByRefReceiver)), "byref_recv");
        assert_ne!(slot_parse("byref_recv"), slot_parse("byref_0"));
    }

    /// 5. The receiver's field path survives the crossing. `(*T).M` writing
    /// `t.f` must taint the caller's `x.f`, not the whole of `x` — the whole
    /// point of doc 20 §2, and paths ride the out-slot, not the base slot.
    #[test]
    fn a_receiver_out_fact_carries_its_field_path_to_the_caller_port() {
        let cat = Catalog::load_str(CAT).unwrap();
        let mut ports = recv_ports();
        ports[0].field_path = vec![4]; // the caller's x[4] variant of port 0
        let ctx = FnCtx::build(&fn_with(ports, recv_cs(true)), &cat);

        let with_path = SlotP { slot: Slot::ByRefReceiver, path: vec![4] };
        assert_eq!(ctx.callee_out_to_vertices(0, &with_path), vec![10]);
        assert!(
            ctx.callee_out_to_vertices(0, &SlotP { slot: Slot::ByRefReceiver, path: vec![9] })
                .is_empty(),
            "a sibling field must not fire the [4] port variant"
        );
    }

    /// 6. Composition end to end: a callee summary `Param(0) -> ByRefReceiver`
    /// (i.e. `func (t *T) M(a string) { t.f = a }`) taints the caller's receiver
    /// argument when the ARGUMENT is tainted. Without W1a this flow has no
    /// representable out-slot at all, so the callee's whole effect is invisible.
    #[test]
    fn a_param_to_receiver_flow_taints_the_callers_receiver_arg() {
        let cat = Catalog::load_str(CAT).unwrap();
        let ctx = FnCtx::build(&fn_with(recv_ports(), recv_cs(true)), &cat);

        let mut sum = Summary::default();
        sum.flows.insert((sp0(Slot::Param(0)).into(), sp0(Slot::ByRefReceiver).into()));
        // `a` is caller port 1 == callee Param(0) under the receiver shift.
        let callee_slot = arg_to_callee_slot(&fn_with(recv_ports(), recv_cs(true)).flow.unwrap().callsites[0], 1, &[]);
        assert_eq!(callee_slot.slot, Slot::Param(0), "the IN direction still shifts");

        let hit: Vec<u32> = sum
            .flows
            .iter()
            .filter(|(isl, _)| slot_compat(isl, &callee_slot))
            .flat_map(|(_, osl)| ctx.callee_out_to_vertices(0, osl))
            .collect();
        assert_eq!(hit, vec![10], "the receiver arg port, not a result and not arg 1");
    }

    /// N3, second half: a callee `Global`/`Field` out-fact is not this call's
    /// first result. Routing it there invented a dataflow edge.
    #[test]
    fn a_global_out_fact_does_not_land_on_result_zero() {
        let cat = Catalog::load_str(CAT).unwrap();
        let f = fn_with(
            vec![vertex(20, cgf::VertexKind::CallResultPort, 0, 0)],
            vec![cgf::CallSite {
                id: 0,
                callee_fqn: "pkg.M".into(),
                argc: 0,
                resultc: 1,
                ..Default::default()
            }],
        );
        let ctx = FnCtx::build(&f, &cat);

        let global = SlotP { slot: Slot::Global("deadbeef".into()), path: Vec::new() };
        assert!(ctx.callee_out_to_vertices(0, &global).is_empty());
        // the Return slot is the one that legitimately lands there
        let ret = SlotP { slot: Slot::Return(0), path: Vec::new() };
        assert_eq!(ctx.callee_out_to_vertices(0, &ret), vec![20]);
    }
}

#[cfg(test)]
mod stream_tests {
    use super::*;
    use crate::graph::Program;
    use cache_tests::{edge, vertex};

    const CAT: &str = r#"
[[sinks]]
class = "sqli"
selector = "db.Exec"
arg = "any"
"#;

    const CONTRACT: [u8; 32] = [0xCC; 32];

    fn remote_stream_cs(id: u32, op: cgf::call_site::StreamOp, client: bool) -> cgf::CallSite {
        cgf::CallSite {
            id,
            kind: cgf::call_site::Kind::InvokesRemote as i32,
            callee_iids: vec![CONTRACT.to_vec()],
            callee_fqn: "pb.Feed/M".into(),
            arg0_is_receiver: true,
            stream_op: op as i32,
            stream_client_side: client,
            ..Default::default()
        }
    }

    fn func(iid: u8, flow: cgf::LocalFlow) -> cgf::Function {
        cgf::Function {
            id: Some(cgf::Ident {
                iid: vec![iid; 32],
                bid: vec![iid; 32],
            }),
            fqn: format!("pkg.F{iid}"),
            has_body: true,
            flow: Some(flow),
            ..Default::default()
        }
    }

    fn engine_prog(fns: Vec<cgf::Function>) -> Program {
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

    /// Server handler: m := stream.Recv(); db.Exec(m) — the Recv result is both
    /// an unconditional Source and the contract StreamIn.
    #[test]
    fn server_recv_is_source_and_stream_in() {
        let mut recv = remote_stream_cs(0, cgf::call_site::StreamOp::Recv, false);
        recv.argc = 1;
        recv.resultc = 2;
        let sink = cgf::CallSite {
            id: 1,
            callee_fqn: "db.Exec".into(),
            argc: 1,
            ..Default::default()
        };
        let f = func(
            0x01,
            cgf::LocalFlow {
                vertices: vec![
                    vertex(1, cgf::VertexKind::CallResultPort, 0, 0), // msg
                    vertex(2, cgf::VertexKind::CallResultPort, 1, 0), // err
                    vertex(3, cgf::VertexKind::CallArgPort, 0, 1),    // db.Exec arg
                ],
                edges: vec![edge(1, 3)],
                callsites: vec![recv, sink],
            },
        );
        let cat = Catalog::load_str(CAT).unwrap();
        let prog = engine_prog(vec![f]);
        let mut eng = Engine::new(&prog, &cat);
        eng.run();
        let sum = &eng.summaries.get(&hexid(&[0x01; 32])).unwrap();
        let classes: Vec<_> = sum
            .sink_hits
            .iter()
            .map(|h| (h.in_slot.clone(), h.class.clone()))
            .collect();
        assert!(
            classes.contains(&(Slot::Source.into(), "sqli".into())),
            "Recv result must be an unconditional source: {classes:?}"
        );
        assert!(
            classes.contains(&(Slot::StreamIn.into(), "sqli".into())),
            "Recv sink must also be keyed StreamIn for cross-repo: {classes:?}"
        );
    }

    /// Endpoint-driven sourcing (doc 19): a fn with source_params=[1] taints
    /// Param(1) unconditionally — no catalog source getter involved.
    #[test]
    fn source_params_seed_param_without_getter() {
        let sink = cgf::CallSite {
            id: 0,
            callee_fqn: "db.Exec".into(),
            argc: 1,
            ..Default::default()
        };
        let mut f = func(
            0x03,
            cgf::LocalFlow {
                vertices: vec![
                    vertex(1, cgf::VertexKind::InParam, 0, 0), // ctx
                    vertex(2, cgf::VertexKind::InParam, 1, 0), // token (untrusted arg)
                    vertex(3, cgf::VertexKind::CallArgPort, 0, 0), // db.Exec arg
                ],
                edges: vec![edge(2, 3)],
                callsites: vec![sink],
            },
        );
        f.source_params = vec![1];
        let cat = Catalog::load_str(CAT).unwrap(); // sink-only catalog, no sources
        let prog = engine_prog(vec![f]);
        let mut eng = Engine::new(&prog, &cat);
        eng.run();
        let sum = &eng.summaries.get(&hexid(&[0x03; 32])).unwrap();
        let hits: Vec<_> = sum
            .sink_hits
            .iter()
            .map(|h| (h.in_slot.clone(), h.class.clone()))
            .collect();
        assert!(
            hits.contains(&(Slot::Source.into(), "sqli".into())),
            "seeded param must reach the sink as Source: {hits:?}"
        );
        // ctx (Param(0), unseeded) alone must NOT produce a Source hit — only
        // the declared arg index is untrusted.
        let mut unseeded = func(
            0x04,
            cgf::LocalFlow {
                vertices: vec![
                    vertex(1, cgf::VertexKind::InParam, 0, 0),
                    vertex(2, cgf::VertexKind::InParam, 1, 0),
                    vertex(3, cgf::VertexKind::CallArgPort, 0, 0),
                ],
                edges: vec![edge(1, 3)],
                callsites: vec![cgf::CallSite {
                    id: 0,
                    callee_fqn: "db.Exec".into(),
                    argc: 1,
                    ..Default::default()
                }],
            },
        );
        unseeded.source_params = vec![1];
        let prog2 = engine_prog(vec![unseeded]);
        let mut eng2 = Engine::new(&prog2, &cat);
        eng2.run();
        let sum2 = &eng2.summaries.get(&hexid(&[0x04; 32])).unwrap();
        assert!(
            !sum2.sink_hits.iter().any(|h| h.in_slot == Slot::Source),
            "unseeded ctx flow must not be a Source hit: {:?}",
            sum2.sink_hits
        );
    }

    /// P11: a numeric sink `arg` fires only when taint reaches that exact
    /// arg-port index ("any" is covered by every other sink test here).
    #[test]
    fn sink_arg_index_matches_only_that_arg() {
        const CAT_IDX: &str = r#"
[[sinks]]
class = "sqli"
selector = "db.Exec"
arg = "1"
"#;
        let cat = Catalog::load_str(CAT_IDX).unwrap();
        let mk = |iid: u8, arg_index: u32| {
            let mut f = func(
                iid,
                cgf::LocalFlow {
                    vertices: vec![
                        vertex(1, cgf::VertexKind::InParam, 0, 0),
                        vertex(2, cgf::VertexKind::CallArgPort, arg_index, 0),
                    ],
                    edges: vec![edge(1, 2)],
                    callsites: vec![cgf::CallSite {
                        id: 0,
                        callee_fqn: "db.Exec".into(),
                        argc: 2,
                        ..Default::default()
                    }],
                },
            );
            f.source_params = vec![0];
            f
        };
        let prog = engine_prog(vec![mk(0x11, 1)]);
        let mut eng = Engine::new(&prog, &cat);
        eng.run();
        assert!(
            eng.summaries.get(&hexid(&[0x11; 32])).unwrap()
                .sink_hits
                .iter()
                .any(|h| h.class == "sqli"),
            "taint at arg 1 must match arg = \"1\""
        );
        let prog = engine_prog(vec![mk(0x12, 0)]);
        let mut eng = Engine::new(&prog, &cat);
        eng.run();
        assert!(
            eng.summaries.get(&hexid(&[0x12; 32])).unwrap().sink_hits.is_empty(),
            "taint at arg 0 must not match arg = \"1\""
        );
    }

    /// Server-stream handler: stream.Send(req) — req is Param(0), the Send data
    /// arg is the contract StreamOut.
    #[test]
    fn server_send_records_stream_out_flow() {
        let mut send = remote_stream_cs(0, cgf::call_site::StreamOp::Send, false);
        send.argc = 2;
        send.resultc = 1;
        let f = func(
            0x02,
            cgf::LocalFlow {
                vertices: vec![
                    vertex(1, cgf::VertexKind::InParam, 0, 0), // req
                    vertex(2, cgf::VertexKind::CallArgPort, 0, 0), // stream recv
                    vertex(3, cgf::VertexKind::CallArgPort, 1, 0), // msg
                ],
                edges: vec![edge(1, 3)],
                callsites: vec![send],
            },
        );
        let cat = Catalog::load_str(CAT).unwrap();
        let prog = engine_prog(vec![f]);
        let mut eng = Engine::new(&prog, &cat);
        eng.run();
        let sum = &eng.summaries.get(&hexid(&[0x02; 32])).unwrap();
        assert!(
            sum.flows.contains(&(Slot::Param(0).into(), Slot::StreamOut.into())),
            "flows: {:?}",
            sum.flows
        );
    }

    /// Handler delegates to a same-repo helper that Sends on the stream:
    /// helper's (Param(1), StreamOut) must surface as the handler's StreamOut.
    #[test]
    fn helper_send_indirection_composes() {
        // helper(stream, data): stream.Send(data)
        let mut send = remote_stream_cs(0, cgf::call_site::StreamOp::Send, false);
        send.argc = 2;
        let helper = func(
            0x03,
            cgf::LocalFlow {
                vertices: vec![
                    vertex(1, cgf::VertexKind::InParam, 0, 0),
                    vertex(2, cgf::VertexKind::InParam, 1, 0),
                    vertex(3, cgf::VertexKind::CallArgPort, 0, 0),
                    vertex(4, cgf::VertexKind::CallArgPort, 1, 0),
                ],
                edges: vec![edge(2, 4)],
                callsites: vec![send],
            },
        );
        // handler(req, stream): helper(stream, req)
        let call_helper = cgf::CallSite {
            id: 0,
            callee_iids: vec![vec![0x03; 32]],
            callee_fqn: "pkg.helper".into(),
            argc: 2,
            ..Default::default()
        };
        let handler = func(
            0x04,
            cgf::LocalFlow {
                vertices: vec![
                    vertex(1, cgf::VertexKind::InParam, 0, 0), // req
                    vertex(2, cgf::VertexKind::InParam, 1, 0), // stream
                    vertex(3, cgf::VertexKind::CallArgPort, 0, 0),
                    vertex(4, cgf::VertexKind::CallArgPort, 1, 0),
                ],
                edges: vec![edge(2, 3), edge(1, 4)],
                callsites: vec![call_helper],
            },
        );
        let cat = Catalog::load_str(CAT).unwrap();
        let prog = engine_prog(vec![helper, handler]);
        let mut eng = Engine::new(&prog, &cat);
        eng.run();
        let hsum = &eng.summaries.get(&hexid(&[0x03; 32])).unwrap();
        assert!(hsum.flows.contains(&(Slot::Param(1).into(), Slot::StreamOut.into())));
        let sum = &eng.summaries.get(&hexid(&[0x04; 32])).unwrap();
        assert!(
            sum.flows.contains(&(Slot::Param(0).into(), Slot::StreamOut.into())),
            "helper StreamOut must surface in handler: {:?}",
            sum.flows
        );
    }

    /// Handler delegates the stream to a helper that Recvs and returns the msg:
    /// helper's (StreamIn, Return(0)) + StreamIn sink must surface in handler.
    #[test]
    fn helper_recv_indirection_composes() {
        let mut recv = remote_stream_cs(0, cgf::call_site::StreamOp::Recv, false);
        recv.argc = 1;
        recv.resultc = 2;
        let sink = cgf::CallSite {
            id: 1,
            callee_fqn: "db.Exec".into(),
            argc: 1,
            ..Default::default()
        };
        // helper(stream): m := stream.Recv(); db.Exec(m); return m
        let helper = func(
            0x05,
            cgf::LocalFlow {
                vertices: vec![
                    vertex(1, cgf::VertexKind::CallResultPort, 0, 0),
                    vertex(2, cgf::VertexKind::CallArgPort, 0, 1),
                    vertex(3, cgf::VertexKind::OutReturn, 0, 0),
                ],
                edges: vec![edge(1, 2), edge(1, 3)],
                callsites: vec![recv, sink],
            },
        );
        // handler(stream): m := helper(stream); db.Exec(m)
        let call_helper = cgf::CallSite {
            id: 0,
            callee_iids: vec![vec![0x05; 32]],
            callee_fqn: "pkg.helper".into(),
            argc: 1,
            resultc: 1,
            ..Default::default()
        };
        let sink2 = cgf::CallSite {
            id: 1,
            callee_fqn: "db.Exec".into(),
            argc: 1,
            ..Default::default()
        };
        let handler = func(
            0x06,
            cgf::LocalFlow {
                vertices: vec![
                    vertex(1, cgf::VertexKind::InParam, 0, 0),
                    vertex(2, cgf::VertexKind::CallArgPort, 0, 0),
                    vertex(3, cgf::VertexKind::CallResultPort, 0, 0),
                    vertex(4, cgf::VertexKind::CallArgPort, 0, 1),
                ],
                edges: vec![edge(1, 2), edge(3, 4)],
                callsites: vec![call_helper, sink2],
            },
        );
        let cat = Catalog::load_str(CAT).unwrap();
        let prog = engine_prog(vec![helper, handler]);
        let mut eng = Engine::new(&prog, &cat);
        eng.run();
        let sum = &eng.summaries.get(&hexid(&[0x06; 32])).unwrap();
        let stream_in_sinks = sum
            .sink_hits
            .iter()
            .filter(|h| h.in_slot == Slot::StreamIn)
            .count();
        assert!(
            stream_in_sinks >= 2,
            "helper's StreamIn sink + handler's own sink on the returned msg: {:?}",
            sum.sink_hits
        );
    }

    /// Client: req := p0; s := c.M(ctx, req); s.Send(p0); m := s.Recv();
    /// return m — with a linked contract summary {(Param(1),StreamOut),
    /// (StreamIn,StreamOut), sink@StreamIn}, the Recv result must taint the
    /// return and the Send must surface the remote sink.
    #[test]
    fn client_composes_stream_out_to_recv_results() {
        let mut open = cgf::CallSite {
            id: 0,
            kind: cgf::call_site::Kind::InvokesRemote as i32,
            callee_iids: vec![CONTRACT.to_vec()],
            callee_fqn: "pb.Feed/M".into(),
            arg0_is_receiver: true,
            argc: 3,
            resultc: 2,
            ..Default::default()
        };
        open.stream_op = cgf::call_site::StreamOp::None as i32;
        let mut send = remote_stream_cs(1, cgf::call_site::StreamOp::Send, true);
        send.argc = 2;
        send.resultc = 1;
        let mut recv = remote_stream_cs(2, cgf::call_site::StreamOp::Recv, true);
        recv.argc = 1;
        recv.resultc = 2;
        let f = func(
            0x07,
            cgf::LocalFlow {
                vertices: vec![
                    vertex(1, cgf::VertexKind::InParam, 0, 0), // p0
                    vertex(2, cgf::VertexKind::CallArgPort, 2, 0), // open req arg
                    vertex(3, cgf::VertexKind::CallResultPort, 0, 0), // stream obj
                    vertex(4, cgf::VertexKind::CallArgPort, 1, 1), // Send msg
                    vertex(5, cgf::VertexKind::CallResultPort, 0, 2), // Recv msg
                    vertex(6, cgf::VertexKind::OutReturn, 0, 0),
                ],
                edges: vec![edge(1, 2), edge(1, 4), edge(5, 6)],
                callsites: vec![open, send, recv],
            },
        );
        let cat = Catalog::load_str(CAT).unwrap();
        let prog = engine_prog(vec![f]);
        let eng = Engine::new(&prog, &cat);
        // simulate compose's view publication: contract summary in the client frame
        let mut csum = Summary {
            confidence: 1.0,
            ..Default::default()
        };
        csum.flows.insert((Slot::Param(1).into(), Slot::StreamOut.into()));
        csum.flows.insert((Slot::StreamIn.into(), Slot::StreamOut.into()));
        csum.sink_hits.push(SinkHit {
            in_slot: Slot::StreamIn.into(),
            class: "sqli".into(),
            callsite: 0,
            span: None,
            via_heap: None,
            terminal: SinkOrigin {
                fn_iid: hexid(&CONTRACT),
                callsite: 0,
            },
        });
        eng.summaries.insert(hexid(&CONTRACT), Arc::new(csum));
        let f = &prog.funcs[&hexid(&[0x07; 32])];
        let sum = eng.summarize(f);
        assert!(
            sum.flows.contains(&(Slot::Param(0).into(), Slot::Return(0).into())),
            "open-call req -> contract StreamOut -> sibling Recv -> return: {:?}",
            sum.flows
        );
        assert!(
            sum.sink_hits
                .iter()
                .any(|h| h.class == "sqli" && h.in_slot == Slot::Param(0)),
            "Send msg must surface the contract's StreamIn sink: {:?}",
            sum.sink_hits
        );
    }
}

/// Field-path composition (doc 20 §2.3): path-variant vertices in the CGF,
/// prefix-comparable matching at call sites, whole-object default leaf.
#[cfg(test)]
mod fieldpath_tests {
    use super::*;
    use crate::graph::Program;
    use cache_tests::{edge, vertex};

    const CAT: &str = r#"
[[sinks]]
class = "sqli"
selector = "db.Exec"
arg = "any"
"#;

    fn vertex_p(
        id: u32,
        kind: cgf::VertexKind,
        index: u32,
        cs: u32,
        path: Vec<u32>,
    ) -> cgf::FlowVertex {
        let mut v = vertex(id, kind, index, cs);
        v.field_path = path;
        v
    }

    fn func(iid: u8, flow: cgf::LocalFlow) -> cgf::Function {
        cgf::Function {
            id: Some(cgf::Ident {
                iid: vec![iid; 32],
                bid: vec![iid; 32],
            }),
            fqn: format!("pkg.F{iid}"),
            has_body: true,
            flow: Some(flow),
            ..Default::default()
        }
    }

    fn engine_prog(fns: Vec<cgf::Function>) -> Program {
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

    /// callee B: only field [3] of its param reaches db.Exec (accessed-path row
    /// param_0[3]). B's iid is 0xB0 + a caller-specific suffix so each caller
    /// composes an identical summary independently.
    fn callee_b(iid: u8) -> cgf::Function {
        func(
            iid,
            cgf::LocalFlow {
                vertices: vec![
                    vertex(1, cgf::VertexKind::InParam, 0, 0), // whole param
                    vertex_p(2, cgf::VertexKind::InParam, 0, 0, vec![3]), // param.[3]
                    vertex(3, cgf::VertexKind::CallArgPort, 0, 0), // db.Exec arg
                ],
                edges: vec![edge(2, 3)], // only the [3] projection flows to the sink
                callsites: vec![cgf::CallSite {
                    id: 0,
                    callee_fqn: "db.Exec".into(),
                    argc: 1,
                    ..Default::default()
                }],
            },
        )
    }

    /// caller passing only fact param_0[arg_path] into B at (cs0, arg0).
    fn caller_with_arg_path(iid: u8, callee: u8, arg_path: Vec<u32>) -> cgf::Function {
        func(
            iid,
            cgf::LocalFlow {
                vertices: vec![
                    vertex(1, cgf::VertexKind::InParam, 0, 0),
                    vertex_p(2, cgf::VertexKind::CallArgPort, 0, 0, arg_path),
                ],
                edges: vec![edge(1, 2)],
                callsites: vec![cgf::CallSite {
                    id: 0,
                    callee_iids: vec![vec![callee; 32]],
                    callee_fqn: format!("pkg.F{callee}"),
                    argc: 1,
                    ..Default::default()
                }],
            },
        )
    }

    #[test]
    fn summary_rows_fire_only_for_comparable_paths() {
        let cat = Catalog::load_str(CAT).unwrap();
        // (arg path fed to B, should B's param_0[3] sink row fire?)
        let cases: Vec<(Vec<u32>, bool)> = vec![
            (vec![3], true),     // exact
            (vec![], true),      // whole-object fact fires the field row
            (vec![3, 1], true),  // finer fact inside the row's region
            (vec![7], false),    // disjoint field: the FP the upgrade kills
        ];
        for (i, (path, want)) in cases.into_iter().enumerate() {
            let b_iid = 0xB0 + i as u8;
            let a_iid = 0xA0 + i as u8;
            let prog = engine_prog(vec![
                callee_b(b_iid),
                caller_with_arg_path(a_iid, b_iid, path.clone()),
            ]);
            let mut eng = Engine::new(&prog, &cat);
            eng.run();
            let got = eng.summaries.get(&hexid(&[a_iid; 32])).unwrap()
                .sink_hits
                .iter()
                .any(|h| h.class == "sqli");
            assert_eq!(got, want, "arg path {path:?}");
        }
    }

    /// callee taints return[3]; caller result variants [3] and [7] feed
    /// separate sinks — only the [3] one may fire. The whole-object [] variant
    /// is also tainted (sound coarsening).
    #[test]
    fn out_landing_selects_comparable_result_variants() {
        let cat = Catalog::load_str(CAT).unwrap();
        let callee = func(
            0xB9,
            cgf::LocalFlow {
                vertices: vec![
                    vertex(1, cgf::VertexKind::InParam, 0, 0),
                    vertex_p(2, cgf::VertexKind::OutReturn, 0, 0, vec![3]),
                ],
                edges: vec![edge(1, 2)],
                callsites: vec![],
            },
        );
        let caller = func(
            0xA9,
            cgf::LocalFlow {
                vertices: vec![
                    vertex(1, cgf::VertexKind::InParam, 0, 0),
                    vertex(2, cgf::VertexKind::CallArgPort, 0, 0),
                    vertex_p(3, cgf::VertexKind::CallResultPort, 0, 0, vec![3]),
                    vertex_p(4, cgf::VertexKind::CallResultPort, 0, 0, vec![7]),
                    vertex(5, cgf::VertexKind::CallResultPort, 0, 0), // whole
                    vertex(6, cgf::VertexKind::CallArgPort, 0, 1),    // sink A ([3])
                    vertex(7, cgf::VertexKind::CallArgPort, 0, 2),    // sink B ([7])
                ],
                edges: vec![edge(1, 2), edge(3, 6), edge(4, 7)],
                callsites: vec![
                    cgf::CallSite {
                        id: 0,
                        callee_iids: vec![vec![0xB9; 32]],
                        callee_fqn: "pkg.F185".into(),
                        argc: 1,
                        resultc: 1,
                        ..Default::default()
                    },
                    cgf::CallSite {
                        id: 1,
                        callee_fqn: "db.Exec".into(),
                        argc: 1,
                        ..Default::default()
                    },
                    cgf::CallSite {
                        id: 2,
                        callee_fqn: "db.Exec".into(),
                        argc: 1,
                        ..Default::default()
                    },
                ],
            },
        );
        let prog = engine_prog(vec![callee, caller]);
        let mut eng = Engine::new(&prog, &cat);
        eng.run();
        let sum = &eng.summaries.get(&hexid(&[0xA9; 32])).unwrap();
        let hit_sites: Vec<usize> = sum.sink_hits.iter().map(|h| h.callsite).collect();
        assert!(hit_sites.contains(&1), "return[3] must taint the [3] variant: {sum:?}");
        assert!(
            !hit_sites.contains(&2),
            "return[3] must NOT taint the disjoint [7] variant: {sum:?}"
        );
    }

    /// unsummarized callee = default leaf: ALL result variants taint (the
    /// doc 20 §2.2.6 whole-object escape hatch for opaque/serialization).
    #[test]
    fn default_leaf_taints_every_result_variant() {
        let cat = Catalog::load_str(CAT).unwrap();
        let caller = func(
            0xAB,
            cgf::LocalFlow {
                vertices: vec![
                    vertex(1, cgf::VertexKind::InParam, 0, 0),
                    vertex(2, cgf::VertexKind::CallArgPort, 0, 0),
                    vertex_p(3, cgf::VertexKind::CallResultPort, 0, 0, vec![3]),
                    vertex_p(4, cgf::VertexKind::CallResultPort, 0, 0, vec![7]),
                    vertex(5, cgf::VertexKind::CallArgPort, 0, 1),
                    vertex(6, cgf::VertexKind::CallArgPort, 0, 2),
                ],
                edges: vec![edge(1, 2), edge(3, 5), edge(4, 6)],
                callsites: vec![
                    cgf::CallSite {
                        id: 0,
                        callee_fqn: "opaque.Marshal".into(), // no summary anywhere
                        argc: 1,
                        resultc: 1,
                        ..Default::default()
                    },
                    cgf::CallSite {
                        id: 1,
                        callee_fqn: "db.Exec".into(),
                        argc: 1,
                        ..Default::default()
                    },
                    cgf::CallSite {
                        id: 2,
                        callee_fqn: "db.Exec".into(),
                        argc: 1,
                        ..Default::default()
                    },
                ],
            },
        );
        let prog = engine_prog(vec![caller]);
        let mut eng = Engine::new(&prog, &cat);
        eng.run();
        let sum = &eng.summaries.get(&hexid(&[0xAB; 32])).unwrap();
        let hit_sites: Vec<usize> = sum.sink_hits.iter().map(|h| h.callsite).collect();
        assert!(
            hit_sites.contains(&1) && hit_sites.contains(&2),
            "default leaf must taint every variant: {sum:?}"
        );
    }

    /// A callee whose parameter does not reach its result: its summary holds
    /// no flow from param 0 to return 0.
    fn callee_without_flow(iid: u8) -> cgf::Function {
        func(
            iid,
            cgf::LocalFlow {
                vertices: vec![
                    vertex(1, cgf::VertexKind::InParam, 0, 0),
                    vertex(2, cgf::VertexKind::OutReturn, 0, 0),
                ],
                edges: vec![],
                callsites: vec![],
            },
        )
    }

    /// A caller whose param 0 goes into one call site (with the given targets)
    /// and whose result goes into a `db.Exec` sink.
    fn caller_of_targets(iid: u8, targets: &[u8]) -> cgf::Function {
        func(
            iid,
            cgf::LocalFlow {
                vertices: vec![
                    vertex(1, cgf::VertexKind::InParam, 0, 0),
                    vertex(2, cgf::VertexKind::CallArgPort, 0, 0),
                    vertex(3, cgf::VertexKind::CallResultPort, 0, 0),
                    vertex(4, cgf::VertexKind::CallArgPort, 0, 1),
                ],
                edges: vec![edge(1, 2), edge(3, 4)],
                callsites: vec![
                    cgf::CallSite {
                        id: 0,
                        callee_iids: targets.iter().map(|t| vec![*t; 32]).collect(),
                        callee_fqn: "pkg.Dispatch".into(),
                        argc: 1,
                        resultc: 1,
                        ..Default::default()
                    },
                    cgf::CallSite { id: 1, callee_fqn: "db.Exec".into(), argc: 1, ..Default::default() },
                ],
            },
        )
    }

    fn sqli_reached(fns: Vec<cgf::Function>, caller: u8) -> bool {
        let cat = Catalog::load_str(CAT).unwrap();
        let prog = engine_prog(fns);
        let mut eng = Engine::new(&prog, &cat);
        eng.run();
        eng.summaries.get(&hexid(&[caller; 32])).unwrap().sink_hits.iter().any(|h| h.class == "sqli")
    }

    /// A dispatch site with two targets: one summarized (no flow from arg 0 to
    /// the result), one not loaded. The unloaded target gets the default leaf,
    /// so taint on arg 0 still reaches the result.
    #[test]
    fn a_site_with_one_unsummarized_target_gets_the_leaf() {
        let fns = vec![callee_without_flow(0xA1), caller_of_targets(0xC1, &[0xA1, 0xB1])];
        assert!(sqli_reached(fns, 0xC1), "the unloaded target must be taint-transparent");
    }

    /// The same site once every target has a summary: no leaf, so the callee
    /// summaries alone decide and no taint reaches the result.
    #[test]
    fn a_site_with_every_target_summarized_gets_no_leaf() {
        let fns = vec![
            callee_without_flow(0xA1),
            callee_without_flow(0xA2),
            caller_of_targets(0xC1, &[0xA1, 0xA2]),
        ];
        assert!(!sqli_reached(fns, 0xC1), "two summarized targets must not add a leaf");
        let fns = vec![callee_without_flow(0xA1), caller_of_targets(0xC1, &[0xA1])];
        assert!(!sqli_reached(fns, 0xC1), "one summarized target must not add a leaf");
    }

    /// A site with no target at all keeps the leaf.
    #[test]
    fn a_site_with_no_target_gets_the_leaf() {
        assert!(sqli_reached(vec![caller_of_targets(0xC1, &[])], 0xC1));
    }

    /// B1 / doc 31 §4. A synthetic CGF is the only way to test this: no fixture
    /// can produce `error_results` on a tree whose frontend does not emit it yet
    /// (HANDOFF trap 5b). Shape: one 2-result leaf whose result 1 is the error,
    /// each result port wired to its own sink.
    fn leaf_with_error_result(callee: &str) -> cgf::Function {
        func(
            0xE1,
            cgf::LocalFlow {
                vertices: vec![
                    vertex(1, cgf::VertexKind::InParam, 0, 0),
                    vertex(2, cgf::VertexKind::CallArgPort, 0, 0),
                    vertex(3, cgf::VertexKind::CallResultPort, 0, 0), // the value
                    vertex(4, cgf::VertexKind::CallResultPort, 1, 0), // the error
                    vertex(5, cgf::VertexKind::CallArgPort, 0, 1),
                    vertex(6, cgf::VertexKind::CallArgPort, 0, 2),
                ],
                edges: vec![edge(1, 2), edge(3, 5), edge(4, 6)],
                callsites: vec![
                    cgf::CallSite {
                        id: 0,
                        callee_fqn: callee.into(),
                        argc: 1,
                        resultc: 2,
                        error_results: 0b10, // result 1 is the error
                        ..Default::default()
                    },
                    cgf::CallSite { id: 1, callee_fqn: "db.Exec".into(), argc: 1, ..Default::default() },
                    cgf::CallSite { id: 2, callee_fqn: "db.Exec".into(), argc: 1, ..Default::default() },
                ],
            },
        )
    }

    fn leaf_hits(callee: &str, no_error_leaf: bool) -> Vec<usize> {
        let cat = Catalog::load_str(CAT_ERR).unwrap();
        let prog = engine_prog(vec![leaf_with_error_result(callee)]);
        let mut eng = Engine::new(&prog, &cat);
        eng.no_error_leaf = no_error_leaf;
        eng.run();
        let mut v: Vec<usize> = eng.summaries.get(&hexid(&[0xE1; 32])).unwrap()
            .sink_hits
            .iter()
            .map(|h| h.callsite)
            .collect();
        v.sort();
        v.dedup();
        v
    }

    const CAT_ERR: &str = r#"
[[sinks]]
class = "sqli"
selector = "db.Exec"
arg = "any"

[[error_wrappers]]
selector = "fmt.Errorf"
"#;

    #[test]
    fn no_error_leaf_suppresses_only_the_error_result_port() {
        // Off: today's behaviour — both ports taint (this is the assertion that
        // fails if the flag ever defaults to on).
        assert_eq!(
            leaf_hits("opaque.Marshal", false),
            vec![1, 2],
            "with the flag OFF the error port must still taint"
        );
        // On: the value port survives, the error port does not. Per PORT, not
        // per callsite — the same callsite feeds both sinks.
        assert_eq!(
            leaf_hits("opaque.Marshal", true),
            vec![1],
            "the error result port must not taint, and the value port must"
        );
    }

    #[test]
    fn an_error_wrapper_keeps_its_error_result() {
        // doc 25 R3: `fmt.Errorf("… %s", account, err)` genuinely carries request
        // data, so a catalog error_wrapper is exempt even with the flag on.
        assert_eq!(
            leaf_hits("fmt.Errorf", true),
            vec![1, 2],
            "a catalog error_wrapper must keep tainting its error result"
        );
    }

    #[test]
    fn a_zero_mask_means_unknown_and_changes_nothing() {
        // Every pre-B1 CGF has error_results == 0. The rule must be inert there —
        // that is what makes the flag an escape hatch rather than a re-baseline.
        let cat = Catalog::load_str(CAT_ERR).unwrap();
        let mut f = leaf_with_error_result("opaque.Marshal");
        f.flow.as_mut().unwrap().callsites[0].error_results = 0;
        let prog = engine_prog(vec![f]);
        let mut eng = Engine::new(&prog, &cat);
        eng.no_error_leaf = true;
        eng.run();
        let hits: Vec<usize> = eng.summaries.get(&hexid(&[0xE1; 32])).unwrap()
            .sink_hits
            .iter()
            .map(|h| h.callsite)
            .collect();
        assert!(
            hits.contains(&1) && hits.contains(&2),
            "a zero mask must be treated as unknown: {hits:?}"
        );
    }

    /// The census must count the STATIC population once — never per descent
    /// (HANDOFF trap 8c: A16's per-drop log produced 7.8 M lines / 2 GB).
    #[test]
    fn error_leaf_census_counts_sites_and_exempts_wrappers() {
        let cat = Catalog::load_str(CAT_ERR).unwrap();
        let prog = engine_prog(vec![leaf_with_error_result("opaque.Marshal")]);
        let eng = Engine::new(&prog, &cat);
        assert_eq!(eng.error_leaf_census(), (1, 0, 1, 1));

        let prog = engine_prog(vec![leaf_with_error_result("fmt.Errorf")]);
        let eng = Engine::new(&prog, &cat);
        let (sites, wrappers, ports, fns) = eng.error_leaf_census();
        assert_eq!(
            (sites, wrappers, ports, fns),
            (1, 1, 0, 1),
            "a wrapper site counts as exempt and suppresses no port"
        );
    }
}

/// A self-recursive singleton SCC is a recursive SCC. These pin the fixpoint
/// the phase-1 loop now runs for one (see `run_with_store`'s `self_rec`).
#[cfg(test)]
mod recursion_tests {
    use super::*;
    use crate::graph::Program;
    use cache_tests::{edge, vertex};

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
            fqn: format!("pkg.F{iid}"),
            has_body: true,
            flow: Some(flow),
            ..Default::default()
        }
    }

    fn engine_prog(fns: Vec<cgf::Function>) -> Program {
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

    fn sink_cs(argc: u32) -> cgf::CallSite {
        cgf::CallSite {
            id: 0,
            callee_fqn: "db.Exec".into(),
            argc,
            ..Default::default()
        }
    }

    /// A call site whose only callee is `iid` itself.
    fn self_cs(id: u32, iid: u8, argc: u32, resultc: u32) -> cgf::CallSite {
        cgf::CallSite {
            id,
            callee_iids: vec![vec![iid; 32]],
            callee_fqn: format!("pkg.F{iid}"),
            argc,
            resultc,
            ..Default::default()
        }
    }

    fn run(prog: &Program) -> Engine<'_> {
        let cat: &'static Catalog = Box::leak(Box::new(Catalog::load_str(CAT).unwrap()));
        let mut eng = Engine::new(prog, cat);
        eng.run();
        eng
    }

    /// `walk(a, b) { db.Exec(b); walk(b, a) }` — the `walk(n)`/`db.Exec(n)`
    /// shape with the arguments swapped, which is the only way the loss is
    /// observable: the sink for `a` exists ONLY at depth >= 1, reached by
    /// composing the function's own summary at its own call site.
    ///
    /// Before the fix the singleton SCC summarized once, the recursive site had
    /// no summary, the default leaf fired (results tainted, no sink hits) and
    /// `Param(0)` carried no sink hit at all — silent recall loss.
    #[test]
    fn a_sink_reachable_only_through_the_recursive_call_is_found() {
        let f = func(
            0xF1,
            cgf::LocalFlow {
                vertices: vec![
                    vertex(1, cgf::VertexKind::InParam, 0, 0),      // a
                    vertex(2, cgf::VertexKind::InParam, 1, 0),      // b
                    vertex(3, cgf::VertexKind::CallArgPort, 0, 0),  // db.Exec(b)
                    vertex(4, cgf::VertexKind::CallArgPort, 0, 1),  // walk arg0 = b
                    vertex(5, cgf::VertexKind::CallArgPort, 1, 1),  // walk arg1 = a
                ],
                edges: vec![edge(2, 3), edge(2, 4), edge(1, 5)],
                callsites: vec![sink_cs(1), self_cs(1, 0xF1, 2, 0)],
            },
        );
        let prog = engine_prog(vec![f]);
        let eng = run(&prog);
        let sum = &eng.summaries.get(&hexid(&[0xF1; 32])).unwrap();

        let hit = |p: u32| {
            sum.sink_hits
                .iter()
                .any(|h| h.class == "sqli" && h.in_slot.slot == Slot::Param(p))
        };
        assert!(hit(1), "param 1 reaches db.Exec directly (found before too)");
        assert!(
            hit(0),
            "param 0 reaches db.Exec only through the recursive call: {:?}",
            sum.sink_hits
                .iter()
                .map(|h| (slot_str(&h.in_slot), h.callsite))
                .collect::<Vec<_>>()
        );
    }

    /// `f(p) { db.Exec(p); f(p) }`. Every iteration re-derives the same hits, so
    /// without `dedup_sink_hits` the multiset would grow per round and the
    /// fixpoint would never converge. The direct sink must appear EXACTLY once.
    #[test]
    fn iterating_a_self_recursive_fn_does_not_duplicate_sink_hits() {
        let f = func(
            0xF2,
            cgf::LocalFlow {
                vertices: vec![
                    vertex(1, cgf::VertexKind::InParam, 0, 0),
                    vertex(2, cgf::VertexKind::CallArgPort, 0, 0), // db.Exec(p)
                    vertex(3, cgf::VertexKind::CallArgPort, 0, 1), // f(p)
                ],
                edges: vec![edge(1, 2), edge(1, 3)],
                callsites: vec![sink_cs(1), self_cs(1, 0xF2, 1, 0)],
            },
        );
        let prog = engine_prog(vec![f]);
        let eng = run(&prog);
        let sum = &eng.summaries.get(&hexid(&[0xF2; 32])).unwrap();

        let direct = sum.sink_hits.iter().filter(|h| h.callsite == 0).count();
        assert_eq!(direct, 1, "the db.Exec site itself, once: {:?}", sum.sink_hits);
        // The recursive site legitimately carries the same class one frame
        // down; that is one hit too, not N. What must never happen is the same
        // (slot, class, callsite) appearing twice.
        let mut keys: Vec<String> = sum.sink_hits.iter().map(|h| format!("{h:?}")).collect();
        let n = keys.len();
        keys.sort();
        keys.dedup();
        assert_eq!(keys.len(), n, "duplicate sink hits survived dedup");
    }

    /// The iteration is visible in the trace for a self-recursive singleton and
    /// absent for a plain one — which is also how we observe that a
    /// non-recursive singleton still summarizes exactly once (one round, no
    /// scc-start, no scc-iter), i.e. the fix costs nothing where it does not
    /// apply.
    #[test]
    fn only_a_self_recursive_singleton_iterates() {
        let trace_of = |prog: &Program, tag: &str| -> String {
            let path = std::env::temp_dir()
                .join(format!("pc-ifds-rec-{tag}-{}.trace", std::process::id()));
            let _ = std::fs::remove_file(&path);
            let cat = Catalog::load_str(CAT).unwrap();
            {
                let tr = crate::trace::Trace::open(&path, None, None).unwrap();
                let mut eng = Engine::new(prog, &cat);
                eng.trace = Some(&tr);
                eng.run();
            }
            let s = std::fs::read_to_string(&path).unwrap_or_default();
            let _ = std::fs::remove_file(&path);
            s
        };

        // plain leaf: db.Exec(p), no self call
        let plain = engine_prog(vec![func(
            0xF3,
            cgf::LocalFlow {
                vertices: vec![
                    vertex(1, cgf::VertexKind::InParam, 0, 0),
                    vertex(2, cgf::VertexKind::CallArgPort, 0, 0),
                ],
                edges: vec![edge(1, 2)],
                callsites: vec![sink_cs(1)],
            },
        )]);
        let t = trace_of(&plain, "plain");
        assert!(!t.contains("scc-iter"), "a plain singleton must not iterate:\n{t}");

        // self-recursive: same body plus f(p)
        let rec = engine_prog(vec![func(
            0xF4,
            cgf::LocalFlow {
                vertices: vec![
                    vertex(1, cgf::VertexKind::InParam, 0, 0),
                    vertex(2, cgf::VertexKind::CallArgPort, 0, 0),
                    vertex(3, cgf::VertexKind::CallArgPort, 0, 1),
                ],
                edges: vec![edge(1, 2), edge(1, 3)],
                callsites: vec![sink_cs(1), self_cs(1, 0xF4, 1, 0)],
            },
        )]);
        let t = trace_of(&rec, "rec");
        assert!(
            t.matches("scc-iter  size=1").count() >= 2,
            "a self-recursive singleton must run more than one round:\n{t}"
        );
        // `scc-start` is reserved for condensed (multi-member) components —
        // see the comment in run_with_store.
        assert!(!t.contains("scc-start"), "singletons must not announce an SCC:\n{t}");
    }

    /// `f(a, b) { if base { return b }; return f(_, a) }` — `a` reaches the
    /// return ONLY by riding the recursive call's result. Seeding the iteration
    /// with an EMPTY summary (⊥) must still find it: the ascent adds the base
    /// case's `Param(1) -> Return(0)` in round 1 and composes it at the
    /// recursive site in round 2. A regression guard on the ⊥ seeding — the old
    /// default-leaf round found this flow only by over-approximating.
    #[test]
    fn a_flow_that_exists_only_through_the_recursive_call_survives_bottom_seeding() {
        let f = func(
            0xF5,
            cgf::LocalFlow {
                vertices: vec![
                    vertex(1, cgf::VertexKind::InParam, 0, 0),        // a
                    vertex(2, cgf::VertexKind::InParam, 1, 0),        // b
                    vertex(3, cgf::VertexKind::CallArgPort, 1, 0),    // f(_, a)
                    vertex(4, cgf::VertexKind::CallResultPort, 0, 0), // its result
                    vertex(5, cgf::VertexKind::OutReturn, 0, 0),
                ],
                edges: vec![edge(1, 3), edge(4, 5), edge(2, 5)],
                callsites: vec![self_cs(0, 0xF5, 2, 1)],
            },
        );
        let prog = engine_prog(vec![f]);
        let eng = run(&prog);
        let flows = &eng.summaries.get(&hexid(&[0xF5; 32])).unwrap().flows;
        let has = |p: u32| {
            flows.iter().any(|(i, o)| {
                i.slot == Slot::Param(p) && o.slot == Slot::Return(0) && o.path.is_empty()
            })
        };
        assert!(has(1), "the base case: param 1 -> return 0");
        assert!(has(0), "param 0 -> return 0 via the recursive call: {flows:?}");
    }
}

#[cfg(test)]
mod propagator_tests {
    use super::cache_tests::{edge, vertex};
    use super::*;
    use crate::graph::Program;

    const SINK: &str = r#"
[[sinks]]
class = "sqli"
selector = "db.Exec"
arg = "any"
"#;
    const RULE: &str = r#"
[[propagators]]
selector_regex = '\(\*strings\.Builder\)\.WriteString$'
from = "1"
to   = "receiver"
"#;
    const REVIEWED: &str = r#"
[[propagators]]
selector_regex = '\(\*strings\.Builder\)\.WriteString$'
from = "any"
to   = "none"
"#;

    /// ```go
    /// func F(s string) { var sb strings.Builder; sb.WriteString(s); db.Exec(sb.String()) }
    /// ```
    /// Vertex 2 → 4 is the frontend's write-back: the WriteString receiver port
    /// flows into the next use of `sb` (the String receiver port).
    fn builder_fn() -> cgf::Function {
        let call = |id: u32, fqn: &str, argc: u32, resultc: u32, recv: bool| cgf::CallSite {
            id,
            callee_fqn: fqn.into(),
            argc,
            resultc,
            arg0_is_receiver: recv,
            ..Default::default()
        };
        cgf::Function {
            id: Some(cgf::Ident { iid: vec![0x42; 32], bid: vec![0x42; 32] }),
            fqn: "pkg.F".into(),
            has_body: true,
            flow: Some(cgf::LocalFlow {
                vertices: vec![
                    vertex(1, cgf::VertexKind::InParam, 0, 0),         // s
                    vertex(2, cgf::VertexKind::CallArgPort, 0, 0),     // WriteString receiver (&sb)
                    vertex(3, cgf::VertexKind::CallArgPort, 1, 0),     // WriteString(s)
                    vertex(4, cgf::VertexKind::CallArgPort, 0, 1),     // String receiver (&sb)
                    vertex(5, cgf::VertexKind::CallResultPort, 0, 1),  // sb.String()
                    vertex(6, cgf::VertexKind::CallArgPort, 0, 2),     // db.Exec(...)
                ],
                edges: vec![edge(1, 3), edge(2, 4), edge(5, 6)],
                callsites: vec![
                    call(0, "(*strings.Builder).WriteString", 2, 2, true),
                    call(1, "(*strings.Builder).String", 1, 1, true),
                    call(2, "db.Exec", 1, 0, false),
                ],
            }),
            ..Default::default()
        }
    }

    fn run(cat_src: &str, unmodeled: bool) -> Vec<(SlotP, String)> {
        let cat = Catalog::load_str(cat_src).unwrap();
        let f = builder_fn();
        let mut prog = Program { funcs: HashMap::new(), repo_of: HashMap::new(), packages: Vec::new() };
        let h = hexid(&f.id.as_ref().unwrap().iid);
        prog.repo_of.insert(h.clone(), "test".into());
        prog.funcs.insert(h.clone(), f);
        let mut eng = Engine::new(&prog, &cat);
        eng.report_unmodeled = unmodeled;
        eng.run();
        eng.summaries.get(&h).unwrap().sink_hits.iter().map(|x| (x.in_slot.clone(), x.class.clone())).collect()
    }

    #[test]
    fn without_a_rule_the_builder_write_is_lost() {
        assert!(run(SINK, false).is_empty(), "default leaf only feeds WriteString's results");
    }

    #[test]
    fn a_propagator_carries_the_write_into_the_receiver() {
        let hits = run(&format!("{SINK}{RULE}"), false);
        assert_eq!(hits, vec![(Slot::Param(0).into(), "sqli".to_string())]);
    }

    #[test]
    fn unmodeled_report_flags_the_call_only_when_no_rule_covers_it() {
        // no rule: s reaches a library call whose receiver port writes back
        let hits = run(SINK, true);
        assert_eq!(hits, vec![(Slot::Param(0).into(), UNMODELED_CLASS.to_string())]);
        // a rule (flowing or `none`) means reviewed: nothing to report
        assert!(!run(&format!("{SINK}{RULE}"), true).iter().any(|(_, c)| c == UNMODELED_CLASS));
        assert!(run(&format!("{SINK}{REVIEWED}"), true).is_empty(), "`none`: reviewed, no flow, no report");
        // and the flag off never reports
        assert!(run(SINK, false).is_empty());
    }
}

/// Coverage wave 1 §4.1 (E1) and §4.2 (E3), end to end through summary,
/// witness and the backward pass — the three places a source seed or a sink
/// port is interpreted, which must agree.
#[cfg(test)]
mod catalog_port_tests {
    use super::cache_tests::{edge, vertex};
    use super::*;
    use crate::graph::Program;

    const GIN_BIND: &str = "(*github.com/gin-gonic/gin.Context).ShouldBindJSON";
    const QUERY: &str = "(*database/sql.DB).QueryContext";

    fn prog_of(f: cgf::Function) -> Program {
        let mut prog = Program { funcs: HashMap::new(), repo_of: HashMap::new(), packages: Vec::new() };
        let h = hexid(&f.id.as_ref().unwrap().iid);
        prog.repo_of.insert(h.clone(), "test".into());
        prog.funcs.insert(h, f);
        prog
    }

    fn func(iid: u8, fqn: &str, flow: cgf::LocalFlow) -> cgf::Function {
        cgf::Function {
            id: Some(cgf::Ident { iid: vec![iid; 32], bid: vec![iid; 32] }),
            fqn: fqn.into(),
            has_body: true,
            flow: Some(flow),
            ..Default::default()
        }
    }

    fn call(id: u32, fqn: &str, argc: u32, resultc: u32, recv: bool) -> cgf::CallSite {
        cgf::CallSite {
            id,
            callee_fqn: fqn.into(),
            argc,
            resultc,
            arg0_is_receiver: recv,
            ..Default::default()
        }
    }

    /// ```go
    /// func Create(c *gin.Context) { var req Req; err := c.ShouldBindJSON(&req); db.Exec(req) }
    /// ```
    /// Vertex 3 -> 5 is the frontend's library write-back: the `&req` arg port
    /// flows into the next use of `req`.
    fn bind_handler() -> cgf::Function {
        func(
            0x61,
            "app.Create",
            cgf::LocalFlow {
                vertices: vec![
                    vertex(1, cgf::VertexKind::InParam, 0, 0),        // c
                    vertex(2, cgf::VertexKind::CallArgPort, 0, 0),    // c (receiver)
                    vertex(3, cgf::VertexKind::CallArgPort, 1, 0),    // &req
                    vertex(4, cgf::VertexKind::CallResultPort, 0, 0), // err
                    vertex(5, cgf::VertexKind::CallArgPort, 0, 1),    // db.Exec(req)
                ],
                edges: vec![edge(1, 2), edge(3, 5)],
                callsites: vec![call(0, GIN_BIND, 2, 1, true), call(1, "db.Exec", 1, 0, false)],
            },
        )
    }

    fn cat_with(to: &str) -> Catalog {
        Catalog::load_str(&format!(
            "[[sources]]\nkind = \"http_bind\"\nselector = \"{GIN_BIND}\"\n{to}\n\
             [[sinks]]\nclass = \"sqli\"\nselector = \"db.Exec\"\n"
        ))
        .unwrap()
    }

    fn source_hits(eng: &Engine, iid: u8) -> Vec<String> {
        eng.summaries.get(&hexid(&[iid; 32])).unwrap()
            .sink_hits
            .iter()
            .filter(|h| h.in_slot == Slot::Source)
            .map(|h| h.class.clone())
            .collect()
    }

    #[test]
    fn a_bind_source_seeds_the_bound_variable_not_the_error() {
        let prog = prog_of(bind_handler());
        // today's rule shape: the result (err) is the source, req is not
        let old = cat_with("");
        let mut eng = Engine::new(&prog, &old);
        eng.run();
        assert!(source_hits(&eng, 0x61).is_empty(), "with to = return only err is tainted");

        let new = cat_with("to = \"1\"");
        let f = &prog.funcs[&hexid(&[0x61; 32])];
        let ctx = FnCtx::build(f, &new);
        assert_eq!(ctx.source_seeds, vec![3], "the seed is the &req arg port, nothing else");
        let mut eng = Engine::new(&prog, &new);
        eng.run();
        assert_eq!(source_hits(&eng, 0x61), vec!["sqli".to_string()]);
        // The seed leaves along the write-back only: it is not an input to the
        // bind call, so the default leaf never taints the bind's `err`.
        let r = eng.propagate(f, &ctx, &ctx.source_seeds);
        assert!(r.tainted.contains(&5), "req's use is tainted");
        assert!(!r.tainted.contains(&4), "err (result port 0 of the bind) must stay clean");
        // ... while the same port reached by ordinary taint is an input as
        // before: from the receiver `c`, the default leaf taints err.
        let r = eng.propagate(f, &ctx, &[1]);
        assert!(r.tainted.contains(&4));
    }

    /// Review finding: `err := c.ShouldBindJSON(&req); db.Exec(err)` — no use
    /// of req at all — reported a Source chain through the bind's `err`.
    #[test]
    fn a_bind_source_never_reaches_a_sink_through_the_error() {
        let f = func(
            0x63,
            "app.CreateErr",
            cgf::LocalFlow {
                vertices: vec![
                    vertex(1, cgf::VertexKind::InParam, 0, 0),
                    vertex(2, cgf::VertexKind::CallArgPort, 0, 0),
                    vertex(3, cgf::VertexKind::CallArgPort, 1, 0),
                    vertex(4, cgf::VertexKind::CallResultPort, 0, 0),
                    vertex(5, cgf::VertexKind::CallArgPort, 0, 1),
                ],
                edges: vec![edge(1, 2), edge(4, 5)],
                callsites: vec![call(0, GIN_BIND, 2, 1, true), call(1, "db.Exec", 1, 0, false)],
            },
        );
        let prog = prog_of(f);
        let cat = cat_with("to = \"1\"");
        let mut eng = Engine::new(&prog, &cat);
        eng.run();
        assert!(source_hits(&eng, 0x63).is_empty(), "no Source hit through err");
        // c itself (Param(0)) still reaches err through the default leaf
        let hits: Vec<SlotP> = eng.summaries.get(&hexid(&[0x63; 32])).unwrap().sink_hits.iter().map(|h| h.in_slot.clone()).collect();
        assert_eq!(hits, vec![SlotP::from(Slot::Param(0))]);
    }

    #[test]
    fn a_bind_chain_has_a_complete_route_and_is_confirmed_backward() {
        let prog = prog_of(bind_handler());
        let cat = cat_with("to = \"1\"");
        let mut eng = Engine::new(&prog, &cat);
        eng.run();
        let mut chains = crate::report::intra_chains(&eng, None, false);
        assert_eq!(chains.len(), 1, "one sqli chain");
        let route = chains[0].route.as_ref().unwrap();
        assert_eq!(route.incomplete, None);
        let shape: Vec<(crate::witness::HopKind, &str)> =
            route.hops.iter().map(|h| (h.kind, h.callee.as_str())).collect();
        use crate::witness::HopKind::*;
        assert_eq!(shape, vec![(Source, ""), (Call, GIN_BIND), (Sink, "db.Exec")]);
        let st = crate::report::backward_check(&eng, &mut chains, crate::backward::BackOpts::default());
        assert_eq!(st.confirmed, 1, "the demand must land on the arg-port seed: {:?}", chains[0].backward);
    }

    /// ```go
    /// func Q(ctx context.Context, q string) { db.QueryContext(ctx, q) }   // source_params = [0, 1]
    /// ```
    /// `ctx_only` drops the `q` edge: the shape that made every ctx-taking sink
    /// a finding once a whole request object was seeded (E3).
    fn query_fn(ctx_only: bool) -> cgf::Function {
        let typed = |mut v: cgf::FlowVertex, t: &str| {
            v.r#type = t.into();
            v
        };
        let mut edges = vec![edge(1, 4)];
        if !ctx_only {
            edges.push(edge(2, 5));
        }
        let mut f = func(
            0x62,
            "app.Q",
            cgf::LocalFlow {
                vertices: vec![
                    typed(vertex(1, cgf::VertexKind::InParam, 0, 0), "context.Context"),
                    typed(vertex(2, cgf::VertexKind::InParam, 1, 0), "string"),
                    typed(vertex(3, cgf::VertexKind::CallArgPort, 0, 0), "*database/sql.DB"),
                    typed(vertex(4, cgf::VertexKind::CallArgPort, 1, 0), "context.Context"),
                    typed(vertex(5, cgf::VertexKind::CallArgPort, 2, 0), "string"),
                ],
                edges,
                callsites: vec![call(0, QUERY, 3, 2, true)],
            },
        );
        f.source_params = vec![0, 1];
        f
    }

    fn query_cat(ignore: bool) -> Catalog {
        Catalog::load_str(&format!(
            "{}[[sinks]]\nclass = \"sqli\"\nselector = \"{QUERY}\"\narg = \"args\"\n",
            if ignore { "sink_ignore_arg_types = [\"context.Context\"]\n" } else { "" }
        ))
        .unwrap()
    }

    #[test]
    fn a_tainted_context_alone_is_not_a_sql_finding() {
        let prog = prog_of(query_fn(true));
        let cat = query_cat(false);
        let mut eng = Engine::new(&prog, &cat);
        eng.run();
        assert_eq!(source_hits(&eng, 0x62), vec!["sqli".to_string()], "absent = today: ctx fires");

        let cat = query_cat(true);
        let mut eng = Engine::new(&prog, &cat);
        eng.run();
        assert!(source_hits(&eng, 0x62).is_empty(), "context.Context ports never fire");
    }

    #[test]
    fn an_ignored_port_does_not_change_the_route_or_the_verdict_of_a_real_one() {
        let prog = prog_of(query_fn(false));
        let cat = query_cat(true);
        let mut eng = Engine::new(&prog, &cat);
        eng.run();
        let mut chains = crate::report::intra_chains(&eng, None, false);
        assert_eq!(chains.len(), 1);
        let route = chains[0].route.as_ref().unwrap();
        assert_eq!(route.incomplete, None, "the witness fires on the same port propagate did");
        let st = crate::report::backward_check(&eng, &mut chains, crate::backward::BackOpts::default());
        assert_eq!(st.confirmed, 1, "{:?}", chains[0].backward);
        assert_eq!(chains[0].backward.as_ref().unwrap().terminal, Some(crate::backward::Verdict::Confirmed));
    }

    /// ```go
    /// // a canonicalized pb getter is a field projection plus a ZERO-ARG
    /// // shell call (the frontend keeps the callee identity and one result
    /// // port, no arg ports):
    /// func Save(r *pb.Request) {   // no source_params
    ///     db.Exec(r.GetId())       // shell call + projection: the route
    ///     db.Exec(r.Note)          // plain read: projection only, no call
    /// }
    /// ```
    /// The catalog's getter [[sources]] rule fires on the shell's result port
    /// — the same CallResultPort seeding any call gets — and nothing seeds a
    /// plain field read, which carries no call site to match.
    fn getter_handler() -> cgf::Function {
        let mut whole = vertex(1, cgf::VertexKind::InParam, 0, 0);
        whole.r#type = "*example.com/api/pb.Request".into();
        let mut id = vertex(2, cgf::VertexKind::InParam, 0, 0);
        id.r#type = "*example.com/api/pb.Request".into();
        id.field_path = vec![1];
        id.field_names = vec!["Id".into()];
        let mut note = vertex(3, cgf::VertexKind::InParam, 0, 0);
        note.r#type = "*example.com/api/pb.Request".into();
        note.field_path = vec![2];
        note.field_names = vec!["Note".into()];
        let mut shell = vertex(4, cgf::VertexKind::CallResultPort, 0, 0);
        shell.r#type = "string".into();
        let mut port = vertex(5, cgf::VertexKind::CallArgPort, 0, 1);
        port.r#type = "string".into();
        let mut port2 = vertex(6, cgf::VertexKind::CallArgPort, 0, 2);
        port2.r#type = "string".into();
        let mut cs0 = call(0, "(*example.com/api/pb.Request).GetId", 0, 1, false);
        cs0.arg0_is_receiver = false;
        func(
            0x64,
            "app.Save",
            cgf::LocalFlow {
                vertices: vec![whole, id, note, shell, port, port2],
                edges: vec![edge(4, 5), edge(3, 6)],
                callsites: vec![
                    cs0,
                    call(1, "db.Exec", 1, 0, false),
                    call(2, "db.Exec", 1, 0, false),
                ],
            },
        )
    }

    fn getter_cat(rule: bool) -> Catalog {
        let src = if rule {
            "[[sources]]\nkind = \"grpc_request\"\nselector_regex = 'Request\\)\\.Get[A-Za-z0-9_]+$'\n"
        } else {
            ""
        };
        Catalog::load_str(&format!(
            "{src}[[sinks]]\nclass = \"sqli\"\nselector = \"db.Exec\"\n"
        ))
        .unwrap()
    }

    #[test]
    fn a_canonicalized_getter_shell_call_still_matches_its_catalog_source_rule() {
        let prog = prog_of(getter_handler());
        // no rule: nothing seeds, no finding
        let ctx = FnCtx::build(&prog.funcs[&hexid(&[0x64; 32])], &getter_cat(false));
        assert!(ctx.source_seeds.is_empty());

        let cat = getter_cat(true);
        let f = &prog.funcs[&hexid(&[0x64; 32])];
        let ctx = FnCtx::build(f, &cat);
        assert_eq!(
            ctx.source_seeds,
            vec![4],
            "the shell's result port seeds; the param and the plain read do not"
        );
        let mut eng = Engine::new(&prog, &cat);
        eng.run();
        assert_eq!(source_hits(&eng, 0x64), vec!["sqli".to_string()]);
        // the Source-keyed hit sits on the Id sink (callsite 1); the Note
        // read (callsite 2) fires only as a caller-facing Param(0) summary
        // row — no source ever taints a plain field read
        let src_cs: Vec<usize> = eng.summaries.get(&hexid(&[0x64; 32])).unwrap()
            .sink_hits
            .iter()
            .filter(|h| h.in_slot == Slot::Source)
            .map(|h| h.callsite)
            .collect();
        assert_eq!(src_cs, vec![1]);
    }
}

/// Fuzz: the parallel scheduler must produce EXACTLY the sequential order's
/// summaries, for any call-graph shape. The generator emits every edge class
/// the engine can see: static calls (incl. self and 2-cycles), VTA fan-out
/// (one site, several callee_iids), dangling targets (iid not in the program),
/// InvokesRemote sites (default leaf), catalog sinks, bodyless fns, empty bids
/// (never cacheable) and isolated fns. Every program runs through the parallel
/// `run_with_store` under the PC_SCHED_SHUFFLE stress (shuffled ready-scan +
/// randomized per-SCC delays) and is then recomputed strictly sequentially in
/// SCC order; `debug_verify_sequential` must report zero differences.
#[cfg(test)]
mod sched_fuzz_tests {
    use super::*;
    use crate::graph::Program;
    use std::collections::HashMap;
    use super::cache_tests::{edge, vertex};

    const CAT: &str = r#"
[[sinks]]
class = "sqli"
selector = "db.Exec"
arg = "any"
"#;

    struct Rng(u64);
    impl Rng {
        fn next(&mut self) -> u64 {
            // xorshift64*
            let mut x = self.0;
            x ^= x >> 12;
            x ^= x << 25;
            x ^= x >> 27;
            self.0 = x;
            x.wrapping_mul(0x2545F4914F6CDD1D)
        }
        fn below(&mut self, n: u64) -> u64 {
            if n == 0 { 0 } else { self.next() % n }
        }
    }

    fn iid_of(n: usize, salt: u8) -> Vec<u8> {
        let mut v = vec![salt; 32];
        v[0] = (n & 0xFF) as u8;
        v[1] = ((n >> 8) & 0xFF) as u8;
        v[2] = ((n >> 16) & 0xFF) as u8;
        v[3] = ((n >> 24) & 0xFF) as u8;
        v
    }

    fn fuzz_program(seed: u64) -> Program {
        let mut r = Rng(seed | 1);
        let n = 4 + r.below(120) as usize; // 4..=123 fns: deep chains and big cycles
        let mut prog = Program {
            funcs: HashMap::new(),
            repo_of: HashMap::new(),
            packages: Vec::new(),
        };
        for i in 0..n {
            let bid = if r.below(100) < 15 {
                Vec::new() // not cacheable: key_of -> None
            } else {
                vec![1 + (r.below(250) as u8); 32]
            };
            let mut vertices = Vec::new();
            let mut edges = Vec::new();
            let mut callsites = Vec::new();
            let has_flow = r.below(100) < 90;
            if has_flow {
                // params p0 (always) and p1 (sometimes) flowing out and into calls
                let nparams = 1 + r.below(2) as u32;
                for p in 0..nparams {
                    vertices.push(vertex(10 + p, cgf::VertexKind::InParam, p, 0));
                }
                vertices.push(vertex(20, cgf::VertexKind::OutReturn, 0, 0));
                let ncalls = r.below(4) as u32; // 0..3 callsites
                let mut next_v = 30u32;
                for c in 0..ncalls {
                    let cs_id = c;
                    let class = r.below(100);
                    let mut cs = cgf::CallSite {
                        id: cs_id,
                        callee_fqn: format!("pkg.f{}/call{}", i, c),
                        argc: 1,
                        resultc: 0,
                        ..Default::default()
                    };
                    // arg port wired from a random param
                    let arg_v = next_v;
                    vertices.push(vertex(arg_v, cgf::VertexKind::CallArgPort, 0, cs_id));
                    next_v += 1;
                    let src = 10 + r.below(nparams as u64) as u32;
                    edges.push(edge(src, arg_v));
                    if class < 35 {
                        // static call to a random fn, maybe itself (cycle)
                        let tgt = r.below(n as u64) as usize;
                        cs.callee_iids = vec![iid_of(tgt, 0xAA)];
                        cs.kind = cgf::call_site::Kind::Static as i32;
                        cs.resultc = 1;
                        let res_v = next_v;
                        vertices.push(vertex(res_v, cgf::VertexKind::CallResultPort, 0, cs_id));
                        next_v += 1;
                        edges.push(edge(res_v, 20));
                    } else if class < 50 {
                        // VTA fan-out: 1-3 targets from one site
                        let k = 1 + r.below(3) as usize;
                        let mut tgts = Vec::new();
                        for _ in 0..k {
                            let tgt = r.below(n as u64) as usize;
                            tgts.push(iid_of(tgt, 0xAA));
                        }
                        cs.callee_iids = tgts;
                        cs.kind = cgf::call_site::Kind::Virtual as i32;
                        cs.resultc = 1;
                        let res_v = next_v;
                        vertices.push(vertex(res_v, cgf::VertexKind::CallResultPort, 0, cs_id));
                        next_v += 1;
                        edges.push(edge(res_v, 20));
                    } else if class < 62 {
                        // dangling target: an iid no function owns
                        cs.callee_iids = vec![iid_of(999, 0xEE)];
                        cs.resultc = 1;
                        let res_v = next_v;
                        vertices.push(vertex(res_v, cgf::VertexKind::CallResultPort, 0, cs_id));
                        next_v += 1;
                        edges.push(edge(res_v, 20));
                    } else if class < 78 {
                        // remote/contract site: default leaf in phase 1
                        cs.kind = cgf::call_site::Kind::InvokesRemote as i32;
                        cs.callee_fqn = "rpc.Do".into();
                        cs.resultc = 1;
                        let res_v = next_v;
                        vertices.push(vertex(res_v, cgf::VertexKind::CallResultPort, 0, cs_id));
                        next_v += 1;
                        edges.push(edge(res_v, 20));
                    } else {
                        // catalog sink: db.Exec(arg)
                        cs.callee_fqn = "db.Exec".into();
                        cs.callee_iids = Vec::new();
                    }
                    callsites.push(cs);
                }
                // sometimes flow a param straight to the return
                if r.below(100) < 40 {
                    edges.push(edge(10, 20));
                }
            }
            let f = cgf::Function {
                id: Some(cgf::Ident { iid: iid_of(i, 0xAA), bid }),
                fqn: format!("pkg.f{i}"),
                has_body: r.below(100) < 90, // 10% bodyless stubs still in funcs
                flow: has_flow.then(|| cgf::LocalFlow { vertices, edges, callsites }),
                ..Default::default()
            };
            let h = hexid(&f.id.as_ref().unwrap().iid);
            prog.repo_of.insert(h.clone(), "test".into());
            prog.funcs.insert(h, f);
        }
        prog
    }

    #[test]
    fn fuzz_parallel_summaries_match_sequential() {
        let cat = Catalog::load_str(CAT).unwrap();
        // Stress the scheduler: shuffled ready-scan + randomized worker delays.
        // (Only affects spawn order; the sequential verification ignores it.)
        std::env::set_var("PC_SCHED_SHUFFLE", "1");
        for seed in 1..=2000u64 {
            let prog = fuzz_program(seed);
            let mut eng = Engine::new(&prog, &cat);
            let mut store = SummaryStore::ephemeral();
            eng.run_with_store(&mut store);
            let bad = eng.debug_verify_sequential();
            assert!(
                bad.is_empty(),
                "seed {seed}: {} summary(ies) differ from the sequential run: {:?}",
                bad.len(),
                &bad[..bad.len().min(8)]
            );
        }
        std::env::remove_var("PC_SCHED_SHUFFLE");
    }

    /// The scan-vs-release race has the widest window on a SMALL pool: the
    /// scope thread walks the ready list while 1-2 workers tabulate and
    /// release. Every seed runs on a dedicated 2-thread pool, then on a
    /// 4-thread pool, each time against the sequential recompute.
    #[test]
    fn fuzz_parallel_small_pools_match_sequential() {
        let cat = Catalog::load_str(CAT).unwrap();
        std::env::set_var("PC_SCHED_SHUFFLE", "1");
        for pool_threads in [2usize, 4] {
            let pool = rayon::ThreadPoolBuilder::new()
                .num_threads(pool_threads)
                .build()
                .unwrap();
            for seed in 1..=600u64 {
                let prog = fuzz_program(seed * 7919 + pool_threads as u64);
                let mut eng = Engine::new(&prog, &cat);
                let mut store = SummaryStore::ephemeral();
                pool.install(|| eng.run_with_store(&mut store));
                let bad = eng.debug_verify_sequential();
                assert!(
                    bad.is_empty(),
                    "pool={pool_threads} seed {seed}: {} differ: {:?}",
                    bad.len(),
                    &bad[..bad.len().min(8)]
                );
            }
        }
        std::env::remove_var("PC_SCHED_SHUFFLE");
    }
}

/// Prod-scale stress: 1.74M functions overflow the 1M-entry store LRU, so the
/// phase runs with a CHURNING cache — evictions, FS blob re-reads and lazy
/// moka housekeeping all mid-flight — and with dependency chains thousands of
/// SCCs deep. Small-graph fuzz cannot reach that state. This fixture builds
/// the production layering (Go resolvers with the sink, GraphQL contracts,
/// TS gateway wrappers whose remote sites name the contract fns as callee_iids,
/// $op fns calling the wrappers, VTA fan-out, self-recursion, cycles, bodyless
/// stubs, empty bids) at 100k+ functions, runs the parallel tabulation against
/// a FS store whose LRU is deliberately tiny (constant eviction pressure), and
/// requires the sequential recompute to agree exactly.
#[cfg(test)]
mod prod_scale_tests {
    use super::*;
    use crate::graph::Program;
    use std::collections::HashMap;

    const CAT: &str = r#"
[[sinks]]
class = "sqli"
selector = "db.Exec"
arg = "any"
"#;

    fn iid_bytes(n: usize, salt: u8) -> Vec<u8> {
        let mut v = vec![salt; 32];
        v[0] = (n & 0xFF) as u8;
        v[1] = ((n >> 8) & 0xFF) as u8;
        v[2] = ((n >> 16) & 0xFF) as u8;
        v[3] = ((n >> 24) & 0xFF) as u8;
        v[4] = ((n >> 32) & 0xFF) as u8;
        v
    }

    fn vertex(id: u32, kind: cgf::VertexKind, index: u32, cs: u32) -> cgf::FlowVertex {
        cgf::FlowVertex { id, kind: kind as i32, index, callsite_id: cs, ..Default::default() }
    }

    fn edge(from: u32, to: u32) -> cgf::FlowEdge {
        cgf::FlowEdge { from, to, via_alias: false }
    }

    pub(super) fn prod_program(layers: usize) -> Program {
        // For i in 0..layers*4 four roles cycle:
        //   i%4==0 resolver  : db.Exec(p0) sink, may self-recurse
        //   i%4==1 contract  : flows p0->ret, named as callee by wrappers
        //   i%4==2 wrapper   : remote site -> contract i-1 (callee_iids set!),
        //                      plus a VTA site over 2-3 resolvers
        //   i%4==3 $op       : static call to wrapper i-1 (and a cycle)
        let n = layers * 4;
        let mut prog = Program { funcs: HashMap::new(), repo_of: HashMap::new(), packages: Vec::new() };
        for i in 0..n {
            let mut callsites = Vec::new();
            let mut vertices = vec![
                vertex(1, cgf::VertexKind::InParam, 0, 0),
                vertex(2, cgf::VertexKind::OutReturn, 0, 0),
            ];
            let mut edges = vec![edge(1, 2)];
            match i % 4 {
                0 => {
                    // resolver: sink on p0; every 16th also self-recursive
                    callsites.push(cgf::CallSite {
                        id: 0,
                        callee_fqn: "db.Exec".into(),
                        argc: 1,
                        ..Default::default()
                    });
                    vertices.push(vertex(3, cgf::VertexKind::CallArgPort, 0, 0));
                    edges.push(edge(1, 3));
                    if i % 16 == 0 {
                        callsites.push(cgf::CallSite {
                            id: 1,
                            callee_iids: vec![iid_bytes(i, 0xA1)],
                            callee_fqn: format!("go.resolve{i}"),
                            argc: 1,
                            resultc: 1,
                            ..Default::default()
                        });
                        vertices.push(vertex(9, cgf::VertexKind::CallResultPort, 0, 1));
                        edges.push(edge(9, 2));
                    }
                }
                1 => {
                    // contract: passes p0 through
                    vertices.push(vertex(3, cgf::VertexKind::OutReturn, 0, 0));
                    edges.push(edge(1, 3));
                }
                2 => {
                    // wrapper: InvokesRemote site whose callee_iids NAME the
                    // contract fn (as httplink/contract linking leaves it),
                    // plus a VTA site over the resolvers i-3, i-5, i-9.
                    callsites.push(cgf::CallSite {
                        id: 0,
                        kind: cgf::call_site::Kind::InvokesRemote as i32,
                        callee_iids: vec![iid_bytes(i - 1, 0xA1)],
                        callee_fqn: format!("gw.query{i}"),
                        argc: 1,
                        resultc: 1,
                        ..Default::default()
                    });
                    vertices.push(vertex(3, cgf::VertexKind::CallArgPort, 0, 0));
                    vertices.push(vertex(4, cgf::VertexKind::CallResultPort, 0, 0));
                    edges.push(edge(1, 3));
                    edges.push(edge(4, 2));
                    let mut tgts = Vec::new();
                    for k in [5usize, 9, 13] {
                        if i > k {
                            tgts.push(iid_bytes(i - k, 0xA1));
                        }
                    }
                    callsites.push(cgf::CallSite {
                        id: 1,
                        kind: cgf::call_site::Kind::Virtual as i32,
                        callee_iids: tgts,
                        callee_fqn: format!("gw.exec{i}"),
                        argc: 1,
                        resultc: 1,
                        ..Default::default()
                    });
                    vertices.push(vertex(5, cgf::VertexKind::CallArgPort, 0, 1));
                    vertices.push(vertex(6, cgf::VertexKind::CallResultPort, 0, 1));
                    edges.push(edge(1, 5));
                    edges.push(edge(6, 2));
                }
                _ => {
                    // $op: static call to the wrapper, result to return
                    let tgt = if i >= 1 { i - 1 } else { n - 1 };
                    callsites.push(cgf::CallSite {
                        id: 0,
                        callee_iids: vec![iid_bytes(tgt, 0xA1)],
                        callee_fqn: format!("ts.op{i}"),
                        argc: 1,
                        resultc: 1,
                        ..Default::default()
                    });
                    vertices.push(vertex(3, cgf::VertexKind::CallArgPort, 0, 0));
                    vertices.push(vertex(4, cgf::VertexKind::CallResultPort, 0, 0));
                    edges.push(edge(1, 3));
                    edges.push(edge(4, 2));
                }
            }
            let bid = if i % 97 == 0 { Vec::new() } else { vec![1u8; 32] };
            let f = cgf::Function {
                id: Some(cgf::Ident { iid: iid_bytes(i, 0xA1), bid }),
                fqn: format!("pkg.f{i}"),
                has_body: i % 211 != 0, // some bodyless stubs stay in funcs
                flow: Some(cgf::LocalFlow { vertices, edges, callsites }),
                ..Default::default()
            };
            let h = hexid(&f.id.as_ref().unwrap().iid);
            prog.repo_of.insert(h.clone(), "r".into());
            prog.funcs.insert(h, f);
        }
        prog
    }

    #[test]
    fn prod_shape_parallel_matches_sequential_under_lru_churn() {
        let cat = Catalog::load_str(CAT).unwrap();
        let prog = prod_program(30_000); // 120k functions
        let dir = std::env::temp_dir().join(format!("pc-prodshape-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::env::set_var("PC_SCHED_SHUFFLE", "1");
        {
            // LRU of 64 against ~120k cacheable fns: permanent eviction churn,
            // every later cache probe falls back to the FS blob mid-run.
            let mut store = SummaryStore::open(Some(&dir), &[0u8; 32], 64).unwrap();
            let mut eng = Engine::new(&prog, &cat);
            eng.run_with_store(&mut store);
            let bad = eng.debug_verify_sequential();
            assert!(
                bad.is_empty(),
                "{} summary(ies) differ from the sequential run: {:?}",
                bad.len(),
                &bad[..bad.len().min(8)]
            );
            store.free_lru();
        }
        std::env::remove_var("PC_SCHED_SHUFFLE");
        std::fs::remove_dir_all(&dir).unwrap();
    }
}

/// Reproduction of the production correctness incident (t8 subset summaries).
///
/// The scheduler that shipped to prod tabulated an SCC from TWO sites — the
/// initial ready-scan and a callee's release path — both gated only on the
/// readiness counter, with no atomic claim:
///
/// ```text
/// for i in 0..n { if deps[i].load(SeqCst) == 0 { spawn_scc(.., i); } }   // scan
/// if deps[d].fetch_sub(1, SeqCst) == 1 { spawn_scc(.., d); }             // release
/// ```
///
/// When a release brings `deps[d]` to 0 while the scan has not reached `d`
/// yet (guaranteed on a 1.7M-function program, where the scan walks for
/// seconds while early callees finish), BOTH sites spawn `d`. The SCC is then
/// tabulated twice concurrently, and EACH copy runs the release loop, so
/// every dependent's counter is decremented twice:
///
/// * a dependent of `d` is released while the second fixpoint is still
///   mid-round — it composes the PARTIAL summaries it finds (subset: flows
///   empty / fewer sink_hits), and
/// * a dependent with two callees is released after only ONE of them
///   completed (the counter hits 0 on the duplicate decrement).
///
/// The stale round's insert can also land after the final one, leaving a
/// non-fixpoint summary in the map. Either way the t8 summary is a strict
/// subset of the sequential one — the production signature.
///
/// This fixture replays that exact pre-fix schedule deterministically (the
/// scan sleeps past the first callee's completion before it reaches the
/// released SCC) and asserts the divergence appears. The current scheduler
/// (claim_scc at both spawn sites) makes the double spawn impossible, which
/// is why this test is `#[ignore]`d: it documents the incident, it must NOT
/// run in CI against the fixed code. Run with `cargo test -- --ignored`.
#[cfg(test)]
mod sched_race_repro {
    use super::*;
    use crate::graph::Program;
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicUsize, Ordering};

    const CAT: &str = r#"
[[sinks]]
class = "sqli"
selector = "db.Exec"
arg = "any"
"#;

    fn vid(n: u8) -> Vec<u8> {
        vec![n; 32]
    }

    fn vertex(id: u32, kind: cgf::VertexKind, index: u32, cs: u32) -> cgf::FlowVertex {
        cgf::FlowVertex { id, kind: kind as i32, index, callsite_id: cs, ..Default::default() }
    }

    fn edge(from: u32, to: u32) -> cgf::FlowEdge {
        cgf::FlowEdge { from, to, via_alias: false }
    }

    /// The orchestrated shape, four functions, SCC order [X, A, B, D2]:
    ///
    /// * X  — `db.Exec(p0)`: a sink leaf, tabulates instantly.
    /// * A  — calls X (so deps[A] = 1). Its release path and the ready-scan
    ///        BOTH spawn it (the double spawn), so its dependent counter is
    ///        decremented TWICE.
    /// * B  — `db.Exec(p0)` plus a `p0 -> ret` flow: its summary is what D2
    ///        misses when the race fires (D2 spawns on the duplicate release,
    ///        before the scan has even reached B).
    /// * D2 — calls A and B (deps[D2] = 2). The DUPLICATE release from A's
    ///        second copy takes deps[D2] 1 -> 0 and spawns it while B has no
    ///        summary: D2 takes the default leaf at B's site and never sees
    ///        B's sink hit — its summary is a strict subset of the sequential
    ///        one, exactly the production signature. (B's later release then
    ///        wraps the counter below zero, which the pre-fix code never
    ///        checks.)
    fn race_program() -> Program {
        let mut prog = Program { funcs: HashMap::new(), repo_of: HashMap::new(), packages: Vec::new() };
        let x = cgf::Function {
            id: Some(cgf::Ident { iid: vid(0x01), bid: vec![1u8; 32] }),
            fqn: "pkg.X".into(),
            has_body: true,
            flow: Some(cgf::LocalFlow {
                vertices: vec![
                    vertex(1, cgf::VertexKind::InParam, 0, 0),
                    vertex(2, cgf::VertexKind::CallArgPort, 0, 0),
                ],
                edges: vec![edge(1, 2)],
                callsites: vec![cgf::CallSite {
                    id: 0,
                    callee_fqn: "db.Exec".into(),
                    argc: 1,
                    ..Default::default()
                }],
            }),
            ..Default::default()
        };
        let a = cgf::Function {
            id: Some(cgf::Ident { iid: vid(0x02), bid: vec![1u8; 32] }),
            fqn: "pkg.A".into(),
            has_body: true,
            flow: Some(cgf::LocalFlow {
                vertices: vec![
                    vertex(1, cgf::VertexKind::InParam, 0, 0),
                    vertex(2, cgf::VertexKind::CallArgPort, 0, 0),
                ],
                edges: vec![edge(1, 2)],
                callsites: vec![cgf::CallSite {
                    id: 0,
                    callee_iids: vec![vid(0x01)],
                    callee_fqn: "pkg.X".into(),
                    argc: 1,
                    ..Default::default()
                }],
            }),
            ..Default::default()
        };
        // B: InParam -> db.Exec arg port (a sink hit in B's own summary) and
        // InParam -> OutReturn (a flow D2 composes). B stays tiny: the race
        // does not need a slow B — it needs D2 to spawn on the DUPLICATE
        // release from A's second copy, which lands before the scan has even
        // reached B. (A 150k-vertex chain would hang the tabulation itself:
        // summarize runs propagate once per in_slot, so a function with k
        // InGlobal vertices costs O(k * V) — quadratic in k. That is an
        // engine cost property, not part of this reproduction.)
        let b = cgf::Function {
            id: Some(cgf::Ident { iid: vid(0x03), bid: vec![1u8; 32] }),
            fqn: "pkg.B".into(),
            has_body: true,
            flow: Some(cgf::LocalFlow {
                vertices: vec![
                    vertex(1, cgf::VertexKind::InParam, 0, 0),
                    vertex(2, cgf::VertexKind::CallArgPort, 0, 0),
                    vertex(3, cgf::VertexKind::OutReturn, 0, 0),
                ],
                edges: vec![edge(1, 2), edge(1, 3)],
                callsites: vec![cgf::CallSite {
                    id: 0,
                    callee_fqn: "db.Exec".into(),
                    argc: 1,
                    ..Default::default()
                }],
            }),
            ..Default::default()
        };
        let d2 = cgf::Function {
            id: Some(cgf::Ident { iid: vid(0x04), bid: vec![1u8; 32] }),
            fqn: "pkg.D2".into(),
            has_body: true,
            flow: Some(cgf::LocalFlow {
                vertices: vec![
                    vertex(1, cgf::VertexKind::InParam, 0, 0),
                    vertex(2, cgf::VertexKind::CallArgPort, 0, 0),
                    vertex(3, cgf::VertexKind::CallResultPort, 0, 0),
                    vertex(4, cgf::VertexKind::CallArgPort, 0, 1),
                    vertex(5, cgf::VertexKind::CallResultPort, 0, 1),
                    vertex(6, cgf::VertexKind::OutReturn, 0, 0),
                ],
                edges: vec![edge(1, 2), edge(3, 6), edge(1, 4), edge(5, 6)],
                callsites: vec![
                    cgf::CallSite {
                        id: 0,
                        callee_iids: vec![vid(0x02)],
                        callee_fqn: "pkg.A".into(),
                        argc: 1,
                        resultc: 1,
                        ..Default::default()
                    },
                    cgf::CallSite {
                        id: 1,
                        callee_iids: vec![vid(0x03)],
                        callee_fqn: "pkg.B".into(),
                        argc: 1,
                        resultc: 1,
                        ..Default::default()
                    },
                ],
            }),
            ..Default::default()
        };
        for f in [x, a, b, d2] {
            let h = hexid(&f.id.as_ref().unwrap().iid);
            prog.repo_of.insert(h.clone(), "r".into());
            prog.funcs.insert(h, f);
        }
        prog
    }

    /// The pre-fix scheduler, verbatim in shape: ready-scan and release path
    /// both spawn on the counter alone, no claim.
    fn run_prefix_scheduler(eng: &Engine<'_>, store: &SummaryStore) {
        let sccs = eng.prog.scc_order();
        let n = sccs.len();
        let mut scc_of: HashMap<&IidHex, usize> = HashMap::new();
        for (i, scc) in sccs.iter().enumerate() {
            for iid in scc {
                scc_of.insert(iid, i);
            }
        }
        let mut dep_sets: Vec<std::collections::HashSet<usize>> = vec![Default::default(); n];
        for (i, scc) in sccs.iter().enumerate() {
            for iid in scc {
                if let Some(f) = eng.prog.funcs.get(iid) {
                    for c in eng.prog.callees(f) {
                        if let Some(&j) = scc_of.get(&c) {
                            if j != i {
                                dep_sets[i].insert(j);
                            }
                        }
                    }
                }
            }
        }
        let deps: Vec<AtomicUsize> = dep_sets.iter().map(|s| AtomicUsize::new(s.len())).collect();
        let mut dependents: Vec<Vec<usize>> = vec![Vec::new(); n];
        for (i, ds) in dep_sets.iter().enumerate() {
            for &j in ds {
                dependents[j].push(i);
            }
        }
        let out = TabOut::default();
        fn spawn_pre<'a>(
            scope: &rayon::Scope<'a>,
            eng: &'a Engine<'a>,
            store: &'a SummaryStore,
            sccs: &'a [Vec<IidHex>],
            deps: &'a [AtomicUsize],
            dependents: &'a [Vec<usize>],
            out: &'a TabOut,
            i: usize,
        ) {
            scope.spawn(move |s| {
                eng.tabulate_scc(&sccs[i], store, out);
                for &d in &dependents[i] {
                    if deps[d].fetch_sub(1, Ordering::SeqCst) == 1 {
                        spawn_pre(s, eng, store, sccs, deps, dependents, out, d);
                    }
                }
            });
        }
        rayon::scope(|scope| {
            for i in 0..n {
                // Hold the scan back so the first callee's release lands
                // before the scan reaches the released SCC — the window the
                // 1.74M-function production run fell into (its scan walked
                // for seconds while early callees finished in milliseconds).
                std::thread::sleep(std::time::Duration::from_millis(2));
                if deps[i].load(Ordering::SeqCst) == 0 {
                    spawn_pre(scope, eng, store, &sccs, &deps, &dependents, &out, i);
                }
            }
        });
    }

    #[test]
    #[ignore = "replays the pre-claim prod scheduler to demonstrate the subset-summary race; the shipped scheduler claims spawns, so this must not run in CI"]
    fn pre_fix_scheduler_loses_summaries() {
        let cat = Catalog::load_str(CAT).unwrap();
        let prog = race_program();
        let mut diverged = 0;
        for attempt in 0..5 {
            eprintln!("attempt {attempt}: start");
            let mut eng = Engine::new(&prog, &cat);
            let store = SummaryStore::ephemeral();
            run_prefix_scheduler(&eng, &store);
            eprintln!("attempt {attempt}: scheduled");
            let bad = eng.debug_verify_sequential();
            eprintln!("attempt {attempt}: verified, {} differ", bad.len());
            if !bad.is_empty() {
                diverged += 1;
                eprintln!("attempt {attempt}: {} subset/incomplete summaries, e.g. {:?}", bad.len(), &bad[..bad.len().min(4)]);
            }
        }
        assert!(
            diverged > 0,
            "the pre-claim schedule did not diverge in 5 attempts — the reproduction window moved"
        );
    }
}
