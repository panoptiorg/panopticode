// Cross-repo composition at invokes_remote sites (doc 04 §4). A gRPC method's
// summary IS its handler's summary — remapped into the CLIENT's slot frame
// (contract_view), so a caller's invokes_remote call site — whose callee_iids
// = [contract_iid] — resolves it via the same summary lookup the intra-repo
// tabulation already uses. No new algorithm.
use crate::graph::{hexid, IidHex};
use crate::ifds::{summary_changed, Engine, Slot, SlotP, Summary};
use crate::proto::cgf;
use std::collections::{HashMap, HashSet};

/// What kind of contract a published view belongs to — the shape decides how a
/// handler's slot frame maps onto the client's call frame.
#[derive(Clone, Debug, PartialEq)]
pub enum ContractShape {
    /// gRPC method: (client_streaming, server_streaming).
    Grpc(bool, bool),
    /// GraphQL field (doc 36 §3.2): the resolver InParam index carrying each
    /// SDL argument, in SDL order. `args[j]` is the client's arg port j.
    Graphql(Vec<u32>),
    /// HTTP route (coverage wave 1 §4.4): the handler InParam indices that
    /// carry request data. A linked client site has ONE arg port, into which
    /// every data-bearing argument of the real request call flows, so each of
    /// these params is that port.
    Http { request_params: Vec<u32> },
}

impl ContractShape {
    /// True when the published view leaves the handler's IN slots where they
    /// are, so a consumer may descend into the handler without undoing a remap.
    /// The backward pass (backward.rs) has no unview step and relies on this.
    pub fn is_identity(&self) -> bool {
        match self {
            ContractShape::Grpc(cs, ss) => !cs && !ss,
            ContractShape::Graphql(args) => {
                args.iter().enumerate().all(|(j, &p)| j as u32 == p)
            }
            // Never: the view drops returns and every non-request param, and
            // folds the request params onto one port.
            ContractShape::Http { .. } => false,
        }
    }

    pub fn view(&self, sum: &Summary) -> Summary {
        match self {
            ContractShape::Grpc(cs, ss) => contract_view(sum, *cs, *ss),
            ContractShape::Graphql(args) => contract_view_graphql(sum, args),
            ContractShape::Http { request_params } => contract_view_http(sum, request_params),
        }
    }
}

/// Remap an HTTP route HANDLER's summary into the frame of a linked client
/// site (coverage wave 1 §4.4).
///
/// The client site is synthetic: `argc 1, resultc 0`, no receiver, every
/// data-bearing argument of the real request call (URL, body) flowing into
/// arg port 0. So `Param(p) -> Param(0)` for every `p` in `request_params`,
/// and every other positional slot is dropped — `w http.ResponseWriter`, a
/// method receiver and by-ref writes are not client-addressable.
///
/// Every RETURN is dropped too: v1 is request-direction only. A response body
/// does not reach the client's variables, because the client site has no
/// result port to land it on, and the frontends do not model the response
/// side (docs/limitations.md). Non-positional slots (Source, Global, stream)
/// pass through, as for gRPC.
pub fn contract_view_http(sum: &Summary, request_params: &[u32]) -> Summary {
    let map_in = |s: &SlotP| -> Option<SlotP> {
        match &s.slot {
            Slot::Param(p) if request_params.contains(p) => {
                Some(SlotP { slot: Slot::Param(0), path: s.path.clone() })
            }
            Slot::Param(_) | Slot::Receiver | Slot::ByRefParam(_) | Slot::ByRefReceiver => None,
            _ => Some(s.clone()),
        }
    };
    let map_out = |s: &SlotP| -> Option<SlotP> {
        match &s.slot {
            Slot::Return(_) | Slot::ByRefParam(_) | Slot::ByRefReceiver | Slot::Field(_) => None,
            _ => Some(s.clone()),
        }
    };
    let mut out = Summary {
        confidence: sum.confidence,
        ..Default::default()
    };
    for (isl, osl) in &sum.flows {
        if let (Some(i), Some(o)) = (map_in(isl), map_out(osl)) {
            out.flows.insert((i, o));
        }
    }
    // Two request params with the same sink fold onto the same port: keep the
    // view a set, as `summarize` keeps every summary (ifds `dedup_sink_hits`).
    let mut seen = HashSet::new();
    for sh in &sum.sink_hits {
        if let Some(i) = map_in(&sh.in_slot) {
            let mut h = sh.clone();
            h.in_slot = i;
            if seen.insert(format!("{h:?}")) {
                out.sink_hits.push(h);
            }
        }
    }
    out
}

/// Remap a gqlgen RESOLVER summary into the frame a GraphQL client calls in.
///
/// A resolver is `(ctx, [obj,] a0, a1, …) (T, error)`; a client's operation
/// callsite is `arg0_is_receiver=false, argc = #args, resultc = 1`, so its arg
/// port j is `Param(j)` and its only result is `Return(0)`. The mapping is
/// therefore `Param(args[j]) -> Param(j)`, with every other positional slot
/// dropped: `ctx` and `obj` are not client-supplied (obj is the PARENT field's
/// output, already modeled on the server side), and `Return(1)` is the
/// resolver's error, which the client never sees as data.
pub fn contract_view_graphql(sum: &Summary, args: &[u32]) -> Summary {
    let map_in = |s: &SlotP| -> Option<SlotP> {
        match &s.slot {
            Slot::Param(p) => args.iter().position(|a| a == p).map(|j| SlotP {
                slot: Slot::Param(j as u32),
                path: s.path.clone(),
            }),
            // ctx/obj/receiver: not a client-addressable slot.
            Slot::Receiver | Slot::ByRefParam(_) | Slot::ByRefReceiver => None,
            _ => Some(s.clone()), // Source / Global / Stream*
        }
    };
    let map_out = |s: &SlotP| -> Option<SlotP> {
        match &s.slot {
            Slot::Return(0) => Some(s.clone()),
            Slot::Return(_) | Slot::ByRefParam(_) | Slot::ByRefReceiver => None,
            _ => Some(s.clone()),
        }
    };
    let mut out = Summary {
        confidence: sum.confidence,
        ..Default::default()
    };
    for (isl, osl) in &sum.flows {
        if let (Some(i), Some(o)) = (map_in(isl), map_out(osl)) {
            out.flows.insert((i, o));
        }
    }
    for sh in &sum.sink_hits {
        if let Some(i) = map_in(&sh.in_slot) {
            let mut h = sh.clone();
            h.in_slot = i;
            out.sink_hits.push(h);
        }
    }
    out
}

/// Remap a handler summary into the slot frame the CLIENT composes against.
///
/// Unary handler (ctx, req) aligns with client args [iface, ctx, req] as-is
/// (req = Param(1) on both sides) — identity. Streaming handlers do not:
///   server-stream (req, stream) error: req is Param(0) server-side but
///   Param(1) client-side; the stream param and the error return must not
///   leak into the client's frame.
/// Stream slots (StreamIn/StreamOut/Source) pass through untouched — they are
/// contract-level, not positional.
pub fn contract_view(sum: &Summary, client_streaming: bool, server_streaming: bool) -> Summary {
    if !client_streaming && !server_streaming {
        return sum.clone(); // unary: identity, current behavior
    }
    // server-stream keeps its req param (shifted); client-stream/bidi handlers
    // take only the stream object, which a client can never taint.
    // Contract remap touches base slots only; field paths ride through
    // unchanged (doc 20 §2.4).
    let map_in = |s: &SlotP| -> Option<SlotP> {
        match &s.slot {
            Slot::Param(0) if server_streaming && !client_streaming => {
                Some(SlotP { slot: Slot::Param(1), path: s.path.clone() })
            }
            Slot::Param(_) | Slot::Receiver => None,
            _ => Some(s.clone()), // StreamIn / Source / Global / ...
        }
    };
    // streaming handlers return only error — dropping Return avoids
    // index-mismatched taint on the client's (stream, err) results.
    let map_out = |s: &SlotP| -> Option<SlotP> {
        match &s.slot {
            Slot::Return(_) => None,
            _ => Some(s.clone()),
        }
    };
    let mut out = Summary {
        confidence: sum.confidence,
        ..Default::default()
    };
    for (isl, osl) in &sum.flows {
        if let (Some(i), Some(o)) = (map_in(isl), map_out(osl)) {
            out.flows.insert((i, o));
        }
    }
    for sh in &sum.sink_hits {
        if let Some(i) = map_in(&sh.in_slot) {
            let mut h = sh.clone();
            h.in_slot = i;
            out.sink_hits.push(h);
        }
    }
    out
}

/// Publish the CURRENT handler summary as `contract`'s view, replacing any
/// earlier publication (or_insert would freeze the iteration-0 view and kill
/// the fixpoint). Returns whether the stored view changed.
fn publish_view(
    engine: &mut Engine,
    contract: &IidHex,
    handler: &IidHex,
    shape: &ContractShape,
) -> bool {
    let Some(sum) = engine.summaries.get(handler) else {
        return false;
    };
    let view = shape.view(sum);
    match engine.summaries.get(contract) {
        Some(prev) if !summary_changed(prev, &view) => false,
        _ => {
            engine.summaries.insert(contract.clone(), view);
            true
        }
    }
}

/// Cross-repo composition to a fixpoint (doc 17). Must run AFTER
/// Engine::run_with_store (phase 1, cache-sound) and BEFORE report generation.
///
/// Iteration 0 publishes every contract's handler-summary view (the old
/// link_cross_repo). But any fn summarized before its remote callee's view
/// existed composed a default leaf (taint-transparent, no sink) — so chained
/// boundaries (A→B→C) and local intermediaries (source → helper → remote)
/// carry stale summaries. Each iteration re-summarizes the fns whose remote
/// callee views changed (resummarize also chases local callers within the
/// pass), then republishes the views of any changed handlers; new dirt is the
/// remote callers of contracts whose view actually changed.
///
/// Terminates: boolean lattice, monotone transfer (bigger callee summaries can
/// only grow summarize output). MAX_ITERS caps pathological contract cycles —
/// sound but possibly incomplete; a warning is printed.
///
/// Returns the number of contracts linked (same count as the old
/// link_cross_repo, for the CLI stderr lines).
pub fn fixpoint(engine: &mut Engine) -> usize {
    fixpoint_with_leaves(engine, HashMap::new()).linked
}

pub struct FixpointStats {
    /// local contracts whose handler summary was published
    pub linked: usize,
    /// PG-loaded views injected for contracts with no local handler
    pub remote_leaves: usize,
}

/// `fixpoint`, plus externally-loaded contract views (PG `contract_summaries`,
/// doc 18 B.3) injected at iteration 0 — NEVER during phase 1, which would
/// poison summary_key cache environments. A leaf is injected only when the
/// contract has no locally-defined handler (fresher local extraction wins);
/// injected leaves dirty their remote callers exactly like a republished view.
pub fn fixpoint_with_leaves(
    engine: &mut Engine,
    leaves: HashMap<IidHex, Summary>,
) -> FixpointStats {
    // (contract, handler, shape) from every repo — gRPC methods, GraphQL
    // fields (doc 36 §3.2: a resolver is a contract handler like any other) and
    // HTTP routes (coverage wave 1 §4.4) — from the one enumeration witness and
    // the backward pass also read, so all three agree on keys and shapes.
    let mut contracts: Vec<(IidHex, IidHex, ContractShape)> = Vec::new();
    // handler iid -> contracts it serves (republish targets on handler change).
    let mut handler_of: HashMap<IidHex, Vec<(IidHex, ContractShape)>> = HashMap::new();
    for c in crate::graph::contracts(engine.prog) {
        contracts.push((c.key.clone(), c.handler.clone(), c.shape.clone()));
        handler_of.entry(c.handler).or_default().push((c.key, c.shape));
    }

    // Reverse deps, built once. prog.callees drops contract iids (no body), so
    // remote callers need their own scan over invokes_remote callsites.
    let mut local_callers: HashMap<IidHex, Vec<IidHex>> = HashMap::new();
    let mut remote_callers: HashMap<IidHex, Vec<IidHex>> = HashMap::new();
    for (iid, f) in &engine.prog.funcs {
        for callee in engine.prog.callees(f) {
            local_callers.entry(callee).or_default().push(iid.clone());
        }
        if let Some(flow) = &f.flow {
            for cs in &flow.callsites {
                if cs.kind == cgf::call_site::Kind::InvokesRemote as i32 {
                    for cid in &cs.callee_iids {
                        remote_callers
                            .entry(hexid(cid))
                            .or_default()
                            .push(iid.clone());
                    }
                }
            }
        }
    }
    let order = engine.prog.scc_order();

    // Iteration 0: publish all views; dirty = remote callers of every contract
    // whose view is new or changed.
    let mut linked = 0;
    let mut dirty: HashSet<IidHex> = HashSet::new();
    for (c, h, shape) in &contracts {
        if engine.summaries.contains_key(h) {
            linked += 1;
        }
        if publish_view(engine, c, h, shape) {
            if let Some(callers) = remote_callers.get(c) {
                dirty.extend(callers.iter().cloned());
            }
        }
    }
    // ... plus PG leaves for contracts we don't define locally (local wins).
    let local: HashSet<&IidHex> = contracts.iter().map(|(c, ..)| c).collect();
    let mut remote_leaves = 0;
    for (c, view) in leaves {
        if local.contains(&c) {
            continue;
        }
        remote_leaves += 1;
        if let Some(callers) = remote_callers.get(&c) {
            dirty.extend(callers.iter().cloned());
        }
        engine.summaries.insert(c, view);
    }

    // Local propagation resolves fully inside each resummarize pass, so every
    // productive iteration here must change >= 1 contract view.
    let max_iters = contracts.len() + 1;
    let mut iters = 0;
    while !dirty.is_empty() {
        if iters >= max_iters {
            eprintln!(
                "panopticode: cross-repo fixpoint hit iteration cap ({max_iters}); \
                 result is sound but may miss deeper chains"
            );
            break;
        }
        iters += 1;
        let changed = engine.resummarize(&dirty, &order, &local_callers);
        dirty = HashSet::new();
        for f in &changed {
            if let Some(served) = handler_of.get(f) {
                for (c, shape) in served.clone() {
                    if publish_view(engine, &c, f, &shape) {
                        if let Some(callers) = remote_callers.get(&c) {
                            dirty.extend(callers.iter().cloned());
                        }
                    }
                }
            }
        }
    }
    FixpointStats {
        linked,
        remote_leaves,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ifds::SinkHit;

    fn sum(flows: Vec<(Slot, Slot)>, sink_in: Vec<Slot>) -> Summary {
        let mut s = Summary {
            confidence: 1.0,
            ..Default::default()
        };
        s.flows
            .extend(flows.into_iter().map(|(a, b)| (a.into(), b.into())));
        for in_slot in sink_in {
            s.sink_hits.push(SinkHit {
                in_slot: in_slot.into(),
                class: "sqli".into(),
                callsite: 0,
                span: None,
                via_heap: None,
            });
        }
        s
    }

    #[test]
    fn unary_view_is_identity() {
        let s = sum(
            vec![(Slot::Param(1), Slot::Return(0))],
            vec![Slot::Param(1)],
        );
        let v = contract_view(&s, false, false);
        assert_eq!(v.flows, s.flows);
        assert_eq!(v.sink_hits.len(), 1);
    }

    /// doc 20 §2.4: contract remap shifts base slots; field paths ride through.
    #[test]
    fn server_stream_remap_carries_field_path() {
        let mut s = Summary {
            confidence: 1.0,
            ..Default::default()
        };
        s.flows.insert((
            SlotP { slot: Slot::Param(0), path: vec![3, 1] },
            Slot::StreamOut.into(),
        ));
        let v = contract_view(&s, false, true);
        assert!(
            v.flows.contains(&(
                SlotP { slot: Slot::Param(1), path: vec![3, 1] },
                Slot::StreamOut.into()
            )),
            "{:?}",
            v.flows
        );
    }

    #[test]
    fn server_stream_remaps_req_and_drops_stream_param() {
        // handler (req, stream): req=Param(0) flows to StreamOut; stream
        // param and the error return must vanish from the client frame.
        let s = sum(
            vec![
                (Slot::Param(0), Slot::StreamOut),
                (Slot::Param(1), Slot::Return(0)),
                (Slot::Param(0), Slot::Return(0)),
                (Slot::Source, Slot::StreamOut),
            ],
            vec![Slot::Param(0), Slot::Param(1)],
        );
        let v = contract_view(&s, false, true);
        assert!(v.flows.contains(&(Slot::Param(1).into(), Slot::StreamOut.into())));
        assert!(!v.flows.iter().any(|(i, _)| *i == Slot::Param(0)));
        assert!(!v.flows.iter().any(|(_, o)| matches!(o.slot, Slot::Return(_))));
        assert!(v.flows.contains(&(Slot::Source.into(), Slot::StreamOut.into())));
        let sink_ins: Vec<_> = v.sink_hits.iter().map(|h| h.in_slot.clone()).collect();
        assert_eq!(sink_ins, vec![Slot::Param(1)]);
    }

    #[test]
    fn client_stream_keeps_only_stream_slots() {
        // handler (stream): all data enters via StreamIn.
        let s = sum(
            vec![
                (Slot::StreamIn, Slot::StreamOut),
                (Slot::Param(0), Slot::Return(0)),
            ],
            vec![Slot::StreamIn, Slot::Param(0), Slot::Receiver],
        );
        let v = contract_view(&s, true, false);
        assert_eq!(
            v.flows,
            [(Slot::StreamIn.into(), Slot::StreamOut.into())]
                .into_iter()
                .collect()
        );
        let sink_ins: Vec<_> = v.sink_hits.iter().map(|h| h.in_slot.clone()).collect();
        assert_eq!(sink_ins, vec![Slot::StreamIn]);
    }
    /// The GraphQL view maps the resolver's own params onto the client's arg
    /// ports and drops everything the client cannot address.
    #[test]
    fn graphql_view_remaps_resolver_params_onto_client_arg_ports() {
        // field resolver (ctx, obj, a, b): a = Param(2), b = Param(3)
        let s = sum(
            vec![
                (Slot::Param(2), Slot::Return(0)),  // a -> data
                (Slot::Param(3), Slot::Return(1)),  // b -> error: dropped
                (Slot::Param(1), Slot::Return(0)),  // obj: not client-supplied
                (Slot::Param(0), Slot::Return(0)),  // ctx: ditto
            ],
            vec![Slot::Param(3), Slot::Param(0)],
        );
        let v = contract_view_graphql(&s, &[2, 3]);
        assert!(v.flows.contains(&(Slot::Param(0).into(), Slot::Return(0).into())));
        assert_eq!(v.flows.len(), 1, "obj/ctx in and the error return are dropped: {:?}", v.flows);
        let hits: Vec<Slot> = v.sink_hits.iter().map(|h| h.in_slot.slot.clone()).collect();
        assert_eq!(hits, vec![Slot::Param(1)], "b's sink moves to arg port 1; ctx's is dropped");
    }

    /// Coverage wave 1 §4.4: every request param lands on the client's one
    /// port; the response writer, the receiver and every return are dropped
    /// (request direction only); Source/Global pass through.
    #[test]
    fn http_view_folds_request_params_onto_port_zero_and_drops_returns() {
        // Next route handler (request, ctx): both carry request data
        let s = sum(
            vec![
                (Slot::Param(0), Slot::Return(0)),            // response: dropped
                (Slot::Param(1), Slot::Global("ab".into())),  // into a heap cell: kept
                (Slot::Receiver, Slot::Global("ab".into())),  // receiver: dropped
            ],
            vec![Slot::Param(0), Slot::Param(1), Slot::Param(2), Slot::Source],
        );
        let shape = ContractShape::Http { request_params: vec![0, 1] };
        assert!(!shape.is_identity());
        let v = shape.view(&s);
        assert_eq!(
            v.flows,
            [(Slot::Param(0).into(), Slot::Global("ab".into()).into())].into_iter().collect(),
        );
        let hits: Vec<Slot> = v.sink_hits.iter().map(|h| h.in_slot.slot.clone()).collect();
        assert_eq!(hits, vec![Slot::Param(0), Slot::Source], "two request params, one port, one hit");
    }

}

#[cfg(test)]
mod fixpoint_tests {
    use super::*;
    use crate::catalog::Catalog;
    use crate::graph::Program;
    use crate::ifds::cache_tests::{edge, vertex};
    use std::collections::HashMap;

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

    fn sink_cs(id: u32) -> cgf::CallSite {
        cgf::CallSite {
            id,
            callee_fqn: "db.Exec".into(),
            argc: 1,
            ..Default::default()
        }
    }

    fn remote_cs(id: u32, contract: u8) -> cgf::CallSite {
        cgf::CallSite {
            id,
            kind: cgf::call_site::Kind::InvokesRemote as i32,
            callee_iids: vec![vec![contract; 32]],
            callee_fqn: "t.Svc/M".into(),
            argc: 2,
            resultc: 1,
            ..Default::default()
        }
    }

    fn local_cs(id: u32, callee: u8) -> cgf::CallSite {
        cgf::CallSite {
            id,
            callee_iids: vec![vec![callee; 32]],
            callee_fqn: format!("pkg.F{callee:02x}"),
            argc: 1,
            ..Default::default()
        }
    }

    fn gm(contract: u8, handler: u8, cs: bool, ss: bool) -> cgf::GrpcMethod {
        cgf::GrpcMethod {
            iid: vec![contract; 32],
            full_name: format!("t.Svc/M{contract:02x}"),
            handler_iid: vec![handler; 32],
            client_streaming: cs,
            server_streaming: ss,
            ..Default::default()
        }
    }

    /// Handler(p0, p1): db.Exec(p1) — remote sink at Param(1), where a unary
    /// client's second call arg lands.
    fn sink_handler(iid: u8) -> cgf::Function {
        func(
            iid,
            cgf::LocalFlow {
                vertices: vec![
                    vertex(1, cgf::VertexKind::InParam, 1, 0),
                    vertex(2, cgf::VertexKind::CallArgPort, 0, 0),
                ],
                edges: vec![edge(1, 2)],
                callsites: vec![sink_cs(0)],
            },
        )
    }

    /// F(p0, p1): remote(_, p1) on `contract` — forwards Param(1) to the
    /// remote arg the contract's Param(1) reads.
    fn forwarding_handler(iid: u8, contract: u8) -> cgf::Function {
        func(
            iid,
            cgf::LocalFlow {
                vertices: vec![
                    vertex(1, cgf::VertexKind::InParam, 1, 0),
                    vertex(2, cgf::VertexKind::CallArgPort, 1, 0),
                ],
                edges: vec![edge(1, 2)],
                callsites: vec![remote_cs(0, contract)],
            },
        )
    }

    /// Root(p0): remote(_, p0) on `contract`.
    fn root_caller(iid: u8, contract: u8) -> cgf::Function {
        func(
            iid,
            cgf::LocalFlow {
                vertices: vec![
                    vertex(1, cgf::VertexKind::InParam, 0, 0),
                    vertex(2, cgf::VertexKind::CallArgPort, 1, 0),
                ],
                edges: vec![edge(1, 2)],
                callsites: vec![remote_cs(0, contract)],
            },
        )
    }

    fn program(fns: Vec<cgf::Function>, gms: Vec<cgf::GrpcMethod>) -> Program {
        let mut prog = Program {
            funcs: HashMap::new(),
            repo_of: HashMap::new(),
            packages: vec![cgf::CgfPackage {
                repo: "test".into(),
                grpc_methods: gms,
                ..Default::default()
            }],
        };
        for f in fns {
            let h = hexid(&f.id.as_ref().unwrap().iid);
            prog.repo_of.insert(h.clone(), "test".into());
            prog.funcs.insert(h, f);
        }
        prog
    }

    fn has_sink(engine: &Engine, iid: u8, slot: Slot) -> bool {
        engine.summaries[&hexid(&[iid; 32])]
            .sink_hits
            .iter()
            .any(|h| h.class == "sqli" && h.in_slot == slot)
    }

    // --- doc 36 §3: GraphQL contracts + by-name argument normalization.

    /// A "ts" package calling a "go" gqlgen resolver by ARGUMENT NAME, in the
    /// wrong positional order. normalize.rs must swap the ports and the GraphQL
    /// contract view must land arg port 0 on the resolver's Param(1), so the
    /// server's SQL sink surfaces on the TS caller's *second* parameter.
    #[test]
    fn mixed_language_by_name_call_reaches_the_go_sink() {
        let cat = Catalog::load_str(CAT).unwrap();
        // TS root R(p0=mode, p1=token): op(mode, token) in DOCUMENT order.
        let root = func(
            0x0A,
            cgf::LocalFlow {
                vertices: vec![
                    vertex(1, cgf::VertexKind::InParam, 0, 0),
                    vertex(2, cgf::VertexKind::InParam, 1, 0),
                    vertex(3, cgf::VertexKind::CallArgPort, 0, 0), // "mode"
                    vertex(4, cgf::VertexKind::CallArgPort, 1, 0), // "token"
                ],
                edges: vec![edge(1, 3), edge(2, 4)],
                callsites: vec![cgf::CallSite {
                    id: 0,
                    kind: cgf::call_site::Kind::InvokesRemote as i32,
                    callee_iids: vec![vec![0xC1; 32]],
                    callee_fqn: "graphql:Query.searchByToken".into(),
                    argc: 2,
                    resultc: 1,
                    arg_names: vec!["mode".into(), "token".into()],
                    ..Default::default()
                }],
            },
        );
        // Go resolver H(ctx, token): db.Exec(token) — sink on Param(1).
        let handler = sink_handler(0x2C);
        let gql = cgf::GraphqlField {
            iid: vec![0xC1; 32],
            type_field: "Query.searchByToken".into(),
            resolver_iid: vec![0x2C; 32],
            endpoint_iid: vec![0xC1; 32],
            // SDL order: token first — the OPPOSITE of the document order above.
            args: vec![
                cgf::GraphqlArg { name: "token".into(), param_idx: 1 },
                cgf::GraphqlArg { name: "mode".into(), param_idx: 2 },
            ],
        };
        let mut prog = Program {
            funcs: HashMap::new(),
            repo_of: HashMap::new(),
            packages: vec![
                cgf::CgfPackage {
                    repo: "webapp".into(),
                    language: "ts".into(),
                    ..Default::default()
                },
                cgf::CgfPackage {
                    repo: "gateway".into(),
                    language: "go".into(),
                    graphql_fields: vec![gql],
                    ..Default::default()
                },
            ],
        };
        for (f, repo) in [(root, "webapp"), (handler, "gateway")] {
            let h = hexid(&f.id.as_ref().unwrap().iid);
            prog.repo_of.insert(h.clone(), repo.into());
            prog.funcs.insert(h, f);
        }

        let st = crate::normalize::normalize(&mut prog);
        assert_eq!((st.callsites, st.ports, st.dangling), (1, 2, 0));

        let mut eng = Engine::new(&prog, &cat);
        eng.run();
        let linked = fixpoint(&mut eng);
        assert_eq!(linked, 1, "the GraphQL field is a contract like any other");
        assert!(
            has_sink(&eng, 0x0A, Slot::Param(1)),
            "the sink must land on `token` (R's Param(1)), not on positional arg 0: {:?}",
            eng.summaries[&hexid(&[0x0A; 32])].sink_hits
        );
        assert!(
            !has_sink(&eng, 0x0A, Slot::Param(0)),
            "`mode` never reaches the resolver's tainted param"
        );
    }

    /// Shape A: R --C1--> H1 --C2--> H2(sink). H1 was summarized before C2's
    /// view existed (default leaf), so only the fixpoint can surface the
    /// two-boundary sink in R.
    #[test]
    fn shape_a_two_boundary_sink_reaches_root() {
        let cat = Catalog::load_str(CAT).unwrap();
        let prog = program(
            vec![
                root_caller(0x0A, 0xC1),
                forwarding_handler(0x1B, 0xC2),
                sink_handler(0x2C),
            ],
            vec![gm(0xC1, 0x1B, false, false), gm(0xC2, 0x2C, false, false)],
        );
        let mut eng = Engine::new(&prog, &cat);
        eng.run();
        assert!(
            eng.summaries[&hexid(&[0x1B; 32])].sink_hits.is_empty(),
            "pre-fixpoint: H1 must have the stale default-leaf view of C2"
        );
        let linked = fixpoint(&mut eng);
        assert_eq!(linked, 2);
        assert!(has_sink(&eng, 0x1B, Slot::Param(1)), "C2 sink must fold into H1");
        assert!(has_sink(&eng, 0x0A, Slot::Param(0)), "two-boundary sink must reach R");
    }

    /// Shape B: R --local--> helper --C--> H(sink). The helper was summarized
    /// pre-alias; resummarize must chase R through local_callers in-pass.
    #[test]
    fn shape_b_local_intermediary_chain_found() {
        let cat = Catalog::load_str(CAT).unwrap();
        // R(p0): helper(p0)
        let root = func(
            0x0A,
            cgf::LocalFlow {
                vertices: vec![
                    vertex(1, cgf::VertexKind::InParam, 0, 0),
                    vertex(2, cgf::VertexKind::CallArgPort, 0, 0),
                ],
                edges: vec![edge(1, 2)],
                callsites: vec![local_cs(0, 0x3D)],
            },
        );
        let prog = program(
            vec![root, root_caller(0x3D, 0xC1), sink_handler(0x2C)],
            vec![gm(0xC1, 0x2C, false, false)],
        );
        let mut eng = Engine::new(&prog, &cat);
        eng.run();
        assert!(eng.summaries[&hexid(&[0x0A; 32])].sink_hits.is_empty());
        fixpoint(&mut eng);
        assert!(has_sink(&eng, 0x3D, Slot::Param(0)), "remote sink must fold into helper");
        assert!(has_sink(&eng, 0x0A, Slot::Param(0)), "and surface in the root via local call");
    }

    /// Contract cycle: HA --CB--> HB --CA--> HA, with a real sink in HB.
    /// Must terminate (set-lattice) with the sink visible on both sides.
    #[test]
    fn contract_cycle_terminates_sound() {
        let cat = Catalog::load_str(CAT).unwrap();
        // HB(p0,p1): remote CA(_, p1); db.Exec(p1)
        let hb = func(
            0x42,
            cgf::LocalFlow {
                vertices: vec![
                    vertex(1, cgf::VertexKind::InParam, 1, 0),
                    vertex(2, cgf::VertexKind::CallArgPort, 1, 0),
                    vertex(3, cgf::VertexKind::CallArgPort, 0, 1),
                ],
                edges: vec![edge(1, 2), edge(1, 3)],
                callsites: vec![remote_cs(0, 0xCA), sink_cs(1)],
            },
        );
        let prog = program(
            vec![forwarding_handler(0x41, 0xCB), hb, root_caller(0x0A, 0xCA)],
            vec![gm(0xCA, 0x41, false, false), gm(0xCB, 0x42, false, false)],
        );
        let mut eng = Engine::new(&prog, &cat);
        eng.run();
        fixpoint(&mut eng); // must return, not spin to the iteration cap
        assert!(has_sink(&eng, 0x42, Slot::Param(1)), "HB's own sink");
        assert!(has_sink(&eng, 0x41, Slot::Param(1)), "HB's sink through CB into HA");
        assert!(has_sink(&eng, 0x0A, Slot::Param(0)), "and out to the external caller");
    }

    fn leaf_with_sink() -> Summary {
        let mut leaf = Summary {
            confidence: 1.0,
            ..Default::default()
        };
        leaf.sink_hits.push(crate::ifds::SinkHit {
            in_slot: Slot::Param(1).into(),
            class: "sqli".into(),
            callsite: 0,
            span: None,
            via_heap: None,
        });
        leaf
    }

    /// PG leaf for a contract with NO local handler: injected at iteration 0,
    /// its remote callers get re-summarized — the transitive sink surfaces.
    /// Phase-1 state (summary_keys / contract_hashes / recomputed / stats)
    /// must be identical with and without leaves.
    #[test]
    fn pg_leaf_injected_at_fixpoint_only() {
        let cat = Catalog::load_str(CAT).unwrap();
        // R(p0): remote(_, p0) on 0xC9 — no local gm defines 0xC9
        let prog = program(vec![root_caller(0x0A, 0xC9)], vec![]);

        let mut plain = Engine::new(&prog, &cat);
        plain.run();
        let mut eng = Engine::new(&prog, &cat);
        eng.run();
        assert_eq!(eng.summary_keys, plain.summary_keys);
        assert!(eng.summaries[&hexid(&[0x0A; 32])].sink_hits.is_empty());

        let mut leaves = HashMap::new();
        leaves.insert(hexid(&[0xC9; 32]), leaf_with_sink());
        let fx = fixpoint_with_leaves(&mut eng, leaves);
        assert_eq!(fx.remote_leaves, 1);
        assert_eq!(fx.linked, 0);
        assert!(has_sink(&eng, 0x0A, Slot::Param(0)), "leaf sink must fold into R");
        // phase-1 bookkeeping untouched by the leaf-composed fixpoint
        assert_eq!(eng.summary_keys, plain.summary_keys);
        assert_eq!(eng.contract_hashes, plain.contract_hashes);
        assert_eq!(eng.recomputed, plain.recomputed);
    }

    /// A leaf for a contract that IS defined locally must be ignored — the
    /// fresher local extraction wins.
    #[test]
    fn local_handler_wins_over_pg_leaf() {
        let cat = Catalog::load_str(CAT).unwrap();
        // C1 defined locally with a SINKLESS handler; a stale PG leaf claims a sink.
        // sinkless handler: H(p0,p1) with no flows/sinks
        let h = func(
            0x1B,
            cgf::LocalFlow {
                vertices: vec![vertex(1, cgf::VertexKind::InParam, 1, 0)],
                edges: vec![],
                callsites: vec![],
            },
        );
        let prog = program(
            vec![root_caller(0x0A, 0xC1), h],
            vec![gm(0xC1, 0x1B, false, false)],
        );
        let mut eng = Engine::new(&prog, &cat);
        eng.run();
        let mut leaves = HashMap::new();
        leaves.insert(hexid(&[0xC1; 32]), leaf_with_sink());
        let fx = fixpoint_with_leaves(&mut eng, leaves);
        assert_eq!(fx.remote_leaves, 0, "local contract must shadow the leaf");
        assert_eq!(fx.linked, 1);
        assert!(
            eng.summaries[&hexid(&[0x0A; 32])].sink_hits.is_empty(),
            "stale leaf sink must NOT surface through the local sinkless handler"
        );
    }

    /// A server-streaming contract republished mid-fixpoint must keep the
    /// contract_view remap: handler req = Param(0) server-side, Param(1) in
    /// the client frame.
    #[test]
    fn streaming_republish_keeps_contract_view_remap() {
        let cat = Catalog::load_str(CAT).unwrap();
        // H1(req, stream) for server-streaming C1: remote unary C2(_, req)
        let h1 = func(
            0x51,
            cgf::LocalFlow {
                vertices: vec![
                    vertex(1, cgf::VertexKind::InParam, 0, 0),
                    vertex(2, cgf::VertexKind::CallArgPort, 1, 0),
                ],
                edges: vec![edge(1, 2)],
                callsites: vec![remote_cs(0, 0xC2)],
            },
        );
        let prog = program(
            vec![h1, sink_handler(0x2C)],
            vec![gm(0xC1, 0x51, false, true), gm(0xC2, 0x2C, false, false)],
        );
        let mut eng = Engine::new(&prog, &cat);
        eng.run();
        fixpoint(&mut eng);
        assert!(has_sink(&eng, 0x51, Slot::Param(0)), "handler frame: sink at Param(0)");
        let view = &eng.summaries[&hexid(&[0xC1; 32])];
        assert!(
            view.sink_hits
                .iter()
                .any(|h| h.class == "sqli" && h.in_slot == Slot::Param(1)),
            "republished server-stream view must remap req to Param(1): {:?}",
            view.sink_hits
        );
    }
}

/// Coverage wave 1 §4.3-4.4 end to end: a client in one repo, a route handler
/// in another, the linker, phase 1, compose, witness and the backward pass.
#[cfg(test)]
mod http_tests {
    use super::*;
    use crate::catalog::Catalog;
    use crate::graph::Program;
    use crate::ifds::cache_tests::{edge, vertex};
    use crate::witness::HopKind;

    const CAT: &str = "[[sinks]]\nclass = \"sqli\"\nselector = \"db.Exec\"\n";

    fn func(iid: u8, fqn: &str, flow: cgf::LocalFlow) -> cgf::Function {
        cgf::Function {
            id: Some(cgf::Ident { iid: vec![iid; 32], bid: vec![iid; 32] }),
            fqn: fqn.into(),
            has_body: true,
            flow: Some(flow),
            ..Default::default()
        }
    }

    /// `web.Submit(q)`: `fetch(`${API}/api/users`, {method: "POST", body: q})`,
    /// q untrusted. The ordinary `fetch` site is omitted — only the synthetic
    /// one matters here.
    fn client(method: &str, path: &str) -> cgf::Function {
        let mut f = func(
            0x0C,
            "web.Submit",
            cgf::LocalFlow {
                vertices: vec![
                    vertex(1, cgf::VertexKind::InParam, 0, 0),
                    vertex(2, cgf::VertexKind::CallArgPort, 0, 0),
                ],
                edges: vec![edge(1, 2)],
                callsites: vec![cgf::CallSite {
                    id: 0,
                    callee_fqn: format!("http:{method} {path}"),
                    argc: 1,
                    opaque: true,
                    http_call: Some(cgf::HttpCall { method: method.into(), path: path.into() }),
                    ..Default::default()
                }],
            },
        );
        f.source_params = vec![0];
        f
    }

    /// `api.CreateUser(w http.ResponseWriter, r *http.Request)`: db.Exec(r…)
    /// — the sink on handler param `sink_param`.
    fn handler(sink_param: u32) -> cgf::Function {
        func(
            0x2D,
            "api.CreateUser",
            cgf::LocalFlow {
                vertices: vec![
                    vertex(1, cgf::VertexKind::InParam, sink_param, 0),
                    vertex(2, cgf::VertexKind::CallArgPort, 0, 0),
                ],
                edges: vec![edge(1, 2)],
                callsites: vec![cgf::CallSite { id: 0, callee_fqn: "db.Exec".into(), argc: 1, ..Default::default() }],
            },
        )
    }

    fn program(client_fn: cgf::Function) -> Program {
        program_with(client_fn, vec![1], 1)
    }

    fn program_with(client_fn: cgf::Function, request_params: Vec<u32>, sink_param: u32) -> Program {
        let route = cgf::HttpRoute {
            iid: vec![0xE1; 32],
            method: "POST".into(),
            path: "/api/users".into(),
            display: "/api/users".into(),
            handler_iid: vec![0x2D; 32],
            endpoint_iid: vec![0xE1; 32],
            request_params,
            framework: "chi".into(),
        };
        let mut prog = Program {
            funcs: HashMap::new(),
            repo_of: HashMap::new(),
            packages: vec![
                cgf::CgfPackage { repo: "web".into(), language: "ts".into(), ..Default::default() },
                cgf::CgfPackage { repo: "api".into(), language: "go".into(), http_routes: vec![route], ..Default::default() },
            ],
        };
        for (f, repo) in [(client_fn, "web"), (handler(sink_param), "api")] {
            let h = hexid(&f.id.as_ref().unwrap().iid);
            prog.repo_of.insert(h.clone(), repo.into());
            prog.funcs.insert(h, f);
        }
        prog
    }

    /// cli.rs `taint`'s phase order
    fn chains(prog: &mut Program, link: bool, cat: &Catalog) -> Vec<crate::report::Chain> {
        crate::httplink::link_loaded(prog, link);
        let mut eng = Engine::new(prog, cat);
        eng.run();
        crate::heap::fixpoint(&mut eng);
        fixpoint_with_leaves(&mut eng, HashMap::new());
        crate::report::intra_chains(&eng, None)
    }

    #[test]
    fn a_linked_client_reaches_the_route_handlers_sink() {
        let cat = Catalog::load_str(CAT).unwrap();
        let mut prog = program(client("POST", "/{}/api/users"));
        let chains = chains(&mut prog, true, &cat);
        assert_eq!(chains.len(), 1, "one cross-repo chain");
        let c = &chains[0];
        assert_eq!((c.source_repo.as_str(), c.source_fn.as_str(), c.sink_class.as_str()), ("web", "web.Submit", "sqli"));
        let route = c.route.as_ref().unwrap();
        assert_eq!(route.incomplete, None);
        assert_eq!(route.boundaries, 1);
        let hops: Vec<(HopKind, &str, &str)> =
            route.hops.iter().map(|h| (h.kind, h.repo.as_str(), h.callee.as_str())).collect();
        assert_eq!(
            hops,
            vec![
                (HopKind::Source, "web", ""),
                // the crossing names the ROUTE it entered, not the client template
                (HopKind::Boundary, "web", "http POST /api/users (chi)"),
                (HopKind::Sink, "api", "db.Exec"),
            ]
        );
    }

    /// A Next route handler `(request, ctx)` carries request data in both
    /// params; the view folds both onto the client's port, so the descent must
    /// re-enter at the one whose rows actually reach the sink.
    #[test]
    fn the_descent_reenters_at_the_request_param_that_carries_the_sink() {
        let cat = Catalog::load_str(CAT).unwrap();
        let mut prog = program_with(client("POST", "/api/users"), vec![0, 1], 1);
        let chains = chains(&mut prog, true, &cat);
        assert_eq!(chains.len(), 1);
        let route = chains[0].route.as_ref().unwrap();
        assert_eq!(route.incomplete, None, "{:?}", route.hops);
        assert_eq!(route.hops.last().unwrap().callee, "db.Exec");
    }

    /// The gin shape: `CreateUser(c *gin.Context) { c.ShouldBindJSON(&req);
    /// db.ExecContext(c, req.Name) }`. The by-ref SOURCE makes the handler an
    /// entry point of its own; the bind PROPAGATOR (receiver -> 1) is what lets
    /// the client's data, arriving on `c`, reach `req` — without it the
    /// cross-service chain does not exist. `c` also reaches the ctx port of
    /// ExecContext, which `sink_ignore_arg_types` must keep silent.
    #[test]
    fn a_client_reaches_the_sink_behind_a_gin_bind() {
        const BIND: &str = "(*github.com/gin-gonic/gin.Context).ShouldBindJSON";
        let typed = |mut v: cgf::FlowVertex, t: &str| {
            v.r#type = t.into();
            v
        };
        let gin = func(
            0x2D,
            "api.CreateUser",
            cgf::LocalFlow {
                vertices: vec![
                    vertex(1, cgf::VertexKind::InParam, 0, 0),                   // c
                    vertex(2, cgf::VertexKind::CallArgPort, 0, 0),               // c.ShouldBindJSON
                    vertex(3, cgf::VertexKind::CallArgPort, 1, 0),               // &req (write-back)
                    typed(vertex(4, cgf::VertexKind::CallArgPort, 0, 1), "context.Context"),
                    typed(vertex(5, cgf::VertexKind::CallArgPort, 1, 1), "string"),
                ],
                edges: vec![edge(1, 2), edge(1, 4), edge(3, 5)],
                callsites: vec![
                    cgf::CallSite { id: 0, callee_fqn: BIND.into(), argc: 2, resultc: 1, arg0_is_receiver: true, ..Default::default() },
                    cgf::CallSite { id: 1, callee_fqn: "db.ExecContext".into(), argc: 2, ..Default::default() },
                ],
            },
        );
        let mk = || {
            let mut prog = program_with(client("POST", "/{}/api/users"), vec![0], 0);
            prog.funcs.insert(hexid(&[0x2D; 32]), gin.clone());
            prog
        };
        let cat_src = |propagator: bool| {
            format!(
                "sink_ignore_arg_types = [\"context.Context\"]\n\
                 [[sources]]\nkind = \"http_request\"\nselector = \"{BIND}\"\nto = \"1\"\n\
                 [[sinks]]\nclass = \"sqli\"\nselector = \"db.ExecContext\"\n{}",
                if propagator {
                    format!("[[propagators]]\nselector = \"{BIND}\"\nfrom = \"receiver\"\nto = \"1\"\n")
                } else {
                    String::new()
                }
            )
        };
        let sources = |chains: &[crate::report::Chain]| -> Vec<String> {
            chains.iter().map(|c| c.source_fn.clone()).collect()
        };
        let cat = Catalog::load_str(&cat_src(false)).unwrap();
        let without = chains(&mut mk(), true, &cat);
        assert_eq!(sources(&without), vec!["api.CreateUser"], "the bind source alone: the handler only");

        let cat = Catalog::load_str(&cat_src(true)).unwrap();
        let with = chains(&mut mk(), true, &cat);
        assert_eq!(sources(&with), vec!["api.CreateUser", "web.Submit"]);
        let route = with[1].route.as_ref().unwrap();
        assert_eq!(route.incomplete, None);
        let callees: Vec<&str> = route.hops.iter().map(|h| h.callee.as_str()).collect();
        assert_eq!(callees, vec!["", "http POST /api/users (chi)", BIND, "db.ExecContext"]);
    }

    /// Two loaded services serve the same route (one iid) and only one has a
    /// sink: the client fans out at 1/2, and the route descends into the one
    /// whose summary carries it.
    #[test]
    fn a_route_two_services_serve_fans_out_and_routes_through_the_sink() {
        let cat = Catalog::load_str(CAT).unwrap();
        let mut prog = program(client("POST", "/api/users"));
        let mut quiet = handler(1);
        quiet.id = Some(cgf::Ident { iid: vec![0x3D; 32], bid: vec![0x3D; 32] });
        quiet.fqn = "api2.CreateUser".into();
        quiet.flow.as_mut().unwrap().edges.clear();
        prog.repo_of.insert(hexid(&[0x3D; 32]), "api2".into());
        prog.funcs.insert(hexid(&[0x3D; 32]), quiet);
        let mut twin = prog.packages[1].http_routes[0].clone();
        twin.handler_iid = vec![0x3D; 32];
        prog.packages.push(cgf::CgfPackage { repo: "api2".into(), http_routes: vec![twin], ..Default::default() });

        let chains = chains(&mut prog, true, &cat);
        assert_eq!(chains.len(), 1);
        let route = chains[0].route.as_ref().unwrap();
        assert_eq!(route.incomplete, None);
        assert_eq!(route.hops.last().unwrap().repo, "api", "the handler with the sink");
        assert_eq!(chains[0].route_confidence, 0.5, "a two-way fan-out");
    }

    /// request_params [0, 1], the sink behind param 1 only: --backward-unview
    /// lands the demand back on the client's one port and confirms.
    #[test]
    fn backward_unview_confirms_through_a_later_request_param() {
        let cat = Catalog::load_str(CAT).unwrap();
        let mut prog = program_with(client("POST", "/api/users"), vec![0, 1], 1);
        crate::httplink::link_loaded(&mut prog, true);
        let mut eng = Engine::new(&prog, &cat);
        eng.run();
        fixpoint_with_leaves(&mut eng, HashMap::new());
        let mut chains = crate::report::intra_chains(&eng, None);
        assert_eq!(chains.len(), 1);
        crate::backward::set_opts(crate::backward::BackOpts { unview: true, ..Default::default() });
        crate::report::backward_check(&eng, &mut chains, false);
        crate::backward::set_opts(Default::default());
        assert_eq!(chains[0].backward.as_ref().unwrap().verdict, crate::backward::Verdict::Confirmed);
    }

    #[test]
    fn without_the_link_there_is_no_chain() {
        let cat = Catalog::load_str(CAT).unwrap();
        assert!(chains(&mut program(client("POST", "/{}/api/users")), false, &cat).is_empty());
        // ... nor with a template no route serves
        assert!(chains(&mut program(client("POST", "/{}/api/orders")), true, &cat).is_empty());
    }

    /// Not identity, so the backward pass gives up at the crossing unless
    /// --backward-unview undoes the view — the permuted-GraphQL rule.
    #[test]
    fn backward_is_undecided_across_the_route_unless_unviewed() {
        let cat = Catalog::load_str(CAT).unwrap();
        let mut prog = program(client("POST", "/{}/api/users"));
        crate::httplink::link_loaded(&mut prog, true);
        let mut eng = Engine::new(&prog, &cat);
        eng.run();
        fixpoint_with_leaves(&mut eng, HashMap::new());
        for (unview, want) in [
            (false, crate::backward::Verdict::Undecided),
            (true, crate::backward::Verdict::Confirmed),
        ] {
            let mut chains = crate::report::intra_chains(&eng, None);
            crate::backward::set_opts(crate::backward::BackOpts { unview, ..Default::default() });
            crate::report::backward_check(&eng, &mut chains, false);
            assert_eq!(chains[0].backward.as_ref().unwrap().verdict, want, "unview={unview}");
        }
        crate::backward::set_opts(Default::default());
    }
}
