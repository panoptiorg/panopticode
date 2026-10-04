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
        }
    }

    pub fn view(&self, sum: &Summary) -> Summary {
        match self {
            ContractShape::Grpc(cs, ss) => contract_view(sum, *cs, *ss),
            ContractShape::Graphql(args) => contract_view_graphql(sum, args),
        }
    }
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
    // (contract, handler, shape) from every repo — gRPC methods AND GraphQL
    // fields (doc 36 §3.2: a resolver is a contract handler like any other).
    let mut contracts: Vec<(IidHex, IidHex, ContractShape)> = Vec::new();
    // handler iid -> contracts it serves (republish targets on handler change).
    let mut handler_of: HashMap<IidHex, Vec<(IidHex, ContractShape)>> = HashMap::new();
    for p in &engine.prog.packages {
        for gm in &p.grpc_methods {
            if gm.handler_iid.is_empty() {
                continue;
            }
            let c = hexid(&gm.iid);
            let h = hexid(&gm.handler_iid);
            let shape = ContractShape::Grpc(gm.client_streaming, gm.server_streaming);
            contracts.push((c.clone(), h.clone(), shape.clone()));
            handler_of.entry(h).or_default().push((c, shape));
        }
        for gf in &p.graphql_fields {
            if gf.resolver_iid.is_empty() || gf.iid.is_empty() {
                continue;
            }
            let c = hexid(&gf.iid);
            let h = hexid(&gf.resolver_iid);
            let shape = ContractShape::Graphql(gf.args.iter().map(|a| a.param_idx).collect());
            contracts.push((c.clone(), h.clone(), shape.clone()));
            handler_of.entry(h).or_default().push((c, shape));
        }
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
