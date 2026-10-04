//! By-name → positional call-argument normalization (doc 36 §3.1).
//!
//! Go's call convention is positional, so a Go frontend can emit
//! `CALL_ARG_PORT.index` directly. A frontend whose GraphQL calls come from an
//! *operation document* (the TS frontend, doc 36 §4) knows argument NAMES, not
//! the resolver's parameter positions — those are a property of the SERVER's
//! generated code, which the client never sees. Such a frontend emits
//! `CallSite.arg_names` and numbers its ports in document order.
//!
//! This pass, run once right after the whole program is loaded (all `--cgf`
//! dirs merged — the contract may be defined in a different dir from the
//! callsite), rewrites those ports into the contract's own frame:
//!
//!   port named `n`  ->  index `j`  where  `GraphqlField.args[j].name == n`
//!
//! so that `ifds::arg_to_callee_slot` (`Param(j)`) meets
//! `compose::contract_view_graphql` (`Param(args[j].param_idx) -> Param(j)`)
//! and the handler's real parameter is hit. Only the vertex `index` moves;
//! edges reference vertex ids, so nothing else in the flow changes.
//!
//! Names the contract does not declare are pushed to indices `>= args.len()`:
//! they address no callee slot and are dropped by the existing composition,
//! which is the sound direction (a dangling arg cannot taint anything).
//! An INVOKES_REMOTE site whose callee is not a loaded GraphQL contract (a
//! PG-only leaf, say) keeps its positional numbering and warns once.

use crate::graph::{hexid, IidHex, Program};
use crate::proto::cgf;
use std::collections::{BTreeSet, HashMap};

#[derive(Default, Debug, PartialEq, Eq)]
pub struct Stats {
    /// callsites whose ports were renumbered
    pub callsites: usize,
    /// CALL_ARG_PORT vertices whose index changed
    pub ports: usize,
    /// named ports whose name the contract does not declare
    pub dangling: usize,
    /// contract iids that carry arg_names but are not loaded GraphQL contracts
    pub unknown_contracts: usize,
}

impl Stats {
    pub fn is_empty(&self) -> bool {
        *self == Stats::default()
    }
}

/// SDL arg names, in contract order, of every loaded GraphQL field.
fn graphql_arg_order(prog: &Program) -> HashMap<IidHex, Vec<String>> {
    let mut out: HashMap<IidHex, Vec<String>> = HashMap::new();
    for p in &prog.packages {
        for gf in &p.graphql_fields {
            if gf.iid.is_empty() {
                continue;
            }
            out.entry(hexid(&gf.iid))
                .or_insert_with(|| gf.args.iter().map(|a| a.name.clone()).collect());
        }
    }
    out
}

/// Rewrite by-name arg ports into contract positions. Idempotent: the callsite's
/// `arg_names` are permuted alongside the ports, so a second pass is a no-op.
pub fn normalize(prog: &mut Program) -> Stats {
    let order = graphql_arg_order(prog);
    let mut st = Stats::default();
    let mut warned: BTreeSet<String> = BTreeSet::new();

    // Deterministic function order: warnings and stats must not depend on the
    // HashMap's iteration order.
    let mut iids: Vec<IidHex> = prog.funcs.keys().cloned().collect();
    iids.sort_unstable();

    for iid in iids {
        let Some(f) = prog.funcs.get_mut(&iid) else {
            continue;
        };
        let fqn = f.fqn.clone();
        let Some(flow) = f.flow.as_mut() else { continue };

        // callsite id -> (old port index -> new port index)
        let mut remap: HashMap<u32, HashMap<u32, u32>> = HashMap::new();
        for cs in &flow.callsites {
            if cs.kind != cgf::call_site::Kind::InvokesRemote as i32 || cs.arg_names.is_empty() {
                continue;
            }
            let names = match single_callee(cs).and_then(|c| order.get(&c).map(|n| (c, n))) {
                Some((_, names)) => names,
                None => {
                    let key = match single_callee(cs) {
                        Some(c) => c,
                        None => format!("multi:{fqn}:{}", cs.id),
                    };
                    if warned.insert(key.clone()) {
                        st.unknown_contracts += 1;
                        eprintln!(
                            "normalize-warn: callsite {} in {fqn} names its args ({}) but its \
                             callee ({}) is not a loaded GraphQL contract — arg ports stay positional",
                            cs.id,
                            cs.arg_names.join(","),
                            &key[..24.min(key.len())],
                        );
                    }
                    continue;
                }
            };
            let mut m: HashMap<u32, u32> = HashMap::new();
            let mut next_dangling = names.len() as u32;
            for (i, n) in cs.arg_names.iter().enumerate() {
                if n.is_empty() {
                    continue; // unnamed port: leave where it is
                }
                match names.iter().position(|x| x == n) {
                    Some(j) => {
                        m.insert(i as u32, j as u32);
                    }
                    None => {
                        m.insert(i as u32, next_dangling);
                        next_dangling += 1;
                        st.dangling += 1;
                    }
                }
            }
            if !m.is_empty() {
                remap.insert(cs.id, m);
            }
        }
        if remap.is_empty() {
            continue;
        }
        st.callsites += remap.len();
        for v in flow.vertices.iter_mut() {
            if v.kind != cgf::VertexKind::CallArgPort as i32 {
                continue;
            }
            let Some(m) = remap.get(&v.callsite_id) else {
                continue;
            };
            if let Some(&j) = m.get(&v.index) {
                if j != v.index {
                    v.index = j;
                    st.ports += 1;
                }
            }
        }
        // Permute the names with the ports so `arg_names[j]` keeps describing
        // port j — and so re-running the pass finds every name in place.
        for cs in flow.callsites.iter_mut() {
            let Some(m) = remap.get(&cs.id) else { continue };
            let width = m.values().copied().max().unwrap_or(0).max(cs.argc.saturating_sub(1)) + 1;
            let mut names = vec![String::new(); width as usize];
            for (i, n) in cs.arg_names.iter().enumerate() {
                let j = m.get(&(i as u32)).copied().unwrap_or(i as u32);
                if (j as usize) < names.len() {
                    names[j as usize] = n.clone();
                }
            }
            cs.arg_names = names;
        }
    }
    st
}

/// `normalize` plus the one-line stderr report — what every command calls
/// right after its `--cgf` dirs are merged into one `Program`.
pub fn normalize_loaded(prog: &mut Program) -> Stats {
    let st = normalize(prog);
    if !st.is_empty() {
        eprintln!(
            "normalize: {} by-name callsite(s), {} arg port(s) moved into contract position, \
             {} dangling name(s), {} unknown contract(s)",
            st.callsites, st.ports, st.dangling, st.unknown_contracts
        );
    }
    st
}

/// The one contract a by-name remote callsite addresses. A GraphQL field is a
/// single contract by construction; a fan-out means we cannot know which frame
/// the names belong to.
fn single_callee(cs: &cgf::CallSite) -> Option<IidHex> {
    match cs.callee_iids.as_slice() {
        [one] => Some(hexid(one)),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::Program;

    fn arg_port(id: u32, cs: u32, index: u32) -> cgf::FlowVertex {
        cgf::FlowVertex {
            id,
            kind: cgf::VertexKind::CallArgPort as i32,
            index,
            callsite_id: cs,
            ..Default::default()
        }
    }

    fn contract(iid: &[u8], args: &[(&str, u32)]) -> cgf::CgfPackage {
        cgf::CgfPackage {
            repo: "srv".into(),
            language: "go".into(),
            graphql_fields: vec![cgf::GraphqlField {
                iid: iid.to_vec(),
                type_field: "Mutation.login".into(),
                resolver_iid: b"handler".to_vec(),
                endpoint_iid: iid.to_vec(),
                args: args
                    .iter()
                    .map(|(n, p)| cgf::GraphqlArg {
                        name: (*n).into(),
                        param_idx: *p,
                    })
                    .collect(),
            }],
            ..Default::default()
        }
    }

    fn caller(names: &[&str], callee: &[u8]) -> cgf::Function {
        cgf::Function {
            fqn: "webapp/src/op.$op".into(),
            id: Some(cgf::Ident {
                iid: b"caller".to_vec(),
                bid: vec![],
            }),
            flow: Some(cgf::LocalFlow {
                vertices: (0..names.len() as u32)
                    .map(|i| arg_port(i, 0, i))
                    .collect(),
                edges: vec![],
                callsites: vec![cgf::CallSite {
                    id: 0,
                    kind: cgf::call_site::Kind::InvokesRemote as i32,
                    callee_iids: vec![callee.to_vec()],
                    argc: names.len() as u32,
                    resultc: 1,
                    arg_names: names.iter().map(|s| (*s).to_string()).collect(),
                    ..Default::default()
                }],
            }),
            ..Default::default()
        }
    }

    fn prog(pkgs: Vec<cgf::CgfPackage>, funcs: Vec<cgf::Function>) -> Program {
        let mut p = Program {
            funcs: Default::default(),
            repo_of: Default::default(),
            packages: pkgs,
        };
        for f in funcs {
            let h = hexid(&f.id.as_ref().unwrap().iid);
            p.repo_of.insert(h.clone(), "webapp".into());
            p.funcs.insert(h, f);
        }
        p
    }

    /// Document order (password, pincode) against a contract declaring
    /// (pincode, password): the ports must SWAP, not stay put.
    #[test]
    fn permuted_names_land_on_contract_positions() {
        let iid = b"C1";
        let mut p = prog(
            vec![contract(iid, &[("pincode", 1), ("password", 2)])],
            vec![caller(&["password", "pincode"], iid)],
        );
        let st = normalize(&mut p);
        assert_eq!(st.callsites, 1);
        assert_eq!(st.ports, 2);
        assert_eq!(st.dangling, 0);
        let flow = p.funcs[&hexid(b"caller")].flow.clone().unwrap();
        let idx: Vec<u32> = flow.vertices.iter().map(|v| v.index).collect();
        assert_eq!(idx, vec![1, 0], "port 0 (password) -> 1, port 1 (pincode) -> 0");
    }

    /// A name the contract does not declare must not collide with a real
    /// position: it goes past the end, where it addresses no callee slot.
    #[test]
    fn unknown_name_goes_past_the_end() {
        let iid = b"C1";
        let mut p = prog(
            vec![contract(iid, &[("pincode", 1)])],
            vec![caller(&["nope", "pincode"], iid)],
        );
        let st = normalize(&mut p);
        assert_eq!(st.dangling, 1);
        let flow = p.funcs[&hexid(b"caller")].flow.clone().unwrap();
        assert_eq!(flow.vertices[0].index, 1, "unknown name pushed to args.len()");
        assert_eq!(flow.vertices[1].index, 0, "pincode takes position 0");
    }

    /// Unknown contract (PG-only leaf): positional numbering survives untouched.
    #[test]
    fn unknown_contract_stays_positional() {
        let iid = b"C1";
        let mut p = prog(
            vec![contract(b"OTHER", &[("pincode", 1)])],
            vec![caller(&["password", "pincode"], iid)],
        );
        let st = normalize(&mut p);
        assert_eq!(st.unknown_contracts, 1);
        assert_eq!(st.ports, 0);
        let flow = p.funcs[&hexid(b"caller")].flow.clone().unwrap();
        assert_eq!(
            flow.vertices.iter().map(|v| v.index).collect::<Vec<_>>(),
            vec![0, 1]
        );
    }

    /// A Go-emitted CGF has no arg_names at all: the pass must be inert on it.
    #[test]
    fn no_arg_names_is_inert() {
        let iid = b"C1";
        let mut f = caller(&[], iid);
        f.flow.as_mut().unwrap().vertices = vec![arg_port(0, 0, 0), arg_port(1, 0, 1)];
        let mut p = prog(vec![contract(iid, &[("pincode", 1)])], vec![f]);
        assert!(normalize(&mut p).is_empty());
    }

    /// Running twice must not move anything the second time.
    #[test]
    fn idempotent() {
        let iid = b"C1";
        let mut p = prog(
            vec![contract(iid, &[("pincode", 1), ("password", 2)])],
            vec![caller(&["password", "pincode"], iid)],
        );
        normalize(&mut p);
        let before: Vec<u32> = p.funcs[&hexid(b"caller")]
            .flow
            .as_ref()
            .unwrap()
            .vertices
            .iter()
            .map(|v| v.index)
            .collect();
        let st = normalize(&mut p);
        let after: Vec<u32> = p.funcs[&hexid(b"caller")]
            .flow
            .as_ref()
            .unwrap()
            .vertices
            .iter()
            .map(|v| v.index)
            .collect();
        assert_eq!(before, after);
        assert_eq!(st.ports, 0);
    }
}
