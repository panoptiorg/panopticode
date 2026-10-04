// Code graph: load CGF packages (prost), index functions by iid, expose the
// call graph + a reverse-topological SCC order for bottom-up summary building.
use crate::proto::cgf;
use anyhow::{Context, Result};
use prost::Message;
use std::collections::HashMap;
use std::path::Path;

pub type IidHex = String;

pub fn hexid(b: &[u8]) -> IidHex {
    hex::encode(b)
}

pub struct Program {
    /// iid(hex) -> function fact
    pub funcs: HashMap<IidHex, cgf::Function>,
    /// iid(hex) -> owning repo
    pub repo_of: HashMap<IidHex, String>,
    /// all loaded packages (for contracts/endpoints)
    pub packages: Vec<cgf::CgfPackage>,
}

/// One cross-repo contract a package DEFINES: a gRPC method or (doc 36 §3.2) a
/// GraphQL field. Both are keyed by a `ContractIID` a client can recompute from
/// the schema alone, and both name a local handler — a gRPC handler or a gqlgen
/// resolver — so composition, persistence and impact treat them uniformly.
pub struct ContractDef<'a> {
    pub iid: &'a [u8],
    pub full_name: &'a str,
    pub handler_iid: &'a [u8],
    /// `cgf::endpoint::Kind` as i16: 0 = GRPC, 1 = GRAPHQL.
    pub kind: i16,
    /// gRPC only (the registry columns); empty for a GraphQL field.
    pub input_msg: &'a str,
    pub output_msg: &'a str,
}

pub const CONTRACT_KIND_GRPC: i16 = 0;
pub const CONTRACT_KIND_GRAPHQL: i16 = 1;

/// Every contract `p` defines, gRPC first (stable order).
pub fn pkg_contracts(p: &cgf::CgfPackage) -> Vec<ContractDef<'_>> {
    let mut out = Vec::with_capacity(p.grpc_methods.len() + p.graphql_fields.len());
    for gm in &p.grpc_methods {
        out.push(ContractDef {
            iid: &gm.iid,
            full_name: &gm.full_name,
            handler_iid: &gm.handler_iid,
            kind: CONTRACT_KIND_GRPC,
            input_msg: &gm.input_msg,
            output_msg: &gm.output_msg,
        });
    }
    for gf in &p.graphql_fields {
        out.push(ContractDef {
            iid: &gf.iid,
            full_name: &gf.type_field,
            handler_iid: &gf.resolver_iid,
            kind: CONTRACT_KIND_GRAPHQL,
            input_msg: "",
            output_msg: "",
        });
    }
    out
}

impl Program {
    pub fn load_dir(dir: &Path) -> Result<Program> {
        let mut prog = Program {
            funcs: HashMap::new(),
            repo_of: HashMap::new(),
            packages: Vec::new(),
        };
        for entry in std::fs::read_dir(dir).with_context(|| format!("read_dir {dir:?}"))? {
            let path = entry?.path();
            if path.extension().and_then(|s| s.to_str()) != Some("pb") {
                continue;
            }
            let bytes = std::fs::read(&path)?;
            let pkg =
                cgf::CgfPackage::decode(&*bytes).with_context(|| format!("decode {path:?}"))?;
            for f in &pkg.functions {
                if let Some(id) = &f.id {
                    let h = hexid(&id.iid);
                    prog.funcs.insert(h.clone(), f.clone());
                    prog.repo_of.insert(h, pkg.repo.clone());
                }
            }
            prog.packages.push(pkg);
        }
        Ok(prog)
    }

    /// Callee iids referenced by f's call sites (that we have bodies for).
    pub fn callees(&self, f: &cgf::Function) -> Vec<IidHex> {
        let mut out = Vec::new();
        if let Some(flow) = &f.flow {
            for cs in &flow.callsites {
                for cid in &cs.callee_iids {
                    let h = hexid(cid);
                    if self.funcs.contains_key(&h) {
                        out.push(h);
                    }
                }
            }
        }
        out
    }

    /// Reverse-topological order over the call graph, condensing SCCs (Tarjan).
    /// Callees precede callers (bottom-up) so summaries compose. Recursive SCCs
    /// are iterated to fixpoint by the tabulator.
    pub fn scc_order(&self) -> Vec<Vec<IidHex>> {
        Tarjan::new(self).run()
    }
}

// ---- Tarjan SCC (iterative) over the function call graph ----
struct Tarjan<'a> {
    prog: &'a Program,
    index: HashMap<IidHex, usize>,
    low: HashMap<IidHex, usize>,
    on_stack: HashMap<IidHex, bool>,
    stack: Vec<IidHex>,
    counter: usize,
    out: Vec<Vec<IidHex>>,
}

impl<'a> Tarjan<'a> {
    fn new(prog: &'a Program) -> Self {
        Tarjan {
            prog,
            index: HashMap::new(),
            low: HashMap::new(),
            on_stack: HashMap::new(),
            stack: Vec::new(),
            counter: 0,
            out: Vec::new(),
        }
    }
    fn run(mut self) -> Vec<Vec<IidHex>> {
        let ids: Vec<IidHex> = self.prog.funcs.keys().cloned().collect();
        for v in ids {
            if !self.index.contains_key(&v) {
                self.strongconnect(&v);
            }
        }
        self.out
    }
    fn strongconnect(&mut self, v: &IidHex) {
        // iterative DFS to avoid native-stack overflow on deep graphs
        let mut work: Vec<(IidHex, usize)> = vec![(v.clone(), 0)];
        while let Some((node, mut ci)) = work.pop() {
            if ci == 0 {
                self.index.insert(node.clone(), self.counter);
                self.low.insert(node.clone(), self.counter);
                self.counter += 1;
                self.stack.push(node.clone());
                self.on_stack.insert(node.clone(), true);
            }
            let succ = self
                .prog
                .funcs
                .get(&node)
                .map(|f| self.prog.callees(f))
                .unwrap_or_default();
            let mut recursed = false;
            while ci < succ.len() {
                let w = succ[ci].clone();
                ci += 1;
                if !self.index.contains_key(&w) {
                    work.push((node.clone(), ci));
                    work.push((w, 0));
                    recursed = true;
                    break;
                } else if *self.on_stack.get(&w).unwrap_or(&false) {
                    let lw = self.index[&w];
                    let ln = self.low[&node];
                    self.low.insert(node.clone(), ln.min(lw));
                }
            }
            if recursed {
                continue;
            }
            if self.low[&node] == self.index[&node] {
                let mut comp = Vec::new();
                loop {
                    let w = self.stack.pop().unwrap();
                    self.on_stack.insert(w.clone(), false);
                    comp.push(w.clone());
                    if w == node {
                        break;
                    }
                }
                self.out.push(comp);
            }
            if let Some((parent, _)) = work.last().cloned() {
                let lp = self.low[&parent];
                let ln = self.low[&node];
                self.low.insert(parent, lp.min(ln));
            }
        }
    }
}
