// Code graph: load CGF packages (prost), index functions by iid, expose the
// call graph + a reverse-topological SCC order for bottom-up summary building.
use crate::compose::ContractShape;
use crate::proto::cgf;
use anyhow::{Context, Result};
use prost::Message;
use std::borrow::Cow;
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

/// One cross-repo contract a package DEFINES: a gRPC method, (doc 36 §3.2) a
/// GraphQL field, or (coverage wave 1 §4.4) an HTTP route. All are keyed by a
/// `ContractIID` a client can recompute from the contract's name alone, and all
/// name a local handler — a gRPC handler, a gqlgen resolver, a route handler —
/// so composition, witness, the backward pass, persistence and impact treat
/// them uniformly. `pkg_contracts` is the ONLY place that knows which package
/// fields hold contracts: the next contract kind is one more block there.
pub struct ContractDef<'a> {
    pub iid: &'a [u8],
    /// gRPC full method name, GraphQL `Type.field`, HTTP `http:<METHOD> <path>`
    pub full_name: Cow<'a, str>,
    pub handler_iid: &'a [u8],
    /// `cgf::endpoint::Kind` as i16: 0 = GRPC, 1 = GRAPHQL, 2 = HTTP.
    pub kind: i16,
    /// gRPC only (the registry columns); empty otherwise.
    pub input_msg: &'a str,
    pub output_msg: &'a str,
    /// how compose remaps the handler's slot frame into the client's
    pub shape: ContractShape,
    /// HTTP only: the route as the frontend reported it
    pub http: Option<&'a cgf::HttpRoute>,
}

pub const CONTRACT_KIND_GRPC: i16 = 0;
pub const CONTRACT_KIND_GRAPHQL: i16 = 1;
pub const CONTRACT_KIND_HTTP: i16 = 2;

/// Every contract `p` defines, gRPC first, then GraphQL, then HTTP (stable order).
pub fn pkg_contracts(p: &cgf::CgfPackage) -> Vec<ContractDef<'_>> {
    let mut out =
        Vec::with_capacity(p.grpc_methods.len() + p.graphql_fields.len() + p.http_routes.len());
    for gm in &p.grpc_methods {
        out.push(ContractDef {
            iid: &gm.iid,
            full_name: Cow::Borrowed(&gm.full_name),
            handler_iid: &gm.handler_iid,
            kind: CONTRACT_KIND_GRPC,
            input_msg: &gm.input_msg,
            output_msg: &gm.output_msg,
            shape: ContractShape::Grpc(gm.client_streaming, gm.server_streaming),
            http: None,
        });
    }
    for gf in &p.graphql_fields {
        out.push(ContractDef {
            iid: &gf.iid,
            full_name: Cow::Borrowed(&gf.type_field),
            handler_iid: &gf.resolver_iid,
            kind: CONTRACT_KIND_GRAPHQL,
            input_msg: "",
            output_msg: "",
            shape: ContractShape::Graphql(gf.args.iter().map(|a| a.param_idx).collect()),
            http: None,
        });
    }
    for r in &p.http_routes {
        out.push(ContractDef {
            iid: &r.iid,
            full_name: Cow::Owned(format!("http:{} {}", r.method, r.path)),
            handler_iid: &r.handler_iid,
            kind: CONTRACT_KIND_HTTP,
            input_msg: "",
            output_msg: "",
            shape: ContractShape::Http { request_params: r.request_params.clone() },
            http: Some(r),
        });
    }
    out
}

/// One contract as the ANALYSIS sees it: the key an INVOKES_REMOTE call site
/// names in `callee_iids`, the handler whose summary compose publishes under
/// that key, and the shape of the remap.
#[derive(Clone, Debug)]
pub struct Contract {
    pub key: IidHex,
    pub handler: IidHex,
    pub shape: ContractShape,
    /// HTTP only: (method, canonical path) the linker matches a client on, and
    /// the crossing as a route hop renders it — `http GET /api/users/{id} (chi)`
    pub http: Option<HttpContract>,
}

#[derive(Clone, Debug)]
pub struct HttpContract {
    pub method: String,
    pub path: String,
    pub label: String,
}

/// Every contract of the loaded program that has a local handler, in package
/// order. Compose, witness, the backward pass and the HTTP linker all read
/// this, so a client site, the published view and the descent agree on keys.
///
/// gRPC and GraphQL contracts are keyed by their iid, exactly as before. An
/// HTTP route's iid is `ContractIID("http:" + method + " " + path)` — it names
/// the ROUTE, not the service — so two loaded services that both serve
/// `GET /health` share it, and one view per key would make whichever handler
/// published last win. Only in that case each handler gets its own key,
/// derived from (iid, handler); the linker then fans a client out over both,
/// which is the honest answer (coverage wave 1 §4.3).
pub fn contracts(prog: &Program) -> Vec<Contract> {
    let defs: Vec<ContractDef<'_>> = prog
        .packages
        .iter()
        .flat_map(pkg_contracts)
        .filter(|c| !c.iid.is_empty() && !c.handler_iid.is_empty())
        .collect();
    // HTTP iid -> its distinct handlers
    let mut http_handlers: HashMap<&[u8], Vec<&[u8]>> = HashMap::new();
    for c in defs.iter().filter(|c| c.kind == CONTRACT_KIND_HTTP) {
        let hs = http_handlers.entry(c.iid).or_default();
        if !hs.contains(&c.handler_iid) {
            hs.push(c.handler_iid);
        }
    }
    let mut seen_http: std::collections::HashSet<(IidHex, IidHex)> = Default::default();
    let mut out = Vec::with_capacity(defs.len());
    for c in defs {
        let handler = hexid(c.handler_iid);
        let Some(r) = c.http else {
            out.push(Contract { key: hexid(c.iid), handler, shape: c.shape, http: None });
            continue;
        };
        let key = if http_handlers[c.iid].len() > 1 {
            crate::ids::hex(&crate::ids::hash_parts(&[b"http-route", c.iid, c.handler_iid]))
        } else {
            hexid(c.iid)
        };
        // the same route reported twice (two muxes, one handler) is one contract
        if !seen_http.insert((key.clone(), handler.clone())) {
            continue;
        }
        let label = format!(
            "http {} {}{}",
            if r.method.is_empty() { "*" } else { r.method.as_str() },
            if r.display.is_empty() { r.path.as_str() } else { r.display.as_str() },
            if r.framework.is_empty() { String::new() } else { format!(" ({})", r.framework) }
        );
        out.push(Contract {
            key,
            handler,
            shape: c.shape,
            http: Some(HttpContract { method: r.method.clone(), path: r.path.clone(), label }),
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
