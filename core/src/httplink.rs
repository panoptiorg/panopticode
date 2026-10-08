//! HTTP client -> route linking (coverage wave 1 §1.1, §4.3).
//!
//! Two frontend facts meet only here. A server route is an `HttpRoute`
//! (method, canonical path, handler). A client request call is, IN ADDITION to
//! the ordinary call site, a synthetic site with `http_call` set: `argc 1,
//! resultc 0`, every data-bearing argument of the request (URL, body) flowing
//! into arg port 0, `callee_fqn = "http:<METHOD> <path>"`. Unlinked, that site
//! is inert: the default leaf has no result port to taint.
//!
//! This pass runs once, right after `normalize`, over the MERGED program (a
//! client in one `--cgf` dir calls a route defined in another) and turns every
//! site it can match into `INVOKES_REMOTE` with `callee_iids` = the matched
//! routes' contract keys (`graph::contracts`). From there it is an ordinary
//! contract call: compose publishes `ContractShape::Http`'s view of the
//! handler under the key and `propagate` composes it at the site, like a gRPC
//! method.
//!
//! Cache safety. Phase 1 never sees a contract view (compose runs after it),
//! and the site has no result port, so a linked and an unlinked site compose
//! the same nothing: no summary exists under a contract key, the default leaf
//! taints zero results, and `Program::callees` — hence `summary_key` — skips
//! iids that are not loaded functions. `bid` is the frontend's and is not
//! recomputed. `phase_one_is_identical_linked_or_not` pins this.

use crate::graph::{IidHex, Program};
use crate::proto::cgf;
use std::collections::{BTreeMap, HashMap};

/// More equally-good routes than this and the site stays unlinked: a client
/// joined to every `GET /{}/{}` in the corpus is a false-positive generator,
/// not a recall feature (§4.3 step 3).
pub const MAX_FANOUT: usize = 4;

/// A suffix match must agree on at least this many literal segments (§4.3
/// step 2): `/users` alone is not evidence that `{}/users` is this service.
pub const MIN_SUFFIX_LITERALS: usize = 2;

/// An exact match must agree on at least one. Without it `/api/users` is an
/// "exact" match for `/{owner}/{repo}`, and `/` for every root route in the
/// corpus — shape coincidences that would outrank any real suffix evidence.
pub const MIN_EXACT_LITERALS: usize = 1;

/// The canonical path (§1.1), the same function both frontends implement and
/// `testdata/http-canon-vectors.json` pins. The frontends emit canonical
/// paths already; the core re-applies it (it is idempotent) so a template that
/// slipped through un-canonicalised still compares equal to its route.
pub fn canonical_path(input: &str) -> String {
    let mut s = input;
    // 1. scheme + authority, if literal
    let lower = s.get(..8).unwrap_or(s).to_ascii_lowercase();
    let after_scheme = if lower.starts_with("https://") {
        Some(&s[8..])
    } else if lower.starts_with("http://") {
        Some(&s[7..])
    } else {
        s.strip_prefix("//")
    };
    if let Some(rest) = after_scheme {
        s = match rest.find('/') {
            Some(i) => &rest[i..],
            None => "",
        };
    }
    // 2. query and fragment
    if let Some(i) = s.find(['?', '#']) {
        s = &s[..i];
    }
    // 3.-5. segments, first matching rule wins, nothing after a catch-all
    let mut out: Vec<&str> = Vec::new();
    for seg in s.split('/').filter(|x| !x.is_empty()) {
        let canon = if seg == "{$}" {
            continue; // Go 1.22 "exact match" anchor, not a segment
        } else if seg == "{*}" || seg.starts_with('*') || is_rest_param(seg) {
            "{*}"
        } else if seg.contains(['{', '[']) || seg.starts_with(':') {
            "{}"
        } else {
            seg
        };
        out.push(canon);
        if canon == "{*}" {
            break;
        }
    }
    format!("/{}", out.join("/"))
}

/// `{name...}` (Go 1.22), `[...x]` / `[[...x]]` (Next, SvelteKit).
fn is_rest_param(seg: &str) -> bool {
    (seg.starts_with('{') && seg.ends_with("...}"))
        || (seg.starts_with("[...") && seg.ends_with(']'))
        || (seg.starts_with("[[...") && seg.ends_with("]]"))
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Seg {
    Lit(String),
    /// `{}`
    Param,
    /// `{*}` — matches whatever is left
    Tail,
}

fn segments(path: &str) -> Vec<Seg> {
    canonical_path(path)
        .split('/')
        .filter(|x| !x.is_empty())
        .map(|x| match x {
            "{}" => Seg::Param,
            "{*}" => Seg::Tail,
            lit => Seg::Lit(lit.to_string()),
        })
        .collect()
}

/// Does `route` match `client` position by position? `Some((n, tail))` = yes,
/// with `n` literal segments in agreement — the evidence a match carries — and
/// `tail` when a `{*}` took the rest.
///
/// A route `{}` takes any client segment. A client `{}` (a value the frontend
/// could not resolve) takes only a route `{}`: a dynamic client segment against
/// a literal route segment is not evidence of anything. `{*}` on either side
/// takes the rest. A bare catch-all (an SPA fallback, a root file server)
/// therefore aligns with everything at 0 literals, which the per-kind
/// minimums in `score` reject.
fn align(route: &[Seg], client: &[Seg]) -> Option<(usize, bool)> {
    let mut lits = 0;
    let mut i = 0;
    loop {
        match (route.get(i), client.get(i)) {
            (None, None) => return Some((lits, false)),
            (Some(Seg::Tail), _) | (_, Some(Seg::Tail)) => return Some((lits, true)),
            (Some(Seg::Param), Some(_)) => {}
            (Some(Seg::Lit(a)), Some(Seg::Lit(b))) if a == b => lits += 1,
            _ => return None,
        }
        i += 1;
    }
}

fn any_method(m: &str) -> bool {
    m.is_empty() || m == "*"
}

/// (compatible, an exact method agreement). Either side `*` / unknown is a
/// wildcard; a route that names the client's method is the more specific one.
fn method_match(route: &str, client: &str) -> (bool, bool) {
    if any_method(route) || any_method(client) {
        (true, false)
    } else {
        let eq = route.eq_ignore_ascii_case(client);
        (eq, eq)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Kind {
    Suffix = 1,
    Exact = 2,
}

/// How well one route matches one client template, compared in order (higher
/// is better): the kind of match; the literal segments that agree; whether
/// every segment matched one for one (`{}` is more specific than a `{*}` that
/// swallowed the same segment, so `/api/users/me` goes to `/api/users/{id}`,
/// not also to `/api/users/{*}`); whether the route names the client's method.
type Score = (Kind, usize, bool, bool);

struct Route {
    key: IidHex,
    method: String,
    segs: Vec<Seg>,
}

/// The best way `route` matches the client path `client` (`base` leading
/// `{}` segments already counted off), or None.
fn score(route: &Route, method: &str, base: usize, client: &[Seg]) -> Option<Score> {
    let (ok, exact_method) = method_match(&route.method, method);
    if !ok {
        return None;
    }
    let rest = &client[base..];
    // 1. exact — only a client whose start is known: a leading `{}` is an
    //    unresolved base URL of unknown length (§1.1 rule 5), so its segment
    //    count says nothing.
    if base == 0 {
        if let Some((l, tail)) = align(&route.segs, rest) {
            if l >= MIN_EXACT_LITERALS {
                return Some((Kind::Exact, l, !tail, exact_method));
            }
        }
    }
    // 2. suffix — the client against a suffix of the route (the base, or a
    //    client-side prefix the frontend could not see, stands for the rest),
    //    or the route against a suffix of the client (an unresolved server
    //    mount prefix, an API gateway's prefix).
    let mut best: Option<(usize, bool)> = None;
    let mut consider = |a: Option<(usize, bool)>| {
        if let Some((l, tail)) = a {
            best = best.max(Some((l, !tail)));
        }
    };
    let from = if base == 0 { 1 } else { 0 };
    for o in from..=route.segs.len() {
        consider(align(&route.segs[o..], rest));
    }
    for o in 1..rest.len() {
        consider(align(&route.segs, &rest[o..]));
    }
    best.filter(|&(l, _)| l >= MIN_SUFFIX_LITERALS)
        .map(|(l, specific)| (Kind::Suffix, l, specific, exact_method))
}

/// What one run of the linker did — the `http-link:` census.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Stats {
    /// synthetic client sites (`http_call` set)
    pub sites: usize,
    pub linked: usize,
    /// linked sites by the kind of their best match
    pub exact: usize,
    pub suffix: usize,
    /// linked sites with more than one equally-good route
    pub fanout: usize,
    /// sites with more than `MAX_FANOUT` equally-good routes — left unlinked
    pub ambiguous: usize,
    /// sites no route matches
    pub unlinked: usize,
    /// HTTP route contracts loaded
    pub routes: usize,
    /// "<METHOD> <path>" of unlinked and ambiguous sites -> count
    pub not_linked: BTreeMap<String, usize>,
}

/// Link every synthetic HTTP client site in `prog` to the routes it matches.
pub fn link(prog: &mut Program) -> Stats {
    let routes: Vec<Route> = crate::graph::contracts(prog)
        .into_iter()
        .filter_map(|c| {
            let h = c.http?;
            Some(Route { key: c.key, method: h.method, segs: segments(&h.path) })
        })
        .collect();
    let mut st = Stats { routes: routes.len(), ..Default::default() };
    // matching is a pure function of (method, path): memoise per template
    let mut memo: HashMap<(String, String), (Vec<IidHex>, Kind)> = HashMap::new();

    // deterministic function order, like normalize: stats must not depend on
    // the HashMap's iteration order
    let mut iids: Vec<IidHex> = prog.funcs.keys().cloned().collect();
    iids.sort_unstable();
    for iid in iids {
        let Some(flow) = prog.funcs.get_mut(&iid).and_then(|f| f.flow.as_mut()) else {
            continue;
        };
        for cs in flow.callsites.iter_mut() {
            let Some(hc) = &cs.http_call else { continue };
            st.sites += 1;
            let method = hc.method.to_ascii_uppercase();
            let tkey = (method.clone(), hc.path.clone());
            let template = format!("{} {}", if method.is_empty() { "*" } else { &method }, hc.path);
            let (picked, kind) = memo
                .entry(tkey)
                .or_insert_with(|| best_routes(&routes, &method, &hc.path))
                .clone();
            if picked.is_empty() {
                st.unlinked += 1;
                *st.not_linked.entry(template).or_default() += 1;
                continue;
            }
            if picked.len() > MAX_FANOUT {
                st.ambiguous += 1;
                *st.not_linked.entry(format!("{template} (ambiguous: {})", picked.len())).or_default() += 1;
                continue;
            }
            match kind {
                Kind::Exact => st.exact += 1,
                Kind::Suffix => st.suffix += 1,
            }
            st.linked += 1;
            if picked.len() > 1 {
                st.fanout += 1;
            }
            cs.kind = cgf::call_site::Kind::InvokesRemote as i32;
            cs.callee_iids = picked.iter().filter_map(|k| hex::decode(k).ok()).collect();
            cs.dispatch_confidence = 1.0 / picked.len() as f32;
            cs.opaque = false;
        }
    }
    st
}

/// The contract keys of every route tied for the best score, sorted, and the
/// kind of that match. More than `MAX_FANOUT` is returned as is; the caller
/// calls that ambiguous. No match is an empty list.
fn best_routes(routes: &[Route], method: &str, path: &str) -> (Vec<IidHex>, Kind) {
    let segs = segments(path);
    let base = segs.iter().take_while(|s| **s == Seg::Param).count();
    let scored: Vec<(Score, &IidHex)> = routes
        .iter()
        .filter_map(|r| score(r, method, base, &segs).map(|s| (s, &r.key)))
        .collect();
    let Some(top) = scored.iter().map(|(s, _)| *s).max() else {
        return (Vec::new(), Kind::Suffix);
    };
    let mut keys: Vec<IidHex> = scored
        .into_iter()
        .filter(|(s, _)| *s == top)
        .map(|(_, k)| k.clone())
        .collect();
    keys.sort();
    keys.dedup();
    (keys, top.0)
}

/// `link` plus the stderr census — what every command that loads CGF for
/// analysis calls right after `normalize_loaded`. Silent on a corpus with no
/// HTTP facts, so every pre-wave-1 run prints exactly what it printed before.
/// `enabled = false` is `taint --no-http-link`: nothing is linked, and the
/// census says how many sites that left inert.
pub fn link_loaded(prog: &mut Program, enabled: bool) -> Stats {
    if !enabled {
        let sites = prog
            .funcs
            .values()
            .filter_map(|f| f.flow.as_ref())
            .flat_map(|fl| fl.callsites.iter())
            .filter(|cs| cs.http_call.is_some())
            .count();
        if sites > 0 {
            eprintln!("http-link: off (--no-http-link) — {sites} client site(s) left unlinked");
        }
        return Stats { sites, unlinked: sites, ..Default::default() };
    }
    let st = link(prog);
    if st.sites == 0 && st.routes == 0 {
        return st;
    }
    eprintln!(
        "http-link: sites={} linked={} (exact={} suffix={} fanout={}) ambiguous={} unlinked={} routes={}",
        st.sites, st.linked, st.exact, st.suffix, st.fanout, st.ambiguous, st.unlinked, st.routes
    );
    if !st.not_linked.is_empty() {
        let mut top: Vec<(&String, &usize)> = st.not_linked.iter().collect();
        top.sort_by(|a, b| b.1.cmp(a.1).then(a.0.cmp(b.0)));
        let shown: Vec<String> = top.iter().take(8).map(|(t, n)| format!("{t} ×{n}")).collect();
        eprintln!(
            "http-link: top unlinked templates: {}{}",
            shown.join(", "),
            if top.len() > 8 { ", …" } else { "" }
        );
    }
    st
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::hexid;
    use crate::ifds::cache_tests::{edge, vertex};

    /// Every vector in `testdata/http-canon-vectors.json` — the file both
    /// frontends test against too. It lives in this repo, so it is always
    /// present here.
    #[test]
    fn canonical_path_passes_every_shared_vector() {
        let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../testdata/http-canon-vectors.json");
        let doc: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&p).unwrap()).unwrap();
        let vectors = doc["vectors"].as_array().unwrap();
        assert!(vectors.len() >= 20, "the vector file shrank: {}", vectors.len());
        for v in vectors {
            let (i, o) = (v["in"].as_str().unwrap(), v["out"].as_str().unwrap());
            assert_eq!(canonical_path(i), o, "canonical_path({i:?})");
            assert_eq!(canonical_path(o), o, "not idempotent on {o:?}");
        }
    }

    fn route(iid: u8, handler: u8, method: &str, path: &str) -> cgf::HttpRoute {
        cgf::HttpRoute {
            iid: vec![iid; 32],
            method: method.into(),
            path: path.into(),
            display: path.into(),
            handler_iid: vec![handler; 32],
            endpoint_iid: vec![iid; 32],
            request_params: vec![1],
            framework: "chi".into(),
        }
    }

    /// One client function with one synthetic site per template.
    fn client(templates: &[(&str, &str)]) -> cgf::Function {
        let mut vertices = Vec::new();
        let mut callsites = Vec::new();
        for (i, (m, p)) in templates.iter().enumerate() {
            vertices.push(vertex(i as u32 + 1, cgf::VertexKind::CallArgPort, 0, i as u32));
            callsites.push(cgf::CallSite {
                id: i as u32,
                callee_fqn: format!("http:{m} {p}"),
                argc: 1,
                opaque: true,
                http_call: Some(cgf::HttpCall { method: m.to_string(), path: p.to_string() }),
                ..Default::default()
            });
        }
        cgf::Function {
            id: Some(cgf::Ident { iid: vec![0xC0; 32], bid: vec![0xC0; 32] }),
            fqn: "web.load".into(),
            has_body: true,
            flow: Some(cgf::LocalFlow { vertices, edges: vec![], callsites }),
            ..Default::default()
        }
    }

    fn prog(templates: &[(&str, &str)], routes: Vec<cgf::HttpRoute>) -> Program {
        let f = client(templates);
        let h = hexid(&f.id.as_ref().unwrap().iid);
        Program {
            funcs: [(h.clone(), f)].into_iter().collect(),
            repo_of: [(h, "web".to_string())].into_iter().collect(),
            packages: vec![cgf::CgfPackage { repo: "api".into(), http_routes: routes, ..Default::default() }],
        }
    }

    /// (kind, callee route iid bytes (first byte), confidence) per site
    fn linked(p: &Program) -> Vec<(i32, Vec<u8>, f32)> {
        let f = &p.funcs[&hexid(&[0xC0; 32])];
        f.flow
            .as_ref()
            .unwrap()
            .callsites
            .iter()
            .map(|cs| (cs.kind, cs.callee_iids.iter().map(|c| c[0]).collect(), cs.dispatch_confidence))
            .collect()
    }

    const REMOTE: i32 = cgf::call_site::Kind::InvokesRemote as i32;
    const STATIC: i32 = cgf::call_site::Kind::Static as i32;

    #[test]
    fn exact_prefers_the_literal_route_and_the_named_method() {
        let mut p = prog(
            &[("GET", "/api/users/me"), ("POST", "/api/users"), ("", "/api/users/{}")],
            vec![
                route(0x01, 0xA1, "GET", "/api/users/{}"),
                route(0x02, 0xA2, "GET", "/api/users/me"),
                route(0x03, 0xA3, "POST", "/api/users"),
                route(0x04, 0xA4, "*", "/api/users"),
            ],
        );
        let st = link(&mut p);
        assert_eq!((st.sites, st.linked, st.exact, st.suffix, st.fanout), (3, 3, 3, 0, 0), "{st:?}");
        let l = linked(&p);
        // a literal route segment is more specific than a route `{}`
        assert_eq!(l[0], (REMOTE, vec![0x02], 1.0));
        // a route naming the method beats the `*` route on the same path
        assert_eq!(l[1], (REMOTE, vec![0x03], 1.0));
        // a client `{}` matches only a route `{}`, never `/api/users/me`
        assert_eq!(l[2], (REMOTE, vec![0x01], 1.0));
    }

    #[test]
    fn a_method_mismatch_or_a_dynamic_client_segment_is_not_evidence() {
        let mut p = prog(
            &[("DELETE", "/api/users"), ("GET", "/api/{}")],
            vec![route(0x03, 0xA3, "POST", "/api/users")],
        );
        let st = link(&mut p);
        assert_eq!((st.linked, st.unlinked), (0, 2), "{st:?}");
        assert!(linked(&p).iter().all(|(k, ids, _)| *k == STATIC && ids.is_empty()));
        assert_eq!(st.not_linked.get("DELETE /api/users"), Some(&1));
    }

    /// `${API}/api/users/${id}`: the leading `{}` is a base of unknown length,
    /// so the rest is matched as a suffix of the route — of any route that has
    /// one, including a route mounted below a prefix the client never shows.
    #[test]
    fn an_unknown_base_matches_by_suffix_and_ties_fan_out() {
        let mut p = prog(
            &[("GET", "/{}/api/users/{}")],
            vec![route(0x01, 0xA1, "GET", "/api/users/{}"), route(0x05, 0xA5, "GET", "/v2/api/users/{}")],
        );
        let st = link(&mut p);
        assert_eq!((st.linked, st.suffix, st.fanout), (1, 1, 1), "{st:?}");
        assert_eq!(linked(&p)[0], (REMOTE, vec![0x01, 0x05], 0.5));
    }

    #[test]
    fn a_suffix_needs_two_literal_segments() {
        // `{}/users` against `/api/users`: one literal agrees — not evidence
        let mut p = prog(&[("GET", "/{}/users")], vec![route(0x01, 0xA1, "GET", "/api/users")]);
        assert_eq!(link(&mut p).unlinked, 1);
        // a route mounted under an unresolved server prefix: the route is a
        // suffix of the client path, two literals agree
        let mut p = prog(&[("GET", "/gw/api/users")], vec![route(0x01, 0xA1, "GET", "/api/users")]);
        let st = link(&mut p);
        assert_eq!((st.linked, st.suffix), (1, 1), "{st:?}");
    }

    /// Review finding: an all-parameter route matched "exactly" with no
    /// literal in agreement, and exact outranked every suffix match.
    #[test]
    fn an_exact_match_needs_a_literal_in_agreement() {
        let mut p = prog(
            &[("GET", "/api/users"), ("GET", "/"), ("GET", "https://api.github.com")],
            vec![
                route(0x01, 0xA1, "GET", "/{owner}/{repo}"),
                route(0x02, 0xA2, "GET", "/v1/api/users"),
                route(0x03, 0xA3, "GET", "/"),
                route(0x04, 0xA4, "*", "/"),
            ],
        );
        let st = link(&mut p);
        let l = linked(&p);
        // the shape coincidence is no candidate; the two-literal suffix wins
        assert_eq!(l[0], (REMOTE, vec![0x02], 1.0));
        // `/` has no literal at all, so it never links — nor does a bare
        // external host, which canonicalises to `/`
        assert_eq!(l[1].0, STATIC);
        assert_eq!(l[2].0, STATIC);
        assert_eq!((st.linked, st.suffix, st.unlinked), (1, 1, 2), "{st:?}");
    }

    /// Review finding: a catch-all tied a single-param route on literals.
    #[test]
    fn a_single_param_route_beats_a_catch_all() {
        let mut p = prog(
            &[("GET", "/api/users/me"), ("GET", "/api/users/me/avatar")],
            vec![route(0x01, 0xA1, "GET", "/api/users/{*}"), route(0x02, 0xA2, "GET", "/api/users/{}")],
        );
        let st = link(&mut p);
        assert_eq!(st.fanout, 0, "{st:?}");
        let l = linked(&p);
        assert_eq!(l[0], (REMOTE, vec![0x02], 1.0), "the more specific route wins outright");
        assert_eq!(l[1], (REMOTE, vec![0x01], 1.0), "only the catch-all takes two segments");
    }

    #[test]
    fn a_catch_all_takes_the_tail_but_not_the_whole_corpus() {
        let mut p = prog(
            &[("GET", "/static/js/app.js"), ("GET", "/api/orders")],
            vec![route(0x06, 0xA6, "GET", "/static/{*}"), route(0x07, 0xA7, "GET", "/{*}")],
        );
        let st = link(&mut p);
        assert_eq!((st.linked, st.unlinked), (1, 1), "{st:?}");
        assert_eq!(linked(&p)[0].1, vec![0x06]);
    }

    #[test]
    fn more_than_four_equal_routes_is_ambiguous() {
        let routes: Vec<_> = (1..=5u8)
            .map(|i| route(i, 0xA0 + i, "GET", &format!("/p{i}/api/users/{{}}")))
            .collect();
        let mut p = prog(&[("GET", "/{}/api/users/{}")], routes);
        let st = link(&mut p);
        assert_eq!((st.ambiguous, st.linked), (1, 0), "{st:?}");
        assert_eq!(linked(&p)[0].0, STATIC, "an ambiguous site stays inert");
    }

    /// Two services serving the same route share its iid (it is the name's
    /// hash), so each handler gets its own key and the client fans out.
    #[test]
    fn the_same_route_in_two_services_is_two_contracts() {
        let mut p = prog(
            &[("GET", "/health/live")],
            vec![route(0x08, 0xB1, "GET", "/health/live"), route(0x08, 0xB2, "GET", "/health/live")],
        );
        let st = link(&mut p);
        assert_eq!((st.routes, st.linked, st.fanout), (2, 1, 1), "{st:?}");
        let cs = &p.funcs[&hexid(&[0xC0; 32])].flow.as_ref().unwrap().callsites[0];
        assert_eq!(cs.callee_iids.len(), 2);
        assert_ne!(cs.callee_iids[0], vec![0x08; 32], "a collision is re-keyed per handler");
        let handlers: Vec<IidHex> = crate::graph::contracts(&p).into_iter().map(|c| c.handler).collect();
        assert_eq!(handlers, vec![hexid(&[0xB1; 32]), hexid(&[0xB2; 32])]);
    }

    #[test]
    fn disabled_links_nothing() {
        let mut p = prog(&[("POST", "/api/users")], vec![route(0x03, 0xA3, "POST", "/api/users")]);
        let st = link_loaded(&mut p, false);
        assert_eq!((st.sites, st.linked, st.unlinked), (1, 0, 1));
        assert_eq!(linked(&p)[0].0, STATIC);
    }

    // -- cache safety (§4.3) ------------------------------------------------

    /// `F(p) { http:POST /api/users (p); db.Exec(p) }` plus a route serving the
    /// template. Phase 1 — every summary, `summary_key` and contract hash —
    /// must be identical whether the site is linked or not: the link may act
    /// only in phase 2, through the contract view, or a warm summary store
    /// would serve a summary computed under a different callee environment.
    #[test]
    fn phase_one_is_identical_linked_or_not() {
        use crate::catalog::Catalog;
        use crate::ifds::Engine;
        let cat = Catalog::load_str("[[sinks]]\nclass = \"sqli\"\nselector = \"db.Exec\"\n").unwrap();
        let mk = || {
            let mut p = prog(&[("POST", "/api/users")], vec![route(0x03, 0xA3, "POST", "/api/users")]);
            let f = p.funcs.get_mut(&hexid(&[0xC0; 32])).unwrap();
            f.source_params = vec![0];
            let fl = f.flow.as_mut().unwrap();
            fl.vertices.push(vertex(10, cgf::VertexKind::InParam, 0, 0));
            fl.vertices.push(vertex(11, cgf::VertexKind::CallArgPort, 0, 1));
            fl.edges = vec![edge(10, 1), edge(10, 11)];
            fl.callsites.push(cgf::CallSite { id: 1, callee_fqn: "db.Exec".into(), argc: 1, ..Default::default() });
            p
        };
        let plain = mk();
        let mut linked_p = mk();
        assert_eq!(link(&mut linked_p).linked, 1);

        let mut a = Engine::new(&plain, &cat);
        let ra = a.run_with_store(&mut crate::summarystore::SummaryStore::ephemeral());
        let mut b = Engine::new(&linked_p, &cat);
        let rb = b.run_with_store(&mut crate::summarystore::SummaryStore::ephemeral());
        assert_eq!((ra.hits, ra.misses, ra.scc_recomputed), (rb.hits, rb.misses, rb.scc_recomputed));
        assert_eq!(a.summary_keys, b.summary_keys);
        assert_eq!(a.contract_hashes, b.contract_hashes);
        assert_eq!(a.summaries.len(), b.summaries.len());
        for (iid, sa) in &a.summaries {
            let sb = &b.summaries[iid];
            assert_eq!(sa.flows, sb.flows);
            assert_eq!(format!("{:?}", sa.sink_hits), format!("{:?}", sb.sink_hits));
        }
        // and the frontend's bid is untouched
        assert_eq!(
            plain.funcs[&hexid(&[0xC0; 32])].id,
            linked_p.funcs[&hexid(&[0xC0; 32])].id
        );
    }
}
