// `taint` output formats: JSON (the chains as they are), text, SARIF 2.1.0.
use crate::catalog::Catalog;
use crate::report::Chain;
use crate::witness::RouteHop;
use anyhow::Result;
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};

#[derive(clap::ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum Format {
    Json,
    Text,
    Sarif,
}

pub fn render(format: Format, chains: &[Chain], cat: &Catalog) -> Result<String> {
    Ok(match format {
        Format::Json => serde_json::to_string_pretty(chains)?,
        Format::Text => text(chains),
        Format::Sarif => serde_json::to_string_pretty(&sarif(chains, cat))?,
    })
}

/// `--fail-on`: the sink classes that fail the run.
#[derive(Debug, PartialEq, Eq)]
pub enum FailOn {
    Any,
    Classes(BTreeSet<String>),
}

impl FailOn {
    /// `any`, or a comma-separated list of sink classes of `cat`. A class the
    /// catalog does not define is an error: a typo must not make CI pass.
    pub fn parse(spec: &str, cat: &Catalog) -> std::result::Result<FailOn, String> {
        let items: Vec<&str> = spec.split(',').map(str::trim).filter(|s| !s.is_empty()).collect();
        if items.is_empty() {
            return Err("--fail-on needs `any` or a comma-separated list of sink classes".into());
        }
        if items.contains(&"any") {
            return Ok(FailOn::Any);
        }
        let known = cat.sink_classes();
        let bad: Vec<&&str> = items.iter().filter(|c| !known.contains(**c)).collect();
        if !bad.is_empty() {
            return Err(format!(
                "--fail-on: {} not a sink class of the catalog (classes: {})",
                bad.iter().map(|c| format!("{c:?} is")).collect::<Vec<_>>().join(", "),
                known.into_iter().collect::<Vec<_>>().join(", ")
            ));
        }
        Ok(FailOn::Classes(items.into_iter().map(String::from).collect()))
    }

    /// How many of `chains` fail the run.
    pub fn count(&self, chains: &[Chain]) -> usize {
        match self {
            FailOn::Any => chains.len(),
            FailOn::Classes(cs) => chains.iter().filter(|c| cs.contains(&c.sink_class)).count(),
        }
    }
}

// --- text ------------------------------------------------------------------

fn location(h: &RouteHop) -> String {
    match (&h.file, h.line) {
        (Some(f), Some(l)) => format!("{f}:{l}"),
        (Some(f), None) => f.clone(),
        _ => "-".into(),
    }
}

fn what(h: &RouteHop) -> &str {
    if h.callee.is_empty() { &h.func } else { &h.callee }
}

fn incomplete_str(c: &Chain) -> Option<String> {
    let i = c.route.as_ref()?.incomplete.as_ref()?;
    serde_json::to_value(i).ok()?.as_str().map(String::from)
}

fn text(chains: &[Chain]) -> String {
    let cw = chains.iter().map(|c| c.sink_class.len()).max().unwrap_or(0);
    let mut out = String::new();
    for c in chains {
        let sink = c.route.as_ref().and_then(|r| r.hops.last());
        let (sink_repo, sink_what) = match sink {
            Some(h) => (h.repo.as_str(), what(h)),
            None => (c.source_repo.as_str(), c.hops.last().map_or("?", |h| h.detail.as_str())),
        };
        out.push_str(&format!(
            "{:cw$}  {} {} → {} {}\n",
            c.sink_class, c.source_repo, c.source_fn, sink_repo, sink_what
        ));
        let Some(r) = &c.route else {
            out.push('\n');
            continue;
        };
        let mut parts = vec![format!("route {}", r.id)];
        if r.boundaries > 0 {
            parts.push(format!(
                "{} boundar{}",
                r.boundaries,
                if r.boundaries == 1 { "y" } else { "ies" }
            ));
        }
        parts.push(format!("confidence {:.2}", c.route_confidence));
        if let Some(b) = &c.backward {
            let v = serde_json::to_value(b.verdict).ok();
            parts.push(format!("backward {}", v.as_ref().and_then(Value::as_str).unwrap_or("?")));
        }
        if let Some(i) = incomplete_str(c) {
            parts.push(format!("incomplete: {i}"));
        }
        out.push_str(&format!("  {}\n", parts.join(" · ")));
        let kw = r.hops.iter().map(|h| format!("{:?}", h.kind).len()).max().unwrap_or(0);
        let rw = r.hops.iter().map(|h| h.repo.chars().count()).max().unwrap_or(0);
        let lw = r.hops.iter().map(|h| location(h).chars().count()).max().unwrap_or(0);
        for h in &r.hops {
            out.push_str(&format!(
                "  {:kw$}  {:rw$}  {:lw$}  {}\n",
                format!("{:?}", h.kind).to_lowercase(),
                h.repo,
                location(h),
                what(h)
            ));
        }
        out.push('\n');
    }
    let mut by: BTreeMap<&str, usize> = BTreeMap::new();
    for c in chains {
        *by.entry(&c.sink_class).or_default() += 1;
    }
    let mut by: Vec<_> = by.into_iter().collect();
    by.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(b.0)));
    out.push_str(&format!(
        "{} finding{}{}{}",
        chains.len(),
        if chains.len() == 1 { "" } else { "s" },
        if by.is_empty() { "" } else { ": " },
        by.iter().map(|(c, n)| format!("{n} {c}")).collect::<Vec<_>>().join(", ")
    ));
    out
}

// --- SARIF -----------------------------------------------------------------

/// Percent-encode what a URI reference cannot hold; `/`, `:`, `$`, `+` and the
/// rest of a path stay as written.
fn uri_escape(p: &str) -> String {
    let mut s = String::with_capacity(p.len());
    for b in p.bytes() {
        match b {
            b' ' | b'%' | b'#' | b'?' | b'[' | b']' | b'{' | b'}' | b'^' | b'`' | b'|' | b'\\'
            | b'"' | b'<' | b'>' => s.push_str(&format!("%{b:02X}")),
            0x80.. => s.push_str(&format!("%{b:02X}")),
            _ => s.push(b as char),
        }
    }
    s
}

/// `physicalLocation` for a file as stored in the CGF: relative paths resolve
/// against the repo's `uriBaseId`, absolute ones are `file://` URIs. Repos that
/// got a base id are collected in `bases`.
fn physical(
    repo: &str,
    file: &str,
    line: Option<i32>,
    col: Option<i32>,
    bases: &mut BTreeSet<String>,
) -> Value {
    let art = if file.starts_with('/') {
        json!({ "uri": format!("file://{}", uri_escape(file)) })
    } else {
        bases.insert(repo.to_string());
        json!({ "uri": uri_escape(file), "uriBaseId": repo })
    };
    let mut loc = json!({ "artifactLocation": art });
    if let Some(l) = line.filter(|l| *l > 0) {
        let mut region = json!({ "startLine": l });
        if let Some(c) = col.filter(|c| *c > 0) {
            region["startColumn"] = json!(c);
        }
        loc["region"] = region;
    }
    loc
}

fn hop_physical(h: &RouteHop, bases: &mut BTreeSet<String>) -> Option<Value> {
    h.file.as_ref().map(|f| physical(&h.repo, f, h.line, h.col, bases))
}

fn kind_str(h: &RouteHop) -> String {
    format!("{:?}", h.kind).to_lowercase()
}

fn sarif(chains: &[Chain], cat: &Catalog) -> Value {
    let classes: BTreeSet<&str> = chains.iter().map(|c| c.sink_class.as_str()).collect();
    let rules: Vec<Value> = classes
        .iter()
        .map(|c| {
            json!({
                "id": c,
                "name": c,
                "shortDescription": { "text": format!("Untrusted data reaches a {c} sink") },
                "defaultConfiguration": { "level": cat.severity_of(c).as_str() },
                "properties": { "tags": ["security"] },
            })
        })
        .collect();
    let rule_index: BTreeMap<&str, usize> =
        classes.iter().enumerate().map(|(i, c)| (*c, i)).collect();

    let mut bases = BTreeSet::new();
    let results: Vec<Value> = chains
        .iter()
        .map(|c| {
            let hops: &[RouteHop] = c.route.as_ref().map_or(&[], |r| r.hops.as_slice());
            let (sink_repo, sink_what) = match hops.last() {
                Some(h) => (h.repo.as_str(), what(h)),
                None => (c.source_repo.as_str(), c.hops.last().map_or("?", |h| h.detail.as_str())),
            };
            let mut msg = format!(
                "{} ({}) reaches {} sink {} in {}",
                c.source_fn, c.source_repo, c.sink_class, sink_what, sink_repo
            );
            let n = c.route.as_ref().map_or(0, |r| r.boundaries);
            if n > 0 {
                msg.push_str(&format!(
                    ", crossing {n} service boundar{}",
                    if n == 1 { "y" } else { "ies" }
                ));
            }
            // the sink hop; an incomplete route has none, so its last located hop
            let primary = hops
                .iter()
                .rev()
                .find_map(|h| hop_physical(h, &mut bases))
                .or_else(|| {
                    c.sink_span
                        .as_ref()
                        .map(|s| physical(&c.source_repo, &s.file, Some(s.line), Some(s.col), &mut bases))
                });
            let flow: Vec<Value> = hops
                .iter()
                .map(|h| {
                    let mut location = json!({
                        "message": { "text": format!("{}: {}", kind_str(h), what(h)) },
                    });
                    if let Some(p) = hop_physical(h, &mut bases) {
                        location["physicalLocation"] = p;
                    }
                    json!({ "location": location, "kinds": [kind_str(h)] })
                })
                .collect();
            let mut props = json!({
                "routeConfidence": c.route_confidence,
                "sourceRepo": c.source_repo,
                "sourceFunction": c.source_fn,
            });
            let mut r = json!({
                "ruleId": c.sink_class,
                "ruleIndex": rule_index[c.sink_class.as_str()],
                "level": cat.severity_of(&c.sink_class).as_str(),
                "message": { "text": msg },
                "locations": primary.map(|p| vec![json!({ "physicalLocation": p })]).unwrap_or_default(),
            });
            if let Some(route) = &c.route {
                r["codeFlows"] = json!([{ "threadFlows": [{ "locations": flow }] }]);
                r["partialFingerprints"] = json!({ "panopticodeRoute/v1": route.fingerprint });
                props["routeId"] = json!(route.id);
                props["boundaries"] = json!(route.boundaries);
            }
            if let Some(b) = &c.backward {
                props["backwardVerdict"] = serde_json::to_value(b.verdict).unwrap_or(Value::Null);
            }
            if let Some(i) = incomplete_str(c) {
                props["incomplete"] = json!(i);
            }
            r["properties"] = props;
            r
        })
        .collect();

    let base_ids: serde_json::Map<String, Value> = bases
        .into_iter()
        .map(|repo| {
            let d = json!({ "description": { "text": format!("root of {repo}") } });
            (repo, d)
        })
        .collect();
    let mut run = json!({
        "tool": { "driver": {
            "name": "panopticode",
            "version": env!("CARGO_PKG_VERSION"),
            "informationUri": "https://panopti.org",
            "rules": rules,
        } },
        "results": results,
    });
    if !base_ids.is_empty() {
        run["originalUriBaseIds"] = Value::Object(base_ids);
    }
    json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [run],
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::witness::{HopKind, Route};

    fn hop(kind: HopKind, repo: &str, file: Option<&str>, line: i32) -> RouteHop {
        RouteHop {
            repo: repo.into(),
            func: "f".into(),
            file: file.map(String::from),
            line: file.map(|_| line),
            col: file.map(|_| 4),
            kind,
            callee: if kind == HopKind::Source { String::new() } else { "g".into() },
            field: None,
            fields: Vec::new(),
            confidence: 1.0,
        }
    }

    fn chain(class: &str, file: &str) -> Chain {
        Chain {
            source_repo: "a".into(),
            source_fn: "a.f".into(),
            sink_class: class.into(),
            sink_span: None,
            sink_field: None,
            sink_fields: Vec::new(),
            hops: Vec::new(),
            route: Some(Route {
                id: "iiii".into(),
                fingerprint: "ffff".into(),
                hops: vec![
                    hop(HopKind::Source, "a", None, 0),
                    hop(HopKind::Boundary, "a", Some("x/y.go"), 3),
                    hop(HopKind::Sink, "b", Some(file), 9),
                ],
                incomplete: None,
                boundaries: 1,
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

    fn cat() -> Catalog {
        Catalog::load_str("[severity]\nsqli = \"error\"\n[[sinks]]\nclass = \"sqli\"\nselector = \"g\"\n").unwrap()
    }

    #[test]
    fn fail_on_parses_and_counts() {
        let c = cat();
        let chains = vec![chain("sqli", "s.go"), chain("xss", "t.go")];
        assert_eq!(FailOn::parse("any", &c), Ok(FailOn::Any));
        assert_eq!(FailOn::Any.count(&chains), 2);
        let f = FailOn::parse("sqli", &c).unwrap();
        assert_eq!(f.count(&chains), 1);
        assert_eq!(f.count(&chains[1..]), 0);
        let e = FailOn::parse("sqli,sqlii", &c).unwrap_err();
        assert!(e.contains("\"sqlii\" is not a sink class"), "{e}");
        assert!(FailOn::parse("", &c).is_err());
    }

    #[test]
    fn severity_must_be_a_known_level() {
        assert!(Catalog::load_str("[severity]\nsqli = \"high\"\n").is_err());
        assert_eq!(cat().severity_of("sqli").as_str(), "error");
        assert_eq!(cat().severity_of("xss").as_str(), "warning");
    }

    #[test]
    fn sarif_shape() {
        let chains = vec![chain("xss", "/abs/s.go"), chain("sqli", "s [1].go")];
        let v = sarif(&chains, &cat());
        assert_eq!(v["version"], "2.1.0");
        let run = &v["runs"][0];
        let ids: Vec<_> = run["tool"]["driver"]["rules"].as_array().unwrap().iter().map(|r| r["id"].clone()).collect();
        assert_eq!(ids, vec![json!("sqli"), json!("xss")]);
        let res = run["results"].as_array().unwrap();
        assert_eq!(res.len(), 2);
        assert_eq!(res[0]["level"], "warning");
        assert_eq!(res[1]["level"], "error");
        assert_eq!(res[1]["ruleIndex"], 0);
        assert_eq!(
            res[0]["message"]["text"],
            "a.f (a) reaches xss sink g in b, crossing 1 service boundary"
        );
        let flow = res[0]["codeFlows"][0]["threadFlows"][0]["locations"].as_array().unwrap();
        assert_eq!(flow.len(), 3);
        assert!(flow[0]["location"].get("physicalLocation").is_none());
        assert_eq!(flow[1]["location"]["physicalLocation"]["artifactLocation"]["uriBaseId"], "a");
        assert_eq!(flow[1]["location"]["physicalLocation"]["region"]["startColumn"], 4);
        // absolute path: file URI, no base id
        let loc = &res[0]["locations"][0]["physicalLocation"]["artifactLocation"];
        assert_eq!(loc["uri"], "file:///abs/s.go");
        assert!(loc.get("uriBaseId").is_none());
        assert_eq!(
            res[1]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
            "s%20%5B1%5D.go"
        );
        assert_eq!(res[0]["partialFingerprints"]["panopticodeRoute/v1"], "ffff");
        let bases: Vec<_> = run["originalUriBaseIds"].as_object().unwrap().keys().cloned().collect();
        assert_eq!(bases, vec!["a", "b"]);
    }

    #[test]
    fn text_shape() {
        let t = text(&[chain("sqli", "s.go"), chain("sqli", "t.go")]);
        assert!(t.starts_with("sqli  a a.f → b g\n  route iiii · 1 boundary · confidence 1.00\n"), "{t}");
        assert!(t.contains("\n  sink      b  s.go:9    g\n"), "{t}");
        assert!(t.ends_with("\n\n2 findings: 2 sqli"), "{t}");
        assert_eq!(text(&[]), "0 findings");
    }
}
