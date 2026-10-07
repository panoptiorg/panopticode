// catalog.toml loader — sources / sinks / sanitizers / propagators (doc 04 §3).
use anyhow::Result;
use regex::Regex;
use serde::Deserialize;
use std::path::Path;

#[derive(Debug, Deserialize)]
pub struct RawCatalog {
    #[serde(default)]
    pub sources: Vec<RawRule>,
    #[serde(default)]
    pub sinks: Vec<RawRule>,
    #[serde(default)]
    pub sanitizers: Vec<RawRule>,
    /// B1 / doc 31 §4: calls that BUILD an error out of other values, so their
    /// `error` result legitimately carries request data
    /// (`fmt.Errorf("… %s", account, err)`). Everything else's error result is
    /// treated as non-data by the default leaf under `--no-error-leaf`.
    #[serde(default)]
    pub error_wrappers: Vec<RawRule>,
    /// Library calls that move data somewhere other than their return value —
    /// into the receiver (`sb.WriteString(s)`) or into a pointer argument
    /// (`json.Unmarshal(data, &v)`). See `PropagatorRule`.
    #[serde(default)]
    pub propagators: Vec<RawPropagator>,
}

#[derive(Debug, Deserialize)]
pub struct RawPropagator {
    pub selector: Option<String>,
    pub selector_regex: Option<String>,
    pub from: String,
    pub to: String,
    #[allow(dead_code)]
    pub note: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct RawRule {
    pub kind: Option<String>,
    pub class: Option<String>,
    pub selector: Option<String>,
    pub selector_regex: Option<String>,
    pub arg: Option<String>,
    #[allow(dead_code)]
    pub note: Option<String>,
}

/// One side of a propagator: which of a call's ports it names. Indices are the
/// same 0-based arg-port numbering sinks use (the receiver is port 0 when
/// `arg0_is_receiver`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortSpec {
    Index(u32),
    /// port 0, only when the call has a receiver
    Receiver,
    /// every port except the receiver
    Args,
    /// every port
    Any,
    /// every result port (`to` only)
    Return,
}

impl PortSpec {
    /// The arg ports this spec names at a call with `argc` ports.
    pub fn ports(self, argc: u32, recv: bool) -> Vec<u32> {
        match self {
            PortSpec::Index(i) if i < argc => vec![i],
            PortSpec::Index(_) | PortSpec::Return => Vec::new(),
            PortSpec::Receiver if recv && argc > 0 => vec![0],
            PortSpec::Receiver => Vec::new(),
            PortSpec::Args => ((recv as u32)..argc).collect(),
            PortSpec::Any => (0..argc).collect(),
        }
    }
}

/// A library call's data movement the default leaf cannot see. The default leaf
/// (ifds.rs) sends every tainted argument to the call's RESULTS only, which is
/// right for `fmt.Sprintf` and wrong for anything that writes into its receiver
/// or through a pointer argument. A propagator says, for calls whose callee
/// matches: data on a `from` port reaches the `to` ports. It only applies where
/// the callee has no summary (a body-less library call) and it only ADDS flow —
/// the default leaf still runs — so a rule can never cost a finding.
///
/// `to = "none"` names no flow at all: it records that the callee was reviewed
/// and writes nothing, which takes it off the `--unmodeled` report.
pub struct PropagatorRule {
    pub m: Matcher,
    pub from: Vec<PortSpec>,
    pub to: Vec<PortSpec>,
}

impl PropagatorRule {
    /// Does data arriving on arg port `port` trigger this rule?
    pub fn fires_from(&self, port: u32, argc: u32, recv: bool) -> bool {
        self.from.iter().any(|p| p.ports(argc, recv).contains(&port))
    }
}

/// `"1"`, `"receiver"`, `"args"`, `"any"`, `"return"`, `"none"`, or a comma
/// list of them. A malformed spec fails the load: a rule that silently never
/// fires is exactly the zero-recall failure catalog-fit exists to catch.
fn parse_ports(spec: &str, side: &str) -> Result<Vec<PortSpec>> {
    let spec = spec.trim();
    if side == "to" && spec == "none" {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    for tok in spec.split(',').map(str::trim) {
        let p = match tok {
            "receiver" => PortSpec::Receiver,
            "args" => PortSpec::Args,
            "any" => PortSpec::Any,
            "return" if side == "to" => PortSpec::Return,
            t => PortSpec::Index(t.parse().map_err(|_| {
                anyhow::anyhow!(
                    "propagator `{side}` must be a 0-based arg index, receiver, args, any{} — got {tok:?}",
                    if side == "to" { ", return or none" } else { "" }
                )
            })?),
        };
        out.push(p);
    }
    Ok(out)
}

pub struct Matcher {
    exact: Option<String>,
    re: Option<Regex>,
    /// the selector text as written — for fit diagnostics only
    pub label: String,
}
impl Matcher {
    /// A `selector_regex` that does not compile is a LOAD ERROR, never a rule
    /// that silently matches nothing: an inert rule is indistinguishable from
    /// "nothing found", which is the single failure mode this tool spends the
    /// most effort making loud.
    fn new(r: &RawRule) -> std::result::Result<Self, String> {
        Self::of(&r.selector, &r.selector_regex)
    }
    fn of(selector: &Option<String>, selector_regex: &Option<String>) -> std::result::Result<Self, String> {
        let re = match selector_regex.as_deref() {
            Some(src) => Some(
                Regex::new(src).map_err(|e| format!("selector_regex {src:?} does not compile: {e}"))?,
            ),
            None => None,
        };
        Ok(Matcher {
            exact: selector.clone(),
            re,
            label: selector.clone().or_else(|| selector_regex.clone()).unwrap_or_default(),
        })
    }
    pub fn matches(&self, fqn: &str) -> bool {
        if let Some(e) = &self.exact {
            if e == fqn || fqn.ends_with(e) {
                return true;
            }
        }
        if let Some(re) = &self.re {
            if re.is_match(fqn) {
                return true;
            }
        }
        false
    }
}

/// Build a rule's matcher, turning a compile failure into a load error that
/// names where in the file it came from.
fn matcher(section: &str, r: &RawRule) -> Result<Matcher> {
    Matcher::new(r).map_err(|e| {
        let label = r
            .selector
            .clone()
            .or_else(|| r.selector_regex.clone())
            .unwrap_or_default();
        anyhow::anyhow!("[[{section}]] rule {label:?}: {e}")
    })
}

pub struct SourceRule {
    pub kind: String,
    pub m: Matcher,
}
/// Sink arg spec: "any", or a 0-based index over the call's arg-ports
/// (receiver is arg 0 when arg0_is_receiver) — catalog.toml header contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SinkArg {
    Any,
    Index(u32),
}

pub struct SinkRule {
    pub class: String,
    pub m: Matcher,
    pub arg: SinkArg,
}
pub struct SanitizerRule {
    pub kind: String,
    pub m: Matcher,
}
/// An error-constructing callee (a measurement on one large Go service found
/// where such a call has a non-error operand, i.e. genuinely carries data).
pub struct ErrorWrapperRule {
    pub m: Matcher,
}

pub struct Catalog {
    pub sources: Vec<SourceRule>,
    pub sinks: Vec<SinkRule>,
    pub sanitizers: Vec<SanitizerRule>,
    pub error_wrappers: Vec<ErrorWrapperRule>,
    pub propagators: Vec<PropagatorRule>,
}

impl Catalog {
    pub fn load(path: &Path) -> Result<Catalog> {
        Self::load_str(&std::fs::read_to_string(path)?)
    }

    pub fn load_str(toml_src: &str) -> Result<Catalog> {
        let raw: RawCatalog = toml::from_str(toml_src)?;
        Ok(Catalog {
            sources: raw
                .sources
                .iter()
                .map(|r| {
                    Ok(SourceRule {
                        kind: r.kind.clone().unwrap_or_default(),
                        m: matcher("sources", r)?,
                    })
                })
                .collect::<Result<Vec<_>>>()?,
            sinks: raw
                .sinks
                .iter()
                .map(|r| {
                    // A malformed index must fail the load, not silently
                    // become a sink that never fires.
                    let arg = match r.arg.as_deref() {
                        None | Some("") | Some("any") => SinkArg::Any,
                        Some(s) => SinkArg::Index(s.parse().map_err(|_| {
                            anyhow::anyhow!(
                                "sink arg must be \"any\" or a 0-based arg index, got {s:?}"
                            )
                        })?),
                    };
                    Ok(SinkRule {
                        class: r.class.clone().unwrap_or_default(),
                        m: matcher("sinks", r)?,
                        arg,
                    })
                })
                .collect::<Result<Vec<_>>>()?,
            sanitizers: raw
                .sanitizers
                .iter()
                .map(|r| {
                    Ok(SanitizerRule {
                        kind: r.kind.clone().unwrap_or_default(),
                        m: matcher("sanitizers", r)?,
                    })
                })
                .collect::<Result<Vec<_>>>()?,
            error_wrappers: raw
                .error_wrappers
                .iter()
                .map(|r| Ok(ErrorWrapperRule { m: matcher("error_wrappers", r)? }))
                .collect::<Result<Vec<_>>>()?,
            propagators: raw
                .propagators
                .iter()
                .map(|r| {
                    let m = Matcher::of(&r.selector, &r.selector_regex).map_err(|e| {
                        let label = r.selector.clone().or_else(|| r.selector_regex.clone()).unwrap_or_default();
                        anyhow::anyhow!("[[propagators]] rule {label:?}: {e}")
                    })?;
                    Ok(PropagatorRule {
                        m,
                        from: parse_ports(&r.from, "from")?,
                        to: parse_ports(&r.to, "to")?,
                    })
                })
                .collect::<Result<Vec<_>>>()?,
        })
    }

    /// Catalog fit: every rule that matches NO callee fqn in the loaded
    /// program. A catalog is policy fitted to some corpus; on another corpus a
    /// rule that matches nothing yields silent zero recall — 41 recall points
    /// on the broker vertical hinged on exactly this. Returns `(section,
    /// class-or-kind, selector)` per inert rule; the `__annotation__` escape
    /// hatch is not a selector and is skipped.
    pub fn unmatched_rules<'a, I>(&self, fqns: I) -> Vec<(&'static str, String, String)>
    where
        I: IntoIterator<Item = &'a str>,
    {
        let mut hit_src = vec![false; self.sources.len()];
        let mut hit_sink = vec![false; self.sinks.len()];
        let mut hit_san = vec![false; self.sanitizers.len()];
        let mut hit_wrap = vec![false; self.error_wrappers.len()];
        for fqn in fqns {
            for (i, r) in self.sources.iter().enumerate() {
                if !hit_src[i] && r.m.matches(fqn) {
                    hit_src[i] = true;
                }
            }
            for (i, r) in self.sinks.iter().enumerate() {
                if !hit_sink[i] && r.m.matches(fqn) {
                    hit_sink[i] = true;
                }
            }
            for (i, r) in self.sanitizers.iter().enumerate() {
                if !hit_san[i] && r.m.matches(fqn) {
                    hit_san[i] = true;
                }
            }
            for (i, r) in self.error_wrappers.iter().enumerate() {
                if !hit_wrap[i] && r.m.matches(fqn) {
                    hit_wrap[i] = true;
                }
            }
        }
        let mut out = Vec::new();
        let skip = |m: &Matcher| m.label.starts_with("__");
        for (i, r) in self.sources.iter().enumerate() {
            if !hit_src[i] && !skip(&r.m) {
                out.push(("sources", r.kind.clone(), r.m.label.clone()));
            }
        }
        for (i, r) in self.sinks.iter().enumerate() {
            if !hit_sink[i] && !skip(&r.m) {
                out.push(("sinks", r.class.clone(), r.m.label.clone()));
            }
        }
        for (i, r) in self.sanitizers.iter().enumerate() {
            if !hit_san[i] && !skip(&r.m) {
                out.push(("sanitizers", r.kind.clone(), r.m.label.clone()));
            }
        }
        for (i, r) in self.error_wrappers.iter().enumerate() {
            if !hit_wrap[i] && !skip(&r.m) {
                out.push(("error_wrappers", String::new(), r.m.label.clone()));
            }
        }
        out
    }
    /// The second way a sink rule can be inert, invisible to `unmatched_rules`:
    /// the fqn matches call sites, but `arg` is an index no call site is wide
    /// enough to have. `sink_matches_arg` is `i == arg_idx`, so a rule with
    /// `arg = "9"` on calls that only ever have 2 arg ports can never fire even
    /// though every fit report calls it "matched".
    ///
    /// Takes `(callee_fqn, argc)` pairs — distinct pairs are enough. Returns
    /// `(class, selector, arg index, largest argc seen)` per rule whose fqn
    /// matched at least once and whose index was never in range. `arg = "any"`
    /// rules are never reported; neither is the `__annotation__` escape hatch.
    pub fn sink_arg_never_in_range<'a, I>(&self, calls: I) -> Vec<(String, String, u32, u32)>
    where
        I: IntoIterator<Item = (&'a str, u32)>,
    {
        let n = self.sinks.len();
        let mut matched = vec![false; n];
        let mut in_range = vec![false; n];
        let mut max_argc = vec![0u32; n];
        for (fqn, argc) in calls {
            for (i, r) in self.sinks.iter().enumerate() {
                let SinkArg::Index(idx) = r.arg else { continue };
                if !r.m.matches(fqn) {
                    continue;
                }
                matched[i] = true;
                max_argc[i] = max_argc[i].max(argc);
                if idx < argc {
                    in_range[i] = true;
                }
            }
        }
        let mut out = Vec::new();
        for (i, r) in self.sinks.iter().enumerate() {
            let SinkArg::Index(idx) = r.arg else { continue };
            if matched[i] && !in_range[i] && !r.m.label.starts_with("__") {
                out.push((r.class.clone(), r.m.label.clone(), idx, max_argc[i]));
            }
        }
        out
    }

    pub fn rule_count(&self) -> usize {
        self.sources.len() + self.sinks.len() + self.sanitizers.len() + self.error_wrappers.len()
    }

    /// Propagator fit: (rules matching at least one callee fqn, total rules).
    /// Reported as one line rather than per rule — a shipped starter set is
    /// mostly stdlib calls a given repo never makes, and a per-rule "inert"
    /// warning for each would bury the source/sink ones that do matter.
    pub fn propagator_fit<'a, I>(&self, fqns: I) -> (usize, usize)
    where
        I: IntoIterator<Item = &'a str>,
    {
        let mut hit = vec![false; self.propagators.len()];
        for fqn in fqns {
            for (i, r) in self.propagators.iter().enumerate() {
                if !hit[i] && r.m.matches(fqn) {
                    hit[i] = true;
                }
            }
        }
        (hit.iter().filter(|h| **h).count(), hit.len())
    }

    /// Every propagator whose selector matches this callee.
    pub fn propagators_for<'a>(&'a self, fqn: &'a str) -> impl Iterator<Item = &'a PropagatorRule> + 'a {
        self.propagators.iter().filter(move |p| p.m.matches(fqn))
    }

    pub fn source_of(&self, fqn: &str) -> Option<&SourceRule> {
        self.sources.iter().find(|s| s.m.matches(fqn))
    }
    pub fn sink_of(&self, fqn: &str) -> Option<&SinkRule> {
        self.sinks.iter().find(|s| s.m.matches(fqn))
    }
    pub fn sanitizer_of(&self, fqn: &str) -> Option<&SanitizerRule> {
        self.sanitizers.iter().find(|s| s.m.matches(fqn))
    }
    /// True when this callee constructs an error from its arguments, so taint
    /// must keep flowing into its `error` result under `--no-error-leaf`.
    pub fn is_error_wrapper(&self, fqn: &str) -> bool {
        self.error_wrappers.iter().any(|w| w.m.matches(fqn))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sink_arg_parses_any_and_index() {
        let cat = Catalog::load_str(
            r#"
[[sinks]]
class = "a"
selector = "x.F"

[[sinks]]
class = "b"
selector = "y.G"
arg = "any"

[[sinks]]
class = "c"
selector = "z.H"
arg = "2"
"#,
        )
        .unwrap();
        assert_eq!(cat.sinks[0].arg, SinkArg::Any);
        assert_eq!(cat.sinks[1].arg, SinkArg::Any);
        assert_eq!(cat.sinks[2].arg, SinkArg::Index(2));
    }

    #[test]
    fn propagator_ports_parse_and_expand() {
        let cat = Catalog::load_str(
            r#"
[[propagators]]
selector_regex = '\(\*strings\.Builder\)\.WriteString$'
from = "1"
to   = "receiver"

[[propagators]]
selector = "encoding/json.Unmarshal"
from = "0"
to   = "1, return"

[[propagators]]
selector = "pkg.Reviewed"
from = "any"
to   = "none"
"#,
        )
        .unwrap();
        let b = &cat.propagators[0];
        assert_eq!(b.from, vec![PortSpec::Index(1)]);
        assert_eq!(b.to, vec![PortSpec::Receiver]);
        assert!(b.fires_from(1, 2, true));
        assert!(!b.fires_from(0, 2, true), "the receiver is not a `from` port here");
        assert_eq!(cat.propagators[1].to, vec![PortSpec::Index(1), PortSpec::Return]);
        assert!(cat.propagators[2].to.is_empty(), "`none` is an empty target list");
        // expansion against a call's shape
        assert_eq!(PortSpec::Receiver.ports(3, true), vec![0]);
        assert_eq!(PortSpec::Receiver.ports(3, false), Vec::<u32>::new());
        assert_eq!(PortSpec::Args.ports(3, true), vec![1, 2]);
        assert_eq!(PortSpec::Args.ports(3, false), vec![0, 1, 2]);
        assert_eq!(PortSpec::Index(5).ports(3, false), Vec::<u32>::new());
        assert_eq!(cat.propagators_for("(*strings.Builder).WriteString").count(), 1);
        assert_eq!(cat.propagators_for("encoding/json.Unmarshal").count(), 1);
        assert_eq!(cat.propagators_for("fmt.Sprintf").count(), 0);
    }

    #[test]
    fn propagator_junk_fails_load() {
        for bad in [
            "from = \"first\"\nto = \"0\"",
            "from = \"return\"\nto = \"0\"",   // return is a target, not a source
            "from = \"none\"\nto = \"0\"",
            "from = \"0\"\nto = \"1,nope\"",
        ] {
            let src = format!("[[propagators]]\nselector = \"x.F\"\n{bad}\n");
            assert!(Catalog::load_str(&src).is_err(), "must fail: {bad}");
        }
        let bad_re = "[[propagators]]\nselector_regex = \"(\"\nfrom = \"0\"\nto = \"1\"\n";
        assert!(Catalog::load_str(bad_re).is_err(), "an invalid regex must fail, not silently never match");
    }

    #[test]
    fn sink_arg_junk_fails_load() {
        let err = Catalog::load_str(
            "[[sinks]]\nclass = \"a\"\nselector = \"x.F\"\narg = \"first\"\n",
        );
        assert!(err.is_err(), "non-numeric sink arg must fail the load");
    }

    #[test]
    fn bad_regex_fails_load_and_names_the_rule() {
        // An uncompilable regex used to become a rule that matches nothing,
        // which is indistinguishable from "nothing found".
        for (section, body) in [
            ("sources", "[[sources]]\nkind = \"k\"\nselector_regex = \"a(b\"\n"),
            ("sinks", "[[sinks]]\nclass = \"sqli\"\nselector_regex = \"a(b\"\n"),
            ("sanitizers", "[[sanitizers]]\nkind = \"k\"\nselector_regex = \"a(b\"\n"),
            ("error_wrappers", "[[error_wrappers]]\nselector_regex = \"a(b\"\n"),
        ] {
            let err = match Catalog::load_str(body) {
                Err(e) => e,
                Ok(_) => panic!("an unparsable regex must fail the load ({section})"),
            };
            let msg = format!("{err:#}");
            assert!(msg.contains(section), "message must name the section: {msg}");
            assert!(msg.contains("a(b"), "message must quote the selector: {msg}");
            assert!(
                msg.contains("does not compile"),
                "message must carry the regex error: {msg}"
            );
        }
    }

    #[test]
    fn a_good_regex_still_loads() {
        let cat = Catalog::load_str("[[sinks]]\nclass = \"sqli\"\nselector_regex = \"^a\\\\.b$\"\n")
            .unwrap();
        assert!(cat.sink_of("a.b").is_some());
    }

    #[test]
    fn sink_arg_out_of_range_is_reported() {
        let cat = Catalog::load_str(
            r#"
[[sinks]]
class = "sqli"
selector = "x.Wide"
arg = "9"

[[sinks]]
class = "sqli"
selector = "x.Fits"
arg = "1"

[[sinks]]
class = "sqli"
selector = "x.Any"

[[sinks]]
class = "sqli"
selector = "x.Absent"
arg = "3"
"#,
        )
        .unwrap();
        // x.Wide is called with 2 arg ports, so arg 9 can never be reached;
        // x.Fits is in range; x.Any has no index; x.Absent matches no call at
        // all, which is unmatched_rules' business, not this one's.
        let calls = [("x.Wide", 2u32), ("x.Wide", 1), ("x.Fits", 2), ("x.Any", 1)];
        let out = cat.sink_arg_never_in_range(calls.iter().copied());
        assert_eq!(out.len(), 1, "exactly one rule is out of range: {out:?}");
        assert_eq!(out[0].1, "x.Wide");
        assert_eq!(out[0].2, 9, "the offending index");
        assert_eq!(out[0].3, 2, "the widest call site seen");
    }

    // -- the shipped example catalog ---------------------------------------

    fn example_catalog() -> Catalog {
        let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../catalog.example.toml");
        Catalog::load(&p).unwrap_or_else(|e| panic!("load {p:?}: {e:#}"))
    }

    /// Every rule in the shipped example must be able to match SOMETHING: a
    /// rule with neither an exact selector nor a compiled regex is inert by
    /// construction, which is the failure this whole file is built to avoid.
    #[test]
    fn example_catalog_has_no_rule_that_is_inert_by_construction() {
        let cat = example_catalog();
        let ms = cat
            .sources
            .iter()
            .map(|r| &r.m)
            .chain(cat.sinks.iter().map(|r| &r.m))
            .chain(cat.sanitizers.iter().map(|r| &r.m))
            .chain(cat.error_wrappers.iter().map(|r| &r.m));
        for m in ms {
            assert!(
                m.exact.is_some() || m.re.is_some(),
                "rule {:?} has neither selector nor selector_regex",
                m.label
            );
        }
    }

    /// Shape test. These are the `callee_fqn` strings the Go frontend emits for
    /// a call into each library — the import path, and a parenthesised receiver
    /// with a `*` only when the receiver is a pointer. Every historical bug in
    /// this catalog was a selector written against the SOURCE spelling instead.
    #[test]
    fn example_catalog_shapes() {
        let cat = example_catalog();
        for (fqn, class) in [
            ("(*database/sql.DB).Query", "sqli"),
            ("(*database/sql.Tx).ExecContext", "sqli"),
            ("(*database/sql.Stmt).QueryRowContext", "sqli"),
            ("(github.com/Masterminds/squirrel.SelectBuilder).ToSql", "sqli"),
            ("(github.com/Masterminds/squirrel.UpdateBuilder).ToSql", "sqli"),
            ("(*github.com/jackc/pgx/v5.Conn).SendBatch", "sqli"),
            ("(*github.com/jackc/pgx/v5.Batch).Queue", "sqli"),
            ("(*gorm.io/gorm.DB).Raw", "sqli"),
            ("(*gorm.io/gorm.DB).Order", "sqli"),
            ("(*go.mongodb.org/mongo-driver/mongo.Collection).Find", "sqli"),
            ("(*github.com/gocql/gocql.Session).Query", "sqli"),
            ("(*go.uber.org/zap.SugaredLogger).Infow", "log"),
            ("go.uber.org/zap.String", "log"),
            ("(*github.com/sirupsen/logrus.Entry).WithField", "log"),
            ("github.com/sirupsen/logrus.Errorf", "log"),
            ("(*github.com/rs/zerolog.Event).Str", "log"),
            ("log.Println", "log"),
            ("(*log.Logger).Printf", "log"),
            ("(*net/http.Client).Do", "egress"),
            ("net/http.NewRequestWithContext", "egress"),
            ("(*github.com/nats-io/nats.go.Conn).Publish", "egress"),
            ("(*os/exec.Cmd).Run", "exec"),
            ("os/exec.CommandContext", "exec"),
            ("(*html/template.Template).Execute", "xss"),
            ("(*text/template.Template).ExecuteTemplate", "xss"),
            ("html/template.HTML", "xss"),
            ("net/http.Redirect", "open_redirect"),
            ("(net/http.Header).Set", "open_redirect"),
            ("os.WriteFile", "file"),
            ("path/filepath.Join", "path"),
            ("(*github.com/redis/go-redis/v9.Client).Set", "storage"),
        ] {
            let got = cat.sink_of(fqn);
            assert_eq!(
                got.map(|s| s.class.as_str()),
                Some(class),
                "sink class for {fqn:?} (matched rule: {:?})",
                got.map(|s| s.m.label.as_str())
            );
        }

        // propagators: library calls that write into an argument
        for fqn in [
            "(*strings.Builder).WriteString",
            "(*bytes.Buffer).Write",
            "(*bufio.Writer).WriteString",
            "(*bytes.Reader).Read",
            "encoding/json.Unmarshal",
            "gopkg.in/yaml.v3.Unmarshal",
            "google.golang.org/protobuf/proto.Unmarshal",
            "(google.golang.org/protobuf/encoding/protojson.UnmarshalOptions).Unmarshal",
            "(*encoding/json.Decoder).Decode",
            "github.com/mitchellh/mapstructure.Decode",
            "github.com/jinzhu/copier.Copy",
            "fmt.Fprintf",
            "io.Copy",
            "io.ReadFull",
            "encoding/binary.Read",
            "(net/url.Values).Set",
            "(net/http.Header).Add",
            "maps.Copy[map[string]string,map[string]string]",
            "(*sync.Map).Store",
            "(*text/template.Template).Execute",
            "(*encoding/base64.Encoding).Decode",
            "encoding/hex.Decode",
            "Array.push",
            "Map.set",
            "Set.add",
            "Object.assign",
            "URLSearchParams.append",
        ] {
            assert!(cat.propagators_for(fqn).next().is_some(), "{fqn:?} must have a propagator");
        }
        // an unknown receiver's `.push` could be `router.push(url)`: never matched
        for fqn in [".push", "router.push", "fmt.Sprintf", "strings.Join", "(*database/sql.Rows).Scan"] {
            assert!(cat.propagators_for(fqn).next().is_none(), "{fqn:?} must NOT have a propagator");
        }

        for fqn in [
            "(*net/http.Request).FormValue",
            "(net/url.Values).Get",
            "(net/http.Header).Get",
            "github.com/go-chi/chi/v5.URLParam",
            "(*github.com/gin-gonic/gin.Context).ShouldBindJSON",
            "(github.com/labstack/echo/v4.Context).QueryParam",
            "github.com/gorilla/mux.Vars",
        ] {
            assert!(cat.source_of(fqn).is_some(), "{fqn:?} must be a source");
            assert!(
                cat.sink_of(fqn).is_none(),
                "{fqn:?} is a source, not a sink"
            );
        }

        for fqn in [
            "net/url.QueryEscape",
            "html.EscapeString",
            "github.com/google/uuid.Parse",
            "(*github.com/go-playground/validator/v10.Validate).Struct",
        ] {
            assert!(cat.sanitizer_of(fqn).is_some(), "{fqn:?} must be a sanitizer");
        }

        // -- negatives ---------------------------------------------------
        // The database/sql rule must be anchored on the import path, not on a
        // bare `.DB).Query` shape that every in-house wrapper also has.
        assert!(
            cat.sink_of("(*example.com/x.DB).Query").is_none(),
            "an in-house DB wrapper must not be swept up by the database/sql rule"
        );
        // fmt.Sprintf builds strings, including error strings: it is an error
        // wrapper, never a terminal operation.
        assert!(cat.sink_of("fmt.Sprintf").is_none(), "fmt.Sprintf is not a sink");
        assert!(cat.is_error_wrapper("fmt.Sprintf"));
        assert!(cat.is_error_wrapper("fmt.Errorf"));
    }
}
