// Step-level trace of a taint run (`--trace <file>`): one grep-stable line per
// analysis event (seed / summary / scc-start / scc-iter / apply / leaf /
// sink-hit / heap-hit / heap-cell / chain / widen), so "why is this chain (not)
// here" and "where does the run spend its time" are answerable from a file
// instead of guesswork. Opt-in; when off, the Engine carries None and no
// formatting work happens.
//
// `heap-cell` is the odd one out: one line per abstract heap cell rather than
// per analysis step, emitted once at the end of the W1F fixpoint. A cell is a
// program-wide object-insensitive join, so its writer/reader shape — 77 writers
// and 8 readers, say — is what separates a genuine producer/consumer pipe from
// an accumulator that merges unrelated request paths (debt A14). Its "fqn" for
// `--trace-fn` purposes is the human cell name, so `--trace-fn Builder.Error`
// selects one cell.
//
// `heap-narrow` (A16, doc 30 §6.1) is the instrument for the interface-cell
// narrowing: one `cell` line per interface-typed cell naming the concrete types
// the readers assert and the writers deposit, plus one `drop` line per pairing
// the narrowing removed. Read it BEFORE any key diff — "0 drops" has two very
// different causes (nothing to narrow vs. the writer tags never materialised)
// and the key counts alone cannot tell them apart.
//
// The type tags are hashes, not names — `hash.IIDFromParts("", "", "type:"+T,
// "")`, i.e. sha256 over four LITTLE-endian-8-byte-length-prefixed fields. To
// go from a candidate Go type string to its tag:
//
//   python3 -c 'import hashlib,struct,sys
//   h=hashlib.sha256()
//   for f in (b"",b"",b"type:"+sys.argv[1].encode(),b""):
//       h.update(struct.pack("<Q",len(f))+f)
//   print(h.hexdigest())' "gitlab.example/svc/domain.SBPParam"
//
// The `drop` lines carry `fn=`, the WRITER, which is usually the answer wanted
// (which type-switch arm lost its pairing) without resolving a tag at all.
//
// `--trace-events <csv>` (debt A11) restricts the trace to named kinds. The
// point is scale, not tidiness: doc 26 §2's fallback-attribution method reads
// only `chain` and `widen`, but at W1F's `--heap-slots-scope=all` the *full*
// trace extrapolates to ~50 GB and hits the 2 GB `ulimit -f` guard having
// emitted 4% of the events. So the kind gate must be checked BEFORE the
// `format_args!` is built — filtering the formatted line would still pay the
// formatting cost for every discarded event, which is most of them.
//
// Kind strings are exactly the line prefixes, so `--trace-events chain,widen`
// yields the same LINES as `grep "^chain\|^widen"` over the unfiltered trace,
// and every existing grep recipe keeps working.
//
// Not the same FILE, though: trace line order is per-process nondeterministic
// (the engine walks a HashMap; the chains JSON is sorted before printing, which
// is why findings are stable and this never showed up). Measured on wc-off: two
// runs of the same binary agree on the multiset and on every chain→widen
// attribution pair, and disagree on the order of whole functions. So attribution
// must always be computed WITHIN one trace file — never by diffing two.
use std::cell::RefCell;
use std::collections::HashSet;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::Path;

pub struct Trace {
    out: RefCell<BufWriter<File>>,
    filter: Option<String>,
    kinds: Option<HashSet<String>>,
}

impl Trace {
    pub fn open(path: &Path, filter: Option<String>, kinds: Option<&str>) -> anyhow::Result<Trace> {
        let kinds = kinds.map(|s| {
            s.split(',')
                .map(str::trim)
                .filter(|k| !k.is_empty())
                .map(str::to_string)
                .collect::<HashSet<_>>()
        });
        if let Some(k) = &kinds {
            if k.is_empty() {
                anyhow::bail!("--trace-events was given no kinds");
            }
            let unknown: Vec<_> = k.iter().filter(|k| !KINDS.contains(&k.as_str())).collect();
            if !unknown.is_empty() {
                anyhow::bail!("--trace-events: unknown kind(s) {unknown:?}; known: {KINDS:?}");
            }
        }
        Ok(Trace {
            out: RefCell::new(BufWriter::new(File::create(path)?)),
            filter,
            kinds,
        })
    }

    /// Gate: no filter, or the function's fqn contains the filter substring.
    pub fn on(&self, fqn: &str) -> bool {
        self.filter.as_deref().map_or(true, |f| fqn.contains(f))
    }

    /// Gate: no `--trace-events`, or this kind was named. Checked by callers
    /// before formatting — see the module header.
    pub fn wants(&self, kind: &str) -> bool {
        self.kinds.as_ref().map_or(true, |k| k.contains(kind))
    }

    /// Both gates in one call, for the `if let Some(t) = tr` sites.
    pub fn on_ev(&self, kind: &str, fqn: &str) -> bool {
        self.wants(kind) && self.on(fqn)
    }

    pub fn log(&self, args: std::fmt::Arguments) {
        let mut o = self.out.borrow_mut();
        let _ = o.write_fmt(args);
        let _ = o.write_all(b"\n");
    }

    /// Flush at phase boundaries so a killed run still leaves a usable prefix.
    pub fn flush(&self) {
        let _ = self.out.borrow_mut().flush();
    }
}

/// Every kind the engine emits. Validated against `--trace-events` so a typo
/// is an error rather than a silently empty trace — an empty trace reads as
/// "the event never happened", which is the failure this mode exists to avoid.
pub const KINDS: [&str; 16] = [
    "seed", "summary", "scc-start", "scc-iter", "apply", "leaf", "propagate", "sink-hit", "heap-hit",
    "heap-cell", "heap-narrow", "chain", "widen", "back", "back-step", "back-frame",
];

/// trace_ev!(engine.trace, "kind", fqn, "fmt", args...) — logs iff tracing is
/// enabled, the kind is wanted, and fqn passes the filter. The kind is a
/// separate argument so both gates precede the formatting.
#[macro_export]
macro_rules! trace_ev {
    ($t:expr, $kind:expr, $fqn:expr, $($arg:tt)*) => {
        if let Some(tr) = $t {
            if tr.on_ev($kind, $fqn) {
                tr.log(format_args!($($arg)*));
            }
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Same shape as `ifds::tests::store_dir` — no new dev-dependency.
    fn tmpdir(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("pc-trace-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn write_all(t: &Trace) {
        crate::trace_ev!(Some(t), "seed", "f", "seed      fn=f vertices=[1]");
        crate::trace_ev!(Some(t), "chain", "f", "chain     src=f sink=sqli hops=2");
        crate::trace_ev!(Some(t), "apply", "f", "apply     fn=f cs=0");
        crate::trace_ev!(Some(t), "widen", "f", "widen     fn=f cs=0 callee=g");
        t.flush();
    }

    #[test]
    fn kind_filter_yields_the_grep_of_the_unfiltered_trace() {
        let d = tmpdir("grep");
        let (full, cmp) = (d.join("full"), d.join("cmp"));
        write_all(&Trace::open(&full, None, None).unwrap());
        write_all(&Trace::open(&cmp, None, Some("chain,widen")).unwrap());

        let grep: String = std::fs::read_to_string(&full)
            .unwrap()
            .lines()
            .filter(|l| l.starts_with("chain") || l.starts_with("widen"))
            .map(|l| format!("{l}\n"))
            .collect();
        assert_eq!(grep, std::fs::read_to_string(&cmp).unwrap());
    }

    #[test]
    fn kind_and_fn_filters_compose() {
        let p = tmpdir("compose").join("t");
        let t = Trace::open(&p, Some("other".into()), Some("chain")).unwrap();
        write_all(&t);
        assert_eq!(std::fs::read_to_string(&p).unwrap(), "", "fqn filter still applies");
        assert!(t.wants("chain") && !t.wants("apply"));
    }

    #[test]
    fn an_unknown_kind_is_an_error_not_an_empty_trace() {
        let p = tmpdir("kinds").join("t");
        assert!(Trace::open(&p, None, Some("chian")).is_err());
        assert!(Trace::open(&p, None, Some("")).is_err());
        assert!(Trace::open(&p, None, Some("chain,widen")).is_ok());
    }
}
