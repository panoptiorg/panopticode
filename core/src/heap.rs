// W1F — abstract heap cells (doc 24 §3 N5, doc 28).
//
// A struct field is a program-wide abstract cell `sym = H(type, field)`, emitted
// by the frontend as IN_GLOBAL (read) / OUT_FIELD-with-sym (write) vertices, so
// phase 1 already produces, for free:
//
//   writer W:  flows  (X            -> Global(s))
//   reader R:  flows  (Global(s)    -> Global(s2))     cell-to-cell
//              sinks  (Global(s), class)
//
// What phase 1 cannot do is JOIN them. Debt A1 is the canonical case: `Submit`
// (producer) and `runBatcher` (consumer) are reached by disjoint call paths from
// the same *Pool, so no call site ever holds both sides and no amount of summary
// composition connects them. That is what this module is for and the ONLY reason
// it exists — if a cheaper join existed it would already have happened in
// `Engine::run_with_store`.
//
// The algorithm is two passes, both over summaries only:
//   1. a boolean fixpoint over the cell graph, computing for each cell the set
//      of sinks reachable from it (directly, or via cell -> cell edges);
//   2. one splice pass: every writer of cell s gains a SinkHit on its own
//      in-slot for every sink reachable from s, tagged `via_heap` so witness can
//      render the crossing instead of dereferencing a callsite that isn't there.
// then the writers' transitive callers are re-summarized so the new hit reaches
// the source functions `report::intra_chains` roots at.
//
// ---------------------------------------------------------------------------
// W1F CACHE DISCIPLINE — the property most likely to be broken by a
// well-meaning refactor, so it is stated here rather than in a doc:
//
//   The sym fixpoint runs in PHASE 2. It mutates nothing in `summary_keys`,
//   `contract_hashes`, `recomputed` or the summary store, and it never
//   re-summarizes anything into the store. Its entire output is
//   `Engine::heap_hits`, an in-memory side table that `summarize` appends and
//   that is empty for the whole of phase 1.
//
// That is the same discipline `ifds.rs:207-215` mandates for compose and debt A6
// tracks: a cached summary and a freshly tabulated one must have seen identical
// callee environments, or `summary_key` stops meaning what it claims and warm
// MR reuse silently rots. The observable check is the real-MR reuse figure —
// 100.000% before and after this module (doc 28 §3).
// ---------------------------------------------------------------------------
use crate::graph::IidHex;
use crate::ifds::{cell_split, paths_comparable, Engine, HeapEntry, HeapVia, Slot, SlotP};
use std::collections::{HashMap, HashSet};

/// Backstop mirroring `ifds.rs`' SCC cap: the cell lattice is boolean and the
/// transfer monotone, so it converges in O(cell-graph diameter) rounds. Hitting
/// the cap means a regression to non-monotone behaviour — warn loudly, keep the
/// sound-so-far result, move on.
const MAX_ITERS: usize = 64;

#[derive(Debug, Default, Clone, Copy)]
pub struct HeapStats {
    /// distinct cells that are written somewhere
    pub cells: usize,
    /// (function, cell) write pairs
    pub writers: usize,
    /// sinks reachable from some cell, after the fixpoint
    pub cell_sinks: usize,
    /// SinkHits spliced into writers
    pub spliced: usize,
    /// fixpoint rounds actually run
    pub iters: usize,
    /// functions re-summarized so the splice reaches chain roots
    pub resummarized: usize,
}

/// One sink reachable through a cell, with everything witness needs to keep
/// descending on the reader's side.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct CellSink {
    class: String,
    reader: IidHex,
    reader_slot: String,
    /// the cell the READER takes it from — the one whose name is rendered
    cell: String,
    /// A16: the concrete type the reader's type assertion demands, when it has
    /// one. Carried through the fixpoint and applied per WRITE SITE in
    /// `propagate` — see `HeapEntry::admits`.
    assert: Option<String>,
}

/// The cell a slot addresses, with the A16 reader constraint stripped off.
/// Every map in the fixpoint is keyed on the BARE cell: a guarded read and a raw
/// read of the same field are the same cell, they merely accept different
/// writers.
fn global_of(s: &SlotP) -> Option<(&str, Option<&str>)> {
    match &s.slot {
        Slot::Global(g) => Some(cell_split(g.as_str())),
        _ => None,
    }
}

/// sym hex -> human name, scanned off the vertices that carry it. Only used for
/// rendering; a cell with no name still joins correctly.
fn cell_names(prog: &crate::graph::Program) -> HashMap<String, String> {
    let mut out = HashMap::new();
    for f in prog.funcs.values() {
        let Some(flow) = &f.flow else { continue };
        for v in &flow.vertices {
            if v.sym.is_empty() || v.sym_name.is_empty() {
                continue;
            }
            out.entry(hex::encode(&v.sym))
                .or_insert_with(|| v.sym_name.clone());
        }
    }
    out
}

// The heap hop's span is NOT resolved here: `propagate` derives the hit at the
// OUT_FIELD vertex itself and takes that vertex's own span, so the crossing
// renders at the exact write that carried the fact — not at some other write of
// the same cell in the same function. That is what lets a heap-mediated route be
// opened against source (doc 24 N2).

/// Join heap-cell writers to heap-cell readers. Returns zeroed stats when the
/// CGF carries no cells at all (i.e. pc-fe ran without --heap-slots), which is
/// the no-op path every pre-W1F corpus takes.
pub fn fixpoint(engine: &mut Engine) -> HeapStats {
    let mut stats = HeapStats::default();

    // ---- collect, from summaries only -------------------------------------
    // writers[cell] = (fn, the fn's own in-slot, the path written at)
    let mut writers: HashMap<String, Vec<(IidHex, SlotP, Vec<u32>)>> = HashMap::new();
    // edges[cell] = cells that a reader of `cell` writes on to
    let mut edges: HashMap<String, HashSet<String>> = HashMap::new();
    // direct[cell] = sinks a reader of `cell` reaches without another crossing
    let mut direct: HashMap<String, HashSet<CellSink>> = HashMap::new();
    // readers[cell] = fns that read it, whatever they then do with the value.
    // Census only (the `heap-cell` trace event): the join itself needs the
    // reader only where it reaches a sink or another cell, but "how many
    // unrelated functions read this field" is precisely the shape that tells an
    // accumulator apart from a pipe (debt A14).
    let mut readers: HashMap<String, HashSet<IidHex>> = HashMap::new();

    for (iid, sum) in &engine.summaries {
        for (isl, osl) in &sum.flows {
            if let Some((from, _)) = global_of(isl) {
                readers.entry(from.to_string()).or_default().insert(iid.clone());
            }
            match (global_of(isl), global_of(osl)) {
                // cell -> cell: the reader forwards taint to another cell.
                // The A16 constraint is DROPPED across a crossing: what the far
                // cell's readers accept says nothing about this one. Keeping the
                // pairing is the sound direction.
                (Some((from, _)), Some((to, _))) => {
                    edges.entry(from.to_string()).or_default().insert(to.to_string());
                    writers
                        .entry(to.to_string())
                        .or_default()
                        .push((iid.clone(), isl.clone(), osl.path.clone()));
                }
                // ordinary in-slot -> cell: a genuine producer
                (None, Some((to, _))) => writers
                    .entry(to.to_string())
                    .or_default()
                    .push((iid.clone(), isl.clone(), osl.path.clone())),
                _ => {}
            }
        }
        for sh in &sum.sink_hits {
            // a hit already spliced by a previous run of this fixpoint must not
            // be re-collected as a cell sink, or the second pass would chase its
            // own tail.
            if sh.via_heap.is_some() {
                continue;
            }
            if let Some((cell, assert)) = global_of(&sh.in_slot) {
                readers.entry(cell.to_string()).or_default().insert(iid.clone());
                direct.entry(cell.to_string()).or_default().insert(CellSink {
                    class: sh.class.clone(),
                    reader: iid.clone(),
                    reader_slot: crate::ifds::slot_str(&sh.in_slot),
                    cell: cell.to_string(),
                    assert: assert.map(str::to_string),
                });
            }
        }
    }

    if writers.is_empty() {
        return stats; // no --heap-slots in this CGF: nothing to do
    }
    stats.cells = writers.len();
    stats.writers = writers.values().map(Vec::len).sum();

    // ---- 1. boolean fixpoint over the cell graph ---------------------------
    // reach[cell] = sinks reachable from cell. Monotone (sets only grow) over a
    // finite lattice, so it terminates; MAX_ITERS is a regression backstop.
    let mut reach: HashMap<String, HashSet<CellSink>> = direct.clone();
    loop {
        if stats.iters >= MAX_ITERS {
            eprintln!(
                "warning: heap-cell fixpoint hit iteration cap ({MAX_ITERS}) without \
                 converging over {} cells — heap-mediated chains may be incomplete",
                reach.len()
            );
            break;
        }
        stats.iters += 1;
        let mut changed = false;
        // deterministic order: HashMap iteration would still converge to the
        // same fixpoint, but a stable order keeps the trace reproducible.
        let mut froms: Vec<&String> = edges.keys().collect();
        froms.sort();
        let mut adds: Vec<(String, CellSink)> = Vec::new();
        for from in froms {
            let mut tos: Vec<&String> = edges[from].iter().collect();
            tos.sort();
            for to in tos {
                let Some(rs) = reach.get(to) else { continue };
                for cs in rs {
                    // A16: the reader's assertion constrains what `to` holds,
                    // NOT what `from` holds — and the entry ends up applied at
                    // `from`'s write sites, whose concrete types belong to a
                    // different field. Carrying it across the crossing would
                    // compare two unrelated types and delete real flows. Strip
                    // it: keeping the pairing is the sound direction.
                    //
                    // Found by the instrument, not by reasoning: `Event.Time`
                    // (not an interface at all) came back with 12 inherited
                    // assertions, harmless only because its writes are untagged.
                    let cs = CellSink { assert: None, ..cs.clone() };
                    if !reach.get(from).is_some_and(|s| s.contains(&cs)) {
                        adds.push((from.clone(), cs));
                    }
                }
            }
        }
        for (from, cs) in adds {
            if reach.entry(from).or_default().insert(cs) {
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }
    stats.cell_sinks = reach.values().map(HashSet::len).sum();

    // ---- 2. splice onto the writers ---------------------------------------
    let names = cell_names(engine.prog);
    let mut touched: HashSet<IidHex> = HashSet::new();
    let mut spliced_per_cell: HashMap<String, usize> = HashMap::new();
    for (cell, ws) in &writers {
        let Some(sinks) = reach.get(cell) else { continue };
        if sinks.is_empty() {
            continue;
        }
        let mut entries: Vec<HeapEntry> = Vec::new();
        for cs in sinks {
            // A write at path p and a read at path q only meet if the paths are
            // prefix-comparable — the rule slot_compat applies at a call site.
            let read_path = crate::ifds::slot_parse(&cs.reader_slot)
                .map(|s| s.path)
                .unwrap_or_default();
            // The cell entry is keyed on the WRITE cell, and `propagate` applies
            // it at an OUT_FIELD vertex whose own path is the write path — so
            // path filtering happens there, per write site. Keep the read path
            // only where it is knowably disjoint from every write of this cell.
            if !ws
                .iter()
                .any(|(_, _, out_path)| paths_comparable(out_path, &read_path))
            {
                continue;
            }
            entries.push(HeapEntry {
                class: cs.class.clone(),
                assert: cs.assert.clone(),
                via: HeapVia {
                    // Name the cell the WRITER writes, because that is the cell
                    // the hop's span points at. When the fixpoint composed
                    // several crossings the reader takes it out of a different
                    // one — say both, or the hop claims a write site that does
                    // not write the cell it names.
                    cell: {
                        let w = names.get(cell).cloned().unwrap_or_else(|| cell.clone());
                        if cs.cell == *cell {
                            w
                        } else {
                            let r = names
                                .get(&cs.cell)
                                .cloned()
                                .unwrap_or_else(|| cs.cell.clone());
                            format!("{w} -> {r}")
                        }
                    },
                    reader: cs.reader.clone(),
                    reader_slot: crate::ifds::slot_parse(&cs.reader_slot)
                        .unwrap_or_else(|| Slot::Global(cs.cell.clone()).into()),
                },
            });
        }
        if entries.is_empty() {
            continue;
        }
        // stable order: witness picks deterministically among candidates and
        // report lists chains in this order. `assert` is part of the key — two
        // readers of one cell demanding different concrete types are two
        // entries, and only one of them survives at any given write site.
        entries.sort_by(|a, b| {
            (&a.class, &a.via.cell, &a.via.reader, &a.assert).cmp(&(
                &b.class,
                &b.via.cell,
                &b.via.reader,
                &b.assert,
            ))
        });
        entries.dedup();
        stats.spliced += entries.len();
        spliced_per_cell.insert(cell.clone(), entries.len());
        engine.heap_cells.insert(cell.clone(), entries);
        for (w_iid, _, _) in ws {
            touched.insert(w_iid.clone());
        }
    }

    // ---- 2b. census (`--trace-events heap-cell`) --------------------------
    // Pure logging, and the only place the writer/reader shape of every cell is
    // visible at once. A14 reads it to tell a producer/consumer pipe (few
    // writers, few readers, one request path) from an accumulator (many writers
    // into one field read program-wide), which is the FP shape object
    // insensitivity manufactures. Nothing here may touch `engine`.
    if let Some(tr) = engine.trace.filter(|t| t.wants("heap-cell")) {
        let fqn = |i: &IidHex| {
            engine
                .prog
                .funcs
                .get(i)
                .map(|f| f.fqn.clone())
                .unwrap_or_else(|| i.to_string())
        };
        let examples = |set: &mut Vec<String>| {
            set.sort();
            set.dedup();
            let n = set.len().min(3);
            set[..n].join(";")
        };
        let mut cells: Vec<&String> = writers.keys().collect();
        cells.sort(); // deterministic: the census is diffed across runs
        for cell in cells {
            let ws = &writers[cell];
            let name = names.get(cell).cloned().unwrap_or_else(|| cell.clone());
            if !tr.on(&name) {
                continue;
            }
            let mut wf: Vec<String> = ws.iter().map(|(i, _, _)| fqn(i)).collect();
            let mut rf: Vec<String> = readers
                .get(cell)
                .map(|s| s.iter().map(fqn).collect())
                .unwrap_or_default();
            let (nwf, nrf) = (
                ws.iter().map(|(i, _, _)| i).collect::<HashSet<_>>().len(),
                readers.get(cell).map_or(0, HashSet::len),
            );
            let sinks = reach.get(cell);
            let mut classes: Vec<&str> = sinks
                .map(|s| s.iter().map(|c| c.class.as_str()).collect())
                .unwrap_or_default();
            classes.sort_unstable();
            classes.dedup();
            tr.log(format_args!(
                "heap-cell cell={} name={} writes={} writer_fns={} reader_fns={} sinks={} \
                 spliced={} classes={} w_ex={} r_ex={}",
                cell,
                name,
                ws.len(),
                nwf,
                nrf,
                sinks.map_or(0, HashSet::len),
                spliced_per_cell.get(cell).copied().unwrap_or(0),
                if classes.is_empty() { "-".into() } else { classes.join(",") },
                examples(&mut wf),
                examples(&mut rf),
            ));
        }
        tr.flush();
    }

    // ---- 2c. A16 instrument (`--trace-events heap-narrow`) ----------------
    // One line per cell that has a constraint on EITHER side. The two sides are
    // reported separately on purpose: a cell with asserts and no write types
    // narrows nothing, and that is a frontend gap (the writers were not
    // `MakeInterface`), not evidence that the narrowing was unnecessary. The
    // drops themselves are logged in `propagate`, per write site.
    if let Some(tr) = engine.trace.filter(|t| t.wants("heap-narrow")) {
        // cell -> the concrete types its writes deposit, and which function
        // deposited each. Straight off the OUT_FIELD vertices: summaries do not
        // carry a write's type, because it is filtered per SITE and so never
        // needed to reach a slot.
        let mut write_tags: HashMap<String, HashSet<String>> = HashMap::new();
        let mut write_sites: HashMap<(String, String), HashSet<String>> = HashMap::new();
        for f in engine.prog.funcs.values() {
            let Some(flow) = &f.flow else { continue };
            for v in &flow.vertices {
                if v.sym.is_empty() || v.iface_type.is_empty() {
                    continue;
                }
                if v.kind() == crate::proto::cgf::VertexKind::OutField {
                    let (c, t) = (hex::encode(&v.sym), hex::encode(&v.iface_type));
                    write_tags.entry(c.clone()).or_default().insert(t.clone());
                    write_sites.entry((c, t)).or_default().insert(f.fqn.clone());
                }
            }
        }
        let join = |s: &HashSet<String>| {
            let mut v: Vec<&str> = s.iter().map(String::as_str).collect();
            v.sort_unstable();
            if v.is_empty() { "-".to_string() } else { v.join(",") }
        };
        let mut cells: Vec<&String> = engine.heap_cells.keys().collect();
        cells.sort();
        for cell in cells {
            let entries = &engine.heap_cells[cell];
            let asserts: HashSet<String> =
                entries.iter().filter_map(|e| e.assert.clone()).collect();
            let writes = write_tags.get(cell).cloned().unwrap_or_default();
            if asserts.is_empty() && writes.is_empty() {
                continue; // not an interface cell, or nothing tagged: no A16 story
            }
            let name = names.get(cell).cloned().unwrap_or_else(|| cell.clone());
            if !tr.on(&name) {
                continue;
            }
            tr.log(format_args!(
                "heap-narrow cell cell={} name={} entries={} constrained={} asserts={} write_types={}",
                cell,
                name,
                entries.len(),
                entries.iter().filter(|e| e.assert.is_some()).count(),
                join(&asserts),
                join(&writes),
            ));
            // One line per pairing the narrowing removes, computed ONCE here
            // rather than per descent (see the note in ifds.rs' propagate).
            // `fn=` is the writer, which is the question actually being asked:
            // which type-switch arm lost its pairing.
            for e in entries {
                let Some(a) = &e.assert else { continue };
                for w in writes.iter().filter(|w| *w != a) {
                    let mut fns: Vec<&str> = write_sites
                        .get(&(cell.clone(), w.clone()))
                        .map(|s| s.iter().map(String::as_str).collect())
                        .unwrap_or_default();
                    fns.sort_unstable();
                    for fq in fns {
                        tr.log(format_args!(
                            "heap-narrow drop cell={name} class={} fn={fq} write_ty={w} assert={a}",
                            e.class,
                        ));
                    }
                }
            }
        }
        tr.flush();
    }

    // ---- 3. push the new sinks up to the chain roots ----------------------
    // report::intra_chains roots only at functions with source_seeds and reads
    // CALLEE summaries at each call site, so a cell sink derived inside `Submit`
    // is invisible until every transitive caller has been re-summarized.
    if !touched.is_empty() {
        let order = engine.prog.scc_order();
        let mut local_callers: HashMap<IidHex, Vec<IidHex>> = HashMap::new();
        for (iid, f) in &engine.prog.funcs {
            for callee in engine.prog.callees(f) {
                local_callers.entry(callee).or_default().push(iid.clone());
            }
        }
        // seed with the writers themselves: their own summaries must be redone
        // first, because propagate only now has heap_cells to consult.
        let changed = engine.resummarize(&touched, &order, &local_callers);
        stats.resummarized = changed.len();
    }
    stats
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::catalog::Catalog;
    use crate::graph::{hexid, Program};
    use crate::ifds::Summary;
    use std::collections::HashMap as Map;

    fn cell(n: u8) -> String {
        hex::encode([n; 4])
    }

    /// An empty program + catalog. These tests exercise the cell join, which
    /// reads `engine.summaries` only — the same hand-built-facts discipline
    /// `ifds::slot_mapping_tests` uses, and the only way to test a defect no
    /// fixture can express yet (HANDOFF trap 5b).
    fn empty() -> (Program, Catalog) {
        (
            Program {
                funcs: Map::new(),
                repo_of: Map::new(),
                packages: Vec::new(),
            },
            Catalog::load_str("").expect("empty catalog"),
        )
    }

    fn sink(cell_hex: &str, class: &str) -> crate::ifds::SinkHit {
        crate::ifds::SinkHit {
            in_slot: Slot::Global(cell_hex.to_string()).into(),
            class: class.into(),
            callsite: 0,
            span: None,
            via_heap: None,
        }
    }

    /// The A1 shape in miniature: W writes a cell, R reads it and sinks. Nothing
    /// connects them by call graph, so no composition can find this.
    #[test]
    fn a_cell_carries_its_readers_sink() {
        let (prog, cat) = empty();
        let mut e = Engine::new(&prog, &cat);
        let (w, r) = (hexid(&[1u8; 32]), hexid(&[2u8; 32]));
        let c = cell(0xAB);

        let mut ws = Summary::default();
        ws.flows.insert((
            Slot::Param(1).into(),
            SlotP { slot: Slot::Global(c.clone()), path: vec![] },
        ));
        let mut rs = Summary::default();
        rs.sink_hits.push(sink(&c, "sqli"));
        e.summaries.insert(w, ws);
        e.summaries.insert(r.clone(), rs);

        let st = fixpoint(&mut e);
        assert_eq!(st.cells, 1, "one written cell");
        let entries = e.heap_cells.get(&c).expect("the written cell must carry a sink");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].class, "sqli");
        assert_eq!(entries[0].via.reader, r, "witness must be told where to resume");
    }

    /// The `heap-cell` census (A14). Two writers, one reader that sinks and one
    /// that only forwards: `reader_fns` must count BOTH, because a reader that
    /// forwards to a non-cell out-slot is invisible to the join and is exactly
    /// what makes a field look like an accumulator. Also pins that the census is
    /// gated — no `--trace-events heap-cell`, no lines.
    #[test]
    fn census_counts_writers_and_readers() {
        let (prog, cat) = empty();
        let c = cell(0xCE);
        let mut summaries = Map::new();
        for (n, from) in [(1u8, Slot::Param(0)), (2u8, Slot::Param(1))] {
            let mut s = Summary::default();
            s.flows
                .insert((from.into(), Slot::Global(c.clone()).into()));
            summaries.insert(hexid(&[n; 32]), s);
        }
        // reader A: cell -> sink. reader B: cell -> an ordinary out-slot.
        let mut ra = Summary::default();
        ra.sink_hits.push(sink(&c, "log"));
        summaries.insert(hexid(&[3u8; 32]), ra);
        let mut rb = Summary::default();
        rb.flows
            .insert((Slot::Global(c.clone()).into(), Slot::Return(0).into()));
        summaries.insert(hexid(&[4u8; 32]), rb);

        let dir = std::env::temp_dir().join(format!("pc-a14-census-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        for (kinds, want) in [(Some("chain"), false), (Some("heap-cell"), true)] {
            let p = dir.join(format!("t-{}.log", want));
            let tr = crate::trace::Trace::open(&p, None, kinds).expect("trace");
            let mut e = Engine::new(&prog, &cat);
            e.trace = Some(&tr);
            e.summaries = summaries.clone();
            fixpoint(&mut e);
            drop(tr);
            let got = std::fs::read_to_string(&p).unwrap_or_default();
            let line = got.lines().find(|l| l.starts_with("heap-cell "));
            match (want, line) {
                (false, l) => assert!(l.is_none(), "census must be gated: {got:?}"),
                (true, None) => panic!("no census line emitted: {got:?}"),
                (true, Some(l)) => {
                    assert!(l.contains(&format!("cell={c}")), "{l}");
                    assert!(l.contains("writes=2 writer_fns=2 reader_fns=2"), "{l}");
                    assert!(l.contains("sinks=1"), "{l}");
                    assert!(l.contains("classes=log"), "{l}");
                }
            }
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Two crossings, which is what the real epool needs: incoming -> pending ->
    /// batches. A one-pass join finds nothing here.
    #[test]
    fn cell_to_cell_edges_compose_transitively() {
        let (prog, cat) = empty();
        let mut e = Engine::new(&prog, &cat);
        let (w, mid, r) = (hexid(&[1u8; 32]), hexid(&[2u8; 32]), hexid(&[3u8; 32]));
        let (c1, c2) = (cell(0x11), cell(0x22));

        let mut ws = Summary::default();
        ws.flows
            .insert((Slot::Param(0).into(), Slot::Global(c1.clone()).into()));
        let mut ms = Summary::default();
        ms.flows
            .insert((Slot::Global(c1.clone()).into(), Slot::Global(c2.clone()).into()));
        let mut rs = Summary::default();
        rs.sink_hits.push(sink(&c2, "log"));
        e.summaries.insert(w, ws);
        e.summaries.insert(mid, ms);
        e.summaries.insert(r, rs);

        let st = fixpoint(&mut e);
        assert!(st.iters >= 2, "a 2-hop chain needs a real fixpoint, not one pass");
        let entries = e
            .heap_cells
            .get(&c1)
            .expect("the FIRST cell must carry the sink reached two crossings away");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].class, "log");
        // the hop must name both ends, or it claims a write site that does not
        // write the cell it names.
        assert!(entries[0].via.cell.contains("->"), "cell = {}", entries[0].via.cell);
    }

    /// A write at [0] and a read at [1] are disjoint fields of the same cell and
    /// must not join. Cells are object-insensitive, NOT field-insensitive.
    #[test]
    fn disjoint_paths_on_one_cell_do_not_join() {
        let (prog, cat) = empty();
        let mut e = Engine::new(&prog, &cat);
        let (w, r) = (hexid(&[1u8; 32]), hexid(&[2u8; 32]));
        let c = cell(0x33);

        let mut ws = Summary::default();
        ws.flows.insert((
            Slot::Param(0).into(),
            SlotP { slot: Slot::Global(c.clone()), path: vec![0] },
        ));
        let mut rs = Summary::default();
        rs.sink_hits.push(crate::ifds::SinkHit {
            in_slot: SlotP { slot: Slot::Global(c.clone()), path: vec![1] },
            class: "sqli".into(),
            callsite: 0,
            span: None,
            via_heap: None,
        });
        e.summaries.insert(w, ws);
        e.summaries.insert(r, rs);

        let st = fixpoint(&mut e);
        assert_eq!(st.spliced, 0, "[0] written, [1] read — different fields");
        assert!(e.heap_cells.is_empty());
    }

    // ---- A16: interface-typed cells (doc 30 §6.1) --------------------------
    //
    // No fixture could express these before the frontend emitted `iface_type`,
    // and the pairing they narrow is cross-function by construction — the
    // hand-built-summary discipline of trap 5b is the only way to pin them.

    fn tagged(cell_hex: &str, ty: &str) -> String {
        format!("{cell_hex}@{}", hex::encode(ty))
    }

    /// The reader's type assertion has to survive the fixpoint and land on the
    /// entry, keyed under the BARE cell — otherwise the guarded read looks like
    /// a different field and joins with nothing at all (which would be a recall
    /// bug wearing a precision bug's clothes).
    #[test]
    fn a_readers_type_assertion_rides_the_cell_and_reaches_the_entry() {
        let (prog, cat) = empty();
        let mut e = Engine::new(&prog, &cat);
        let (w, r) = (hexid(&[1u8; 32]), hexid(&[2u8; 32]));
        let c = cell(0xA1);

        let mut ws = Summary::default();
        ws.flows
            .insert((Slot::Param(0).into(), Slot::Global(c.clone()).into()));
        let mut rs = Summary::default();
        rs.sink_hits.push(sink(&tagged(&c, "domain.SBPParam"), "sqli"));
        e.summaries.insert(w, ws);
        e.summaries.insert(r, rs);

        fixpoint(&mut e);
        let entries = e
            .heap_cells
            .get(&c)
            .expect("the guarded read must key under the BARE cell, not the tagged one");
        assert_eq!(entries.len(), 1);
        assert_eq!(
            entries[0].assert.as_deref(),
            Some(hex::encode("domain.SBPParam").as_str()),
            "the assertion is the whole point — it must reach the write site"
        );
    }

    /// One cell read twice in one program: once behind `.(SBPParam)`, once raw
    /// (e.g. `fmt.Errorf(..., event.EventSrc)` on the failure branch). They
    /// must stay SEPARATE entries — collapsing them either loses the constraint
    /// or wrongly applies it to the raw sink.
    #[test]
    fn a_raw_read_and_a_guarded_read_of_one_cell_stay_separate() {
        let (prog, cat) = empty();
        let mut e = Engine::new(&prog, &cat);
        let c = cell(0xA2);
        let mut ws = Summary::default();
        ws.flows
            .insert((Slot::Param(0).into(), Slot::Global(c.clone()).into()));
        e.summaries.insert(hexid(&[1u8; 32]), ws);

        let mut rs = Summary::default();
        rs.sink_hits.push(sink(&tagged(&c, "domain.SBPParam"), "sqli"));
        rs.sink_hits.push(sink(&c, "log"));
        e.summaries.insert(hexid(&[2u8; 32]), rs);

        fixpoint(&mut e);
        let entries = e.heap_cells.get(&c).expect("cell carries both sinks");
        assert_eq!(entries.len(), 2, "{entries:?}");
        let by_class = |cl: &str| entries.iter().find(|x| x.class == cl).expect("class");
        assert!(by_class("sqli").assert.is_some(), "the guarded read is constrained");
        assert!(by_class("log").assert.is_none(), "the raw read is not");
    }

    /// A reader's assertion must NOT survive a cell -> cell crossing. It
    /// constrains what the FAR cell holds; the entry is applied at the NEAR
    /// cell's write sites, whose concrete types belong to a different field, so
    /// carrying it would compare two unrelated types and delete real flows.
    ///
    /// Found by `--trace-events heap-narrow` on a real corpus, not by reasoning:
    /// `domain.Event.Time` — not an interface at all — came back carrying 12
    /// inherited assertions, harmless there only because a non-interface field's
    /// writes are never tagged.
    #[test]
    fn an_assertion_does_not_survive_a_cell_to_cell_crossing() {
        let (prog, cat) = empty();
        let mut e = Engine::new(&prog, &cat);
        let (c1, c2) = (cell(0x44), cell(0x55));

        let mut ws = Summary::default();
        ws.flows
            .insert((Slot::Param(0).into(), Slot::Global(c1.clone()).into()));
        let mut ms = Summary::default();
        ms.flows
            .insert((Slot::Global(c1.clone()).into(), Slot::Global(c2.clone()).into()));
        let mut rs = Summary::default();
        rs.sink_hits.push(sink(&tagged(&c2, "domain.SBPParam"), "sqli"));
        e.summaries.insert(hexid(&[1u8; 32]), ws);
        e.summaries.insert(hexid(&[2u8; 32]), ms);
        e.summaries.insert(hexid(&[3u8; 32]), rs);

        fixpoint(&mut e);
        assert_eq!(
            e.heap_cells[&c2][0].assert.as_deref(),
            Some(hex::encode("domain.SBPParam").as_str()),
            "the cell the reader actually reads keeps the constraint"
        );
        assert!(
            e.heap_cells[&c1][0].assert.is_none(),
            "the far cell's assertion leaked one crossing back: {:?}",
            e.heap_cells[&c1]
        );
    }

    /// `admits` is the whole narrowing, applied per write site in `propagate`.
    /// The three "unknown" rows are the sound direction: A16 removes pairings it
    /// can PROVE impossible and nothing else.
    #[test]
    fn admits_drops_only_a_provably_impossible_pairing() {
        let sbp = hex::encode("domain.SBPParam");
        let dfa = hex::encode("domain.DFAParam");
        let mk = |assert: Option<&str>| crate::ifds::HeapEntry {
            class: "sqli".into(),
            via: HeapVia {
                cell: "c".into(),
                reader: hexid(&[2u8; 32]),
                reader_slot: Slot::Global("c".into()).into(),
            },
            assert: assert.map(str::to_string),
        };
        let bytes = |h: &str| hex::decode(h).expect("hex");

        assert!(mk(Some(&sbp)).admits(&bytes(&sbp)), "same concrete type: the legal pairing");
        assert!(
            !mk(Some(&sbp)).admits(&bytes(&dfa)),
            "a different type-switch arm cannot be the value the assertion accepted"
        );
        assert!(mk(Some(&sbp)).admits(&[]), "unknown write type ⇒ keep");
        assert!(mk(None).admits(&bytes(&dfa)), "reader does not discriminate ⇒ keep");
        assert!(mk(None).admits(&[]), "nothing known on either side ⇒ keep");
    }

    /// A CGF with no cells at all (every corpus before W1F, and every run with
    /// --heap-slots off) must be an exact no-op — this is what keeps `off`
    /// byte-identical and the A/B attributable.
    #[test]
    fn no_cells_is_a_no_op() {
        let (prog, cat) = empty();
        let mut e = Engine::new(&prog, &cat);
        let mut s = Summary::default();
        s.flows
            .insert((Slot::Param(0).into(), Slot::Return(0).into()));
        e.summaries.insert(hexid(&[9u8; 32]), s);
        let st = fixpoint(&mut e);
        assert_eq!(st.cells, 0);
        assert_eq!(st.spliced, 0);
        assert!(e.heap_cells.is_empty());
    }
}

/// Coverage wave 1 §2.4: a Kafka topic is a heap cell with
/// `sym = ContractIID("msg:kafka:<topic>")`, written by the producer
/// (OUT_FIELD) and read by the consumer (IN_GLOBAL) — in DIFFERENT repos. The
/// design claims this needs no engine change because the phase-2 join above is
/// program-wide and every `--cgf` dir is merged into one program. This pins
/// the claim through the same phase order `taint` runs.
#[cfg(test)]
mod topic_cell_tests {
    use crate::catalog::Catalog;
    use crate::graph::{hexid, Program};
    use crate::ifds::cache_tests::{edge, vertex};
    use crate::ifds::Engine;
    use crate::proto::cgf;
    use crate::witness::HopKind;
    use std::collections::HashMap;

    const CAT: &str = "[[sources]]\nkind = \"http_request\"\nselector = \"(*net/http.Request).FormValue\"\n\
                       [[sinks]]\nclass = \"sqli\"\nselector = \"db.Exec\"\n";

    fn cell_vertex(id: u32, kind: cgf::VertexKind, topic: &str) -> cgf::FlowVertex {
        cgf::FlowVertex {
            sym: crate::ids::hash_parts(&[format!("msg:kafka:{topic}").as_bytes()]).to_vec(),
            sym_name: format!("kafka topic {topic}"),
            ..vertex(id, kind, 0, 0)
        }
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

    /// repo `orders`: `w.WriteMessages(ctx, kafka.Message{Value: r.FormValue("q")})`
    /// — the payload flows into the topic cell.
    fn producer(topic: &str) -> cgf::Function {
        func(
            0x71,
            "orders.Publish",
            cgf::LocalFlow {
                vertices: vec![
                    vertex(1, cgf::VertexKind::CallResultPort, 0, 0),
                    cell_vertex(2, cgf::VertexKind::OutField, topic),
                ],
                edges: vec![edge(1, 2)],
                callsites: vec![cgf::CallSite {
                    id: 0,
                    callee_fqn: "(*net/http.Request).FormValue".into(),
                    argc: 1,
                    resultc: 1,
                    arg0_is_receiver: true,
                    ..Default::default()
                }],
            },
        )
    }

    /// repo `billing`: `m, _ := r.ReadMessage(ctx); db.Exec(m.Value)`
    fn consumer(topic: &str) -> cgf::Function {
        func(
            0x72,
            "billing.Consume",
            cgf::LocalFlow {
                vertices: vec![
                    cell_vertex(1, cgf::VertexKind::InGlobal, topic),
                    vertex(2, cgf::VertexKind::CallArgPort, 0, 0),
                ],
                edges: vec![edge(1, 2)],
                callsites: vec![cgf::CallSite { id: 0, callee_fqn: "db.Exec".into(), argc: 1, ..Default::default() }],
            },
        )
    }

    /// cli.rs `taint`, minus I/O: phase 1, heap join, compose, report.
    fn taint(fns: Vec<(cgf::Function, &str)>) -> Vec<crate::report::Chain> {
        let mut prog = Program { funcs: HashMap::new(), repo_of: HashMap::new(), packages: Vec::new() };
        for (f, repo) in fns {
            let h = hexid(&f.id.as_ref().unwrap().iid);
            prog.repo_of.insert(h.clone(), repo.into());
            prog.funcs.insert(h, f);
            prog.packages.push(cgf::CgfPackage { repo: repo.into(), ..Default::default() });
        }
        let cat = Catalog::load_str(CAT).unwrap();
        let mut eng = Engine::new(&prog, &cat);
        eng.run();
        let hs = super::fixpoint(&mut eng);
        assert_eq!(hs.cells, 1, "one written cell: {hs:?}");
        crate::compose::fixpoint_with_leaves(&mut eng, HashMap::new());
        crate::report::intra_chains(&eng, None)
    }

    #[test]
    fn a_topic_cell_joins_a_producer_and_a_consumer_in_two_repos() {
        let chains = taint(vec![(producer("orders"), "orders"), (consumer("orders"), "billing")]);
        assert_eq!(chains.len(), 1, "one cross-repo chain");
        let c = &chains[0];
        assert_eq!((c.source_repo.as_str(), c.source_fn.as_str(), c.sink_class.as_str()), ("orders", "orders.Publish", "sqli"));
        let route = c.route.as_ref().unwrap();
        assert_eq!(route.incomplete, None);
        let hops: Vec<(HopKind, &str, &str)> =
            route.hops.iter().map(|h| (h.kind, h.repo.as_str(), h.callee.as_str())).collect();
        assert_eq!(
            hops,
            vec![
                (HopKind::Source, "orders", ""),
                (HopKind::Call, "orders", "(*net/http.Request).FormValue"),
                // the crossing renders the cell's sym_name
                (HopKind::Heap, "orders", "kafka topic orders"),
                (HopKind::Sink, "billing", "db.Exec"),
            ]
        );
    }

    #[test]
    fn different_topics_do_not_join() {
        let chains = taint(vec![(producer("orders"), "orders"), (consumer("refunds"), "billing")]);
        assert!(chains.is_empty(), "{:?}", chains.iter().map(|c| &c.source_fn).collect::<Vec<_>>());
    }
}
