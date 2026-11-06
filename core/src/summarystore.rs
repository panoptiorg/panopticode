// Summary store: moka LRU in front of an optional FS content-addressed dir,
// keyed by summary_key = H(bid ++ sorted callee contract_hashes) (doc 05).
// The FS namespace embeds a hash of catalog.toml: the catalog is an input to
// summarize() but not to the key, so a catalog edit must cold-start the cache.
use crate::ids;
use crate::ifds::{slot_str, SinkHit, SlotP, Summary};
use crate::proto::cgf;
use anyhow::{Context, Result};
use moka::sync::Cache;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

/// contract_hash = behavior-only hash (flows ∪ sinks), body-independent.
/// Equal public taint behavior ⇒ equal hash ⇒ callers' summary_keys unchanged
/// (the early-cutoff that stops invalidation cascades).
///
/// The sink's TERMINAL (leaf fn iid + callsite in the leaf) is part of the
/// hash. It is body-derived, but it is identity the caller's summary row
/// carries: an edit that only moves a sink call changes the terminal without
/// changing any flow, and a caller that kept the old hash would reuse its
/// cached summary with a stale terminal — witness would then fail to reproduce
/// the route. This weakens the early cutoff for callsite-shifting edits only.
pub fn contract_hash(s: &Summary) -> ids::Hash {
    let mut items: Vec<String> = s
        .flows
        .iter()
        .map(|(a, b)| format!("F:{}->{}", slot_str(a), slot_str(b)))
        .chain(
            s.sink_hits
                .iter()
                .map(|h| {
                    format!(
                        "S:{}:{}:{}:{}",
                        slot_str(&h.in_slot),
                        h.class,
                        h.terminal.fn_iid,
                        h.terminal.callsite
                    )
                }),
        )
        .collect();
    items.sort();
    let joined = items.join("\n");
    ids::hash_parts(&[joined.as_bytes()])
}

pub struct Cached {
    pub summary: Summary,
    pub contract_hash: ids::Hash,
}

pub struct SummaryStore {
    /// catalog-namespaced FS dir; None = in-process only (plain `taint` runs, tests)
    dir: Option<PathBuf>,
    lru: Cache<ids::Hash, Arc<Cached>>,
    /// Atomic because the parallel tabulation shares one `&SummaryStore` across
    /// the rayon pool (the phase reads them back into RunStats at the end).
    pub hits: AtomicU64,
    pub misses: AtomicU64,
}

/// Namespace for the on-disk store: the catalog is an input to `summarize()`
/// but not to `summary_key`, and so is every CORE SEMANTICS flag. Both must
/// therefore namespace the cache, or a store warmed under one setting serves
/// summaries computed under the other — silently, and it would make trap 1's
/// 100.000% reuse figure meaningless. `env` is a short stable string per flag
/// (B1, doc 31 §6).
///
/// `STORE_FMT` is the BLOB format version, always mixed in. Bumped when the
/// StoredSummary projection changes shape so stores warmed by an older binary
/// miss (and recompute) instead of decoding wrongly. fmt2 = SinkHit carries the
/// terminal sink identity (SinkOrigin) — pre-fmt2 blobs lack the field, would
/// fail to deserialize anyway, and their namespace token changed so they are
/// never probed. The empty-env case no longer falls back to the old layout —
/// which mixed only the catalog hash, without the blob format — so stores
/// written before terminals were part of a summary cannot be probed at all.
pub const STORE_FMT: &str = "fmt2-terminal";

pub fn env_hash(catalog_hash: &ids::Hash, env: &str) -> ids::Hash {
    if env.is_empty() {
        return ids::hash_parts(&[catalog_hash.as_slice(), STORE_FMT.as_bytes()]);
    }
    ids::hash_parts(&[
        catalog_hash.as_slice(),
        env.as_bytes(),
        STORE_FMT.as_bytes(),
    ])
}

impl SummaryStore {
    /// `dir` is the user-facing store root; entries land under
    /// `<dir>/<hex(catalog_hash)[..12]>/<hex(key)[..2]>/<hex(key)>.json`.
    pub fn open(dir: Option<&Path>, catalog_hash: &ids::Hash, capacity: u64) -> Result<Self> {
        let dir = match dir {
            Some(d) => {
                let ns = d.join(&ids::hex(catalog_hash)[..12]);
                std::fs::create_dir_all(&ns).with_context(|| format!("create store {ns:?}"))?;
                Some(ns)
            }
            None => None,
        };
        Ok(SummaryStore {
            dir,
            lru: Cache::new(capacity),
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
        })
    }

    /// In-process-only store (no FS); used by Engine::run().
    pub fn ephemeral() -> Self {
        SummaryStore {
            dir: None,
            lru: Cache::new(100_000),
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
        }
    }

    /// `&self`: concurrent workers call this. The moka LRU is already
    /// concurrent; the FS read is per-key and read-only. Concurrent `put`s of
    /// the same key cannot happen inside one run (a fn is tabulated once), and
    /// a blob's bytes are content-derived, so no write-write race exists.
    pub fn get(&self, key: &ids::Hash) -> Option<Arc<Cached>> {
        if let Some(c) = self.lru.get(key) {
            self.hits.fetch_add(1, Ordering::Relaxed);
            return Some(c);
        }
        if let Some(dir) = &self.dir {
            // unreadable/corrupt blob = miss, never a failed run
            if let Ok(bytes) = std::fs::read(blob_path(dir, key)) {
                if let Ok(stored) = serde_json::from_slice::<StoredSummary>(&bytes) {
                    let c = Arc::new(stored.into_cached());
                    self.lru.insert(*key, c.clone());
                    self.hits.fetch_add(1, Ordering::Relaxed);
                    return Some(c);
                }
            }
        }
        self.misses.fetch_add(1, Ordering::Relaxed);
        None
    }

    pub fn put(&self, key: ids::Hash, sum: &Summary, ch: ids::Hash) -> Result<()> {
        let cached = Arc::new(Cached {
            summary: sum.clone(),
            contract_hash: ch,
        });
        self.lru.insert(key, cached);
        if let Some(dir) = &self.dir {
            let path = blob_path(dir, &key);
            std::fs::create_dir_all(path.parent().unwrap())?;
            let blob = serde_json::to_vec(&StoredSummary::from_summary(sum, &ch))?;
            std::fs::write(&path, blob).with_context(|| format!("write {path:?}"))?;
        }
        Ok(())
    }

    /// Free the in-memory LRU now, not at drop time: the store is the second
    /// copy of many summaries, and after the summaries phase nothing reads it
    /// (the only callers — cli.rs `taint` and impact.rs — scope it to the
    /// phase; FS blobs are already durable, hits/misses live in RunStats).
    /// moka evicts lazily through a background housekeeper, so force the
    /// pending invalidations before returning or RSS would not fall.
    pub fn free_lru(&mut self) {
        self.lru.invalidate_all();
        self.lru.run_pending_tasks();
    }
}

fn blob_path(dir: &Path, key: &ids::Hash) -> PathBuf {
    let k = ids::hex(key);
    dir.join(&k[..2]).join(format!("{k}.json"))
}

// ---- lossless serde projection (prost types carry no serde derives) ----

// NB: pre-fieldpath blobs (Slot without the path wrapper) fail to deserialize
// ⇒ cache miss ⇒ recompute. Dead weight, not corruption — their keys embed the
// old bids and are never probed again anyway.
#[derive(Serialize, Deserialize)]
struct StoredSummary {
    flows: Vec<(SlotP, SlotP)>,
    sink_hits: Vec<StoredSinkHit>,
    confidence: f32,
    contract_hash: String, // hex; kept in-blob so get() restores it without recompute
}

#[derive(Serialize, Deserialize)]
struct StoredSinkHit {
    in_slot: SlotP,
    class: String,
    callsite: usize,
    span: Option<(String, i32, i32)>, // (file, line, col)
    // terminal sink identity (leaf fn iid + callsite in the leaf). fmt1 blobs
    // lack it and fail to deserialize ⇒ cache miss ⇒ recompute — never a
    // summary with a stale terminal.
    terminal_fn: String,
    terminal_callsite: usize,
}

impl StoredSummary {
    fn from_summary(s: &Summary, ch: &ids::Hash) -> StoredSummary {
        let mut flows: Vec<(SlotP, SlotP)> = s.flows.iter().cloned().collect();
        flows.sort_by_key(|(a, b)| (slot_str(a), slot_str(b))); // deterministic blobs
        // sink_hits too: a warm store must serve byte-identical blobs for
        // byte-identical summaries. The Vec's order is deterministic now
        // (propagate applies callee flows in sorted order), but sorting here
        // makes blob bytes independent of that order entirely.
        let mut sink_hits: Vec<StoredSinkHit> = s
            .sink_hits
            .iter()
            .map(|h| StoredSinkHit {
                in_slot: h.in_slot.clone(),
                class: h.class.clone(),
                callsite: h.callsite,
                span: h.span.as_ref().map(|sp| (sp.file.clone(), sp.line, sp.col)),
                terminal_fn: h.terminal.fn_iid.clone(),
                terminal_callsite: h.terminal.callsite,
            })
            .collect();
        sink_hits.sort_by(|a, b| {
            slot_str(&a.in_slot)
                .cmp(&slot_str(&b.in_slot))
                .then(a.class.cmp(&b.class))
                .then(a.callsite.cmp(&b.callsite))
                .then(a.span.cmp(&b.span))
                .then(a.terminal_fn.cmp(&b.terminal_fn))
                .then(a.terminal_callsite.cmp(&b.terminal_callsite))
        });
        StoredSummary {
            flows,
            sink_hits,
            confidence: s.confidence,
            contract_hash: ids::hex(ch),
        }
    }

    fn into_cached(self) -> Cached {
        let mut ch: ids::Hash = [0u8; 32];
        if let Ok(v) = hex::decode(&self.contract_hash) {
            if v.len() == 32 {
                ch.copy_from_slice(&v);
            }
        }
        let summary = Summary {
            flows: self.flows.into_iter().collect(),
            sink_hits: self
                .sink_hits
                .into_iter()
                .map(|h| SinkHit {
                    in_slot: h.in_slot,
                    class: h.class,
                    callsite: h.callsite,
                    span: h.span.map(|(file, line, col)| cgf::Span { file, line, col }),
                    // heap-mediated hits are phase-2 and never written to the
                    // store, so a decoded one is always a phase-1 hit.
                    via_heap: None,
                    terminal: crate::ifds::SinkOrigin {
                        fn_iid: h.terminal_fn,
                        callsite: h.terminal_callsite,
                    },
                })
                .collect(),
            confidence: self.confidence,
        };
        Cached {
            summary,
            contract_hash: ch,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ifds::Slot;
    use std::collections::HashSet;

    fn sample() -> Summary {
        let mut flows = HashSet::new();
        flows.insert((Slot::Param(1).into(), Slot::Return(0).into()));
        flows.insert((Slot::Source.into(), Slot::ByRefParam(2).into()));
        Summary {
            flows,
            sink_hits: vec![SinkHit {
                in_slot: Slot::Param(1).into(),
                class: "sqli".into(),
                callsite: 3,
                span: Some(cgf::Span {
                    file: "a/b.go".into(),
                    line: 42,
                    col: 7,
                }),
                via_heap: None,
                terminal: crate::ifds::SinkOrigin {
                    fn_iid: "aaaa".into(),
                    callsite: 7,
                },
            }],
            confidence: 1.0,
        }
    }

    // SPEC §8.3: contract_hash is behavior-only — two summaries with the same
    // public taint behavior MUST hash identically (drives early-cutoff).
    // Exception: the sink's TERMINAL is included. It is body-derived, but a
    // caller's summary row carries it, so an edit that only moves a sink call
    // must invalidate callers' cached rows (a stale terminal would make
    // witness reproduce the wrong route).
    #[test]
    fn contract_hash_is_behavior_only_and_stable() {
        let mk = sample;
        let mut b = mk();
        b.confidence = 0.5;
        b.sink_hits[0].callsite = 99;
        b.sink_hits[0].span = None;
        assert_eq!(contract_hash(&mk()), contract_hash(&b));
        let mut c = mk();
        c.sink_hits[0].class = "log".into();
        assert_ne!(contract_hash(&mk()), contract_hash(&c));
        let mut d = mk();
        d.sink_hits[0].terminal = crate::ifds::SinkOrigin {
            fn_iid: "bbbb".into(),
            callsite: 7,
        };
        assert_ne!(contract_hash(&mk()), contract_hash(&d), "moved sink call");
    }

    #[test]
    fn fs_round_trip_survives_process_restart() {
        let tmp = std::env::temp_dir().join(format!("pc-store-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        let cat: ids::Hash = [7u8; 32];
        let key: ids::Hash = [9u8; 32];
        let s = sample();
        let ch = contract_hash(&s);
        {
            let w = SummaryStore::open(Some(&tmp), &cat, 16).unwrap();
            w.put(key, &s, ch).unwrap();
        }
        // fresh store instance = empty LRU, must fall back to FS
        let r = SummaryStore::open(Some(&tmp), &cat, 16).unwrap();
        let c = r.get(&key).expect("fs hit");
        assert_eq!(r.hits.load(Ordering::Relaxed), 1);
        assert_eq!(c.contract_hash, ch);
        assert_eq!(c.summary.flows, s.flows);
        assert_eq!(c.summary.sink_hits.len(), 1);
        let hit = &c.summary.sink_hits[0];
        assert_eq!(hit.class, "sqli");
        assert_eq!(hit.callsite, 3);
        assert_eq!(hit.span.as_ref().unwrap().line, 42);
        std::fs::remove_dir_all(&tmp).unwrap();
    }

    #[test]
    fn catalog_hash_namespaces_entries() {
        let tmp = std::env::temp_dir().join(format!("pc-store-ns-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        let key: ids::Hash = [9u8; 32];
        let s = sample();
        let ch = contract_hash(&s);
        let a = SummaryStore::open(Some(&tmp), &[1u8; 32], 16).unwrap();
        a.put(key, &s, ch).unwrap();
        let b = SummaryStore::open(Some(&tmp), &[2u8; 32], 16).unwrap();
        assert!(b.get(&key).is_none(), "other catalog namespace must miss");
        assert_eq!(b.misses.load(Ordering::Relaxed), 1);
        std::fs::remove_dir_all(&tmp).unwrap();
    }
}
