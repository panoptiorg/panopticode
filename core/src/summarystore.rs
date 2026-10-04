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
use std::sync::Arc;

/// contract_hash = behavior-only hash (flows ∪ sinks), body-independent.
/// Equal public taint behavior ⇒ equal hash ⇒ callers' summary_keys unchanged
/// (the early-cutoff that stops invalidation cascades).
pub fn contract_hash(s: &Summary) -> ids::Hash {
    let mut items: Vec<String> = s
        .flows
        .iter()
        .map(|(a, b)| format!("F:{}->{}", slot_str(a), slot_str(b)))
        .chain(
            s.sink_hits
                .iter()
                .map(|h| format!("S:{}:{}", slot_str(&h.in_slot), h.class)),
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
    pub hits: u64,
    pub misses: u64,
}

/// Namespace for the on-disk store: the catalog is an input to `summarize()`
/// but not to `summary_key`, and so is every CORE SEMANTICS flag. Both must
/// therefore namespace the cache, or a store warmed under one setting serves
/// summaries computed under the other — silently, and it would make trap 1's
/// 100.000% reuse figure meaningless. `env` is a short stable string per flag
/// (B1, doc 31 §6).
pub fn env_hash(catalog_hash: &ids::Hash, env: &str) -> ids::Hash {
    if env.is_empty() {
        return *catalog_hash; // pre-B1 layout: catalog only, so old stores stay warm
    }
    ids::hash_parts(&[catalog_hash.as_slice(), env.as_bytes()])
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
            hits: 0,
            misses: 0,
        })
    }

    /// In-process-only store (no FS); used by Engine::run().
    pub fn ephemeral() -> Self {
        SummaryStore {
            dir: None,
            lru: Cache::new(100_000),
            hits: 0,
            misses: 0,
        }
    }

    pub fn get(&mut self, key: &ids::Hash) -> Option<Arc<Cached>> {
        if let Some(c) = self.lru.get(key) {
            self.hits += 1;
            return Some(c);
        }
        if let Some(dir) = &self.dir {
            // unreadable/corrupt blob = miss, never a failed run
            if let Ok(bytes) = std::fs::read(blob_path(dir, key)) {
                if let Ok(stored) = serde_json::from_slice::<StoredSummary>(&bytes) {
                    let c = Arc::new(stored.into_cached());
                    self.lru.insert(*key, c.clone());
                    self.hits += 1;
                    return Some(c);
                }
            }
        }
        self.misses += 1;
        None
    }

    pub fn put(&mut self, key: ids::Hash, sum: &Summary, ch: ids::Hash) -> Result<()> {
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
}

impl StoredSummary {
    fn from_summary(s: &Summary, ch: &ids::Hash) -> StoredSummary {
        let mut flows: Vec<(SlotP, SlotP)> = s.flows.iter().cloned().collect();
        flows.sort_by_key(|(a, b)| (slot_str(a), slot_str(b))); // deterministic blobs
        StoredSummary {
            flows,
            sink_hits: s
                .sink_hits
                .iter()
                .map(|h| StoredSinkHit {
                    in_slot: h.in_slot.clone(),
                    class: h.class.clone(),
                    callsite: h.callsite,
                    span: h.span.as_ref().map(|sp| (sp.file.clone(), sp.line, sp.col)),
                })
                .collect(),
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
            }],
            confidence: 1.0,
        }
    }

    // SPEC §8.3: contract_hash is behavior-only — two summaries with the same
    // public taint behavior MUST hash identically (drives early-cutoff).
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
            let mut w = SummaryStore::open(Some(&tmp), &cat, 16).unwrap();
            w.put(key, &s, ch).unwrap();
        }
        // fresh store instance = empty LRU, must fall back to FS
        let mut r = SummaryStore::open(Some(&tmp), &cat, 16).unwrap();
        let c = r.get(&key).expect("fs hit");
        assert_eq!(r.hits, 1);
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
        let mut a = SummaryStore::open(Some(&tmp), &[1u8; 32], 16).unwrap();
        a.put(key, &s, ch).unwrap();
        let mut b = SummaryStore::open(Some(&tmp), &[2u8; 32], 16).unwrap();
        assert!(b.get(&key).is_none(), "other catalog namespace must miss");
        assert_eq!(b.misses, 1);
        std::fs::remove_dir_all(&tmp).unwrap();
    }
}
