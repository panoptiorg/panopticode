// A sharded concurrent map (IidHex -> V) for the parallel summaries phase.
//
// The tabulation over the SCC DAG runs on the global rayon pool: every worker
// reads callee summaries and writes completed ones. A plain `HashMap` is neither
// concurrent nor `Sync`, so the engine's `summaries` / `contract_hashes` live in
// this type instead. Values that readers would otherwise deep-clone are stored
// as `Arc` (callers pass `Arc<Summary>`), so a lookup is an atomic increment,
// not a copy of a summary.
//
// Sharded `RwLock<HashMap>` rather than a single lock: `propagate` looks up a
// callee summary at every call site it walks, so reads dominate ~1000:1; 64
// read locks keep that contention off one cache line. Writes happen once per
// completed SCC. Shards are keyed by a deterministic hash of the iid, so two
// runs with the same content build byte-identical shardings — `PartialEq`
// compares by content, never by layout.
use crate::graph::IidHex;
use std::collections::hash_map::DefaultHasher;
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{RwLock};

const SHARDS: usize = 64;

pub struct ShardMap<V> {
    shards: Vec<RwLock<HashMap<IidHex, V>>>,
    len: AtomicUsize,
}

impl<V> Default for ShardMap<V> {
    fn default() -> Self {
        Self::new()
    }
}

impl<V> ShardMap<V> {
    pub fn new() -> Self {
        ShardMap {
            shards: (0..SHARDS).map(|_| RwLock::new(HashMap::new())).collect(),
            len: AtomicUsize::new(0),
        }
    }

    fn shard_of(k: &IidHex) -> usize {
        // DefaultHasher::new() is keyed with fixed keys: the shard of an iid is
        // stable within a process, which is all a lookup needs.
        let mut h = DefaultHasher::new();
        k.hash(&mut h);
        (h.finish() % SHARDS as u64) as usize
    }

    /// Clone the value out (an `Arc::clone` for the summary map).
    pub fn get(&self, k: &IidHex) -> Option<V>
    where
        V: Clone,
    {
        self.shards[Self::shard_of(k)]
            .read()
            .unwrap()
            .get(k)
            .cloned()
    }

    pub fn contains_key(&self, k: &IidHex) -> bool {
        self.shards[Self::shard_of(k)].read().unwrap().contains_key(k)
    }

    pub fn insert(&self, k: IidHex, v: V) -> Option<V> {
        let mut g = self.shards[Self::shard_of(&k)].write().unwrap();
        let prev = g.insert(k, v);
        if prev.is_none() {
            self.len.fetch_add(1, Ordering::Relaxed);
        }
        prev
    }

    /// Insert `make()` iff absent; always return the stored value. The ⊥
    /// seeding of a self-recursive singleton uses this.
    pub fn get_or_insert(&self, k: IidHex, make: impl FnOnce() -> V) -> V
    where
        V: Clone,
    {
        let mut g = self.shards[Self::shard_of(&k)].write().unwrap();
        let before = g.len();
        let v = g.entry(k).or_insert_with(make).clone();
        if g.len() != before {
            self.len.fetch_add(1, Ordering::Relaxed);
        }
        v
    }

    pub fn len(&self) -> usize {
        self.len.load(Ordering::Relaxed)
    }

    /// Snapshot iteration: materializes one shard at a time, so the peak extra
    /// memory is one shard of (String, Arc) pairs, never the whole map. The
    /// order is shard-major then per-shard HashMap order — every consumer of
    /// this either re-sorts or keys its output, so the order never leaks.
    pub fn iter(&self) -> impl Iterator<Item = (IidHex, V)> + '_
    where
        V: Clone,
    {
        let shards = &self.shards;
        (0..SHARDS).flat_map(move |i| {
            let g = shards[i].read().unwrap();
            g.iter().map(|(k, v)| (k.clone(), v.clone())).collect::<Vec<_>>()
        })
    }
}

impl<V: PartialEq + Clone> PartialEq for ShardMap<V> {
    fn eq(&self, other: &Self) -> bool {
        self.len() == other.len()
            && self.iter().all(|(k, v)| other.get(&k).as_ref() == Some(&v))
    }
}

impl<V: Eq + Clone> Eq for ShardMap<V> {}

impl<V: std::fmt::Debug + Clone> std::fmt::Debug for ShardMap<V> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_map().entries(self.iter()).finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn insert_get_roundtrip_and_eq() {
        let a: ShardMap<u32> = ShardMap::new();
        a.insert("k1".into(), 1);
        a.insert("k2".into(), 2);
        assert_eq!(a.get(&"k1".into()), Some(1));
        assert_eq!(a.len(), 2);
        let b: ShardMap<u32> = ShardMap::new();
        b.insert("k2".into(), 2);
        b.insert("k1".into(), 1);
        assert_eq!(a, b);
        b.insert("k1".into(), 9);
        assert_ne!(a, b);
    }

    #[test]
    fn get_or_insert_seeds_once() {
        let m: ShardMap<u32> = ShardMap::new();
        assert_eq!(m.get_or_insert("x".into(), || 7), 7);
        assert_eq!(m.get_or_insert("x".into(), || 9), 7);
        assert_eq!(m.len(), 1);
    }
}
