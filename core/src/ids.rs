// Content addressing (doc 03 §2 + the contract_hash/summary_key soundness fix).
use sha2::{Digest, Sha256};

pub type Hash = [u8; 32];

pub fn hex(h: &Hash) -> String {
    hex::encode(h)
}

/// Hash a set of byte slices in the given order.
pub fn hash_parts(parts: &[&[u8]]) -> Hash {
    let mut h = Sha256::new();
    for p in parts {
        h.update((p.len() as u64).to_le_bytes()); // length-prefix to avoid ambiguity
        h.update(p);
    }
    h.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn summary_key_stable_and_order_independent() {
        let bid = b"body-hash";
        let a: Hash = [1u8; 32];
        let b: Hash = [2u8; 32];
        let k1 = summary_key(bid, &[], vec![a, b]);
        let k2 = summary_key(bid, &[], vec![b, a]); // order independent
        assert_eq!(k1, k2);
        // a callee contract change flips the key (caller must recompute)
        let c: Hash = [3u8; 32];
        assert_ne!(k1, summary_key(bid, &[], vec![a, c]));
        // a body edit flips the key
        assert_ne!(k1, summary_key(b"other-body", &[], vec![a, b]));
    }

    #[test]
    fn summary_key_source_params() {
        let bid = b"body-hash";
        let a: Hash = [1u8; 32];
        // seeding an endpoint arg re-keys the summary (doc 20 §4 option 3)
        let plain = summary_key(bid, &[], vec![a]);
        let seeded = summary_key(bid, &[1], vec![a]);
        assert_ne!(plain, seeded);
        // order/dup independent
        assert_eq!(summary_key(bid, &[2, 1], vec![a]), summary_key(bid, &[1, 2, 2], vec![a]));
        // different arg sets differ
        assert_ne!(seeded, summary_key(bid, &[2], vec![a]));
    }
}

/// summary_key = H(bid ++ own source_params ++ sorted[callee.contract_hash]).
/// A body-only edit to a callee whose behavior is unchanged leaves its
/// contract_hash unchanged => caller summary_key unchanged => cache hit.
/// source_params (doc 19 endpoint seeding) is a summary input that is NOT part
/// of bid (doc 20 §4 option 3): a schema change re-keys the summary without
/// mislabeling the fn as body-changed. Empty source_params contributes nothing,
/// so keys of unseeded functions are unchanged (no store cold start).
pub fn summary_key(bid: &[u8], source_params: &[u32], mut callee_contract_hashes: Vec<Hash>) -> Hash {
    callee_contract_hashes.sort_unstable();
    let mut parts: Vec<&[u8]> = vec![bid];
    let sp_bytes: Vec<u8>;
    if !source_params.is_empty() {
        let mut sp: Vec<u32> = source_params.to_vec();
        sp.sort_unstable();
        sp.dedup();
        sp_bytes = sp.iter().flat_map(|i| i.to_le_bytes()).collect();
        parts.push(&sp_bytes);
    }
    for c in &callee_contract_hashes {
        parts.push(c);
    }
    hash_parts(&parts)
}
