use sha2::{Sha256, Digest};
use hex;

pub fn merkle_tree(tx_str: &str) -> String {
    let txs: Vec<&str> = tx_str.split('-').collect();
    let mut hashes: Vec<String> = txs.into_iter().map(merkle_hash).collect();

    while hashes.len() > 1 {
        let mut new_hashes = Vec::new();
        for chunk in hashes.chunks(2) {
            let combined_hash = if chunk.len() == 2 {
                combine_and_hash(&chunk[0], &chunk[1])
            } else {
                chunk[0].clone()
            };
            new_hashes.push(combined_hash);
        }
        hashes = new_hashes;
    }

    hashes[0].clone()
}

fn merkle_hash(tx: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(tx.as_bytes());
    let result = hasher.finalize();
    hex::encode(result)
}

fn combine_and_hash(hash1: &str, hash2: &str) -> String {
    let combined = format!("{}{}", hash1, hash2);
    merkle_hash(&combined)
}
