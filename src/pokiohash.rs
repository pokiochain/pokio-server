use sha2::{Sha256, Digest};
use ethereum_types::U256;
use hex;

use crate::constants::*;

#[inline(always)]
fn hash_func(args: &[&[u8]]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    for arg in args {
        hasher.update(arg);
    }
    hasher.finalize().to_vec()
}

fn expand(buf: &mut Vec<Vec<u8>>, space_cost: usize) {
    buf.reserve(space_cost - 1);
    for s in 1..space_cost {
        let new_hash = hash_func(&[&buf[s - 1]]);
        buf.push(new_hash);
    }
}

fn mix(buf: &mut Vec<Vec<u8>>, delta: usize, salt: &[u8], space_cost: usize, time_cost: usize) {
    for _ in 0..time_cost {
        for s in 0..space_cost {
            let prev = &buf[s.saturating_sub(1)];
            buf[s] = hash_func(&[prev, &buf[s]]);
            
            for i in 0..delta {
                let idx_block = hash_func(&[salt, &i.to_le_bytes()]);
                let other = usize::from_le_bytes(idx_block[..8].try_into().unwrap()) % space_cost;
                buf[s] = hash_func(&[&buf[s], &buf[other]]);
            }
        }
    }
}

fn extract(buf: &[Vec<u8>]) -> Vec<u8> {
    buf.last().unwrap().to_vec()
}

fn pokiohash(password: &str, salt: &str, space_cost: usize, time_cost: usize, delta: usize) -> Vec<u8> {
    let salt_bytes = salt.as_bytes();
    let mut buf = Vec::with_capacity(space_cost);
    buf.push(hash_func(&[password.as_bytes(), salt_bytes]));
    
    expand(&mut buf, space_cost);
    mix(&mut buf, delta, salt_bytes, space_cost, time_cost);
    extract(&buf)
}

pub fn pokiohash_hash(password: &str, salt: &str) -> String {
    let hash_bytes = pokiohash(password, salt, HASHING_SPACE_COST, HASHING_TIME_COST, HASHING_DELTA);
    hex::encode(hash_bytes)
}

#[inline(always)]
pub fn hash_to_difficulty(hash: &str) -> U256 {
    let hash_value = U256::from_str_radix(hash, 16).unwrap_or(U256::zero());
    let max_value = U256::MAX;
    max_value / hash_value
}
