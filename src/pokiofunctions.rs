use serde::{Serialize, Deserialize};
use tiny_keccak::{Hasher, Keccak};
use sha2::{Sha256, Digest};
use hex;
use ethers::prelude::*;
use ethers::types::{Transaction, TransactionRequest};
use ethers::types::transaction::eip2718::TypedTransaction;
use eyre::Result;
use rlp;
use num_bigint::BigUint;
use num_bigint::BigInt;
use ethereum_types::{H160, H256, U256};
use ethers::types::U256 as EthersU256;
use secp256k1::{Secp256k1, Message, ecdsa::{RecoverableSignature, RecoveryId}};
use sha3::{Keccak256};
use num_traits::Num;
use rlp::RlpStream;
use num_traits::Zero;
use std::cmp::max; 
use eyre::anyhow;
use std::str::FromStr;
use sled::IVec;
use std::error::Error;
use serde_json::json;
use serde_json::Value;
use std::time::{SystemTime, UNIX_EPOCH};
use std::collections::HashMap;
use chrono::Local;
use std::collections::VecDeque;
use std::sync::Mutex;
use once_cell::sync::Lazy;
use num_traits::ToPrimitive;
use std::io::{BufReader as iBufReader, Write as iWrite};
use std::net::{TcpListener as nTcpListener, TcpStream as nTcpStream};
use std::io::BufRead;
use monero::{blockdata::block::Block as MoneroBlock, consensus::encode::deserialize, consensus::encode::serialize};
use hex::FromHex;

use crate::constants::*;
use crate::merkle::*;
use crate::balances::*;
use crate::pokiohash::*;
use crate::config;

#[derive(Serialize, Deserialize, Debug)]
pub struct Block {
    pub height: u64,
    pub hash: String,
    pub prev_hash: String,
    pub timestamp: u64,
    pub nonce: String,
    pub transactions: String,
    // pub transactions: Vec<String>,
    pub gas_limit: u64,
    pub gas_used: u64,
    pub miner: String,
    pub difficulty: u64,
    pub block_reward: u64,
    pub state_root: String,
    pub receipts_root: String,
    pub logs_bloom: String,
    pub extra_data: String,
    pub version: u32,
    pub signature: String,
}

#[derive(Debug)]
pub struct MinerInfo {
    pub id: String,
    pub target: String,
    pub hr: String,
    pub timestamp: u64,
    pub mined_blocks: u64,
}

pub static BLOCK_HISTORY: Lazy<Mutex<VecDeque<(u64, u64, u64, u8)>>> = Lazy::new(|| {
    Mutex::new(VecDeque::new())
});

pub fn add_block_to_history(height: u64, timestamp: u64, difficulty: u64, is_local: u8) {
    let mut history = BLOCK_HISTORY.lock().unwrap();
    let pos = history.iter().position(|(h, _, _, _)| *h < height).unwrap_or(history.len());
    history.insert(pos, (height, timestamp, difficulty, is_local));
    if history.len() > 600 {
        history.pop_back();
    }
}

pub fn sum_recent_difficulty(seconds: u64, is_local_filter: u8) -> u64 {
    let _now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards")
        .as_secs();
    let cutoff = config::actual_timestamp() - seconds;
    let history = BLOCK_HISTORY.lock().unwrap();
    history.iter()
        .filter(|(_, timestamp, _, is_local)| {
            *timestamp >= cutoff && (is_local_filter == 0 || *is_local == 1)
        })
        .map(|(_, _, difficulty, _)| *difficulty)
        .sum()
}

pub fn get_block_tx_hashes(blockhash: &str) -> Option<String> {
	let db = config::db();
	let blockhash_key = format!("txblock:{}", blockhash);
	let txs = db.get(blockhash_key).ok().flatten()?;
	let txs_str = String::from_utf8(txs.to_vec()).ok()?;
	Some(txs_str)
}

pub fn keccak256(data: &str) -> String {
	let mut hasher = Keccak::v256();
	let mut output = [0u8; 32];
	hasher.update(data.as_bytes());
	hasher.finalize(&mut output);
	hex::encode(output)
}

pub fn calculate_diff(coins: u64, actual_height: u64) -> u64 {
	let mut mult: u64 = 1;

	if actual_height > UPDATE_4_HEIGHT {
		if let Some((_, _, _, m, _)) = get_block_range_analysis(actual_height) {
			mult = m;
		}
	}
	
	if actual_height > UPDATE_6_HEIGHT {
		if coins > (mult - 1) * 10 {
			mult = 1;
		}
	}
	
	if actual_height <= PREMINE_BLOCKS {
		coins
	}
	else if actual_height >= UPDATE_1_HEIGHT {
		if coins < MAX_COIN_DELAY { mult * coins * (COIN_DIFF_2 - ( coins * COIN_DIFF_DELAY) ) }
		else { mult * coins * (COIN_DIFF_2 - ( MAX_COIN_DELAY * COIN_DIFF_DELAY) ) }
	}
	else
	{
		let result = max(1, (4.0 - (coins as f64).log(10.0).ceil()) as u64);
		mult * coins * (COIN_DIFF * result)
	}
}

pub fn calculate_rx_diff(coins: u64, actual_height: u64) -> u64 {
	
	let mut mult: u64 = 1;

	if actual_height > UPDATE_4_HEIGHT {
		if let Some((_, _, _, _, m)) = get_block_range_analysis(actual_height) {
			mult = m;
		}
	}
	
	if actual_height <= PREMINE_BLOCKS {
		coins
	}
	else {
		if coins < MAX_COIN_DELAY { mult * coins * (COIN_DIFF_RX - ( coins * COIN_DIFF_DELAY) ) }
		else { mult * coins * (COIN_DIFF_RX - ( MAX_COIN_DELAY * COIN_DIFF_DELAY) ) }
	}
}


pub fn get_latest_block_info() -> (u64, String, u64) {
	(config::actual_height(), config::actual_hash(), config::actual_timestamp())
}

pub fn set_latest_block_info() {
	let db = config::db();
	if let Some(latest) = db.get("chain:latest_block").unwrap() {
		let latest_height = u64::from_be_bytes(latest.as_ref().try_into().unwrap());
		let block_key = format!("block:{:08}", latest_height);
		if let Some(block_data) = db.get(block_key).unwrap() {
			let block: Block = bincode::deserialize(&block_data).unwrap();
			config::update_actual_height(block.height);
			config::update_actual_hash(block.hash);
			config::update_actual_timestamp(block.timestamp);
			return;
		}
	}
	config::update_actual_height(0);
	config::update_actual_hash("0000000000000000000000000000000000000000000000000000000000000000".to_string());
	config::update_actual_timestamp(0);
}

fn recover_sender_address(v: u8, r: &str, s: &str, message_hash: [u8; 32]) -> Result<H160, String> {
	let secp = Secp256k1::new();

	let recovery_id = RecoveryId::from_i32(v as i32).map_err(|e| e.to_string())?;

	let r_bigint = BigInt::from_str_radix(r, 16).map_err(|e| e.to_string())?;
	let s_bigint = BigInt::from_str_radix(s, 16).map_err(|e| e.to_string())?;

	let mut r_bytes = [0u8; 32];
	let mut s_bytes = [0u8; 32];

	let r_bytes_raw = r_bigint.to_bytes_be().1;
	let s_bytes_raw = s_bigint.to_bytes_be().1;

	r_bytes[32 - r_bytes_raw.len()..].copy_from_slice(&r_bytes_raw);
	s_bytes[32 - s_bytes_raw.len()..].copy_from_slice(&s_bytes_raw);

	let mut signature_bytes = [0u8; 64];
	signature_bytes[..32].copy_from_slice(&r_bytes);
	signature_bytes[32..].copy_from_slice(&s_bytes);

	let signature = RecoverableSignature::from_compact(&signature_bytes, recovery_id)
		.map_err(|e| e.to_string())?;

	let message = Message::from_slice(&message_hash).map_err(|e| e.to_string())?;
	let public_key = secp.recover_ecdsa(&message, &signature).map_err(|e| e.to_string())?;

	let public_key_bytes = public_key.serialize_uncompressed();
	let address_bytes = Keccak256::digest(&public_key_bytes[1..]);
	let address = H160::from_slice(&address_bytes[12..]);

	Ok(address)
}

fn calculate_message_hash(
	nonce: U256,
	gas_price: U256,
	gas: U256,
	to: H160,
	value: U256,
	input: &[u8],
	chain_id: u64,
) -> H256 {
	let mut rlp_stream = RlpStream::new();
	rlp_stream.begin_list(9);
	rlp_stream.append(&nonce);
	rlp_stream.append(&gas_price);
	rlp_stream.append(&gas);
	rlp_stream.append(&to);
	rlp_stream.append(&value);
	rlp_stream.append(&input);
	rlp_stream.append(&chain_id);
	rlp_stream.append(&0u8);
	rlp_stream.append(&0u8);

	let rlp_encoded = rlp_stream.out();
	let hash = Keccak256::digest(&rlp_encoded);
	H256::from_slice(&hash)
}

pub fn decode_transaction(raw_tx_hex: &str) -> Result<Transaction> {
	let raw_tx_bytes = hex::decode(raw_tx_hex.strip_prefix("0x").unwrap_or(raw_tx_hex))?;
	let mut tx: Transaction = rlp::decode(&raw_tx_bytes)?;
	
	let mut bytes = [0u8; 32];
	tx.nonce.to_little_endian(&mut bytes);
	let nonce = U256::from_little_endian(&bytes);
	
	let mut gpbytes = [0u8; 32];
	let gas_price_value = tx.gas_price.unwrap_or(EthersU256::zero());
	gas_price_value.to_little_endian(&mut gpbytes);
	let gas_price = U256::from_little_endian(&gpbytes);
	
	let mut gbytes = [0u8; 32];
	tx.gas.to_little_endian(&mut gbytes);
	let gas = U256::from_little_endian(&gbytes);
	
	let mut valbytes = [0u8; 32];
	tx.value.to_little_endian(&mut valbytes);
	let value = U256::from_little_endian(&valbytes);
	
	let input = tx.input.clone();
	let dest_str = tx.to.map(|addr| format!("{:x}", addr)).unwrap_or_default();
	let to = H160::from_slice(&hex::decode(dest_str).unwrap());
	let chain_id = tx.chain_id.unwrap_or(EthersU256::zero()).as_u64();

	let message_hash = calculate_message_hash(nonce, gas_price, gas, to, value, &input, chain_id);

	let v: U64 = tx.v;
	let r = tx.r.to_string();
	let s = tx.s.to_string();
	let r_bigint = BigInt::from_str_radix(&r, 10).unwrap();
	let s_bigint = BigInt::from_str_radix(&s, 10).unwrap();
	let r_hex = format!("{:064x}", r_bigint);
	let s_hex = format!("{:064x}", s_bigint);

	let adjusted_v = (v.as_u64() - (2 * chain_id + 35)) as u8;

	if adjusted_v > 1 {
		print_log_message(format!("Invalid adjusted `v` value: {}", adjusted_v), 4);
		return Err(anyhow!("Invalid adjusted v value"));
	}

	match recover_sender_address(adjusted_v, &r_hex, &s_hex, message_hash.into()) {
		Ok(address) => {
			tx.from = ethers::types::H160::from_slice(address.as_bytes());
			Ok(tx)
		},
		Err(e) => {
			print_log_message(format!("Error: {}", e), 4);
			Err(anyhow!("Failed to recover sender address"))
		}
	}
}

pub fn generate_reward_tx(
	private_key: &str,
	nonce: u64,
	miner_address: &str,
	reward_amount: EthersU256,
) -> eyre::Result<String> {
	let wallet = LocalWallet::from_str(private_key)?.with_chain_id(CHAIN_ID);

	let tx = TransactionRequest::new()
		.nonce(nonce)
		.to(miner_address)
		.value(reward_amount)
		.gas(21000)
		.gas_price(0);

	let tx: TypedTransaction = tx.into();
	let signature = wallet.sign_transaction_sync(&tx)?;
	let raw_signed_tx = tx.rlp_signed(&signature);
	let _dtx = decode_transaction(&hex::encode(&raw_signed_tx))?;

	Ok(hex::encode(raw_signed_tx))
}

pub fn get_mining_template(coins: &str, miner: &str) -> String {
	let (height, prevhash, _ts) = get_latest_block_info();
	let coins_dec = max(10, coins.parse::<u64>().unwrap_or(10));
	let diff_dec = calculate_diff(coins_dec, height.clone());
	let diff = format!("{:016X}", diff_dec);
	let nonce = MINING_TX_NONCE + height + 1;
	let fee: u64 = config::mining_fee().try_into().unwrap();;
	let _fee_biguint = BigUint::from(fee);
	let fee_base_wei = BigUint::parse_bytes(b"10000000000000000", 10).unwrap();
	let fee_coins_biguint = BigUint::from(coins_dec);
	let fee_wei_amount = fee_coins_biguint * &fee_base_wei * fee;
	let fee_reward_amount = EthersU256::from_dec_str(&fee_wei_amount.to_str_radix(10)).unwrap();
	let fee_raw_tx: String;
	let signer: String;
	signer = format!("0x{}", ethers::utils::hex::encode(config::address()));
	let base_wei = BigUint::parse_bytes(b"1000000000000000000", 10).unwrap();
	let coins_biguint = BigUint::from(coins_dec);
	let wei_amount = (coins_biguint * &base_wei) - fee_wei_amount;
	let reward_amount = EthersU256::from_dec_str(&wei_amount.to_str_radix(10)).unwrap();
	let raw_tx: String;
	match generate_reward_tx(config::pkey(), nonce, miner, reward_amount) {
		Ok(tx) => {
			raw_tx = tx;
		}
		Err(_e) => {
			raw_tx = String::new();
		}
	}
	match generate_reward_tx(config::pkey(), nonce, &signer, fee_reward_amount) {
		Ok(tx) => {
			fee_raw_tx = tx;
		}
		Err(_e) => {
			fee_raw_tx = String::new();
		}
	}
	format!("0000000000000000-{}-{}-{}-{}-{}-{}-{}", coins_dec, diff, height+1, prevhash, miner, raw_tx, fee_raw_tx).to_lowercase()
}

pub fn fix_blockchain(last_valid_height: u64) -> Option<Block> {
	if config::async_status() == 0
	{
		while config::sync_status() == 1 {
			std::thread::sleep(std::time::Duration::from_millis(10));
		}
	}
	config::update_sync(1);
	if last_valid_height > UNLOCK_OFFSET {
		let db = config::db();
		let latest = db.get("chain:latest_block").unwrap();
		if let Some(latest) = latest {
			let latest_height = u64::from_be_bytes(latest.as_ref().try_into().unwrap());
			for h in last_valid_height + 1..=latest_height {
				let key_to_delete = format!("block:{:08}", h);
				if let Some(block_data) = db.get(&key_to_delete).unwrap() {
					if let Ok(block) = bincode::deserialize::<Block>(&block_data) {
						let parts: Vec<&str> = block.extra_data.split(':').collect();
						if parts.len() >= 2 {
							let blobmining = parts[0];
							let blob_prefix_mining = &blobmining[..78.min(blobmining.len())];
							let blobsave = format!("{}{}", blob_prefix_mining, block.nonce);
							let pooldb = config::pooldb();
							let _ = pooldb.remove(blobsave.as_str());
						}
					}
				}
				db.remove(&key_to_delete).unwrap();
			}
			let _ = db.insert("chain:latest_block", &last_valid_height.to_be_bytes()).unwrap();
			let block_key = format!("block:{:08}", last_valid_height);
			if let Some(block_data) = db.get(block_key).unwrap() {
				let block: Block = bincode::deserialize(&block_data).unwrap();
				config::update_actual_height(block.height);
				config::update_actual_hash(block.hash);
				config::update_actual_timestamp(block.timestamp);
			}
			print_log_message(format!("Blockchain reordered"), 1);
		}
	}
	config::update_sync(0);
	None
}

pub fn preload_block_history() {
    let db = config::db();
    let my_address = format!("0x{}", hex::encode(config::address())).to_lowercase();
    if let Some(latest) = db.get("chain:latest_block").unwrap() {
        let mut height = u64::from_be_bytes(latest.as_ref().try_into().unwrap());
        for _ in 0..600 {
            let key = format!("block:{:08}", height);
            if let Some(block_data) = db.get(&key).unwrap() {
                if let Ok(block) = bincode::deserialize::<Block>(&block_data) {
                    let mut is_local = 0;
                    if let Some(first_tx) = block.transactions.split('-').next() {
                        if let Ok(decoded_tx) = decode_transaction(first_tx) {
                            let sender_address = format!("0x{}", hex::encode(decoded_tx.from)).to_lowercase();
                            if sender_address == my_address {
                                is_local = 1;
                            }
                        }
                    }
                    add_block_to_history(block.height, block.timestamp, block.difficulty, is_local);
                }
            }
            if height == 0 {
                break;
            } else {
                height -= 1;
            }
        }
    }
}

pub fn get_16th_block() -> Option<Block> {
	let db = config::db();
	if let Some(latest) = db.get("chain:latest_block").unwrap() {
		let latest_height = u64::from_be_bytes(latest.as_ref().try_into().unwrap());
		let mut block_key = format!("block:{:08}", latest_height);

		for i in 0..UNLOCK_OFFSET {
			if let Some(block_data) = db.get(&block_key).unwrap() {
				let block: Block = bincode::deserialize(&block_data).unwrap();

				if i == UNLOCK_OFFSET - 1 {
					return Some(block);
				}

				if block.prev_hash.is_empty() {
					break;
				}

				if let Some(prev_height) = db.get(format!("hash:{}", block.prev_hash)).unwrap() {
					let prev_height = u64::from_be_bytes(prev_height.as_ref().try_into().unwrap());
					let prev_block_key = format!("block:{:08}", prev_height);

					if let Some(prev_block_data) = db.get(&prev_block_key).unwrap() {
						let prev_block: Block = bincode::deserialize(&prev_block_data).unwrap();

						if prev_block.hash != block.prev_hash {
							print_log_message(format!("Reordering blockchain..."), 1);
							config::update_full_sync(1);
							fix_blockchain(block.height - FIX_BC_OFFSET);
							config::update_full_sync(0);
							return None;
						}
						block_key = prev_block_key;
					} else {
						config::update_full_sync(1);
						fix_blockchain(block.height - FIX_BC_OFFSET);
						config::update_full_sync(0);
						break;
					}
				} else {
					config::update_full_sync(1);
					fix_blockchain(block.height - FIX_BC_OFFSET);
					config::update_full_sync(0);
					break;
				}
			} else {
				break;
			}
		}
	}
	None
}

pub fn get_block_range_analysis(height: u64) -> Option<(
    u64, // duration 100 blocks
    usize, // blocks POKIOHash
    usize, // blocks RandomX
    u64, // multiplier POKIOHash
    u64  // multiplier RandomX
)> {

    let db = config::db();

    if height < 200 {
        return None;
    }

    let (start, end) = if height > UPDATE_5_HEIGHT {
		let s = ((height + 100) / 100 - 2) * 100;
		if height % 100 == 0 {
			(s - 100, s)
		} else {
			(s, s + 100)
		}
	} else {
		let s = ((height / 100) - 2) * 100;
		(s, s + 100)
	};

    let mut timestamps = Vec::new();
    let mut pokiohash_count = 0;
    let mut randomx_count = 0;
    let mut pokiohash_multiplier = 0u64;
    let mut randomx_multiplier = 0u64;

    for h in start..end {
        let key = format!("block:{:08}", h);
        if let Some(data) = db.get(&key).unwrap() {
            let block: Block = bincode::deserialize(&data).unwrap();
            timestamps.push(block.timestamp);

            let reward = block.block_reward as f64;
            let diff = block.difficulty as f64;

            if reward == 0.0 {
                continue;
            }

            let diff_per_coin = diff / reward;

            match block.nonce.len() {
                16 => {
                    let norm = diff_per_coin / (COIN_DIFF_2 as f64);
                    let floored = norm.floor() as u64;
                    pokiohash_multiplier = floored + 1;
                    pokiohash_count += 1;
                }
                8 => {
                    let norm = diff_per_coin / (COIN_DIFF_RX as f64);
                    let floored = norm.floor() as u64;
                    randomx_multiplier = floored + 1;
                    randomx_count += 1;
                }
                _ => {}
            }
        } else {
            return None;
        }
    }

    if let (Some(first), Some(last)) = (timestamps.first(), timestamps.last()) {
        let duration = last.saturating_sub(*first);
		
		let (dmin, dmax) = if height > UPDATE_5_HEIGHT {
			(1200, 2400)
		} else {
			(600, 3000)
		};

        if duration < dmin {
            if pokiohash_count > 60 {
                pokiohash_multiplier += 1;
            }
            if randomx_count > 60 {
                randomx_multiplier += 1;
            }
            if pokiohash_count <= 60 && randomx_count <= 60 {
                pokiohash_multiplier += 1;
                randomx_multiplier += 1;
            }
        }

        if duration > dmax {
            pokiohash_multiplier = pokiohash_multiplier.saturating_sub(1).max(1);
            randomx_multiplier = randomx_multiplier.saturating_sub(1).max(1);
        } else {
            pokiohash_multiplier = pokiohash_multiplier.max(1);
            randomx_multiplier = randomx_multiplier.max(1);
        }

        Some((
            duration,
            pokiohash_count,
            randomx_count,
            pokiohash_multiplier,
            randomx_multiplier
        ))
    } else {
        None
    }
}



pub fn get_block_as_json(block_number: u64) -> Value {
	let db = config::db();
	let block_key = format!("block:{:08}", block_number);

	if let Some(block_data) = db.get(block_key).ok().flatten() {
		if let Ok(block) = bincode::deserialize::<Block>(&block_data) {
			return serde_json::to_value(block).unwrap()
		}
	}

	json!(null)
}

pub fn print_log_message(message: String, level: u64) {
    let actual_level = config::log_level();
    if level <= actual_level {
        let now = Local::now();
        let timestamp = now.format("[%d %b %H:%M:%S]").to_string();
        println!("{} {}", timestamp, message);
    }
}

pub fn get_next_blocks(start_height: u64) -> Value {
	let mut blocks = Vec::new();
	let db = config::db();
	for i in 0..1000 {
		let height = start_height + i;
		let key = format!("block:{:08}", height);

		if let Some(serialized_block) = db.get(&key).unwrap() {
			if let Ok(block) = bincode::deserialize::<Block>(&serialized_block) {
				blocks.push(block);
			}
		} else {
			break;
		}
	}
	json!(blocks)
}

pub fn get_rawtx_status(rawtx: &str) -> Option<String> {
	let db = config::db();
	let rawtx_key = format!("{}", rawtx);
	let txs = db.get(rawtx_key).ok().flatten()?;
	let txs_str = String::from_utf8(txs.to_vec()).ok()?;
	Some(txs_str)
}

pub fn get_receipt_info(_txhash: &str) -> Option<(String, u64)> {
	/*let db = config::db();
	let receipt_key = format!("receipt:{}", txhash);
	let receiptblock_key = format!("receiptblock:{}", txhash);
	let receipt = db.get(receipt_key).ok().flatten()?;
	let block_bytes = db.get(receiptblock_key).ok().flatten()?;
	let receipt_str = String::from_utf8(receipt.to_vec()).ok()?;
	let txheight = u64::from_be_bytes(block_bytes.as_ref().try_into().ok()?);*/
	let (actual_height, actual_hash, _) = get_latest_block_info();
	//Some((receipt_str, txheight))
	Some((actual_hash, actual_height - 1))
}

pub fn get_last_nonce(address: &str, checkpool: u64) -> u64 {
	let db = config::db();
	let nonce_key = format!("count:{}", address.to_lowercase());
	let mut mempool_nonce: EthersU256 = EthersU256::zero();
	if checkpool == 1
	{
		let mempooldb = config::mempooldb();
		for result in mempooldb.iter() {
			if let Ok((_, value)) = result {
				if let Ok(raw_tx) = std::str::from_utf8(&value) {
					let dtx = decode_transaction(&raw_tx);
					match dtx {
						Ok(decoded_tx) => {
							let sender_address = format!("0x{}", hex::encode(decoded_tx.from));
							if sender_address.to_lowercase() == address.to_lowercase() {
								if mempool_nonce < decoded_tx.nonce {
									mempool_nonce = decoded_tx.nonce;
								}
							}
						},
						Err(_) => {}
					}
				}
			}
		}
	}
	let db_nonce: u64;
	
	if let Some(nonce_bytes) = db.get(&nonce_key).unwrap() {
		let nonce_array: [u8; 32] = nonce_bytes.as_ref().try_into().unwrap();
		let last_8_bytes = &nonce_array[24..];

		db_nonce = u64::from_be_bytes(last_8_bytes.try_into().unwrap())
	} else {
		db_nonce = 0;
	}
	
	let f_mempool_nonce = mempool_nonce.as_u64();
	
	if f_mempool_nonce > db_nonce {
		print_log_message(format!("mempoolnonce: {}", f_mempool_nonce), 2);
		f_mempool_nonce
	} else {
		print_log_message(format!("dbnonce: {}", db_nonce), 2);
		db_nonce
	}
}

pub fn store_raw_transaction(raw_tx: String) -> String {
	
	let mempooldb = config::mempooldb();
	let db = config::db();
	
	match get_rawtx_status(&raw_tx.clone()) {
        Some(status) if status == "confirmed" => {
			let _ = mempooldb.remove(&raw_tx.clone());
            return String::from("");
        }
        _ => {}
    }
	
	let dtx = decode_transaction(&raw_tx);
	match dtx {
		Ok(decoded_tx) => {
			let raw_tx_str = raw_tx.to_string();
			let sender_address = format!("0x{}", hex::encode(decoded_tx.from));
			//let nonce_key = format!("count:{}", sender_address);
			let last_nonce = get_last_nonce(&sender_address, 0);
			if decoded_tx.nonce < EthersU256::from(last_nonce + 1) {
				print_log_message(format!("Invalid nonce: {}, expected: {}", decoded_tx.nonce, last_nonce + 1), 4);
				return String::from("");
			} else {
				print_log_message(format!("Valid nonce {}", decoded_tx.nonce), 3);
			}
			let _ = mempooldb.insert(raw_tx_str.clone(), IVec::from(raw_tx_str.as_bytes()))
				.expect("Failed to store raw transaction in sled");
			let mut nonce_bytes = [0u8; 32];
			decoded_tx.nonce.to_big_endian(&mut nonce_bytes);
			//let _ = db.insert(nonce_key.clone(), IVec::from(&nonce_bytes[..]))
			//	.expect("Failed to store nonce in sled");
			mempooldb.flush().expect("Failed to flush sled database");
			db.flush().expect("Failed to flush sled database");
			//decoded_tx.hash.to_string()
			keccak256(&raw_tx)
		}
		Err(_) => String::from(""),
	}
}

pub fn difficulty_to_target(difficulty: u64) -> String {
    let max_target = 0xffff_ffff_u64;
    let target = max_target / difficulty;
    let target_bytes = target.to_le_bytes();
    hex::encode(&target_bytes[..4])
}

pub fn compute_randomx_hash(blob_hex: &str, nonce_hex: &str) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    let mut blob = hex::decode(blob_hex)?;
    let nonce_bytes = hex::decode(nonce_hex)?;
    if nonce_bytes.len() != 4 {
        return Err("Invalid nonce".into());
    }
    if blob.len() < 43 {
        return Err("Invalid blob".into());
    }
    blob[39..43].copy_from_slice(&nonce_bytes);
    let hash = config::with_vm(|vm| vm.calculate_hash(&blob))?;
    Ok(hex::encode(hash))
}

pub fn dynamic_compute_randomx_hash(blob_hex: &str, nonce_hex: &str, seed_hex: &str) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    
	let seed = match config::current_dynamic_seed() {
        Some(seed) => seed,
        None => "".to_string(),
    };
	
    if seed_hex != seed {
        config::set_dynamic_vm(seed_hex);
        print_log_message(format!("New dynamic seed: {:?}", config::current_dynamic_seed()), 1);
    }

    let mut blob = hex::decode(blob_hex)?;
    let nonce_bytes = hex::decode(nonce_hex)?;
    if nonce_bytes.len() != 4 {
        return Err("Invalid nonce".into());
    }
    if blob.len() < 43 {
        return Err("Invalid blob".into());
    }
    blob[39..43].copy_from_slice(&nonce_bytes);

    let hash_result = config::with_dynamic_vm(|vm| vm.calculate_hash(&blob));

    match hash_result {
        Some(Ok(hash)) => Ok(hex::encode(hash)),
        Some(Err(e)) => Err(Box::new(e)),
        None => Err("Dynamic VM not initialized".into()),
    }
}


pub fn rx_hash_to_difficulty(hash_hex: &str) -> Result<u64, Box<dyn std::error::Error>> {
    let hash_bytes = hex::decode(hash_hex)?;
    if hash_bytes.len() != 32 {
        return Err("Invalid hash".into());
    }
    let mut reversed_bytes = hash_bytes.clone();
    reversed_bytes.reverse();
    let hash_num = BigUint::from_bytes_be(&reversed_bytes);
    let base_diff = BigUint::from_bytes_be(&[0xff; 32]);
    let hash_diff = if hash_num.is_zero() {
        BigUint::zero()
    } else {
        &base_diff / hash_num
    };
    Ok(hash_diff.to_u64().unwrap_or(u64::MAX))
}

pub fn save_block_to_db(new_block: &mut Block, checkpoint: u8) -> Result<(), Box<dyn Error>> {
	
	if config::async_status() == 0
	{
		while config::sync_status() == 1 {
			std::thread::sleep(std::time::Duration::from_millis(10));
		}
	}
	config::update_sync(1);
	
	let result = (|| {
		let db = config::db();
		let pooldb = config::pooldb();
		let mempooldb = config::mempooldb();
		let (actual_height, prev_hash, ts) = get_latest_block_info();
		
		let expected_height: u64 = actual_height.clone() + 1;
		
		if expected_height == new_block.height && prev_hash == new_block.prev_hash {
			
			if  checkpoint > 0
			{
				if new_block.height > UPDATE_2_HEIGHT && new_block.timestamp < ts {
					return Err(format!(
						"Invalid timestamp for block {}: expected >= {}, got {}",
						new_block.height, ts, new_block.timestamp
					).into());
				}
				
				let receipts_root = merkle_tree(&new_block.transactions);
				if receipts_root != new_block.receipts_root {
					return Err(format!(
						"Merkle check mismatch at block {}: expected {}, got {}",
						new_block.height, receipts_root, new_block.receipts_root
					).into());
				}
				
				let c_difficulty = calculate_diff(new_block.block_reward, actual_height);
				let rx_difficulty = calculate_rx_diff(new_block.block_reward, actual_height);
				
				if c_difficulty != new_block.difficulty && rx_difficulty != new_block.difficulty {
					return Err(format!(
						"Difficulty mismatch at block {}: expected {}, got {}",
						new_block.height, c_difficulty, new_block.difficulty
					).into());
				}
				
				let hash = new_block.hash.clone();
				new_block.signature = "".to_string();
				new_block.hash = "".to_string();
				let unhashed_serialized_block = serde_json::to_string_pretty(&new_block).unwrap();
				let block_hash = keccak256(&unhashed_serialized_block);
				
				if hash != block_hash {
					return Err(format!(
						"Hash mismatch for block {}: expected {}, got {}",
						new_block.height, block_hash, hash
					).into());
				}
				new_block.hash = block_hash;
				let unsigned_serialized_block = serde_json::to_string_pretty(&new_block).unwrap();
				let block_signature = keccak256(&unsigned_serialized_block);
				new_block.signature = block_signature;
			
				let diff_hex = format!("{:016X}", new_block.difficulty);
				
				let tx_parts: Vec<&str> = new_block.transactions.split('-').collect();
				let first_two_txs = tx_parts.iter().take(2).cloned().collect::<Vec<&str>>().join("-");
				
				if new_block.difficulty == rx_difficulty && new_block.height <= UPDATE_RX_HEIGHT {
					return Err(format!(
						"Invalid algorithm: RANDOMX"
					).into());
				}
				
				let mut seedhash = "";
				if new_block.difficulty == rx_difficulty && new_block.height > UPDATE_RX_HEIGHT {
					let ts_hex = format!("{:010x}", ts);
					let target = difficulty_to_target(new_block.difficulty);
					let rx_first_two_txs = tx_parts.iter().take(2).cloned().collect::<Vec<&str>>().join("0000000000000000");
					let rx_blob = match new_block.extra_data.len() {
						0..=3 => format!(
							"0101{}{}0000000001{}{}",
							ts_hex,
							prev_hash,
							target,
							rx_first_two_txs
						),
						4 => format!(
							"{}{}{}0000000001{}{}",
							new_block.extra_data,
							ts_hex,
							prev_hash,
							target,
							rx_first_two_txs
						),
						_ => {
							let parts: Vec<&str> = new_block.extra_data.split(':').collect();
							if parts.len() == 3 {
								let (blobmining, blobblock, blobseed) = (parts[0], parts[1], parts[2]);
								let blob_prefix_mining = &blobmining[..78.min(blobmining.len())];
								let mut blobsave: String = blobmining.to_string();
								if new_block.height > UPDATE_4_HEIGHT {
									blobsave = format!("{}{}", blob_prefix_mining, new_block.nonce);
								}
								let blob_prefix_block = &blobblock[..78.min(blobblock.len())];
								if blob_prefix_mining != blob_prefix_block {
									return Err(format!("Blobmining and Blobblock prefix mismatch").into());
								}
								if pooldb.contains_key(&blobsave)? {
									return Err(format!("Duplicated mining blob").into());
								}
								//println!("blobsave: {}", blobsave);
								let _ = pooldb.insert(blobsave.clone(), IVec::from(blobsave.as_bytes()));
								let blob_bytes = Vec::from_hex(blobblock)?;
								let mut block: MoneroBlock = deserialize(&blob_bytes)?;
								{
									if block.header.major_version < monero::VarInt(16) {
										return Err(format!("Invalid major version").into());
									}
									if block.header.timestamp < monero::VarInt(ts-240) || block.header.timestamp > monero::VarInt(ts+3600) {
										return Err(format!("Invalid block date").into());
									}
								}
								let valid_seedhash = blobseed.len() == 64 && hex::decode(blobseed).is_ok();
								let valid_blobs = blobmining.len() > 64 && blobblock.len() > blobmining.len();
								if valid_seedhash && valid_blobs {
									seedhash = blobseed;
									blobmining.to_string()
								} else {
									return Err(format!("Invalid merged blob data").into());
								}
							} else if parts.len() == 2 {
								let (blobmining, blobseed) = (parts[0], parts[1]);
								let blob_prefix_mining = &blobmining[..78.min(blobmining.len())];
								let blobblock = format!("{}{}{}", blob_prefix_mining, new_block.nonce, MONERO_RX_RANDOM_DATA);
								let mut blobsave: String = blobmining.to_string();
								if new_block.height > UPDATE_4_HEIGHT {
									blobsave = format!("{}{}", blob_prefix_mining, new_block.nonce);
								}
								if pooldb.contains_key(&blobsave)? {
									return Err(format!("Duplicated mining blob").into());
								}
								let _ = pooldb.insert(blobsave.clone(), IVec::from(blobsave.as_bytes()));
								let blob_bytes = Vec::from_hex(&blobblock)?;
								if blobseed != "b38737d8f08e1b0b033611bb268bd79b236c3089a756b79906eff085c67a7e31"
								{
									let mut block: MoneroBlock = deserialize(&blob_bytes)?;
									{
										if block.header.major_version < monero::VarInt(16) {
											return Err(format!("Invalid major version").into());
										}
										if block.header.timestamp < monero::VarInt(ts-240) || block.header.timestamp > monero::VarInt(ts+3600) {
											return Err(format!("Invalid block date").into());
										}
									}
								}
								let valid_seedhash = blobseed.len() == 64 && hex::decode(blobseed).is_ok();
								let valid_blobs = blobmining.len() > 64 && hex::decode(blobmining).is_ok();
								if valid_seedhash && valid_blobs {
									seedhash = blobseed;
									blobmining.to_string()
								} else {
									return Err(format!("Invalid merged blob data").into());
								}
							} else {
								return Err(format!("Invalid extra_data field").into());
							}
						}
					};

					let mut rx_hashdiff = 0;

					if let Ok(mut stream) = nTcpStream::connect("127.0.0.1:6789") {
						let request = json!({
							"blob": &rx_blob, 
							"nonce": &new_block.nonce,
							"seed": &seedhash
						});
						if let Ok(req_str) = serde_json::to_string(&request) {
							let _ = stream.write_all(req_str.as_bytes());
							let _ = stream.write_all(b"\n");
							let mut reader = iBufReader::new(stream);
							let mut response = String::new();
							if let Ok(_) = reader.read_line(&mut response) {
								if let Ok(json_resp) = serde_json::from_str::<serde_json::Value>(&response) {
									if json_resp["status"] == "ok" {
										if let Some(hash_str) = json_resp["hash"].as_str() {
											if let Ok(diff) = rx_hash_to_difficulty(hash_str) {
												rx_hashdiff = diff;
											}
										}
									}
								}
							}
						}
					}
					
					if new_block.extra_data.len() > 4 && rx_hashdiff > MAX_MONERO_DIFF {
						return Err(format!(
							"Difficulty too high for block {}",
							new_block.height
						).into());
					}
					
					if rx_hashdiff < rx_difficulty {
						return Err(format!(
							"Difficulty mismatch for block {}: expected {}, got {}",
							new_block.height, rx_difficulty, rx_hashdiff
						).into());
					}
				}
				
				if new_block.difficulty == c_difficulty && new_block.height > UPDATE_3_HEIGHT {
					return Err(format!(
						"Invalid algorithm: BALLOON"
					).into());
				}
				
				if new_block.difficulty == c_difficulty && new_block.height > UPDATE_2_HEIGHT {
					
					let mining_template = format!("{}-{}-{}-{}-{}-{}-{}", new_block.nonce, new_block.block_reward, 
						diff_hex, new_block.height, new_block.prev_hash, new_block.miner, first_two_txs).to_lowercase();
					let mining_hash = pokiohash_hash(&mining_template, &new_block.nonce);
					let mining_difficulty = hash_to_difficulty(&mining_hash) as U256;
					
					if mining_difficulty < c_difficulty.into() {
						return Err(format!(
							"Difficulty mismatch for block {}: expected {}, got {}",
							new_block.height, c_difficulty, mining_difficulty
						).into());
					}
				}
			
				/*let unsigned_serialized_block = serde_json::to_string_pretty(&new_block).unwrap();
				let block_signature = keccak256(&unsigned_serialized_block);
				new_block.signature = block_signature;
				let serialized_block = bincode::serialize(&new_block).unwrap();
				let unsigned_serialized_block = serde_json::to_string_pretty(&new_block).unwrap();*/
			}
			
			let amount_block_transactions: Vec<&str> = new_block.transactions.split('-').collect();
			
			let mut reward_amount: EthersU256 = EthersU256::from(0u64);
			for tx_str in amount_block_transactions {
				if tx_str == "" {
					continue;
				}
				let dtx = decode_transaction(tx_str);
				match dtx {
					Ok(tx) => {
						let amount = tx.value.clone();
						if tx.nonce > EthersU256::from(100_000_000u64) {
							reward_amount += amount;
						}
					}
					Err(e) => {
						reward_amount += EthersU256::from(0u64);
					}
				}
			}
			
			let decimals = EthersU256::from_dec_str("1000000000000000000").unwrap();
			let xrw = EthersU256::from(new_block.block_reward) * decimals;
			
			if reward_amount > xrw {
				return Err(format!(
					"Invalid coinbase transactions"
				).into());
			}
			
			let serialized_block = bincode::serialize(new_block)?;
			let _ = db.insert(format!("block:{:08}", new_block.height), serialized_block)?;
			let _ = db.insert(format!("hash:{}", new_block.hash), &new_block.height.to_be_bytes())?;
			let _ = db.insert("chain:latest_block", &new_block.height.to_be_bytes())?;
			
			config::update_actual_height(new_block.height.clone());
			config::update_actual_hash(new_block.hash.clone());
			config::update_actual_timestamp(new_block.timestamp.clone());
			
			let block_transactions: Vec<&str> = new_block.transactions.split('-').collect();

			for tx_str in block_transactions {
				/*if let Err(e) = mempooldb.remove(&tx_str) {
					eprintln!("Error deleting mempool entry: {:?}", e);
				}*/
				if tx_str == "" {
					continue;
				}
				
				if db.contains_key(tx_str)? {
					continue;
				}

				let dtx = decode_transaction(tx_str);
				match dtx {
					Ok(tx) => {
						let address = tx.to.map(|addr| format!("{:?}", addr)).unwrap_or("None".to_string());
						let sender_address = format!("0x{}", hex::encode(tx.from));
						let txhash = keccak256(&tx_str); //format!("0x{}", ethers::utils::hex::encode(tx.hash.to_string()));
						let amount = tx.value.clone().to_string();
						let fee = tx.gas * tx.gas_price.unwrap_or(EthersU256::zero());
						let total_deducted = (tx.value + fee).to_string();
						if tx.nonce < EthersU256::from(100_000_000u64) {
							let last_nonce = get_last_nonce(&sender_address, 0);
							if new_block.height > UPDATE_2_HEIGHT {
								if tx.nonce == EthersU256::from(last_nonce + 1) {
									if let Err(_e) = update_balance(&sender_address, &total_deducted, 1) {
										//eprintln!("Error in transaction: {}", e);
										let _ = db.insert(tx_str, b"error")?;
									} else {
										let _ = db.insert(tx_str, b"processed")?;
										update_balance(&address, &amount, 0)
											.expect("Error updating balance");
									}
									if tx.nonce > EthersU256::from(last_nonce) {
										print_log_message(format!("Valid nonce {}", tx.nonce), 4);
										let nonce_key = format!("count:{}", sender_address.to_lowercase());
										print_log_message(format!("Nonce updated {}, {}", tx.nonce, nonce_key), 2);
										let mut nonce_bytes = [0u8; 32];
										tx.nonce.to_big_endian(&mut nonce_bytes);
										let _ = db.insert(nonce_key.clone(), IVec::from(&nonce_bytes[..]))
											.expect("Failed to store nonce in sled");
									} else {
										print_log_message(format!("Invalid nonce: {}, expected: {}", tx.nonce, last_nonce + 1), 2);
									}
									let receipt_key = format!("receipt:{}", txhash.clone());
									db.insert(receipt_key, tx_str.as_bytes())?;
										
									let (ah, _, _) = get_latest_block_info();
									let txheight = ah + 1;
									let receipt_key = format!("receiptblock:{}", txhash.clone());
									db.insert(receipt_key, &txheight.to_be_bytes())?;
								}
							} else {
								if let Err(_e) = update_balance(&sender_address, &total_deducted, 1) {
									//eprintln!("Error in transaction: {}", e);
									let _ = db.insert(tx_str, b"error")?;
								} else {
									let _ = db.insert(tx_str, b"processed")?;
									update_balance(&address, &amount, 0)
										.expect("Error updating balance");
								}
								if tx.nonce > EthersU256::from(last_nonce) {
									print_log_message(format!("Valid nonce {}", tx.nonce), 4);
									let nonce_key = format!("count:{}", sender_address.to_lowercase());
									print_log_message(format!("Nonce updated {}, {}", tx.nonce, nonce_key), 2);
									let mut nonce_bytes = [0u8; 32];
									tx.nonce.to_big_endian(&mut nonce_bytes);
									let _ = db.insert(nonce_key.clone(), IVec::from(&nonce_bytes[..]))
										.expect("Failed to store nonce in sled");
								} else {
									print_log_message(format!("Invalid nonce: {}, expected: {}", tx.nonce, last_nonce + 1), 2);
								}
								let receipt_key = format!("receipt:{}", txhash.clone());
								db.insert(receipt_key, tx_str.as_bytes())?;
									
								let (ah, _, _) = get_latest_block_info();
								let txheight = ah + 1;
								let receipt_key = format!("receiptblock:{}", txhash.clone());
								db.insert(receipt_key, &txheight.to_be_bytes())?;
							}						
						}
					}
					Err(e) => {
						eprintln!("Error processing tx: {:?}", e);
					}
				}
			}
			
			print_log_message(format!("Block {} successfully saved in DB", new_block.height), 3);
			if new_block.height >= UNLOCK_OFFSET {
				if let Some(block) = get_16th_block() {
					let transactions: Vec<&str> = block.transactions.split('-').collect();

					for tx_str in transactions {
						
						if tx_str == "" {
							continue;
						}
						
						match get_rawtx_status(tx_str) {
							Some(status) if status == "processed" => {
								let _ = db.insert(tx_str, b"confirmed")?;
								continue;
							}
							Some(status) if status == "error" => {
								let _ = db.insert(tx_str, b"confirmed_with_error")?;
								continue;
							}
							Some(status) => {
								print_log_message(format!("Unexpected status  {}: {}", tx_str, status), 4);
								continue;
							}
							None => { }
						}

						let dtx = decode_transaction(tx_str);
						
						match dtx {
							Ok(tx) => {
								let address = tx.to.map(|addr| format!("{:?}", addr)).unwrap_or("None".to_string());
								let sender_address = format!("0x{}", hex::encode(tx.from));
								let txhash = keccak256(&tx_str); //format!("0x{}", ethers::utils::hex::encode(tx.hash.to_string()));
								let amount = tx.value.clone().to_string();
								let fee = tx.gas * tx.gas_price.unwrap_or(EthersU256::zero());
								let total_deducted = (tx.value + fee).to_string();
									
								if tx.nonce > EthersU256::from(100_000_000u64) {
									update_balance(&address, &amount, 0).expect("Error updating balance");
									let _ = db.insert(tx_str, b"confirmed")?;
								}
								else {
									if let Err(_e) = update_balance(&sender_address, &total_deducted, 1) {
										//eprintln!("Error in transaction: {}", e);
										let _ = db.insert(tx_str, b"confirmed_with_error")?;
									} else {
										let _ = db.insert(tx_str, b"confirmed")?;
										update_balance(&address, &amount, 0)
											.expect("Error updating balance");
										/*let nonce_key = format!("count:{}", sender_address);
										let mut nonce_bytes = [0u8; 32];
										tx.nonce.to_big_endian(&mut nonce_bytes);
										let _ = db.insert(nonce_key.clone(), IVec::from(&nonce_bytes[..]))
											.expect("Failed to store nonce in sled");*/
									}
									
									let receipt_key = format!("receipt:{}", txhash.clone());
									db.insert(receipt_key, tx_str.as_bytes())?;
									
									let (ah, _, _) = get_latest_block_info();
									let txheight = ah + 1;
									let receipt_key = format!("receiptblock:{}", txhash.clone());
									db.insert(receipt_key, &txheight.to_be_bytes())?;							
								}
							}
							Err(e) => {
								eprintln!("Error processing tx: {:?}", e);
							}
						}
						if let Err(e) = mempooldb.remove(&tx_str) {
							eprintln!("Error deleting mempool entry: {:?}", e);
						}
					}
				}
			}
		}
		
		Ok(())
	})();
	config::update_sync(0);
	result
}

pub fn save_mined_block(new_block: &mut Block, miningid: &str) -> Result<(), Box<dyn Error>> {
    let result = (|| {
        let db = config::pooldb();
        new_block.miner = new_block.miner.to_lowercase();
        let serialized_block = bincode::serialize(&new_block)?;
        db.insert(format!("block:{:08}", new_block.height), serialized_block)?;
        let counter_key = format!("minedblocks:{}:{}", new_block.miner, miningid);
        let current_count = db
            .get(&counter_key)?
            .map(|val| {
                let bytes: [u8; 8] = val.as_ref().try_into().unwrap_or([0u8; 8]);
                u64::from_be_bytes(bytes)
            })
            .unwrap_or(0);
        let new_count = current_count + 1;
        db.insert(counter_key, &new_count.to_be_bytes())?;
        print_log_message(
            format!(
                "Block {} saved. Total blocks mined by {}: {}",
                new_block.height,
                new_block.miner,
                new_count
            ),
            3,
        );

        Ok(())
    })();
    result
}

pub fn get_all_miningids_for_miner(miner: &str) -> Result<Vec<(String, u64)>, Box<dyn std::error::Error>> {
    let db = config::pooldb();
    let miner_lower = miner.to_lowercase();
    let prefix = format!("minedblocks:{}:", miner_lower);
    let mut results = Vec::new();
    for item in db.scan_prefix(prefix.as_bytes()) {
        let (key, value) = item?;
        let key_str = std::str::from_utf8(&key)?;
        let parts: Vec<&str> = key_str.splitn(3, ':').collect();
        if parts.len() == 3 {
            let miningid = parts[2].to_string();
            let count_bytes: [u8; 8] = value.as_ref().try_into().unwrap_or([0u8; 8]);
            let count = u64::from_be_bytes(count_bytes);
            results.push((miningid, count));
        }
    }
    Ok(results)
}

pub fn get_blocks_paginated(limit: usize, offset: usize) -> Result<Vec<Block>, Box<dyn std::error::Error>> {
    let db = config::pooldb();
    let mut blocks = Vec::new();
    let mut skipped = 0;
    for item in db.iter().rev() {
        let (key, value) = item?;
        let key_str = std::str::from_utf8(&key)?;
        if key_str.starts_with("block:") {
            if skipped < offset {
                skipped += 1;
                continue;
            }

            let block: Block = bincode::deserialize(&value)?;
            blocks.push(block);

            if blocks.len() >= limit {
                break;
            }
        }
    }
    Ok(blocks)
}

pub fn get_mempool_records() -> Result<serde_json::Value, sled::Error> {
    let mut records = Vec::new();
    let mempooldb = config::mempooldb();
    let db = config::db();

    for result in mempooldb.iter() {
        if let Ok((_, value)) = result {
            if let Ok(raw_tx) = std::str::from_utf8(&value) {
                if db.contains_key(raw_tx)? {
                    if let Err(e) = mempooldb.remove(&raw_tx) {
                        eprintln!("Error deleting mempool entry: {:?}", e);
                    }
                    continue;
                }
                records.push(raw_tx.to_string());
            }
        }
    }
    Ok(json!(records))
}

pub fn save_miner(miner: &str, id: &str, coins: &str, hr: &str) {
	let db = config::pooldb();
	let timestamp = SystemTime::now()
		.duration_since(UNIX_EPOCH)
		.unwrap()
		.as_millis();

	let miner_data = json!({
		"miner": miner,
		"id": id,
		"target" : coins,
		"hr" : hr,
		"timestamp": timestamp
	});

	let key = format!("miner_{}", id);
	let _ = db.insert(key, serde_json::to_vec(&miner_data).unwrap()).unwrap();
}

pub fn count_active_miners(seconds: u64) -> HashMap<String, Vec<MinerInfo>> {
    let db = config::pooldb();
    let mut miners_map: HashMap<String, Vec<MinerInfo>> = HashMap::new();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis();
    let mut miningid_block_counts: HashMap<String, u64> = HashMap::new();
    for item in db.iter() {
        if let Ok((key, value)) = item {
            let key_str = String::from_utf8_lossy(&key);
            if key_str.starts_with("miner_") {
                if let Ok(json) = serde_json::from_slice::<Value>(&value) {
                    if let (Some(miner), Some(id), Some(target), Some(hr), Some(timestamp)) = (
                        json["miner"].as_str(),
                        json["id"].as_str(),
                        json["target"].as_str(),
                        json["hr"].as_str(),
                        json["timestamp"].as_u64(),
                    ) {
                        if now - timestamp as u128 <= (seconds * 1000) as u128 {
                            let miner_str = miner.to_string();
                            if !miningid_block_counts.contains_key(id) {
                                if let Ok(mined_blocks_data) = get_all_miningids_for_miner(miner) {
                                    for (miningid, count) in mined_blocks_data {
                                        miningid_block_counts.insert(miningid, count);
                                    }
                                }
                            }
                            let mined_blocks = *miningid_block_counts.get(id).unwrap_or(&0);

                            let miner_info = MinerInfo {
                                id: id.to_string(),
                                target: target.to_string(),
                                hr: hr.to_string(),
                                timestamp,
                                mined_blocks,
                            };

                            miners_map.entry(miner_str)
                                .or_insert(Vec::new())
                                .push(miner_info);
                        }
                    }
                }
            }
        }
    }

    miners_map
}
