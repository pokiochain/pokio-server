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
	if actual_height <= UNLOCK_OFFSET {
		coins
	}
	else if actual_height >= UPDATE_1_HEIGHT {
		if coins < MAX_COIN_DELAY { coins * (COIN_DIFF_2 - ( coins * COIN_DIFF_DELAY) ) }
		else { coins * (COIN_DIFF_2 - ( MAX_COIN_DELAY * COIN_DIFF_DELAY) ) }
	}
	else
	{
		let result = max(1, (4.0 - (coins as f64).log(10.0).ceil()) as u64);
		coins * (COIN_DIFF * result)
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
		println!("Invalid adjusted `v` value: {}", adjusted_v);
		return Err(anyhow!("Invalid adjusted v value"));
	}

	match recover_sender_address(adjusted_v, &r_hex, &s_hex, message_hash.into()) {
		Ok(address) => {
			tx.from = ethers::types::H160::from_slice(address.as_bytes());
			Ok(tx)
		},
		Err(e) => {
			println!("Error: {}", e);
			Err(anyhow!("Failed to recover sender address"))
		}
	}
}

fn generate_reward_tx(
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
	if last_valid_height > UNLOCK_OFFSET {
		let db = config::db();

		let latest = db.get("chain:latest_block").unwrap();
		if let Some(latest) = latest {
			let latest_height = u64::from_be_bytes(latest.as_ref().try_into().unwrap());

			for h in last_valid_height + 1..=latest_height {
				let key_to_delete = format!("block:{:08}", h);
				db.remove(&key_to_delete).unwrap();
			}
			let _ = db.insert("chain:latest_block", &last_valid_height.to_be_bytes())
				.unwrap();
			println!(
				"Blockchain reordered, height: {}.",
				last_valid_height
			);
		}
	}
	None
}

pub fn get_16th_block() -> Option<Block> {
	let db = config::db();
	if let Some(latest) = db.get("chain:latest_block").unwrap() {
		let latest_height = u64::from_be_bytes(latest.as_ref().try_into().unwrap());
		let mut block_key = format!("block:{:08}", latest_height);

		for i in 0..UNLOCK_OFFSET {
			if let Some(block_data) = db.get(&block_key).unwrap() {
				let block: Block = bincode::deserialize(&block_data).unwrap();

				if i == 15 {
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
							println!("Reordering blockchain from block...");
							fix_blockchain(block.height - FIX_BC_OFFSET);
							return None;
						}
						block_key = prev_block_key;
					} else {
						fix_blockchain(block.height - FIX_BC_OFFSET);
						break;
					}
				} else {
					fix_blockchain(block.height - FIX_BC_OFFSET);
					break;
				}
			} else {
				break;
			}
		}
	}
	None
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

pub fn get_receipt_info(txhash: &str) -> Option<(String, u64)> {
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

pub fn get_last_nonce(address: &str) -> u64 {
	let db = config::db();
	let nonce_key = format!("count:{}", address.to_lowercase());

	if let Some(nonce_bytes) = db.get(&nonce_key).unwrap() {
		let nonce_array: [u8; 32] = nonce_bytes.as_ref().try_into().unwrap();
		let last_8_bytes = &nonce_array[24..];

		u64::from_be_bytes(last_8_bytes.try_into().unwrap())
	} else {
		0
	}
}

pub fn store_raw_transaction(raw_tx: String) -> String {
	let dtx = decode_transaction(&raw_tx);
	match dtx {
		Ok(decoded_tx) => {
			let mempooldb = config::mempooldb();
			let db = config::db();
			let raw_tx_str = raw_tx.to_string();
			let sender_address = format!("0x{}", hex::encode(decoded_tx.from));
			//let nonce_key = format!("count:{}", sender_address);
			let last_nonce = get_last_nonce(&sender_address);
			if decoded_tx.nonce < EthersU256::from(last_nonce + 1) {
				//println!("Invalid nonce: {}, expected: {}", decoded_tx.nonce, last_nonce);
				return String::from("");
			} /*else {
				println!("Valid nonce {}", decoded_tx.nonce);
			}*/
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

pub fn save_block_to_db(new_block: &mut Block) -> Result<(), Box<dyn Error>> {
	
	while config::sync_status() == 1 {
		std::thread::sleep(std::time::Duration::from_millis(10));
	}
	config::update_sync(1);
	
	let result = (|| {
		let db = config::db();
		let mempooldb = config::mempooldb();
		let (actual_height, prev_hash, ts) = get_latest_block_info();
		
		let expected_height: u64 = actual_height.clone() + 1;
		
		if expected_height == new_block.height && prev_hash == new_block.prev_hash {
			
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
			if c_difficulty != new_block.difficulty {
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
			
			let mining_template = format!("{}-{}-{}-{}-{}-{}-{}", new_block.nonce, new_block.block_reward, 
				diff_hex, new_block.height, new_block.prev_hash, new_block.miner, first_two_txs).to_lowercase();
			let mining_hash = pokiohash_hash(&mining_template, &new_block.nonce);
			let mining_difficulty = hash_to_difficulty(&mining_hash) as U256;
			
			if new_block.height > UPDATE_2_HEIGHT && mining_difficulty < c_difficulty.into() {
				return Err(format!(
					"Difficulty mismatch for block {}: expected {}, got {}",
					new_block.height, c_difficulty, mining_difficulty
				).into());
			}
			
			/*let unsigned_serialized_block = serde_json::to_string_pretty(&new_block).unwrap();
			let block_signature = keccak256(&unsigned_serialized_block);
			new_block.signature = block_signature;
			let serialized_block = bincode::serialize(&new_block).unwrap();
			let unsigned_serialized_block = serde_json::to_string_pretty(&new_block).unwrap();*/
			
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
							if let Err(e) = update_balance(&sender_address, &total_deducted, 1) {
								//eprintln!("Error in transaction: {}", e);
								let _ = db.insert(tx_str, b"error")?;
							} else {
								let _ = db.insert(tx_str, b"processed")?;
								update_balance(&address, &amount, 0)
									.expect("Error updating balance");
								let nonce_key = format!("count:{}", sender_address.to_lowercase());
								let mut nonce_bytes = [0u8; 32];
								tx.nonce.to_big_endian(&mut nonce_bytes);
								let _ = db.insert(nonce_key.clone(), IVec::from(&nonce_bytes[..]))
									.expect("Failed to store nonce in sled");
							}
							let receipt_key = format!("receipt:{}", txhash.clone());
							db.insert(receipt_key, tx_str.clone().as_bytes())?;
								
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
			}
			
			//println!("Block {} successfully saved in DB", new_block.height);
			if new_block.height >= UNLOCK_OFFSET {
				if let Some(block) = get_16th_block() {
					let transactions: Vec<&str> = block.transactions.split('-').collect();

					for tx_str in transactions {
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
									
								if tx.nonce > EthersU256::from(100_000_000u64) {
									update_balance(&address, &amount, 0).expect("Error updating balance");
									let _ = db.insert(tx_str, b"processed")?;
								}
								else {
									if let Err(e) = update_balance(&sender_address, &total_deducted, 1) {
										//eprintln!("Error in transaction: {}", e);
										let _ = db.insert(tx_str, b"error")?;
									} else {
										let _ = db.insert(tx_str, b"processed")?;
										update_balance(&address, &amount, 0)
											.expect("Error updating balance");
										/*let nonce_key = format!("count:{}", sender_address);
										let mut nonce_bytes = [0u8; 32];
										tx.nonce.to_big_endian(&mut nonce_bytes);
										let _ = db.insert(nonce_key.clone(), IVec::from(&nonce_bytes[..]))
											.expect("Failed to store nonce in sled");*/
									}
									
									let receipt_key = format!("receipt:{}", txhash.clone());
									db.insert(receipt_key, tx_str.clone().as_bytes())?;
									
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

pub fn get_mempool_records() -> serde_json::Value {
    let mut records = Vec::new();
    let db = config::mempooldb();

    for result in db.iter() {
        if let Ok((_, value)) = result {
            if let Ok(raw_tx) = std::str::from_utf8(&value) {
                records.push(raw_tx.to_string());
            }
        }
    }

    json!(records)
}

pub fn save_miner(miner: &str, id: &str) {
	let db = config::pooldb();
	let timestamp = SystemTime::now()
		.duration_since(UNIX_EPOCH)
		.unwrap()
		.as_millis();

	let miner_data = json!({
		"miner": miner,
		"id": id,
		"timestamp": timestamp
	});

	let key = format!("miner_{}", id);
	let _ = db.insert(key, serde_json::to_vec(&miner_data).unwrap()).unwrap();
}

pub fn count_active_miners(seconds: u64) -> HashMap<String, Vec<String>> {
	let db = config::pooldb();
	let mut miners_map: HashMap<String, Vec<String>> = HashMap::new();
	let now = SystemTime::now()
		.duration_since(UNIX_EPOCH)
		.unwrap()
		.as_millis();

	for item in db.iter() {
		if let Ok((key, value)) = item {
			let key_str = String::from_utf8_lossy(&key);

			if key_str.starts_with("miner_") {
				if let Ok(json) = serde_json::from_slice::<Value>(&value) {
					if let (Some(miner), Some(id), Some(timestamp)) = (
						json["miner"].as_str(),
						json["id"].as_str(),
						json["timestamp"].as_u64(),
					) {
						if now - timestamp as u128 <= (seconds * 1000) as u128 {
							miners_map.entry(miner.to_string())
								.or_insert(Vec::new())
								.push(id.to_string());
						}
					}
				}
			}
		}
	}

	miners_map
}