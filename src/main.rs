use sled;
use serde::{Serialize, Deserialize};
use std::time::{SystemTime, UNIX_EPOCH};
use tiny_keccak::{Hasher, Keccak};
use sha2::{Sha256, Digest};
use hex;
use ethers::prelude::*;
use ethers::types::{Transaction, TransactionRequest};
use ethers::types::transaction::eip2718::TypedTransaction;
use std::str::FromStr;
use eyre::Result;
//use tokio::runtime::Runtime;
use rlp;
use num_bigint::BigUint;
use num_bigint::BigInt;
use tokio;
use warp::Filter;
use std::sync::Arc;
//use std::thread;
//use std::sync::Mutex;
use serde_json::json;
use ethereum_types::{H160, H256, U256};
use ethers::types::U256 as EthersU256;
use secp256k1::{Secp256k1, Message, ecdsa::{RecoverableSignature, RecoveryId}};
use sha3::{Keccak256};
use num_traits::Num;
use rlp::RlpStream;
use eyre::anyhow;
use std::thread;
use std::io::{self};
use serde_json::Value;
use num_traits::Zero;
use std::cmp::max; 
use nng::{Socket, Protocol};
use std::time::Duration;
use reqwest::Client;
use sled::IVec;
use nng::options::protocol::pubsub::Subscribe;
use nng::options::Options;
use std::error::Error;
use std::collections::HashMap;

mod config;

fn update_balance(address: &str, amount_to_add: &str, operation_type: u8) -> Result<(), Box<dyn std::error::Error>> {
    let db = config::db();
    let address_lowercase = address.to_lowercase();
    let address_key = address_lowercase.as_bytes();

    let amount_to_add_biguint = BigUint::parse_bytes(amount_to_add.as_bytes(), 10)
        .ok_or("Error converting to BigUint")?;

    let current_balance = if let Some(existing_balance) = db.get(address_key)? {
        let existing_balance_str = String::from_utf8_lossy(&existing_balance);
        BigUint::parse_bytes(existing_balance_str.as_bytes(), 10)
            .ok_or("Error converting to BigUint")?
    } else {
        BigUint::zero()
    };

    let new_balance = if operation_type == 1 {
        if amount_to_add_biguint > current_balance {
            return Err("Insufficient balance".into());
        }
        current_balance - amount_to_add_biguint
    } else {
        current_balance + amount_to_add_biguint
    };

    let _ = db.insert(address_key, new_balance.to_string().as_bytes())?;

    Ok(())
}


fn get_balance(address: &str) -> Result<String, Box<dyn std::error::Error>> {
	let db = config::db();
	let address_lowercase = address.to_lowercase();
	let address_key = address_lowercase.as_bytes();

	if let Some(balance) = db.get(address_key)? {
		let balance_str = String::from_utf8_lossy(&balance);
		Ok(balance_str.to_string())
	} else {
		Ok("0".to_string())
	}
}


pub fn recover_sender_address(v: u8, r: &str, s: &str, message_hash: [u8; 32]) -> Result<H160, String> {
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

fn hash_func(args: &[&[u8]]) -> Vec<u8> {
	let mut hasher = Sha256::new();
	for arg in args {
		hasher.update(arg);
	}
	hasher.finalize().to_vec()
}

fn expand(buf: &mut Vec<Vec<u8>>, space_cost: usize) {
	for s in 1..space_cost {
		let new_hash = hash_func(&[&buf[s - 1]]);
		buf.push(new_hash);
	}
}

fn mix(buf: &mut Vec<Vec<u8>>, delta: usize, salt: &[u8], space_cost: usize, time_cost: usize) {
	for _ in 0..time_cost {
		for s in 0..space_cost {
			let prev = buf[s.saturating_sub(1)].clone();
			buf[s] = hash_func(&[&prev, &buf[s]]);
			
			for i in 0..delta {
				let idx_block = hash_func(&[salt, &i.to_le_bytes()]);
				let other = usize::from_le_bytes(idx_block[..8].try_into().unwrap()) % space_cost;
				buf[s] = hash_func(&[&buf[s], &buf[other]]);
			}
		}
	}
}

fn extract(buf: &Vec<Vec<u8>>) -> Vec<u8> {
	buf.last().unwrap().clone()
}

pub fn pokiohash(password: &str, salt: &str, space_cost: usize, time_cost: usize, delta: usize) -> Vec<u8> {
	let salt_bytes = salt.as_bytes();
	let mut buf = vec![hash_func(&[password.as_bytes(), salt_bytes])];
	
	expand(&mut buf, space_cost);
	mix(&mut buf, delta, salt_bytes, space_cost, time_cost);
	extract(&buf)
}

pub fn pokiohash_hash(password: &str, salt: &str) -> String {
	let hash_bytes = pokiohash(password, salt, 16, 20, 4);
	hex::encode(hash_bytes)
}

fn hash_to_difficulty(hash: &str) -> U256 {
	let hash_value = U256::from_str_radix(hash, 16).unwrap_or(U256::zero());
	let max_value = U256::MAX;
	let difficulty = max_value / hash_value;
	difficulty
}

fn merkle_tree(tx_str: &str) -> String {
	let txs: Vec<&str> = tx_str.split('-').collect();
	let mut hashes: Vec<String> = txs.into_iter().map(|tx| hash(tx)).collect();
	while hashes.len() > 1 {
		let mut new_hashes = Vec::new();
		for chunk in hashes.chunks(2) {
			if chunk.len() == 2 {
				let combined_hash = combine_and_hash(&chunk[0], &chunk[1]);
				new_hashes.push(combined_hash);
			} else {
				new_hashes.push(chunk[0].to_string());
			}
		}
		hashes = new_hashes;
	}
	hashes[0].clone()
}

fn hash(tx: &str) -> String {
	let mut hasher = Sha256::new();
	hasher.update(tx.as_bytes());
	let result = hasher.finalize();
	hex::encode(result)
}

fn combine_and_hash(hash1: &str, hash2: &str) -> String {
	let combined = format!("{}{}", hash1, hash2);
	hash(&combined)
}

#[derive(Serialize, Deserialize, Debug)]
struct Block {
	height: u64,
	hash: String,
	prev_hash: String,
	timestamp: u64,
	nonce: String,
	transactions: String,
	//transactions: Vec<String>,
	gas_limit: u64,
	gas_used: u64,
	miner: String,
	difficulty: u64,
	block_reward: u64,
	state_root: String,
	receipts_root: String,
	logs_bloom: String,
	extra_data: String,
	version: u32,
	signature: String,
}

fn keccak256(data: &str) -> String {
	let mut hasher = Keccak::v256();
	let mut output = [0u8; 32];
	hasher.update(data.as_bytes());
	hasher.finalize(&mut output);
	hex::encode(output)
}

fn get_latest_block_info() -> (u64, String, u64) {
	let db = config::db();
	if let Some(latest) = db.get("chain:latest_block").unwrap() {
		let latest_height = u64::from_be_bytes(latest.as_ref().try_into().unwrap());
		let block_key = format!("block:{:08}", latest_height);
		if let Some(block_data) = db.get(block_key).unwrap() {
			let block: Block = bincode::deserialize(&block_data).unwrap();
			return (block.height, block.hash, block.timestamp);
		}
	}
	(0, "0000000000000000000000000000000000000000000000000000000000000000".to_string(), 0)
}

fn calculate_diff(coins: u64) -> u64 {
	let (actual_height, _, _) = get_latest_block_info();
	if actual_height == 0 {
		coins
	}
	else
	{
		let result = max(1, (4.0 - (coins as f64).log(10.0).ceil()) as u64);
		coins * (250 * result)
	}
}

fn get_mining_template(coins: &str, miner: &str) -> String {
	let db = config::db();
	let (prevhash, height) = if let Some(latest) = db.get("chain:latest_block").unwrap() {
		let latest_height = u64::from_be_bytes(latest.as_ref().try_into().unwrap());
		let block_key = format!("block:{:08}", latest_height);
		if let Some(block_data) = db.get(block_key).unwrap() {
			let block: Block = bincode::deserialize(&block_data).unwrap();
			(block.hash, latest_height)
		} else {
			(
				"0000000000000000000000000000000000000000000000000000000000000000".to_string(),
				0,
			)
		}
	} else {
		(
			"0000000000000000000000000000000000000000000000000000000000000000".to_string(),
			0,
		)
	};
	
	let coins_dec = max(10, coins.parse::<u64>().unwrap_or(10));
	let diff_dec = calculate_diff(coins_dec);
	let diff = format!("{:016X}", diff_dec);
	
	let nonce = 100000000 + height + 1;
	
	let fee: u64 = 3;
	let fee_biguint = BigUint::from(fee);
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
		Err(e) => {
			raw_tx = String::new();
		}
	}

	match generate_reward_tx(config::pkey(), nonce, &signer, fee_reward_amount) {
		Ok(tx) => {
			fee_raw_tx = tx;
		}
		Err(e) => {
			fee_raw_tx = String::new();
		}
	}
	format!("0000000000000000-{}-{}-{}-{}-{}-{}-{}", coins_dec, diff, height+1, prevhash, miner, raw_tx, fee_raw_tx).to_lowercase()
}

fn generate_reward_tx(
	private_key: &str,
	nonce: u64,
	miner_address: &str,
	reward_amount: EthersU256,
) -> eyre::Result<String> {
	let wallet = LocalWallet::from_str(private_key)?.with_chain_id(850401u64);

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

fn decode_transaction(raw_tx_hex: &str) -> Result<Transaction> {
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

fn fix_blockchain(last_valid_height: u64) -> Option<Block> {
	if last_valid_height > 16 {
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

fn get_16th_block() -> Option<Block> {
    let db = config::db();
    if let Some(latest) = db.get("chain:latest_block").unwrap() {
        let latest_height = u64::from_be_bytes(latest.as_ref().try_into().unwrap());
        let mut block_key = format!("block:{:08}", latest_height);
        let mut last_valid_height = latest_height;

        for i in 0..16 {
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

                        // Verify prev_hash 
                        if prev_block.hash != block.prev_hash {
                            /*println!(
                                "Error: Inconsistency at block {} -> prev_hash ({}) different than ({})",
                                block.height, block.prev_hash, prev_block.hash
                            );*/

                            // Reorder blockchain inconsistency
                            println!(
                                "Reordering blockchain from block {}...",
                                block.height - 1
                            );

                            fix_blockchain(block.height - 1);

                            return None;
                        }

                        block_key = prev_block_key;
                        last_valid_height = block.height;
                    } else {
                        /*println!(
                            "Error: Blockheight {} with prev_hash {} not found",
                            prev_height, block.prev_hash
                        );*/
						fix_blockchain(block.height - 1);
                        break;
                    }
                } else {
                    /*println!(
                        "Error: Cant' map prev_hash {} at block {}",
                        block.prev_hash, block.height
                    );*/
					fix_blockchain(block.height - 1);
                    break;
                }
            } else {
                break;
            }
        }
    }
    None
}

fn get_block_tx_hashes(blockhash: &str) -> Option<String> {
    let db = config::db();

    let blockhash_key = format!("txblock:{}", blockhash);
    let txs = db.get(blockhash_key).ok().flatten()?;

    let txs_str = String::from_utf8(txs.to_vec()).ok()?;

    Some(txs_str)
}

fn get_receipt_info(txhash: &str) -> Option<(String, u64)> {
    let db = config::db();

    let receipt_key = format!("receipt:{}", txhash);
    let receiptblock_key = format!("receiptblock:{}", txhash);

    let receipt = db.get(receipt_key).ok().flatten()?;
    let block_bytes = db.get(receiptblock_key).ok().flatten()?;

    let receipt_str = String::from_utf8(receipt.to_vec()).ok()?;
    let txheight = u64::from_be_bytes(block_bytes.as_ref().try_into().ok()?);

    Some((receipt_str, txheight))
}


fn mine_block(coins: &str, miner: &str, nonce: &str) -> sled::Result<()> {
	//let miner = format!("0x{}", hex::encode(config::address()));
	let mining_template = get_mining_template(&coins, &miner);
	let mut modified_password = nonce.to_string();
	if mining_template.len() > 16 {
		modified_password.push_str(&mining_template[16..]);
	}
	//println!("Mining Template: {}", mining_template);
	
	let parts: Vec<&str> = mining_template.split('-').collect();
	//println!("Nonce: {}", parts[0]);
	//println!("PrevHash: {}", parts[3]);
	//println!("Miner: {}", parts[4]);
	
	let mined_coins: u64 = parts[1].parse().unwrap();
	let mined_coins_difficulty = u64::from_str_radix(parts[2], 16).unwrap_or(u64::MAX);
	let block_difficulty = mined_coins_difficulty.clone();
	
	let mining_hash = pokiohash_hash(&modified_password, nonce);
	let mining_difficulty = hash_to_difficulty(&mining_hash) as U256;
	
	let mining_transaction = parts[6];
	let fee_transaction = parts[7];
	let block_transactions = format!("{}-{}", mining_transaction, fee_transaction);

	let db = config::db();
	if mining_difficulty > block_difficulty.into()
	{
		let (actual_height, actual_hash, _) = get_latest_block_info();

		let mut new_block = Block {
			height: actual_height + 1,
			hash: "".to_string(),
			prev_hash: actual_hash,
			timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
			nonce: nonce.to_string(),
			//transactions: vec!["tx1".to_string(), "tx2".to_string()],
			transactions: block_transactions.to_string(),
			gas_limit: 1000000,
			gas_used: 750000,
			miner: miner.to_string(),
			difficulty: mined_coins_difficulty,
			block_reward: mined_coins,
			state_root: "".to_string(),
			receipts_root: "".to_string(),
			logs_bloom: "".to_string(),
			extra_data: "".to_string(),
			version: 1,
			signature: "".to_string(),
		};
		
		let mempooldb = config::mempooldb();
		let mut transactions_list = block_transactions.clone();
		let mut transactions_hash_list = "".to_string();
		for entry in mempooldb.iter() {
			match entry {
				Ok((key, value)) => {
					let tx_value_str = String::from_utf8(value.to_vec()).unwrap_or_else(|_| String::from("Invalid UTF-8"));
					let tx_str = tx_value_str.clone();
					let dtx = decode_transaction(&tx_str);
					match dtx {
						Ok(tx) => {
							let address = tx.to.map(|addr| format!("{:?}", addr)).unwrap_or("None".to_string());
							let sender_address = format!("0x{}", hex::encode(tx.from));
							let amount = tx.value.clone().to_string();
							let txhash = format!("0x{}", ethers::utils::hex::encode(tx.hash.to_string()));
							let fee = tx.gas * tx.gas_price.unwrap_or(EthersU256::zero());
							let total_deducted = (tx.value + fee).to_string();
							if let Err(e) = update_balance(&sender_address, &total_deducted, 1) {
								eprintln!("Error in transaction: {}", e);
							} else {
								update_balance(&address, &amount, 0)
									.expect("Error updating balance");
							}
							//println!("Processed tx: {} -> {}", address, amount);
							let _ = db.insert(tx_value_str.clone(), b"processed")?;
							
							let receipt_key = format!("receipt:{}", txhash.clone());
							db.insert(receipt_key, tx_value_str.clone().as_bytes())?;
							
							let (ah, _, _) = get_latest_block_info();
							let txheight = ah + 1;
							let receipt_key = format!("receiptblock:{}", txhash.clone());
							db.insert(receipt_key, &txheight.to_be_bytes())?;
							
							if transactions_hash_list.clone() == "" {
								transactions_hash_list = format!("{}", txhash.clone());
							} else {
								transactions_hash_list = format!("{}-{}", transactions_hash_list, txhash.clone());
							}
						}
						Err(e) => {
							eprintln!("Error processing tx: {:?}", e);
						}
					}
					
					transactions_list = format!("{}-{}", transactions_list, tx_value_str);
					if let Err(e) = mempooldb.remove(&key) {
						eprintln!("Error deleting mempool entry: {:?}", e);
					}
				}
				Err(e) => {
					eprintln!("Error reading mempool entry: {:?}", e);
				}
			}
		}
		
		new_block.transactions = transactions_list;
		
		//get merkle tx's receipt
		new_block.receipts_root = merkle_tree(&new_block.transactions);
		//get blockhash
		let unhashed_serialized_block = serde_json::to_string_pretty(&new_block).unwrap();
		let block_hash = keccak256(&unhashed_serialized_block);
		
		let txblock_key = format!("txblock:{}", block_hash.clone());
		db.insert(txblock_key, transactions_hash_list.as_bytes())?;
		
		/*if let Some(txhashes) = get_block_tx_hashes(&block_hash.clone()) {
			println!("TXHASHES: {}", txhashes);
		}*/
		
		println!("Block found. Diff: {}, Hash: {}", mining_difficulty, block_hash.clone());
		
		new_block.hash = block_hash;
		
		//sign block
		let unsigned_serialized_block = serde_json::to_string_pretty(&new_block).unwrap();
		let block_signature = keccak256(&unsigned_serialized_block);
		new_block.signature = block_signature;
		//serialize block to save in sled
		let serialized_block = bincode::serialize(&new_block).unwrap();
		let sync_height = new_block.height;
		//height as key
		let _ = db.insert(format!("block:{:08}", new_block.height), serialized_block)?;
		//index hash -> height
		let _ = db.insert(format!("hash:{}", new_block.hash), &new_block.height.to_be_bytes())?;
		//save lastest_block
		let _ = db.insert("chain:latest_block", &new_block.height.to_be_bytes())?;
		
		if let Some(latest) = db.get("chain:latest_block")? {
			let latest_height = u64::from_be_bytes(latest.as_ref().try_into().unwrap());
			let block_key = format!("block:{:08}", latest_height);
			if let Some(block_data) = db.get(block_key)? {
				let block: Block = bincode::deserialize(&block_data).unwrap();
				//println!("Last block tx: {:?}", block.transactions);
			}
		}
		
		view_mempool();
		
		if let Some(block) = get_16th_block() {
			let transactions: Vec<&str> = block.transactions.split('-').collect();

			for tx_str in transactions {
				if db.contains_key(tx_str)? {
					//println!("Skipping already processed transaction: {}", tx_str);
					continue;
				}
				let dtx = decode_transaction(tx_str);
				match dtx {
					Ok(tx) => {
						let address = tx.to.map(|addr| format!("{:?}", addr)).unwrap_or("None".to_string());
						let sender_address = format!("0x{}", hex::encode(tx.from));
						let amount = tx.value.clone().to_string();
						let fee = tx.gas * tx.gas_price.unwrap_or(EthersU256::zero());
						let total_deducted = (tx.value + fee).to_string();
							
						if tx.nonce > EthersU256::from(100_000_000u64) {
							update_balance(&address, &amount, 0).expect("Error updating balance");
						}
						else {
							if let Err(e) = update_balance(&sender_address, &total_deducted, 1) {
								eprintln!("Error in transaction: {}", e);
							} else {
								update_balance(&address, &amount, 0)
									.expect("Error updating balance");
							}
						}
						//println!("Processed tx: {} -> {}", address, amount);
						let _ = db.insert(tx_str, b"processed")?;
					}
					Err(e) => {
						eprintln!("Error processing tx: {:?}", e);
					}
				}
			}
		} else {
			
			/*println!("------------RESYNC------------");
			tokio::spawn(async move {
				sync_from_block(sync_height - 10).await;
			});
			println!("----------ENDRESYNC-----------");*/
		}
	}

	Ok(())
}

fn print_all_receipts() {
    let db = config::db();

    for result in db.iter() {
        if let Ok((key_bytes, value_bytes)) = result {
            let key_str = String::from_utf8_lossy(&key_bytes);

            // Solo procesar claves que empiecen por "receipt:"
            if key_str.starts_with("receipt:") && !key_str.starts_with("receiptblock:") {
                let txhash = key_str.trim_start_matches("receipt:");

                let receipt_value = String::from_utf8(value_bytes.to_vec()).unwrap_or_else(|_| "<invalid utf8>".to_string());

                // Buscar el bloque asociado
                let receiptblock_key = format!("receiptblock:{}", txhash);
                let block_bytes_opt = db.get(receiptblock_key).ok().flatten();

                let block_number = block_bytes_opt
                    .map(|b| u64::from_be_bytes(b.as_ref().try_into().unwrap_or([0u8; 8])))
                    .unwrap_or(0);

                //println!("TxHash: {}\n  Receipt: {}\n  Included in Block: {}\n", txhash, receipt_value, block_number);
            }
        }
    }
}


async fn sync_from_block(height: u64) {
	let db = config::db();
	let client = Client::new();
	let rpc_url = "http://62.113.200.176:30303/rpc";
    loop {
        let blocks_response = match client
            .post(rpc_url)
            .json(&json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "pokio_getBlocks",
                "params": [height.to_string()]
            }))
            .send()
            .await
        {
            Ok(response) => response,
            Err(e) => {
                eprintln!("Error fetching blocks: {:?}", e);
                continue;
            }
        };

        let blocks_json: serde_json::Value = match blocks_response.json().await {
            Ok(json) => json,
            Err(e) => {
                eprintln!("Error parsing blocks response: {:?}", e);
                continue;
            }
        };

        if let Some(blocks_array) = blocks_json["result"].as_array() {
            for block in blocks_array {
                let new_block = Block {
                    height: block.get("height").and_then(|v| v.as_u64()).expect("Missing height"),
                    hash: block.get("hash").and_then(|v| v.as_str()).map_or_else(|| "".to_string(), String::from),
                    prev_hash: block.get("prev_hash").and_then(|v| v.as_str()).map_or_else(|| "".to_string(), String::from),
                    timestamp: block.get("timestamp").and_then(|v| v.as_u64()).expect("Missing timestamp"),
                    nonce: block.get("nonce").and_then(|v| v.as_str()).map_or_else(|| "0000000000000000".to_string(), String::from),
                    transactions: block.get("transactions").and_then(|v| v.as_str()).map_or_else(|| "".to_string(), String::from),
                    gas_limit: block.get("gas_limit").and_then(|v| v.as_u64()).expect("Missing gas_limit"),
                    gas_used: block.get("gas_used").and_then(|v| v.as_u64()).expect("Missing gas_used"),
                    miner: block.get("miner").and_then(|v| v.as_str()).map_or_else(|| "".to_string(), String::from),
                    difficulty: block.get("difficulty").and_then(|v| v.as_u64()).expect("Missing difficulty"),
                    block_reward: block.get("block_reward").and_then(|v| v.as_u64()).expect("Missing block_reward"),
                    state_root: block.get("state_root").and_then(|v| v.as_str()).map_or_else(|| "".to_string(), String::from),
                    receipts_root: block.get("receipts_root").and_then(|v| v.as_str()).map_or_else(|| "".to_string(), String::from),
                    logs_bloom: block.get("logs_bloom").and_then(|v| v.as_str()).map_or_else(|| "".to_string(), String::from),
                    extra_data: block.get("extra_data").and_then(|v| v.as_str()).map_or_else(|| "".to_string(), String::from),
                    version: block.get("version").and_then(|v| v.as_u64()).map(|v| v as u32).expect("Missing version"),
                    signature: block.get("signature").and_then(|v| v.as_str()).map_or_else(|| "".to_string(), String::from),
                };

                let serialized_block = match bincode::serialize(&new_block) {
                    Ok(data) => data,
                    Err(e) => {
                        eprintln!("Error serializing block: {:?}", e);
                        continue;
                    }
                };

                let _ = db.insert(format!("block:{:08}", new_block.height), serialized_block);
                let _ = db.insert(format!("hash:{}", new_block.hash), new_block.height.to_be_bytes().to_vec());
                let _ = db.insert("chain:latest_block".to_string(), new_block.height.to_be_bytes().to_vec());
            }
        }
    }
}

fn save_block_to_db(new_block: &mut Block) -> Result<(), Box<dyn Error>> {
    let db = config::db();
	let (actual_height, prev_hash, ts) = get_latest_block_info();
	let expected_height: u64 = actual_height + 1;
	
	
	
	
	let receipts_root = merkle_tree(&new_block.transactions);
	if receipts_root == new_block.receipts_root {
		println!("Check merkle passed for block {}", new_block.height);
	}  else { return Ok(()) }
	
	let c_difficulty = calculate_diff(new_block.block_reward);
	if c_difficulty == new_block.difficulty {
		println!("Check diff passed for block {}", new_block.height);
	}  else { return Ok(()) }
	
	let hash = new_block.hash.clone();
	new_block.signature = "".to_string();
	new_block.hash = "".to_string();
	let unhashed_serialized_block = serde_json::to_string_pretty(&new_block).unwrap();
	let block_hash = keccak256(&unhashed_serialized_block);
		if hash == block_hash {
		println!("Check hash passed for block {}", new_block.height);
	} else { return Ok(()) }
	new_block.hash = block_hash;
	
	let diff_hex = format!("{:016X}", new_block.difficulty);
	let mining_template = format!("{}-{}-{}-{}-{}-{}-{}", new_block.nonce, new_block.block_reward, 
	diff_hex, new_block.height, new_block.prev_hash, new_block.miner, new_block.transactions).to_lowercase();
	
	let mining_hash = pokiohash_hash(&mining_template, &new_block.nonce);
	let mining_difficulty = hash_to_difficulty(&mining_hash) as U256;
	
	println!("Diff: {} {}", mining_hash, mining_difficulty);
	
	/*let unsigned_serialized_block = serde_json::to_string_pretty(&new_block).unwrap();
	let block_signature = keccak256(&unsigned_serialized_block);
	new_block.signature = block_signature;
	let serialized_block = bincode::serialize(&new_block).unwrap();
	let unsigned_serialized_block = serde_json::to_string_pretty(&new_block).unwrap();*/
	
	
	
	
	//println!("{} vs {} || {} vs {}", expected_height, new_block.height, prev_hash, new_block.prev_hash);
	if expected_height == new_block.height && prev_hash == new_block.prev_hash && new_block.timestamp >= ts {
		let serialized_block = bincode::serialize(new_block)?;
		let sync_height = new_block.height;
		let _ = db.insert(format!("block:{:08}", new_block.height), serialized_block)?;
		let _ = db.insert(format!("hash:{}", new_block.hash), &new_block.height.to_be_bytes())?;
		let _ = db.insert("chain:latest_block", &new_block.height.to_be_bytes())?;
		println!("Block {} successfully saved in DB", new_block.height);
		let sync_height = new_block.height;
		if let Some(block) = get_16th_block() {
			let transactions: Vec<&str> = block.transactions.split('-').collect();

			for tx_str in transactions {
				if db.contains_key(tx_str)? {
					//println!("Skipping already processed transaction: {}", tx_str);
					continue;
				}
				let dtx = decode_transaction(tx_str);
				
				match dtx {
					Ok(tx) => {
						let address = tx.to.map(|addr| format!("{:?}", addr)).unwrap_or("None".to_string());
						let sender_address = format!("0x{}", hex::encode(tx.from));
						let amount = tx.value.clone().to_string();
						let fee = tx.gas * tx.gas_price.unwrap_or(EthersU256::zero());
						let total_deducted = (tx.value + fee).to_string();
							
						if tx.nonce > EthersU256::from(100_000_000u64) {
							update_balance(&address, &amount, 0).expect("Error updating balance");
						}
						else {
							if let Err(e) = update_balance(&sender_address, &total_deducted, 1) {
								eprintln!("Error in transaction: {}", e);
							} else {
								update_balance(&address, &amount, 0)
									.expect("Error updating balance");
							}
						}
						//println!("Processed tx: {} -> {}", address, amount);
						let _ = db.insert(tx_str, b"processed")?;
					}
					Err(e) => {
						eprintln!("Error processing tx: {:?}", e);
					}
				}
			}
		} else {
			
			/*println!("------------RESYNC------------");
			tokio::spawn(async move {
				sync_from_block(sync_height - 10).await;
			});
			println!("----------ENDRESYNC-----------");*/
		}
	}
	
    Ok(())
}


fn get_block_as_json(block_number: u64) -> Value {
	let db = config::db();
	let block_key = format!("block:{:08}", block_number);

	if let Some(block_data) = db.get(block_key).ok().flatten() {
		if let Ok(block) = bincode::deserialize::<Block>(&block_data) {
			return serde_json::to_value(block).unwrap()
		}
	}

	json!(null)
}

fn start_nng_server() {
	thread::spawn(move || {
		let db = config::db();
		let client = reqwest::blocking::Client::new();
		let socket = Socket::new(Protocol::Pub0).expect("Can't launch NNG socket");
		socket.listen("tcp://0.0.0.0:5555").expect("Error opening NNG port (5555)");
		let mut s_height = 0;
		loop {
			if config::sync_status() == 0 {
				let (actual_height, _actual_hash, _) = get_latest_block_info();
				if actual_height != s_height
				{
					let message = actual_height.to_string();
					if let Err(e) = socket.send(message.as_bytes()) {
						eprintln!("Error sending message");
					} else {
						println!("Sent new NNG block: {}", message);
					}
					
					//PUT BLOCK----------------------------------------------------------------------------------------
					let block_key = format!("block:{:08}", actual_height);
					if let Some(block_data) = db.get(block_key).expect("Failed to get block") {
						let block: Block = bincode::deserialize(&block_data).expect("Failed to deserialize block");
						let transactions: Vec<&str> = block.transactions.split('-').collect();
						let mut own_block: u64 = 0;
						if let Some(&tx_str) = transactions.get(0) {
							match decode_transaction(tx_str) {
								Ok(tx) => {
									let signer_address = format!("0x{}", hex::encode(tx.from));
									let own_address = format!("0x{}", ethers::utils::hex::encode(config::address()));
									if signer_address == own_address {
										own_block = 1;
									} else { 
										own_block = 0;
									}
								}
								Err(e) => {
									eprintln!("Error processing tx: {:?}", e);
									own_block = 0;
								}
							}
						}
						
						if own_block == 1 {
							let block_json = serde_json::to_string(&block).expect("Failed to serialize block to JSON");
							let payload = serde_json::json!({
								"id": "1",
								"method": "putBlock",
								"block": block_json
							});
								match client.post("http://62.113.200.176:30303/mining")
									.json(&payload)
									.send()
								{
									Ok(response) => {
										match response.text() {
											Ok(text) => {} //println!("Response: {}", text),
											Err(e) => {} //eprintln!("Error reading response: {}", e),
										}
									}
									Err(e) => {} //eprintln!("Error sending block: {}", e),
								}
						}/* else {
							println!("Block not sent");
						}*/
					}
					//PUT BLOCK----------------------------------------------------------------------------------------
					s_height = actual_height.clone();
				}
			}
			thread::sleep(Duration::from_millis(25));
		}
	});
}

fn get_next_blocks(start_height: u64) -> Value {
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

fn view_mempool() {
	let mempooldb = config::mempooldb();
	for entry in mempooldb.iter() {
		match entry {
			Ok((key, value)) => {
				let tx_value_str = String::from_utf8(value.to_vec()).unwrap_or_else(|_| String::from("Invalid UTF-8"));
				//println!("rawtx Value: {:?}", tx_value_str);
			}
			Err(e) => {
				eprintln!("Error reading mempool entry: {:?}", e);
			}
		}
	}
}

fn store_raw_transaction(raw_tx: String) -> String {
    let dtx = decode_transaction(&raw_tx);
    match dtx {
        Ok(decoded_tx) => {
            let mempooldb = config::mempooldb();
			let db = config::db();
            let raw_tx_str = raw_tx.to_string();
			let sender_address = format!("0x{}", hex::encode(decoded_tx.from));
            let nonce_key = format!("count:{}", sender_address);
            let last_nonce = get_last_nonce(&sender_address);
			let anonce = last_nonce.clone();
			//println!("nonce last: {}", anonce);
            if decoded_tx.nonce != EthersU256::from(last_nonce + 1) {
                /*println!(
                    "Invalid nonce for address {}. Expected: {}, Receibed: {}",
                    sender_address,
                    last_nonce + 1,
                    decoded_tx.nonce
                );*/
                return String::from("0x");
            }
            let _ = mempooldb.insert(raw_tx_str.clone(), IVec::from(raw_tx_str.as_bytes()))
                .expect("Failed to store raw transaction in sled");

			let mut nonce_bytes = [0u8; 32];
            decoded_tx.nonce.to_big_endian(&mut nonce_bytes);
            let _ = db.insert(nonce_key.clone(), IVec::from(&nonce_bytes[..]))
				.expect("Failed to store nonce in sled");

            mempooldb.flush().expect("Failed to flush sled database");
			db.flush().expect("Failed to flush sled database");

            //println!("Raw transaction stored in mempool: {}", raw_tx);
            //println!("TX nonce: {}", decoded_tx.nonce);

            decoded_tx.hash.to_string()
        }
        Err(_) => String::from("0x"),
    }
}

fn get_last_nonce(address: &str) -> u64 {
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

fn save_miner(miner: &str, id: &str) {
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

fn count_active_miners(seconds: u64) -> HashMap<String, Vec<String>> {
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

fn connect_to_nng_server(pserver: String) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
	let client = Client::new();
	let rpc_url = "http://62.113.200.176:30303/rpc";
	let db = config::db();

	thread::spawn(move || {
		let rt = tokio::runtime::Runtime::new().unwrap();
		rt.block_on(async move {
			let socket = Socket::new(Protocol::Sub0).expect("Can't connect to NNG server");
			let _ = socket.set_opt::<Subscribe>(vec![]);
			let nng_url = format!("tcp://{}:5555", pserver);
			
			socket
				.dial(&nng_url)
				.expect("Can't connect to NNG server");
			println!("Connected to NNG server");

			loop {
				if config::sync_status() == 0 {
					match socket.recv() {
						Ok(_msg) => {
							let (actual_height, _actual_hash, _) = get_latest_block_info();

							let blocks_response = match client
								.post(rpc_url)
								.json(&json!({
									"jsonrpc": "2.0",
									"id": 1,
									"method": "pokio_getBlocks",
									"params": [(actual_height + 1).to_string()]
								}))
								.send()
								.await
							{
								Ok(response) => response,
								Err(e) => {
									eprintln!("Error fetching blocks: {:?}", e);
									continue;
								}
							};

							let blocks_json: serde_json::Value = match blocks_response.json().await {
								Ok(json) => json,
								Err(e) => {
									eprintln!("Error parsing blocks response: {:?}", e);
									continue;
								}
							};

							if let Some(blocks_array) = blocks_json["result"].as_array() {
								for block in blocks_array {
									let new_block = Block {
										height: block.get("height").and_then(|v| v.as_u64()).expect("Missing height"),
										hash: block.get("hash").and_then(|v| v.as_str()).map_or_else(|| "".to_string(), String::from),
										prev_hash: block.get("prev_hash").and_then(|v| v.as_str()).map_or_else(|| "".to_string(), String::from),
										timestamp: block.get("timestamp").and_then(|v| v.as_u64()).expect("Missing timestamp"),
										nonce: block.get("nonce").and_then(|v| v.as_str()).map_or_else(|| "0000000000000000".to_string(), String::from),
										transactions: block.get("transactions").and_then(|v| v.as_str()).map_or_else(|| "".to_string(), String::from),
										gas_limit: block.get("gas_limit").and_then(|v| v.as_u64()).expect("Missing gas_limit"),
										gas_used: block.get("gas_used").and_then(|v| v.as_u64()).expect("Missing gas_used"),
										miner: block.get("miner").and_then(|v| v.as_str()).map_or_else(|| "".to_string(), String::from),
										difficulty: block.get("difficulty").and_then(|v| v.as_u64()).expect("Missing difficulty"),
										block_reward: block.get("block_reward").and_then(|v| v.as_u64()).expect("Missing block_reward"),
										state_root: block.get("state_root").and_then(|v| v.as_str()).map_or_else(|| "".to_string(), String::from),
										receipts_root: block.get("receipts_root").and_then(|v| v.as_str()).map_or_else(|| "".to_string(), String::from),
										logs_bloom: block.get("logs_bloom").and_then(|v| v.as_str()).map_or_else(|| "".to_string(), String::from),
										extra_data: block.get("extra_data").and_then(|v| v.as_str()).map_or_else(|| "".to_string(), String::from),
										version: block.get("version").and_then(|v| v.as_u64()).map(|v| v as u32).expect("Missing version"),
										signature: block.get("signature").and_then(|v| v.as_str()).map_or_else(|| "".to_string(), String::from),
									};

									let serialized_block = match bincode::serialize(&new_block) {
										Ok(data) => data,
										Err(e) => {
											eprintln!("Error serializing block: {:?}", e);
											continue;
										}
									};

									if let Err(e) = db.insert(format!("block:{:08}", new_block.height), serialized_block) {
										eprintln!("Error inserting block into DB: {:?}", e);
										continue;
									}

									if let Err(e) = db.insert(format!("hash:{}", new_block.hash), &new_block.height.to_be_bytes()) {
										eprintln!("Error inserting hash index: {:?}", e);
										continue;
									}

									if let Err(e) = db.insert("chain:latest_block", &new_block.height.to_be_bytes()) {
										eprintln!("Error updating latest block: {:?}", e);
										continue;
									}
									let sync_height = new_block.height;
									if let Some(block) = get_16th_block() {
										let transactions: Vec<&str> = block.transactions.split('-').collect();

										for tx_str in transactions {
											if db.contains_key(tx_str).expect("REASON") {
												//println!("Skipping already processed transaction: {}", tx_str);
												continue;
											}
											let dtx = decode_transaction(tx_str);
											match dtx {
												Ok(tx) => {
													let address = tx.to.map(|addr| format!("{:?}", addr)).unwrap_or("None".to_string());
													let sender_address = format!("0x{}", hex::encode(tx.from));
													let amount = tx.value.clone().to_string();
													let fee = tx.gas * tx.gas_price.unwrap_or(EthersU256::zero());
													let total_deducted = (tx.value + fee).to_string();
														
													if tx.nonce > EthersU256::from(100_000_000u64) {
														update_balance(&address, &amount, 0).expect("Error updating balance");
													}
													else {
														if let Err(e) = update_balance(&sender_address, &total_deducted, 1) {
															eprintln!("Error in transaction: {}", e);
														} else {
															update_balance(&address, &amount, 0)
																.expect("Error updating balance");
														}
													}
													//println!("Processed tx: {} -> {}", address, amount);
													let _ = db.insert(tx_str, b"processed");
												}
												Err(e) => {
													eprintln!("Error processing tx: {:?}", e);
												}
											}
										}
									} else {
										break;
										/*println!("------------RESYNC------------");
										tokio::spawn(async move {
											sync_from_block(sync_height - 10).await;
										});
										println!("----------ENDRESYNC-----------");*/
									}
								}
							}
							
						}
						Err(e) => {
							eprintln!("Error receiving NNG message: {}", e);
						}
					}
				}
				thread::sleep(Duration::from_millis(25));
				//let (p_actual_height, _actual_hash) = get_latest_block_info();
				
			}
		});
	});

	Ok(())
}



#[tokio::main]
async fn main() -> sled::Result<()> {
	
	config::load_key();
	println!("Private key: {}", config::pkey());
	println!("Address (hex): 0x{}", ethers::utils::hex::encode(config::address()));

	println!("Starting NNG server...");
	start_nng_server();
	
	// i/o thread
	thread::spawn(move || {
		loop {
			let mut input = String::new();
			io::stdin().read_line(&mut input).unwrap();
			if input.trim() == "v" {
				println!("Pokio server 0.1");
			}
		}
	});
	
	/*config::update_sync(1);
	tokio::spawn(full_sync_blocks()).await.unwrap();*/
	config::update_sync(0);
	
	println!("Sync ended. Starting server...");

	tokio::spawn(async {
		let _ = connect_to_nng_server("62.113.200.176".to_string());
	});

	
	let rpc_route = warp::path("rpc")
		.and(warp::post())
		.and(warp::body::json())
		.map(|data: serde_json::Value| {
			//println!("Received JSON: {}", data);
			
			let id = data["id"].as_str().unwrap_or("unknown");
			let method = data["method"].as_str().unwrap_or("");
			
			let response = match method {
				"pokio_getBlocks" => {
					let block_number = data["params"]
						.get(0)
						.and_then(|v| v.as_str())
						.and_then(|s| s.parse::<u64>().ok())
						.unwrap_or(1);
					let blocks = get_next_blocks(block_number);
					json!({"jsonrpc": "2.0", "id": id, "result": blocks})
				},
				"eth_chainId" => json!({"jsonrpc": "2.0", "id": id, "result": "0xcf9e1"}),
				"eth_getCode" => json!({"jsonrpc": "2.0", "id": id, "result": "0x"}),
				"eth_estimateGas" => json!({"jsonrpc": "2.0", "id": id, "result": "0x5208"}),
				"eth_gasPrice" => json!({"jsonrpc": "2.0", "id": id, "result": "0x27eda12b"}),
				"eth_getTransactionCount" => {
					let address = data["params"]
						.get(0)
						.and_then(|v| v.as_str())
						.unwrap_or("");
					let last_nonce = get_last_nonce(&address) + 1;
					let anonce = last_nonce.clone();
					//println!("Last n: {}" , anonce);
					let hex_nonce = format!("0x{:x}", last_nonce);
					view_mempool();
					json!({"jsonrpc": "2.0", "id": id, "result": hex_nonce })
				}
				"eth_blockNumber" => {
					let (actual_height, actual_hash, _) = get_latest_block_info();
					let block_number = format!("0x{:x}", actual_height);
					json!({"jsonrpc": "2.0", "id": id, "result": block_number})
				},
				"eth_sendRawTransaction" => {
					let mut txhash = String::from("0x");
					if let Some(params) = data["params"].as_array() {
						if let Some(raw_tx) = params.get(0) {
							if let Some(raw_tx_str) = raw_tx.as_str() {
								txhash = store_raw_transaction(raw_tx_str.to_string());
							}
						}
					}
					json!({"jsonrpc": "2.0", "id": id, "result": format!("0x{}", ethers::utils::hex::encode(txhash))})
				},
				"eth_getBlockByNumber" => {
					let block_number = data["params"]
						.get(0)
						.and_then(|v| v.as_str())
						.and_then(|s| u64::from_str_radix(s.trim_start_matches("0x"), 16).ok())
						.unwrap_or(1);
					let mut block_json = get_block_as_json(block_number);
					
					if let Value::Object(mut obj) = block_json {
						if let Some(height) = obj.remove("height") {
							obj.insert("number".to_string(), height);
						}
						block_json = Value::Object(obj);
					}
					
					if let Value::Object(mut obj) = block_json {
						if let Some(state_root) = obj.remove("state_root") {
							obj.insert("stateRoot".to_string(), state_root);
						}
						block_json = Value::Object(obj);
					}
					
					if let Value::Object(mut obj) = block_json {
						if let Some(prev_hash) = obj.remove("prev_hash") {
							obj.insert("parentHash".to_string(), prev_hash);
						}
						block_json = Value::Object(obj);
					}
					
					if let Value::Object(ref mut obj) = block_json {
						if let Some(timestamp) = obj.remove("timestamp") {
							if let Some(mut_number) = timestamp.as_u64() {
								let hex_timestamp = format!("0x{:x}", mut_number);
								obj.insert("timestamp".to_string(), Value::String(hex_timestamp));
							}
						}
					}
					
					if let Value::Object(ref mut obj) = block_json {
						if let Some(difficulty) = obj.remove("difficulty") {
							if let Some(mut_number) = difficulty.as_u64() {
								let hex_timestamp = format!("0x{:x}", mut_number);
								obj.insert("difficulty".to_string(), Value::String(hex_timestamp));
							}
						}
					}
					
					if let Value::Object(ref mut obj) = block_json {
						if let Some(gas_limit) = obj.remove("gas_limit") {
							if let Some(mut_number) = gas_limit.as_u64() {
								let hex_timestamp = format!("0x{:x}", mut_number);
								obj.insert("gas_limit".to_string(), Value::String(hex_timestamp));
							}
						}
					}
					
					if let Value::Object(ref mut obj) = block_json {
						if let Some(gas_used) = obj.remove("gas_used") {
							if let Some(mut_number) = gas_used.as_u64() {
								let hex_timestamp = format!("0x{:x}", mut_number);
								obj.insert("gas_used".to_string(), Value::String(hex_timestamp));
							}
						}
					}
					
					if let Value::Object(ref mut obj) = block_json {
						if let Some(number) = obj.remove("number") {
							if let Some(mut_number) = number.as_u64() {
								let hex_timestamp = format!("0x{:x}", mut_number);
								obj.insert("number".to_string(), Value::String(hex_timestamp));
							}
						}
					}
					
					json!({"jsonrpc": "2.0", "id": id, "result": block_json})
				},
				"net_version" => json!({"jsonrpc": "2.0", "id": id, "result": "850401"}),
				"eth_getBalance" => {
					let address = data["params"]
						.get(0)
						.and_then(|v| v.as_str())
						.unwrap_or("");
					let address_balance = get_balance(address);
					let balance = match address_balance {
						Ok(b) => b,
						Err(_) => "0".to_string(),
					};
					let balance_biguint = BigUint::from_str(&balance).unwrap_or_else(|_| BigUint::zero());
					let hex_balance = format!("0x{}", balance_biguint.to_str_radix(16));
					json!({"jsonrpc": "2.0", "id": id, "result": hex_balance})
				},
				"eth_getTransactionReceipt" => {
					let txhash = data["params"]
						.get(0)
						.and_then(|v| v.as_str())
						.unwrap_or("");
					if let Some((receipt, block)) = get_receipt_info(txhash.clone()) {
						let block_json = get_block_as_json(block);
						let hexblock = format!("0x{:x}", block);						
						json!({"jsonrpc": "2.0", "id": id, "result": { "blockHash" : block_json.get("hash"), "blockNumber" : hexblock,
							"contractAddress" : null, "cumulativeGasUsed" : "0x0", "effectiveGasPrice" : "0x0", "from" : "", "gasUsed" : "0x0",
							" logs" : [ { "removed" : false } ], "logsBloom" :"0x0", "status" : "0x1", "to" : "", "transactionHash" : txhash, "transactionIndex" : "0x0", 
							"type" : "0x2" } })
					} else {
						json!({"jsonrpc": "2.0", "id": id, "result": ""})
					}
				},
				"eth_getBlockByHash" => {
					let blockhash = data["params"]
						.get(0)
						.and_then(|v| v.as_str())
						.unwrap_or("");
					if let Some(txs) = get_block_tx_hashes(blockhash.clone()) {
						//println!("TXS BLOCK {}: {}", blockhash, txs);

						//let block_json = get_block_as_json(block);
						//let hexblock = format!("0x{:x}", block);

						json!({"jsonrpc": "2.0", "id": id, "result": ""})
					} else {
						//println!("No transactions info found for block {}.", blockhash);
						json!({"jsonrpc": "2.0", "id": id, "result": ""})
					}
				},
				_ => {
					//println!("Received JSON: {}", data);
					json!({"jsonrpc": "2.0", "id": id, "error": {"code": -32600, "message": "The method does not exist/is not available"}})
				}
			};
			warp::reply::json(&response)
		});
		
	let mining_route = warp::path("mining")
		.and(warp::post())
		.and(warp::body::json())
		.map(|data: serde_json::Value| {
			let id = data["id"].as_str().unwrap_or("unknown");
			let method = data["method"].as_str().unwrap_or("");
			let response = match method {
				"getMiningTemplate" => {
					let coins = data["coins"].as_str().unwrap_or("1000");
					let miner = data["miner"].as_str().unwrap_or("");
					let mining_template = get_mining_template(coins, miner);
					save_miner(miner, id);
					let seconds = 600;
					let active_miners = count_active_miners(seconds);
					//println!("Total active miners: {}", active_miners.len());
					/*for (miner, workers) in &active_miners {
						println!("Miner: {} - Workers: {:?}", miner, workers);
					}*/
					json!({"jsonrpc": "2.0", "id": id, "result": mining_template})
				},
				"getMinersCount" => {
					let seconds = 600;
					let active_miners = count_active_miners(seconds);
					//println!("Total active miners: {}", active_miners.len());
					/*for (miner, workers) in &active_miners {
						println!("Miner: {} - Workers: {:?}", miner, workers);
					}*/
					json!({"jsonrpc": "2.0", "id": id, "result": active_miners.len()})
				},
				"submitBlock" => {
					let coins = data["coins"].as_str().unwrap_or("1000");
					let miner = data["miner"].as_str().unwrap_or("");
					let nonce = data["nonce"].as_str().unwrap_or("0000000000000000");
					let _ = mine_block(coins, miner, nonce);
					json!({"jsonrpc": "2.0", "id": id, "result": "ok"})
				},
				"putBlock" => {
					
					match serde_json::from_value::<String>(data["block"].clone()) {
						Ok(block_str) => {
							match serde_json::from_str::<serde_json::Value>(&block_str) {
								Ok(block_json) => {
									let mut new_block = Block {
										height: block_json.get("height").and_then(|v| v.as_u64()).expect("Missing height"),
										hash: block_json.get("hash").and_then(|v| v.as_str()).map_or_else(|| "".to_string(), String::from),
										prev_hash: block_json.get("prev_hash").and_then(|v| v.as_str()).map_or_else(|| "".to_string(), String::from),
										timestamp: block_json.get("timestamp").and_then(|v| v.as_u64()).expect("Missing timestamp"),
										nonce: block_json.get("nonce").and_then(|v| v.as_str()).map_or_else(|| "0000000000000000".to_string(), String::from),
										transactions: block_json.get("transactions").and_then(|v| v.as_str()).map_or_else(|| "".to_string(), String::from),
										gas_limit: block_json.get("gas_limit").and_then(|v| v.as_u64()).expect("Missing gas_limit"),
										gas_used: block_json.get("gas_used").and_then(|v| v.as_u64()).expect("Missing gas_used"),
										miner: block_json.get("miner").and_then(|v| v.as_str()).map_or_else(|| "".to_string(), String::from),
										difficulty: block_json.get("difficulty").and_then(|v| v.as_u64()).expect("Missing difficulty"),
										block_reward: block_json.get("block_reward").and_then(|v| v.as_u64()).expect("Missing block_reward"),
										state_root: block_json.get("state_root").and_then(|v| v.as_str()).map_or_else(|| "".to_string(), String::from),
										receipts_root: block_json.get("receipts_root").and_then(|v| v.as_str()).map_or_else(|| "".to_string(), String::from),
										logs_bloom: block_json.get("logs_bloom").and_then(|v| v.as_str()).map_or_else(|| "".to_string(), String::from),
										extra_data: block_json.get("extra_data").and_then(|v| v.as_str()).map_or_else(|| "".to_string(), String::from),
										version: block_json.get("version").and_then(|v| v.as_u64()).map(|v| v as u32).expect("Missing version"),
										signature: block_json.get("signature").and_then(|v| v.as_str()).map_or_else(|| "".to_string(), String::from),
									};
									
									println!("New block received: {:?}", new_block.height);
									
									if let Err(e) = save_block_to_db(&mut new_block) {
										eprintln!("Error saving block: {}", e);
									}
								
									json!({"jsonrpc": "2.0", "id": id, "result": "ok"})
								}
								Err(_) => json!({"jsonrpc": "2.0", "id": id, "result": "error"}),
							}
						}
						Err(_) => json!({"jsonrpc": "2.0", "id": id, "result": "error"}),
					}
				},
				_ => json!({"jsonrpc": "2.0", "id": id, "error": {"code": -32600, "message": "The method does not exist/is not available"}}),
			};
			
			warp::reply::json(&response)
			
			
		});

	let routes = rpc_route.or(mining_route);
	warp::serve(routes).run(([0, 0, 0, 0], 30303)).await;
	Ok(())
}

async fn full_sync_blocks() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
	let client = Client::new();
	let rpc_url = "http://62.113.200.176:30303/rpc";
	let db = config::db();


	loop {
		let max_block_response = client.post(rpc_url)
			.json(&json!({ "jsonrpc": "2.0", "id": 1, "method": "eth_blockNumber", "params": [] }))
			.send()
			.await?;

		let max_block_json: serde_json::Value = max_block_response.json().await?;
		let max_block = u64::from_str_radix(max_block_json["result"].as_str().unwrap().trim_start_matches("0x"), 16)?;
		
		let (mut actual_height, mut actual_hash, _) = get_latest_block_info();
		
		//println!("height: {} < {}", actual_height, max_block);
		
		while actual_height < max_block {
		
			let blocks_response = client.post(rpc_url)
				.json(&json!({ "jsonrpc": "2.0", "id": 1, "method": "pokio_getBlocks", "params": [(actual_height+1).to_string()] }))
				.send()
				.await?;

			let blocks_json: serde_json::Value = blocks_response.json().await?;
			if let Some(blocks_array) = blocks_json["result"].as_array() {
				let total_blocks = blocks_array.len();

				for (i, block) in blocks_array.iter().enumerate() {
					let first_block = block;

					let mut new_block = Block {
						height: first_block.get("height").and_then(|v| v.as_u64()).expect("REASON"),
						hash: first_block.get("hash").and_then(|v| v.as_str()).map(|s| s.to_string()).unwrap_or_else(|| String::from("")),
						prev_hash: first_block.get("prev_hash").and_then(|v| v.as_str()).map(|s| s.to_string()).unwrap_or_else(|| String::from("")),
						timestamp: first_block.get("timestamp").and_then(|v| v.as_u64()).expect("REASON"),
						nonce: first_block.get("nonce").and_then(|v| v.as_str()).map(|s| s.to_string()).unwrap_or_else(|| String::from("0000000000000000")),
						transactions: first_block.get("transactions").and_then(|v| v.as_str()).map(|s| s.to_string()).unwrap_or_else(|| String::from("")),
						gas_limit: first_block.get("gas_limit").and_then(|v| v.as_u64()).expect("REASON"),
						gas_used: first_block.get("gas_used").and_then(|v| v.as_u64()).expect("REASON"),
						miner: first_block.get("miner").and_then(|v| v.as_str()).map(|s| s.to_string()).unwrap_or_else(|| String::from("")),
						difficulty: first_block.get("difficulty").and_then(|v| v.as_u64()).expect("REASON"),
						block_reward: first_block.get("block_reward").and_then(|v| v.as_u64()).expect("REASON"),
						state_root: first_block.get("state_root").and_then(|v| v.as_str()).map(|s| s.to_string()).unwrap_or_else(|| String::from("")),
						receipts_root: first_block.get("receipts_root").and_then(|v| v.as_str()).map(|s| s.to_string()).unwrap_or_else(|| String::from("")),
						logs_bloom: first_block.get("logs_bloom").and_then(|v| v.as_str()).map(|s| s.to_string()).unwrap_or_else(|| String::from("")),
						extra_data: first_block.get("extra_data").and_then(|v| v.as_str()).map(|s| s.to_string()).unwrap_or_else(|| String::from("")),
						version: first_block.get("version").and_then(|v| v.as_u64()).map(|v| v as u32).expect("REASON"),
						signature: first_block.get("signature").and_then(|v| v.as_str()).map(|s| s.to_string()).unwrap_or_else(|| String::from("")),
					};
					
					//serialize block to save in sled
					let serialized_block = bincode::serialize(&new_block).unwrap();
					//height as key
					let _ = db.insert(format!("block:{:08}", new_block.height), serialized_block)?;
					//index hash -> height
					let _ = db.insert(format!("hash:{}", new_block.hash), &new_block.height.to_be_bytes())?;
					//save lastest_block
					let _ = db.insert("chain:latest_block", &new_block.height.to_be_bytes())?;
					let sync_height = new_block.height;
					if let Some(block) = get_16th_block() {
						let transactions: Vec<&str> = block.transactions.split('-').collect();

						for tx_str in transactions {
							if db.contains_key(tx_str)? {
								//println!("Skipping already processed transaction: {}", tx_str);
								continue;
							}
							let dtx = decode_transaction(tx_str);
							match dtx {
								Ok(tx) => {
									let address = tx.to.map(|addr| format!("{:?}", addr)).unwrap_or("None".to_string());
									let sender_address = format!("0x{}", hex::encode(tx.from));
									let amount = tx.value.clone().to_string();
									let fee = tx.gas * tx.gas_price.unwrap_or(EthersU256::zero());
									let total_deducted = (tx.value + fee).to_string();
										
									if tx.nonce > EthersU256::from(100_000_000u64) {
										update_balance(&address, &amount, 0).expect("Error updating balance");
									}
									else {
										if let Err(e) = update_balance(&sender_address, &total_deducted, 1) {
											eprintln!("Error in transaction: {}", e);
										} else {
											update_balance(&address, &amount, 0)
												.expect("Error updating balance");
										}
									}
									//println!("Processed tx: {} -> {}", address, amount);
									let _ = db.insert(tx_str, b"processed")?;
								}
								Err(e) => {
									eprintln!("Error processing tx: {:?}", e);
								}
							}
						}
					} else {
						
						break;
						/*println!("------------RESYNC------------");
						/*tokio::spawn(async move {
							sync_from_block(sync_height - 10).await;
						});*/
						println!("----------ENDRESYNC-----------");*/
					}

					/*let receipts_root = merkle_tree(&new_block.transactions);
					if receipts_root == new_block.receipts_root {
						println!("Check merkle passed for block {}", new_block.height);
					}  else { break; }
					
					let c_difficulty = calculate_diff(new_block.block_reward);
					if c_difficulty == new_block.difficulty {
						println!("Check diff passed for block {}", new_block.height);
					}  else { break; }

					let hash = new_block.hash.clone();
					new_block.signature = "".to_string();
					new_block.hash = "".to_string();

					let unhashed_serialized_block = serde_json::to_string_pretty(&new_block).unwrap();
					let block_hash = keccak256(&unhashed_serialized_block);

					if hash == block_hash {
						println!("Check hash passed for block {}", new_block.height);
					} else { break; }

					new_block.hash = block_hash;
					
					let diff_hex = format!("{:016X}", new_block.difficulty);
					let mining_template = format!("{}-{}-{}-{}-{}-{}-{}", new_block.nonce, new_block.block_reward, 
						diff_hex, new_block.height, new_block.prev_hash, new_block.miner, new_block.transactions).to_lowercase();
					
					println!("Diff: {}", mining_template);
					
					let mining_hash = pokiohash_hash(&mining_template, &new_block.nonce);
					let mining_difficulty = hash_to_difficulty(&mining_hash) as U256;
					
					println!("Diff: {} {}", mining_hash, mining_difficulty);*/
					/*
					let unsigned_serialized_block = serde_json::to_string_pretty(&new_block).unwrap();
					let block_signature = keccak256(&unsigned_serialized_block);
					new_block.signature = block_signature;

					let serialized_block = bincode::serialize(&new_block).unwrap();
					let unsigned_serialized_block = serde_json::to_string_pretty(&new_block).unwrap();
					*/
				}
			}
			(actual_height, actual_hash, _) = get_latest_block_info();
			println!("Block {} synced...", actual_height);
		}
		break;
		//thread::sleep(Duration::from_millis(10000));
	}
	println!("SYNC ENDED NOW!");
	Ok(())
}

