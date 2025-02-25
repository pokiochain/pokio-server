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

mod config;

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

fn get_latest_block_info(db: &sled::Db) -> (u64, String) {
	if let Some(latest) = db.get("chain:latest_block").unwrap() {
		let latest_height = u64::from_be_bytes(latest.as_ref().try_into().unwrap());
		let block_key = format!("block:{:08}", latest_height);
		if let Some(block_data) = db.get(block_key).unwrap() {
			let block: Block = bincode::deserialize(&block_data).unwrap();
			return (block.height, block.hash.clone());
		}
	}
	(0, "0000000000000000000000000000000000000000000000000000000000000000".to_string())
}

fn get_mining_template(db: &sled::Db, coins: &str, miner: &str) -> String {
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
	
	let coins_dec = u64::from_str_radix(coins, 16).unwrap_or(0);
	let diff = format!("{:016X}", coins_dec * 10000);
	
	let nonce = 100000000 + height;
	let private_key = "";
	let base_wei = BigUint::parse_bytes(b"1000000000000000000", 10).unwrap();
	let coins_biguint = BigUint::from_str(coins).unwrap();
	let wei_amount = coins_biguint * &base_wei;
	let reward_amount = EthersU256::from_dec_str(&wei_amount.to_str_radix(10)).unwrap();
	let raw_tx: String;

	match generate_reward_tx(config::pkey(), nonce, miner, reward_amount) {
		Ok(tx) => {
			println!("Raw Signed Reward TX: 0x{}", tx);
			raw_tx = tx;
		}
		Err(e) => {
			println!("Error generating reward transaction: {}", e);
			raw_tx = String::new();
		}
	}
	format!("0000000000000000-{}-{}-{}-{}-{}", coins_dec, diff, prevhash, miner, raw_tx)
}

fn generate_reward_tx(
	private_key: &str,
	nonce: u64,
	miner_address: &str,
	reward_amount: EthersU256,
) -> eyre::Result<String> {
	let wallet = LocalWallet::from_str(private_key)?.with_chain_id(291287u64);

	let tx = TransactionRequest::new()
		.nonce(nonce)
		.to(miner_address)
		.value(reward_amount)
		.gas(21000)
		.gas_price(0);

	let tx: TypedTransaction = tx.into();
	let signature = wallet.sign_transaction_sync(&tx)?;
	let raw_signed_tx = tx.rlp_signed(&signature);
	decode_transaction(&hex::encode(&raw_signed_tx))?;

	Ok(hex::encode(raw_signed_tx))
}

fn decode_transaction(raw_tx_hex: &str) -> Result<()> {
	let raw_tx_bytes = hex::decode(raw_tx_hex.strip_prefix("0x").unwrap_or(raw_tx_hex))?;
	let tx: Transaction = rlp::decode(&raw_tx_bytes)?;
	println!("Chain ID: {:?}", tx);
	
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
	
	let input = tx.input;
	let dest_str = tx.to.map(|addr| format!("{:x}", addr)).unwrap_or_default();
	let to = H160::from_slice(&hex::decode(dest_str).unwrap());
	let chain_id = tx.chain_id.unwrap_or(EthersU256::zero()).as_u64();

	let message_hash = calculate_message_hash(nonce, gas_price, gas, to, value, &input, chain_id);
	//println!("Message hash: {}", hex::encode(message_hash));

	let v: U64 = tx.v;
	let r = tx.r.to_string();
	let s = tx.s.to_string();
	let r_bigint = BigInt::from_str_radix(&r, 10).unwrap();
	let s_bigint = BigInt::from_str_radix(&s, 10).unwrap();
	let r_hex = format!("{:064x}", r_bigint);
	let s_hex = format!("{:064x}", s_bigint);

	let adjusted_v = (v.as_u64() - (2 * chain_id + 35)) as u8;
	//println!("Original v: {}, Adjusted v: {}", v, adjusted_v);

	if adjusted_v > 1 {
		println!("Invalid adjusted `v` value: {}", adjusted_v);
		return Ok(());
	}

	match recover_sender_address(adjusted_v, &r_hex, &s_hex, message_hash.into()) {
		Ok(address) => println!("Recovered address: {:?}", address),
		Err(e) => println!("Error: {}", e),
	}
	Ok(())
}

fn mine_block() -> sled::Result<()> {
	let db = sled::open("blockchain_db")?;
	let coins = "3"; //hex
	let miner = format!("0x{}", hex::encode(config::address()));
	let mining_template = get_mining_template(&db, coins, &miner);
	println!("Mining Template: {}", mining_template);
	
	let parts: Vec<&str> = mining_template.split('-').collect();
	//println!("Nonce: {}", parts[0]);
	//println!("PrevHash: {}", parts[3]);
	//println!("Miner: {}", parts[4]);
	
	let mined_coins: u64 = parts[1].parse().unwrap();
	let mined_coins_difficulty = u64::from_str_radix(parts[2], 16).unwrap_or(u64::MAX);
	let block_difficulty = mined_coins_difficulty.clone();
	
	let mining_hash = pokiohash_hash(&mining_template, &miner);
	let mining_difficulty = hash_to_difficulty(&mining_hash) as U256;
	
	let block_transactions = parts[5];

	println!("Block found. Diff: {}, Hash: {}", mining_difficulty, mining_hash);
	
	if mining_difficulty < block_difficulty.into()
	{
		let (actual_height, actual_hash) = get_latest_block_info(&db);

		let mut new_block = Block {
			height: actual_height + 1,
			hash: "".to_string(),
			prev_hash: actual_hash,
			timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
			nonce: "".to_string(),
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
		//get merkle tx's receipt
		new_block.receipts_root = merkle_tree(&new_block.transactions);
		//get blockhash
		let unhashed_serialized_block = serde_json::to_string_pretty(&new_block).unwrap();
		let block_hash = keccak256(&unhashed_serialized_block);
		new_block.hash = block_hash;
		//sign block
		let unsigned_serialized_block = serde_json::to_string_pretty(&new_block).unwrap();
		let block_signature = keccak256(&unsigned_serialized_block);
		new_block.signature = block_signature;
		//serialize block to save in sled
		let serialized_block = bincode::serialize(&new_block).unwrap();
		//height as key
		db.insert(format!("block:{:08}", new_block.height), serialized_block)?;
		//index hash -> height
		db.insert(format!("hash:{}", new_block.hash), &new_block.height.to_be_bytes())?;
		//save lastest_block
		db.insert("chain:latest_block", &new_block.height.to_be_bytes())?;
	}

	if let Some(latest) = db.get("chain:latest_block")? {
		let latest_height = u64::from_be_bytes(latest.as_ref().try_into().unwrap());
		let block_key = format!("block:{:08}", latest_height);
		if let Some(block_data) = db.get(block_key)? {
			let block: Block = bincode::deserialize(&block_data).unwrap();
			println!("Last block: {:?}", block);
		}
	}

	Ok(())
}

#[tokio::main]
async fn main() -> sled::Result<()> {
	
    config::load_key();
    println!("Private key: {}", config::pkey());
	println!("Address (hex): 0x{}", ethers::utils::hex::encode(config::address())); 
	
	mine_block();
	
	let rpc_route = warp::path("rpc")
		.and(warp::post())
		.and(warp::body::json())
		.map(|data: serde_json::Value| {
			println!("Received JSON: {}", data);
			
			let id = data["id"].as_str().unwrap_or("unknown");
			let method = data["method"].as_str().unwrap_or("");
			
			let response = match method {
				"eth_chainId" => json!({"jsonrpc": "2.0", "id": id, "result": "0x471d7"}),
				"eth_blockNumber" => {
					let block_number = format!("0x{:x}", (chrono::Utc::now().timestamp() / 1000000));
					json!({"jsonrpc": "2.0", "id": id, "result": block_number})
				},
				"net_version" => json!({"jsonrpc": "2.0", "id": id, "result": "291287"}),
				"eth_getBalance" => json!({"jsonrpc": "2.0", "id": id, "result": "0xfadfafaafffffffffff"}),
				_ => json!({"jsonrpc": "2.0", "id": id, "error": {"code": -32600, "message": "The method does not exist/is not available"}}),
			};
			
			warp::reply::json(&response)
			
			
		});
		
	let mining_route = warp::path("mining")
		.and(warp::post())
		.and(warp::body::json())
		.map(|data: serde_json::Value| {
			println!("Received JSON: {}", data);
			
			
			
			let id = data["id"].as_str().unwrap_or("unknown");
			let method = data["method"].as_str().unwrap_or("");
			
			let response = match method {
				"getMiningTemplate" => {
					
					json!({"jsonrpc": "2.0", "id": id, "result": "0x471d7"})
				},
				"eth_blockNumber" => {
					let block_number = format!("0x{:x}", (chrono::Utc::now().timestamp() / 1000000));
					json!({"jsonrpc": "2.0", "id": id, "result": block_number})
				},
				"net_version" => json!({"jsonrpc": "2.0", "id": id, "result": "291287"}),
				"eth_getBalance" => json!({"jsonrpc": "2.0", "id": id, "result": "0xfadfafaafffffffffff"}),
				_ => json!({"jsonrpc": "2.0", "id": id, "error": {"code": -32600, "message": "The method does not exist/is not available"}}),
			};
			
			warp::reply::json(&response)
			
			
		});
		/*.map(|| {
			println!("Mining requested");
			let _ = mine_block();
			warp::reply::json(&json!({"status": "mining", "message": "Mining operation started"}))
		});*/

	let routes = rpc_route.or(mining_route);
	warp::serve(routes).run(([127, 0, 0, 1], 3030)).await;
	Ok(())
}