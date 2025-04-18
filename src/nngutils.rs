use nng::{Socket, Protocol};
use reqwest::Client;
use nng::options::protocol::pubsub::Subscribe;
use nng::options::Options;
use std::time::{Instant, Duration};
use serde_json::json;
use std::thread;


use crate::constants::*;
use crate::config;
use crate::pokiofunctions::*;
use crate::pokiofunctions::Block;

pub fn start_nng_server(ips: Vec<String>) {
	thread::spawn(move || {
		let db = config::db();
		let mempooldb = config::mempooldb();
		let rt = tokio::runtime::Runtime::new().unwrap();
		rt.block_on(async {
			let client = reqwest::Client::new();
			let socket = Socket::new(Protocol::Pub0).expect("Can't launch NNG socket");
			socket.listen("tcp://0.0.0.0:5555").expect("Error opening NNG port (5555)");
			let mut s_height = 0;

			let mining_urls: Vec<String> = ips
				.iter()
				.map(|ip| format!("http://{}:30303/mining", ip))
				.collect();

			let rpc_urls: Vec<String> = ips
				.iter()
				.map(|ip| format!("http://{}:30303/rpc", ip))
				.collect();

			loop {
				if config::full_sync_status() == 0 {
					let (actual_height, _actual_hash, _) = get_latest_block_info();
					if actual_height != s_height {
						let message = actual_height.to_string();
						if let Err(_e) = socket.send(message.as_bytes()) {
							eprintln!("Error sending message");
						} else {
							println!("New block inserted: {}", message);
						}

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
										}
									}
									Err(e) => {
										eprintln!("Error processing tx: {:?}", e);
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

								for url in mining_urls.iter() {
									let client = client.clone();
									let payload = payload.clone();
									let url = url.to_string();
									
									tokio::spawn(async move {
										let _ = client.post(&url).json(&payload).send().await;
										println!("PUT Block to {}", url);
									});
									
									/*tokio::spawn(async move {
										match client.post(&url).json(&payload).send().await {
											Ok(resp) => {
												if let Ok(text) = resp.text().await {
													println!("PUT Block to {}: {}", url, text);
												}
											}
											Err(e) => {
												eprintln!("Error sending to {}: {:?}", url, e);
											}
										}
									});*/
								}
							}
						}

						s_height = actual_height;
						for entry in mempooldb.iter() {
							match entry {
								Ok((key, value)) => {
									let tx_value_str = String::from_utf8(value.to_vec()).unwrap_or_else(|_| String::from("Invalid UTF-8"));

									if db.contains_key(tx_value_str.clone()).expect("REASON") {
										continue;
									}

									let payload = json!({
										"jsonrpc": "2.0",
										"method": "eth_sendRawTransaction",
										"params": [tx_value_str.clone()],
										"id": "mempool_auto"
									});

									for url in rpc_urls.iter() {
										let client = client.clone();
										let payload = payload.clone();
										let url = url.to_string();
										
										tokio::spawn(async move {
											let _ = client.post(&url).json(&payload).send().await;
											println!("TX Sent to {}", url);
										});

										/*tokio::spawn(async move {
											match client.post(&url).json(&payload).send().await {
												Ok(resp) => {
													if let Ok(text) = resp.text().await {
														println!("TX Sent to {}: {}", url, text);
													}
												}
												Err(e) => {
													eprintln!("Error sending to {}: {:?}", url, e);
												}
											}
										});*/
									}
									//println!("rawtx Value: {:?}", tx_value_str);
									
									/*let dtx = decode_transaction(&tx_value_str);
									match dtx {
										Ok(decoded_tx) => {
											let sender_address = format!("0x{}", hex::encode(decoded_tx.from));
											let last_nonce = get_last_nonce(&sender_address);
											
											if decoded_tx.nonce < last_nonce.into() {
												if let Err(e) = mempooldb.remove(&tx_value_str) {
													eprintln!("Error deleting mempool entry: {:?}", e);
												}
											}
										}
										Err(_) => {}
									}*/
									
								}
								Err(e) => {
									eprintln!("Error reading mempool entry: {:?}", e);
								}
							}
						}
					}
				}
				tokio::time::sleep(Duration::from_millis(50)).await;
			}
		});
	});
}

pub fn connect_to_nng_server(pserver: String) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
	let client = Client::new();
	let rpc_url = format!("http://{}:30303/rpc", pserver);
	let db = config::db();
	let mempooldb = config::mempooldb();

	thread::spawn(move || {
		let rt = tokio::runtime::Runtime::new().unwrap();
		rt.block_on(async move {
			let socket = Socket::new(Protocol::Sub0).expect("Can't connect to NNG server");
			let _ = socket.set_opt::<Subscribe>(vec![]);
			let nng_url = format!("tcp://{}:5555", pserver);
			socket
				.dial(&nng_url)
				.expect("Can't connect to NNG server");
			println!("Connected to {} NNG server", pserver);
			let mut last_mempool_check = Instant::now();
			loop {
				if config::sync_status() == 0 {
					if last_mempool_check.elapsed() >= Duration::from_secs(5) {
						last_mempool_check = Instant::now();
						if let Ok(response) = client
							.post(rpc_url.clone())
							.json(&json!({
								"jsonrpc": "2.0",
								"id": 1,
								"method": "pokio_getMempool",
								"params": []
							}))
							.send()
							.await
						{
							if let Ok(json_response) = response.json::<serde_json::Value>().await {
								if let Some(mempool_array) = json_response["result"].as_array() {
									for raw_tx in mempool_array {
										if let Some(raw_tx_str) = raw_tx.as_str() {
											let _txres = store_raw_transaction(raw_tx_str.to_string());
											//println!("tx {} stored in mempool", txres);
										}
									}
								}
							}
						}
					}
					
					match socket.recv() {
						Ok(_msg) => {
							let (actual_height, _actual_hash, _) = get_latest_block_info();

							let blocks_response = match client
								.post(rpc_url.clone())
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
							while config::sync_status() == 1 {
								std::thread::sleep(std::time::Duration::from_millis(50));
							}
							
							if let Some(blocks_array) = blocks_json["result"].as_array() {
								for block in blocks_array {
									let mut new_block = Block {
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
									
									if let Err(e) = save_block_to_db(&mut new_block) {
										eprintln!("Error saving block: {}", e);
									}
								}
							}
							
						}
						Err(e) => {
							eprintln!("Error receiving NNG message: {}", e);
						}
					}
				}
				thread::sleep(Duration::from_millis(50));
				
			}
		});
	});

	Ok(())
}