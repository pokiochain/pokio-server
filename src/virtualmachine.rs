use nng::{Socket, Protocol};
use reqwest::Client;
use nng::options::protocol::pubsub::Subscribe;
use nng::options::Options;
use std::time::{Instant, Duration};
use serde_json::json;
use std::thread;
use tokio::time::{interval, Duration as tDuration};
use tokio::select;
use sled::Db;
use tokio::runtime::Runtime;
use ethers::types::U256 as EthersU256;
use ethers::types::Bytes;
use num_bigint::BigUint;
use num_traits::FromPrimitive;

use crate::constants::*;
use crate::config;
use crate::pokiofunctions::*;
use crate::pokiofunctions::Block;

pub const ERC20_SYMBOL_BYTES: &str = "0000000000000000000000000000000000000000000000000000000000000020";
pub const VM_ZERO_24: &str = "000000000000000000000000";
pub const ERC20_FN_CHECK_BALANCE: &str = "0x70a08231";
pub const ERC20_FN_CHECK_NAME: &str = "0x06fdde03";
pub const ERC20_FN_CHECK_SYMBOL: &str = "0x95d89b41";
pub const ERC20_FN_CHECK_DECIMALS: &str = "0x313ce567";
pub const ERC20_NON_MINTABLE_CREATE: &str = "0xc0000001";
pub const ERC20_MINTABLE_CREATE: &str = "0xc0000002";


pub fn vm_process_eth_call(to: &str, data: &str) -> Result<serde_json::Value, String> {
    let vmdb = config::vmdb();
    let key = format!("{}:{}", to.to_lowercase(), data.to_lowercase());
    println!("{}", key);

    match vmdb.get(key) {
        Ok(Some(value)) => {
            let hex_str = String::from_utf8_lossy(value.as_ref());
            Ok(serde_json::json!(format!("0x{}", hex_str)))
        },
        Ok(None) => {
            if data.starts_with(ERC20_FN_CHECK_BALANCE) {
                return Ok(serde_json::json!("0x0000000000000000000000000000000000000000000000000000000000000000"));
            }
            Err("Method not found in storage".to_string())
        },
        Err(e) => Err(format!("Database error: {}", e)),
    }
}

fn encoded_string_length_hex64(hex: &str) -> String {
    let bytes = hex::decode(hex).expect("Invalid hex string");
    let null_pos = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    format!("{:0>64}", format!("{:x}", null_pos))
}


fn parse_tx_input(input: &str) -> (String, Vec<String>) {
    if !input.starts_with("0x") || input.len() < 10 {
        return ("".to_string(), vec![]);
    }
    let method = input[..10].to_string();
    let params_str = &input[10..];
    let mut params = vec![];
    let mut i = 0;
    while i + 64 <= params_str.len() {
        params.push(params_str[i..i + 64].to_string());
        i += 64;
    }
    (method, params)
}


pub fn start_virtual_machine() {
    thread::spawn(move || {
        let vmdb = config::vmdb();
        let rt = Runtime::new().unwrap();

        rt.block_on(async {
            let mut vm_height: u64 = match vmdb.get("vm_height") {
                Ok(Some(ivec)) => {
                    let bytes: [u8; 8] = ivec.as_ref().try_into().unwrap_or([0; 8]);
                    u64::from_le_bytes(bytes)
                }
                _ => 298300,
            };
            print_log_message(format!("Virtual Machine started with height: {}", vm_height), 1);
            let mut ticker = interval(tDuration::from_millis(2000));
            loop {
                ticker.tick().await;
                let (actual_height, _actual_hash, _) = get_latest_block_info();
				let actual_vm_height = actual_height - UNLOCK_OFFSET;
				if actual_vm_height > vm_height {
					for height in (vm_height + 1)..=actual_vm_height {
						let block = get_block_as_json(height);
						if let Some(transactions_str) = block.get("transactions").and_then(|v| v.as_str()) {
							let transactions: Vec<&str> = transactions_str.split('-').collect();
							for tx_str in transactions {
								let dtx = decode_transaction(tx_str);
								match dtx {
									Ok(tx) => {
										let address = tx.to.map(|addr| format!("{:?}", addr)).unwrap_or("None".to_string());
										let sender_address = format!("0x{}", hex::encode(tx.from));
										let txhash = keccak256(&tx_str);
										let amount = tx.value.clone().to_string();
										let input_hex = format!("0x{}", hex::encode(&tx.input));
										//let fee = tx.gas * tx.gas_price.unwrap_or(EthersU256::zero());
										//let total_deducted = (tx.value + fee).to_string();
										if input_hex != "0x" && address != CONTRACT_CREATOR {
											if tx.gas < EthersU256::from(300_000u64)
											{
												print_log_message(format!("VM Not enought gas: {:?}", tx.gas), 1);
												continue;
											}
											let (method, params) = parse_tx_input(&input_hex);
											if method == "0xa9059cbb" {
												let vm_sender = sender_address.trim_start_matches("0x");
												let hex_vm_sender = format!("{:0>64}", vm_sender);
												let sender_balance_key = format!("{}:{}{}", address, ERC20_FN_CHECK_BALANCE, hex_vm_sender);
												println!("{}", sender_balance_key);
												let receiver_balance_key = format!("{}:{}{}", address, ERC20_FN_CHECK_BALANCE, params[0]);
												let big_int_amount = BigUint::parse_bytes(params[1].as_bytes(), 16).expect("Invalid hex string");
												let mut sender_balance: BigUint;;
												match vmdb.get(&sender_balance_key) {
													Ok(Some(value)) => {
														let hex_str = String::from_utf8_lossy(value.as_ref());
														sender_balance = BigUint::parse_bytes(hex_str.as_bytes(), 16).expect("Invalid hex string");
													},
													Ok(None) => {
														sender_balance = BigUint::from(0u64);
													},
													Err(e) => { sender_balance = BigUint::from(0u64); }
												}
												if sender_balance >= big_int_amount {
													let mut receiver_balance: BigUint;;
													match vmdb.get(&receiver_balance_key) {
														Ok(Some(value)) => {
															let hex_str = String::from_utf8_lossy(value.as_ref());
															receiver_balance = BigUint::parse_bytes(hex_str.as_bytes(), 16).expect("Invalid hex string");
														},
														Ok(None) => {
															receiver_balance = BigUint::from(0u64);
														},
														Err(e) => { continue; }
													}
													
													let final_sender_balance = sender_balance - big_int_amount.clone();
													let final_receiver_balance = receiver_balance + big_int_amount.clone();
													
													let hex_sender_balance = format!("{:0>64}", final_sender_balance.to_str_radix(16));
													let hex_receiver_balance = format!("{:0>64}", final_receiver_balance.to_str_radix(16));
													match vmdb.insert(&sender_balance_key, hex_sender_balance.as_bytes()) {
														Ok(_) => println!("Sender balance updated"),
														Err(e) => println!("Error updating sender balance: {}", e),
													}
													match vmdb.insert(&receiver_balance_key, hex_receiver_balance.as_bytes()) {
														Ok(_) => println!("Receiver balance updated"),
														Err(e) => println!("Error updating receiver balance: {}", e),
													}
													let _ = vmdb.flush();
													print_log_message(format!("{} : {}", hex_receiver_balance, hex_sender_balance), 1);
													print_log_message(format!("{} -> {} : {}", vm_sender, params[0], big_int_amount), 1);
												}
											}
											continue;
										}
										
										if address == CONTRACT_CREATOR {
											if tx.gas < EthersU256::from(2_000_000u64)
											{
												print_log_message(format!("VM Not enought gas: {:?}", tx.gas), 1);
												continue;
											}
											print_log_message(format!("VM contract creation started"), 1);
											
											if input_hex != "0x" {
												let (method, params) = parse_tx_input(&input_hex);
												println!("{}", method);
												if method == ERC20_MINTABLE_CREATE || method == ERC20_NON_MINTABLE_CREATE {
													if params.len() == 4 {
														let full_contract_hash = keccak256(&txhash);
														let contract_hash = full_contract_hash[..40].to_string();
														let info_key = format!("0x{}:type", contract_hash);
														let info_value = method;
														let name_key = format!("0x{}:{}", contract_hash, ERC20_FN_CHECK_NAME);
														let name = params[0].clone();
														
														let hex_len_name = encoded_string_length_hex64(&name);
														
														let name_value = format!("{}{}{}", ERC20_SYMBOL_BYTES, hex_len_name, name);
														let symbol_key = format!("0x{}:{}", contract_hash, ERC20_FN_CHECK_SYMBOL);
														let symbol = params[1].clone();
														
														let hex_len_symbol = encoded_string_length_hex64(&symbol);
														
														let symbol_value = format!("{}{}{}", ERC20_SYMBOL_BYTES, hex_len_symbol, symbol);
														let decimals_key = format!("0x{}:{}", contract_hash, ERC20_FN_CHECK_DECIMALS);
														let decimals_value = params[2].clone();
														let clean_sender = sender_address.strip_prefix("0x").unwrap_or(&sender_address);
														//let balance_method = "70a08231"; //ERC20_FN_CHECK_BALANCE[..8].to_string();
														let balance_key = format!("0x{}:{}{}{}", contract_hash, ERC20_FN_CHECK_BALANCE, VM_ZERO_24, clean_sender);
														let balance_value = params[3].clone();
														println!("{}", balance_key);
														let inserts = vec![
															(info_key, info_value),
															(symbol_key, symbol_value),
															(name_key, name_value),
															(decimals_key, decimals_value),
															(balance_key, balance_value),
														];
														for (key, value) in inserts {
															if let Err(e) = vmdb.insert(key, value.as_bytes()) {
																print_log_message(format!("Error inserting into DB: {}", e), 1);
															}
														}
														print_log_message(format!("Contract created: 0x{}", contract_hash), 1);
														let _ = vmdb.flush();
													}
												}
											}
											continue;
										}
									}
									Err(e) => {
										eprintln!("VM error processing tx: {:?}", e);
									}
								}
							}
						}
						vm_height = height;
						let bytes = vm_height.to_le_bytes();
						if let Err(e) = vmdb.insert("vm_height", &bytes) {
							print_log_message(format!("Error saving vm_height: {}", e), 2);
						}
						if let Err(e) = vmdb.flush() {
							print_log_message(format!("Error flushing sled db: {}", e), 2);
						}
						print_log_message(format!("VM Height updated: {}", vm_height), 2);
					}
				}

            }
        });
    });
}
