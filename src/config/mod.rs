use ethers::signers::{LocalWallet, Signer};
use ethers::types::Address;
use serde::Deserialize;
use std::fs;
use std::str::FromStr;
use std::sync::OnceLock;
use sled;

static PKEY: OnceLock<String> = OnceLock::new();
static ETH_ADDRESS: OnceLock<Address> = OnceLock::new();
static DB: OnceLock<sled::Db> = OnceLock::new();

#[derive(Deserialize)]
struct KeyFile {
    privatekey: String,
}

pub fn load_key() {
    let data = fs::read_to_string("pokio.json").expect("Can't load pokio.json");
    let key_file: KeyFile = serde_json::from_str(&data).expect("JSON mal formado");

    PKEY.set(key_file.privatekey.clone()).expect("Private key was started");

    let wallet = LocalWallet::from_str(&key_file.privatekey).expect("Invalid private key");
    let address = wallet.address();

    ETH_ADDRESS.set(address).expect("Address was started");

    let db = sled::open("blockchain_db").expect("Failed to open blockchain database");
    DB.set(db).expect("Database was already initialized");
}

pub fn pkey() -> &'static str {
    PKEY.get().expect("Private key not loaded")
}

pub fn address() -> Address {
    *ETH_ADDRESS.get().expect("Address not loaded")
}

pub fn db() -> &'static sled::Db {
    DB.get().expect("Database not loaded")
}
