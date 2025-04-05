use ethers::signers::{LocalWallet, Signer};
use ethers::types::Address;
use serde::Deserialize;
use std::fs;
use std::str::FromStr;
use std::sync::{OnceLock, atomic::{AtomicUsize, Ordering}};
use sled;

static PKEY: OnceLock<String> = OnceLock::new();
static ETH_ADDRESS: OnceLock<Address> = OnceLock::new();
static DB: OnceLock<sled::Db> = OnceLock::new();
static MEMPOOLDB: OnceLock<sled::Db> = OnceLock::new();
static POOLDB: OnceLock<sled::Db> = OnceLock::new();
static SYNC_STATUS: OnceLock<AtomicUsize> = OnceLock::new(); // Nueva variable

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
    
    let mempooldb = sled::open("mempool_db").expect("Failed to open mempool database");
    MEMPOOLDB.set(mempooldb).expect("Mempool was already initialized");
    
    let pooldb = sled::open("pool_db").expect("Failed to open mempool database");
    POOLDB.set(pooldb).expect("Mempool was already initialized");

    SYNC_STATUS.set(AtomicUsize::new(0)).expect("Sync status already initialized");
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

pub fn mempooldb() -> &'static sled::Db {
    MEMPOOLDB.get().expect("Database not loaded")
}

pub fn pooldb() -> &'static sled::Db {
    POOLDB.get().expect("Database not loaded")
}

pub fn sync_status() -> usize {
    SYNC_STATUS.get().expect("Sync status not initialized").load(Ordering::SeqCst)
}

pub fn update_sync(value: usize) {
    if let Some(status) = SYNC_STATUS.get() {
        status.store(value, Ordering::SeqCst);
    } else {
        panic!("Sync status not initialized");
    }
}
