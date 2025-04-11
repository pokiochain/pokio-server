use ethers::signers::{LocalWallet, Signer};
use ethers::types::Address;
use serde::Deserialize;
use std::fs;
use std::str::FromStr;
use std::sync::{Mutex, OnceLock, atomic::{AtomicUsize, Ordering}};
use sled;

static PKEY: OnceLock<String> = OnceLock::new();
static ETH_ADDRESS: OnceLock<Address> = OnceLock::new();
static DB: OnceLock<sled::Db> = OnceLock::new();
static MEMPOOLDB: OnceLock<sled::Db> = OnceLock::new();
static POOLDB: OnceLock<sled::Db> = OnceLock::new();
static SYNC_STATUS: OnceLock<AtomicUsize> = OnceLock::new();
static ACTUAL_HEIGHT: OnceLock<AtomicUsize> = OnceLock::new();
static ACTUAL_HASH: OnceLock<Mutex<String>> = OnceLock::new();
static ACTUAL_TIMESTAMP: OnceLock<AtomicUsize> = OnceLock::new();

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
	
	ACTUAL_HEIGHT.set(AtomicUsize::new(0)).expect("Actual height already initialized");
	ACTUAL_HASH.set(Mutex::new("0000000000000000000000000000000000000000000000000000000000000000".to_string())).expect("Actual hash key was started");
	ACTUAL_TIMESTAMP.set(AtomicUsize::new(0)).expect("Actual timestamp already initialized");
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

pub fn actual_height() -> usize {
    ACTUAL_HEIGHT.get().expect("Actual height not initialized").load(Ordering::SeqCst)
}

pub fn update_actual_height(value: usize) {
    if let Some(status) = ACTUAL_HEIGHT.get() {
        status.store(value, Ordering::SeqCst);
    } else {
        panic!("Actual height not initialized");
    }
}

pub fn update_actual_hash(value: String) {
    if let Some(hash_mutex) = ACTUAL_HASH.get() {
        let mut hash = hash_mutex.lock().expect("Failed to lock hash mutex");
        *hash = value;
    } else {
        panic!("Actual hash not initialized");
    }
}

pub fn actual_hash() -> String {
    ACTUAL_HASH
        .get()
        .expect("Actual hash not loaded")
        .lock()
        .expect("Failed to lock hash mutex")
        .clone()
}

pub fn actual_timestamp() -> usize {
    ACTUAL_TIMESTAMP.get().expect("Actual timestamp not initialized").load(Ordering::SeqCst)
}

pub fn update_actual_timestamp(value: usize) {
    if let Some(status) = ACTUAL_TIMESTAMP.get() {
        status.store(value, Ordering::SeqCst);
    } else {
        panic!("Actual timestamp not initialized");
    }
}