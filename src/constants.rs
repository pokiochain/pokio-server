pub struct Checkpoint {
    pub height: u64,
    pub hash: &'static str,
}

pub const FIX_BC_OFFSET: u64 = 1;
pub const DEFAULT_MINING_FEE: usize = 5;
pub const HALVING_INTERVAL: u64 = 31536000;
pub const CHAIN_ID: u64 = 850401;
pub const UNLOCK_OFFSET: u64 = 3;
pub const PREMINE_BLOCKS: u64 = 16;
pub const MINING_TX_NONCE: u64 = 100000000;
pub const HASHING_SPACE_COST: usize = 16;
pub const HASHING_TIME_COST: usize = 20;
pub const HASHING_DELTA: usize = 4;
pub const UPDATE_1_HEIGHT: u64 = 65002;
pub const UPDATE_2_HEIGHT: u64 = 200000;
pub const UPDATE_3_HEIGHT: u64 = 2000000000;
pub const UPDATE_4_HEIGHT: u64 = 710000;
pub const UPDATE_5_HEIGHT: u64 = 758000;
pub const UPDATE_RX_HEIGHT: u64 = 480000;
pub const MAX_MONERO_DIFF: u64 = 100000000000;
pub const MONERO_RX_RANDOM_DATA: &str = "02e8a5d10101ffaca5d10101b0c68fcabf110371a9489b19d9431e792f3b102caa82fb44a2f080a1423812f791903baf978d8f8b3401c7a682fe6ab464d46b112c597614c10cd164a17861da3632f7209309a62e6910021100000001b49101240000000000000000000008cf7c5b0d8c834fef2a28495af196488db1d55f882c8245ec376a7cd5eef4a8113840e822dfb107c0f051e2885a06d880f3804ade0707bedc82aae49bda730cc45d2eb5d9b7ed36e6dc67293bdfcca516a5e936276368bc360d513e3ef3a70a0d200b2c415d4530f05fa0a7ff3633ea24bf9260c15c1f374b6e5bc7ca43bcc1277cc01aae2f972332cab6c9a83226a3a1fb35fdc0cc7975e427d589a79ec24254d21a2a46d4f6ae60eb4bffc210f0f7b066de50e00ad6e2845feb4ac0228d5499e872a0333a3cf86be91f90271e216e178f648e13431306f90fb7b270dffc3c7ad3b0bc9d0abc3a21e49f7a95c563081afaea65a1b760ff219844655179321de0";
pub const EXTRA_NONCE_HEIGHT: u64 = 520000;
pub const COIN_DIFF: u64 = 2500000;
pub const COIN_DIFF_2: u64 = 5000000;
pub const COIN_DIFF_RX: u64 = 1000000;
pub const COIN_DIFF_DELAY: u64 = 100;
pub const MAX_COIN_DELAY: u64 = 10000;
pub const CONTRACT_CREATOR: &str = "0x0000000000000000000000000000000000000000";
pub const CHECKPOINTS: [Checkpoint; 14] = [
    Checkpoint { height: 5000, hash: "5dc59b4850c155832b29e490fb85db6735fc0777fc372ba90955e876aabc1267" },
    Checkpoint { height: 15000, hash: "82d7456b8587dcbb206d4d20f0fc5c9e118c7c79560a25caa97e254fe93cff9b" },
    Checkpoint { height: 35000, hash: "913f0359d81561649fe31f0f438797a12974c10f7e19f5eacc0baaed18c3eb40" },
    Checkpoint { height: 75000, hash: "645d4314c4466d28b335a93d7db17459032975346171770ec0ef8c704774bda1" },
    Checkpoint { height: 110000, hash: "322c30dc700bc6ee13fc71ecafdfd8105f59de631b886eb6c88c1a6f6374854a" },
    Checkpoint { height: 150000, hash: "671c4a8930a967077c7842055afb45641047238062ade248b905665ffcc0ecb3" },
    Checkpoint { height: 188000, hash: "a5a494f292ba14117028a7cc957e870469193d60dbed801ab4092aa91a694d29" },
	Checkpoint { height: 222900, hash: "ee41684b5f172f01efdd5d2289eb05b6cc36ddcda2a5bb825c4ec69d80ac0e2d" },
	Checkpoint { height: 279680, hash: "0fb1c2bf090452ca3ba3b3d5457b3253c5391983f7aecdc064c3c02c8d70d6d3" },
	Checkpoint { height: 306665, hash: "e6b0a8cca31ae9edc1c1c0acdfd91f731e184ef6cdad22b2306750f26288d107" },
	Checkpoint { height: 396000, hash: "c9a34be0e45c528b15cb285f494a856e44002510cefcaf75dc62013ae710cebe" },
	Checkpoint { height: 466000, hash: "fc2a00b13ee6ade449fdd1ce80712bdba848418701f5073c57a8ccb05f74eb27" },
	Checkpoint { height: 499000, hash: "19733f53a490180a2d08be87173d2ab903d30ac31d274da337636731038cbe21" },
	Checkpoint { height: 690767, hash: "88b0cf566916c40785847eea8921b4878d3e463d1d3c556e2b1cf71168d09016" },
];