use num_bigint::BigUint;
use num_traits::Zero;

use crate::config;

pub fn update_balance(address: &str, amount_to_add: &str, operation_type: u8) -> Result<(), Box<dyn std::error::Error>> {
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

pub fn get_balance(address: &str) -> Result<String, Box<dyn std::error::Error>> {
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

