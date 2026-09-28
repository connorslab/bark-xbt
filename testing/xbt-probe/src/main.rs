//! Deterministic, worthless regtest keys only. Never use these addresses with funds.
use std::{env, io::{self, Read}};

use ark::board::BoardBuilder;
use ark::ProtocolEncoding;
use ark::vtxo::policy::clause::{DelayedSignClause, TapScriptClause};
use bitcoin::consensus::deserialize;
use bitcoin::consensus::encode::serialize_hex;
use bitcoin::hex::FromHex;
use bitcoin::hashes::{sha256, Hash};
use bitcoin::key::TapTweak;
use bitcoin::secp256k1::{Keypair, SecretKey};
use bitcoin::{Address, Amount, Network, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness};
use bitcoin_ext::{BlockDelta, BlockHeight};
use bitcoin_ext::unified::{self, Execution};
use serde_json::json;
use lightning_invoice::{Bolt11Invoice, Currency, InvoiceBuilder, PaymentSecret, RawTaggedField, TaggedField};
use lightning_types::features::Bolt11InvoiceFeatures;

fn main() -> Result<(), Box<dyn std::error::Error>> {
	let args: Vec<_> = env::args().collect();
	let user = Keypair::from_secret_key(&ark::SECP, &SecretKey::from_slice(&[4; 32])?);
	let server = Keypair::from_secret_key(&ark::SECP, &SecretKey::from_slice(&[5; 32])?);
	if args.get(1).map(String::as_str) == Some("identity") {
		let invoice = InvoiceBuilder::new(Currency::Regtest).description("private XBT test".into())
			.payment_hash(sha256::Hash::hash(&[7; 32])).payment_secret(PaymentSecret([8; 32]))
			.current_timestamp().min_final_cltv_expiry_delta(18).amount_milli_satoshis(1000)
			.build_signed(|m| ark::SECP.sign_ecdsa_recoverable(m, &user.secret_key()))?;
		assert!(ark::lightning::Invoice::Bolt11(invoice.clone()).require_xbt().is_err());
		let original = invoice.into_signed_raw().into_parts().0;
		for mode in [0u8, 1, 2] {
			let mut raw = original.clone();
			for field in &mut raw.data.tagged_fields {
				if let RawTaggedField::KnownSemantics(TaggedField::Features(features)) = field {
					features.set_blake2b_identity_required();
					if mode == 1 { features.clear_blake2b_identity(); features.set_blake2b_identity_optional(); }
					if mode == 2 {
						let mut flags = features.le_flags().to_vec(); flags[64] |= 4;
						*features = Bolt11InvoiceFeatures::from_le_bytes(flags);
					}
				}
			}
			let signed = raw.sign(|m| Ok::<_, std::convert::Infallible>(ark::SECP.sign_ecdsa_recoverable(m, &user.secret_key())))?;
			let parsed = signed.to_string().parse::<Bolt11Invoice>();
			if mode == 2 { assert!(parsed.is_err()); }
			else {
				let check = ark::lightning::Invoice::Bolt11(parsed?).require_xbt();
				assert_eq!(check.is_ok(), mode == 0);
			}
		}
		println!("{}", json!({"required_512_accepted": true, "missing_or_optional_rejected": true, "unknown_required_rejected": true}));
		return Ok(());
	}
	let key_spk = ScriptBuf::new_p2tr(&ark::SECP, user.x_only_public_key().0, None);
	let builder = BoardBuilder::new(user.public_key(), BlockHeight::new(1000),
		server.public_key(), BlockDelta::new(6));
	if args.get(1).map(String::as_str) == Some("addresses") {
		println!("{}", json!({
			"key": Address::from_script(&key_spk, Network::Regtest)?.to_string(),
			"board": Address::from_script(&builder.funding_script_pubkey(), Network::Regtest)?.to_string(),
		}));
		return Ok(());
	}
	let mut input = String::new(); io::stdin().read_to_string(&mut input)?;
	if args.get(1).map(String::as_str) == Some("header-variants") {
		let base: bitcoin::block::Header = deserialize(&Vec::<u8>::from_hex(input.trim())?)?;
		let mut variants = Vec::new();
		for flags in 0u8..8 {
			for clear in [0, 7, 8, 255] {
				let mut header = base;
				let extra = header.blake2b.as_mut().ok_or("missing extended header")?;
				extra.flags = flags;
				extra.time_offset = 5;
				extra.nonce2 = 9;
				extra.nonce3 = 8;
				extra.extranonce = [9; 16];
				extra.xor_key = [7; 16];
				extra.xor_mask_clear_bits = clear;
				extra.merge_mining_rhs = [6; 32];
				header.nonce = 0;
				while header.validate_pow(header.target()).is_err() {
					header.nonce = header.nonce.checked_add(1).ok_or("nonce overflow")?;
					assert!(header.nonce < 1000, "regtest-only header probe");
				}
				variants.push(json!({"hash": header.block_hash().to_string(), "hex": serialize_hex(&header), "flags": flags, "clear": clear}));
			}
		}
		println!("{}", json!(variants));
		return Ok(());
	}
	if args.get(1).map(String::as_str) == Some("block") {
		let raw = Vec::<u8>::from_hex(input.trim())?;
		let block: bitcoin::Block = deserialize(&raw)?;
		assert!(block.check_merkle_root());
		println!("{}", json!({"hash": block.block_hash().to_string(), "roundtrip": serialize_hex(&block)}));
		return Ok(());
	}
	if args.get(1).map(String::as_str) == Some("header") {
		let raw = Vec::<u8>::from_hex(input.trim())?;
		let header: bitcoin::block::Header = deserialize(&raw)?;
		println!("{}", json!({"hash": header.block_hash().to_string(),
			"time": header.time, "roundtrip": serialize_hex(&header)}));
		return Ok(());
	}
	let funding: Transaction = deserialize(&Vec::<u8>::from_hex(input.trim())?)?;
	let key_idx = funding.output.iter().position(|o| o.script_pubkey == key_spk).ok_or("key output")?;
	let board_idx = funding.output.iter().position(|o| o.script_pubkey == builder.funding_script_pubkey()).ok_or("board output")?;
	let make_tx = |point, value, sequence| Transaction {
		version: bitcoin::transaction::Version(3), lock_time: bitcoin::absolute::LockTime::ZERO,
		input: vec![TxIn { previous_output: point, sequence, ..TxIn::default() }],
		output: vec![TxOut { value, script_pubkey: key_spk.clone() }],
	};
	let mut key_tx = make_tx(OutPoint::new(funding.compute_txid(), key_idx as u32),
		funding.output[key_idx].value - Amount::from_sat(500), Sequence::MAX);
	let key_hash = unified::digest(&key_tx, 0, &[funding.output[key_idx].clone()], unified::ALL,
		Execution { script_type: 2, script_code: None, annex: None, leaf: None })?;
	let tweaked = user.tap_tweak(&ark::SECP, None).to_keypair();
	let sig = ark::SECP.sign_schnorr(&key_hash.into(), &tweaked);
	key_tx.input[0].witness = Witness::from_slice(&[unified::signature(&sig)]);
	let mut legacy = key_tx.clone();
	let hash = bitcoin::sighash::SighashCache::new(&legacy).taproot_key_spend_signature_hash(
		0, &bitcoin::sighash::Prevouts::All(&[funding.output[key_idx].clone()]),
		bitcoin::TapSighashType::Default)?;
	legacy.input[0].witness = Witness::from_slice(&[ark::SECP.sign_schnorr(&hash.into(), &tweaked).as_ref()]);
	let amount = funding.output[board_idx].value;
	let fee = Amount::from_sat(2000);
	let point = OutPoint::new(funding.compute_txid(), board_idx as u32);
	let funded = args.get(1).map(String::as_str) == Some("funded");
	let miner_fee = Amount::from_sat(500);
	let builder = if funded {
		builder.set_funded_funding_details(amount, fee, miner_fee, point)?
	} else {
		builder.set_funding_details(amount, fee, point)?
	}.generate_user_nonces();
	let cosigner = if funded {
		BoardBuilder::new_for_funded_cosign(user.public_key(), BlockHeight::new(1000),
			server.public_key(), BlockDelta::new(6), amount, fee, miner_fee, point,
			*builder.user_pub_nonce())?
	} else {
		BoardBuilder::new_for_cosign(user.public_key(), BlockHeight::new(1000),
			server.public_key(), BlockDelta::new(6), amount, fee, point, *builder.user_pub_nonce())
	};
	let response = cosigner.server_cosign(&server);
	assert!(builder.verify_cosign_response(&response));
	let vtxo = builder.build_vtxo(&response, &user)?;
	vtxo.validate(&funding)?;
	let restored = ark::Vtxo::<ark::vtxo::Full>::deserialize(&vtxo.serialize())?;
	restored.validate(&funding)?;
	assert_eq!(restored.transactions().collect::<Vec<_>>(), vtxo.transactions().collect::<Vec<_>>());
	let board = vtxo.transactions().next().ok_or("missing exit")?.tx;
	let mut cpfp = make_tx(OutPoint::new(board.compute_txid(), 1), Amount::from_sat(330), Sequence::MAX);
	cpfp.input[0].witness = Witness::new(); // P2A, deliberately signature-free.
	let mut claim = make_tx(OutPoint::new(board.compute_txid(), 0),
		board.output[0].value - Amount::from_sat(700), Sequence(6));
	let clause = DelayedSignClause { pubkey: user.public_key(), block_delta: BlockDelta::new(6) };
	let script = clause.tapscript();
	let hash = unified::digest(&claim, 0, &[board.output[0].clone()], unified::ALL,
		Execution { script_type: 3, script_code: None, annex: None,
			leaf: Some((bitcoin::TapLeafHash::from_script(&script, bitcoin::taproot::LeafVersion::TapScript), u32::MAX)) })?;
	let sig = ark::SECP.sign_schnorr(&hash.into(), &user);
	claim.input[0].witness = clause.witness(&sig, &clause.control_block(&vtxo));
	println!("{}", json!({"key": serialize_hex(&key_tx), "legacy": serialize_hex(&legacy),
		"board": serialize_hex(&board), "cpfp": serialize_hex(&cpfp), "claim": serialize_hex(&claim)}));
	Ok(())
}
