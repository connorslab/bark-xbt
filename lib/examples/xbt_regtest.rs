//! Deterministic, worthless regtest keys only. Never use these addresses with funds.
use std::{env, io::{self, Read}};

use ark::board::BoardBuilder;
use ark::vtxo::policy::clause::{DelayedSignClause, TapScriptClause};
use bitcoin::consensus::{deserialize, serialize_hex};
use bitcoin::hex::FromHex;
use bitcoin::key::TapTweak;
use bitcoin::secp256k1::{Keypair, SecretKey};
use bitcoin::{Address, Amount, Network, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness};
use bitcoin_ext::{BlockDelta, BlockHeight};
use bitcoin_ext::unified::{self, Execution};
use serde_json::json;

fn main() -> Result<(), Box<dyn std::error::Error>> {
	let args: Vec<_> = env::args().collect();
	let user = Keypair::from_secret_key(&ark::SECP, &SecretKey::from_slice(&[4; 32])?);
	let server = Keypair::from_secret_key(&ark::SECP, &SecretKey::from_slice(&[5; 32])?);
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
	let builder = builder.set_funding_details(amount, fee, point)?.generate_user_nonces();
	let cosigner = BoardBuilder::new_for_cosign(user.public_key(), BlockHeight::new(1000),
		server.public_key(), BlockDelta::new(6), amount, fee, point, *builder.user_pub_nonce());
	let response = cosigner.server_cosign(&server);
	assert!(builder.verify_cosign_response(&response));
	let vtxo = builder.build_vtxo(&response, &user)?;
	vtxo.validate(&funding)?;
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
