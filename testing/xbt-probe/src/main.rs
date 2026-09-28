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

fn funded_tree_spec(user: &Keypair, server: &Keypair) -> Result<ark::tree::signed::VtxoTreeSpec, Box<dyn std::error::Error>> {
	use ark::tree::signed::{VtxoTreeSpec, VtxoLeafSpec, TreeExitFunding};
	let cosign = Keypair::from_secret_key(&ark::SECP, &SecretKey::from_slice(&[8; 32])?);
	Ok(VtxoTreeSpec::new([30_000, 50_000].into_iter().map(|sats| VtxoLeafSpec {
		vtxo: ark::VtxoRequest { amount: Amount::from_sat(sats), policy: ark::VtxoPolicy::new_pubkey(user.public_key()) },
		cosign_pubkey: None, unlock_hash: sha256::Hash::hash(&[7; 32]),
	}).collect(), server.public_key(), BlockHeight::new(1000), BlockDelta::new(6),
		vec![cosign.public_key(), server.public_key()])
		.with_exit_funding(TreeExitFunding::new(Amount::from_sat(330), Amount::from_sat(1000))?)?)
}

fn funded_tree_recovery(funding: &Transaction, user: &Keypair, server: &Keypair) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
	use ark::tree::signed::{LeafVtxoCosignContext, LeafVtxoCosignResponse};
	let spec = funded_tree_spec(user, server)?;
	let idx = funding.output.iter().position(|o| *o == spec.funding_tx_txout()).ok_or("tree funding mismatch")?;
	let unsigned = spec.into_unsigned_tree(OutPoint::new(funding.compute_txid(), idx as u32));
	let cosign = Keypair::from_secret_key(&ark::SECP, &SecretKey::from_slice(&[8; 32])?);
	let nonces = |key: &Keypair| -> (Vec<_>, Vec<_>) {
		unsigned.internal_sighashes.iter().map(|h| ark::musig::nonce_pair_with_msg(key, &h.to_byte_array())).unzip()
	};
	let (user_secs, user_pubs) = nonces(&cosign);
	let (server_secs, server_pubs) = nonces(server);
	let agg = user_pubs.iter().zip(&server_pubs).map(|(u, s)| ark::musig::AggregatedNonce::new(&[u, s])).collect::<Vec<_>>();
	let us = unsigned.cosign_tree(&agg, &cosign, user_secs);
	let ss = unsigned.cosign_tree(&agg, server, server_secs);
	let sigs = unsigned.combine_partial_signatures(&agg, &std::collections::HashMap::new(), &[&us, &ss])?;
	let cached = unsigned.into_signed_tree(sigs).into_cached_tree();
	let mut parents = Vec::new();
	let mut seen = std::collections::HashSet::new();
	let mut claims = Vec::new();
	for mut vtxo in cached.output_vtxos() {
		let (ctx, request) = LeafVtxoCosignContext::new(&vtxo, funding, user)?;
		let response = LeafVtxoCosignResponse::new_cosign(&request, &vtxo, funding, server)?;
		assert!(ctx.finalize(&mut vtxo, response));
		assert!(vtxo.provide_unlock_preimage([7; 32]));
		vtxo.validate(funding)?;
		let restored = ark::Vtxo::<ark::vtxo::Full>::deserialize(&vtxo.serialize())?;
		restored.validate(funding)?;
		for item in restored.transactions() {
			if seen.insert(item.tx.compute_txid()) { parents.push(serialize_hex(&item.tx)); }
		}
		let mut claim = Transaction {
			version: bitcoin::transaction::Version(3), lock_time: bitcoin::absolute::LockTime::ZERO,
			input: vec![TxIn { previous_output: vtxo.point(), sequence: Sequence(6), ..TxIn::default() }],
			output: vec![TxOut { value: vtxo.amount() - Amount::from_sat(700),
				script_pubkey: ScriptBuf::new_p2tr(&ark::SECP, user.x_only_public_key().0, None) }],
		};
		let clause = DelayedSignClause { pubkey: user.public_key(), block_delta: BlockDelta::new(6) };
		let script = clause.tapscript();
		let hash = unified::digest(&claim, 0, &[vtxo.txout()], unified::ALL, Execution {
			script_type: 3, script_code: None, annex: None,
			leaf: Some((bitcoin::TapLeafHash::from_script(&script, bitcoin::taproot::LeafVersion::TapScript), u32::MAX)),
		})?;
		let sig = ark::SECP.sign_schnorr(&hash.into(), user);
		claim.input[0].witness = clause.witness(&sig, &clause.control_block(&vtxo));
		claims.push(serialize_hex(&claim));
	}
	Ok(json!({"parents": parents, "claims": claims}))
}

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
		let tree = funded_tree_spec(&user, &server)?;
		println!("{}", json!({
			"key": Address::from_script(&key_spk, Network::Regtest)?.to_string(),
			"board": Address::from_script(&builder.funding_script_pubkey(), Network::Regtest)?.to_string(),
			"tree": Address::from_script(&tree.funding_tx_script_pubkey(), Network::Regtest)?.to_string(),
			"tree_amount_sat": tree.total_required_value().to_sat(),
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
	if args.get(1).map(String::as_str) == Some("funded-tree") {
		println!("{}", funded_tree_recovery(&funding, &user, &server)?);
		return Ok(());
	}
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
	let funded = args.get(1).is_some_and(|m| m.starts_with("funded"));
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
	let mut vtxo = builder.build_vtxo(&response, &user)?;
	vtxo.validate(&funding)?;
	let mut claim_key = user;
	if args.get(1).map(String::as_str) == Some("funded-transfer") {
		let bob = Keypair::from_secret_key(&ark::SECP, &SecretKey::from_slice(&[6; 32])?);
		let profile = ark::tree::signed::TreeExitFunding::new(Amount::from_sat(330), Amount::from_sat(1000))?;
		for (recipient, payment) in [(bob, Amount::from_sat(50_000)), (user, Amount::from_sat(30_000))] {
			let outputs = vec![
				ark::arkoor::ArkoorDestination { total_amount: payment,
					policy: ark::VtxoPolicy::new_pubkey(recipient.public_key()) },
				ark::arkoor::ArkoorDestination { total_amount: vtxo.amount() - payment - profile.per_transaction() * 3,
					policy: ark::VtxoPolicy::new_pubkey(claim_key.public_key()) },
			];
			let builder = ark::arkoor::ArkoorBuilder::new_funded(vtxo, outputs, true, profile)?
				.generate_user_nonces(claim_key);
			let cosigner = ark::arkoor::ArkoorBuilder::from_cosign_request(builder.cosign_request())?
				.server_cosign(&server)?;
			vtxo = builder.user_cosign(&claim_key, &cosigner.cosign_response())?
				.build_signed_vtxos().into_iter().next().ok_or("missing payment output")?;
			vtxo.validate(&funding)?;
			claim_key = recipient;
		}
	}
	let restored = ark::Vtxo::<ark::vtxo::Full>::deserialize(&vtxo.serialize())?;
	restored.validate(&funding)?;
	assert_eq!(restored.transactions().collect::<Vec<_>>(), vtxo.transactions().collect::<Vec<_>>());
	if funded {
		let policy = ark::exit_policy::FundedExitPolicy {
			minimum_relay: bitcoin::FeeRate::from_sat_per_vb(1).unwrap(),
			dust_relay: bitcoin::FeeRate::from_sat_per_vb(3).unwrap(),
			confirmation_margin: BlockDelta::new(12), claim_fee: Amount::from_sat(700),
		};
		policy.check(&vtxo, &funding, BlockHeight::new(131))?;
		assert!(policy.check(&vtxo, &funding, BlockHeight::new(1000)).is_err());
		assert!(ark::exit_policy::FundedExitPolicy {
			minimum_relay: bitcoin::FeeRate::from_sat_per_vb(100).unwrap(), ..policy
		}.check(&vtxo, &funding, BlockHeight::new(131)).is_err());
		assert!(ark::exit_policy::FundedExitPolicy {
			claim_fee: amount, ..policy
		}.check(&vtxo, &funding, BlockHeight::new(131)).is_err());
	}
	let board = vtxo.transactions().next().ok_or("missing exit")?.tx;
	let final_tx = vtxo.transactions().last().ok_or("missing final exit")?.tx;
	let mut cpfp = make_tx(OutPoint::new(board.compute_txid(), 1), Amount::from_sat(330), Sequence::MAX);
	cpfp.input[0].witness = Witness::new(); // P2A, deliberately signature-free.
	if funded {
		let outsider = Keypair::from_secret_key(&ark::SECP, &SecretKey::from_slice(&[9; 32])?);
		cpfp.output[0].script_pubkey = ScriptBuf::new_p2tr(&ark::SECP, outsider.x_only_public_key().0, None);
	}
	let mut claim = make_tx(vtxo.point(),
		vtxo.amount() - Amount::from_sat(700), Sequence(6));
	let clause = DelayedSignClause { pubkey: claim_key.public_key(), block_delta: BlockDelta::new(6) };
	let script = clause.tapscript();
	let hash = unified::digest(&claim, 0, &[final_tx.output[vtxo.point().vout as usize].clone()], unified::ALL,
		Execution { script_type: 3, script_code: None, annex: None,
			leaf: Some((bitcoin::TapLeafHash::from_script(&script, bitcoin::taproot::LeafVersion::TapScript), u32::MAX)) })?;
	let sig = ark::SECP.sign_schnorr(&hash.into(), &claim_key);
	claim.input[0].witness = clause.witness(&sig, &clause.control_block(&vtxo));
	println!("{}", json!({"key": serialize_hex(&key_tx), "legacy": serialize_hex(&legacy),
		"board": serialize_hex(&board), "cpfp": serialize_hex(&cpfp), "claim": serialize_hex(&claim),
		"recovery_parents": vtxo.transactions().map(|t| serialize_hex(&t.tx)).collect::<Vec<_>>() }));
	Ok(())
}
