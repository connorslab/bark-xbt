//! Explicit unified signer for Bark's `tr(key)` BDK wallets.
//! Unsupported descriptors fail closed; there is no call to BDK's legacy signer.

use bdk_wallet::{KeychainKind, Wallet};
use bdk_wallet::miniscript::descriptor::DescriptorSecretKey;
use bitcoin::key::TapTweak;
use bitcoin::secp256k1::{Keypair, Secp256k1};
use bitcoin::{Psbt, ScriptBuf, Witness};

use crate::unified::{self, Execution};

#[derive(Debug, thiserror::Error)]
pub enum Error {
	#[error("missing or conflicting previous output")]
	Prevout,
	#[error("unsupported wallet input or signature mode")]
	Unsupported,
	#[error(transparent)]
	Digest(#[from] unified::Error),
}

pub fn sign(wallet: &Wallet, psbt: &mut Psbt) -> Result<bool, Error> {
	if psbt.inputs.len() != psbt.unsigned_tx.input.len() { return Err(Error::Prevout); }
	let secp = Secp256k1::new();
	let mut keys = wallet.get_signers(KeychainKind::External).as_key_map(&secp);
	keys.extend(wallet.get_signers(KeychainKind::Internal).as_key_map(&secp));
	let prevouts = psbt.inputs.iter().zip(&psbt.unsigned_tx.input).map(|(p, vin)| {
		let out = p.witness_utxo.clone().ok_or(Error::Prevout)?;
		if let Some(tx) = &p.non_witness_utxo {
			if tx.compute_txid() != vin.previous_output.txid
				|| tx.output.get(vin.previous_output.vout as usize) != Some(&out) {
				return Err(Error::Prevout);
			}
		}
		Ok(out)
	}).collect::<Result<Vec<_>, Error>>()?;
	// Work on a copy: any error leaves the caller's PSBT untouched.
	let mut result = psbt.clone();
	for (idx, input) in result.inputs.iter_mut().enumerate() {
		if input.sighash_type.is_some_and(|s| s.to_u32() != u32::from(unified::ALL)) {
			return Err(Error::Unsupported);
		}
		if let Some(witness) = &input.final_script_witness {
			if prevouts[idx].script_pubkey == ScriptBuf::new_p2a() && witness.is_empty() {
				continue;
			}
			// Foreign exit inputs are signed by the Ark signer. Check all
			// signature-sized stack elements, excluding script/control block.
			if !prevouts[idx].script_pubkey.is_p2tr() { return Err(Error::Unsupported); }
			let stack = witness.iter().collect::<Vec<_>>();
			// Annexes are not produced by our wallet and require separate parsing.
			if stack.len() == 2 || stack.last().is_some_and(|s| s.first() == Some(&0x50)) {
				return Err(Error::Unsupported);
			}
			let stack = if stack.len() >= 3 { &stack[..stack.len()-2] } else { &stack[..] };
			if !stack.iter().any(|s| s.len() == 65 && s[64] == unified::ALL)
				|| stack.iter().any(|s| s.len() == 64
				|| (s.len() == 65 && s[64] != unified::ALL)) {
				return Err(Error::Unsupported);
			}
			continue;
		}
		if input.sighash_type.is_some_and(|s| s.to_u32() != u32::from(unified::ALL)) {
			return Err(Error::Unsupported);
		}
		let internal = input.tap_internal_key.ok_or(Error::Unsupported)?;
		if input.tap_merkle_root.is_some() || !input.tap_scripts.is_empty() {
			return Err(Error::Unsupported);
		}
		if prevouts[idx].script_pubkey != ScriptBuf::new_p2tr(&secp, internal, None) {
			return Err(Error::Prevout);
		}
		let (_, (fingerprint, path)) = input.tap_key_origins.get(&internal).ok_or(Error::Unsupported)?;
		let mut keypair = None;
		for secret in keys.values() {
			let xkey = match secret { DescriptorSecretKey::XPrv(k) => k, _ => continue };
			let (expected, prefix) = match &xkey.origin {
				Some((fp, p)) => (*fp, p.as_ref()),
				None => (xkey.xkey.fingerprint(&secp), &[][..]),
			};
			let full = path.as_ref();
			if *fingerprint != expected || !full.starts_with(prefix) { continue; }
			let derived = xkey.xkey.derive_priv(&secp, &&full[prefix.len()..])
				.map_err(|_| Error::Unsupported)?;
			let pair = Keypair::from_secret_key(&secp, &derived.private_key);
			if pair.x_only_public_key().0 == internal { keypair = Some(pair); break; }
		}
		let pair = keypair.ok_or(Error::Unsupported)?.tap_tweak(&secp, None).to_keypair();
		let hash = unified::digest(&psbt.unsigned_tx, idx, &prevouts, unified::ALL,
			Execution { script_type: 2, script_code: None, annex: None, leaf: None })?;
		let sig = secp.sign_schnorr(&hash.into(), &pair);
		input.sighash_type = Some(bitcoin::psbt::PsbtSighashType::from_u32(u32::from(unified::ALL)));
		input.final_script_witness = Some(Witness::from_slice(&[unified::signature(&sig)]));
	}
	*psbt = result;
	Ok(true)
}
