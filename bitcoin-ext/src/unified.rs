//! Blake2b's opt-in signature digest. Never substitutes a legacy digest.
//!
//! Consensus reference: Knots v29.4.2.knots20260508rc2,
//! doc/unified-sighash.md. Transaction ids and Taproot tweaks are unchanged.

use std::borrow::Borrow;

use bitcoin::consensus::serialize;
use bitcoin::hashes::{sha256, Hash};
use bitcoin::secp256k1::schnorr;
use bitcoin::sighash::{Annex, Prevouts, SighashCache, TapSighashType};
use bitcoin::{Script, TapLeafHash, TapSighash, Transaction, TxOut};

pub const ALL: u8 = 0x21;
pub const SIGNATURE_SIZE: usize = 65;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Error {
	#[error("unified signing requires every prevout in input order")]
	Prevouts,
	#[error("signature input index is outside the transaction")]
	Input,
	#[error("unsupported unified signature hash type")]
	HashType,
	#[error("SIGHASH_SINGLE has no corresponding output")]
	Single,
	#[error("inconsistent script execution context")]
	Context,
}

/// Execution context is explicit: key path, script path and segwit must not alias.
pub struct Execution<'a> {
	pub script_type: u8,
	pub script_code: Option<&'a Script>,
	pub annex: Option<&'a [u8]>,
	pub leaf: Option<(TapLeafHash, u32)>,
}

/// Compute the exact Knots digest, including its five-byte locktime field.
pub fn digest(
	tx: &Transaction, input: usize, prevouts: &[TxOut], hash_type: u8,
	exec: Execution<'_>,
) -> Result<TapSighash, Error> {
	if input >= tx.input.len() { return Err(Error::Input); }
	if prevouts.len() != tx.input.len() { return Err(Error::Prevouts); }
	if !matches!(hash_type, 0x21 | 0x22 | 0x23 | 0xa1 | 0xa2 | 0xa3) {
		return Err(Error::HashType);
	}
	if exec.script_type > 3
		|| (exec.script_type < 2) != exec.script_code.is_some()
		|| (exec.script_type == 3) != exec.leaf.is_some()
		|| (exec.script_type < 2 && exec.annex.is_some())
		|| exec.annex.is_some_and(|a| a.first() != Some(&0x50)) {
		return Err(Error::Context);
	}
	let base = hash_type & 0x1f;
	let acp = hash_type & 0x80 != 0;
	let mut msg = vec![0, hash_type];
	msg.extend(serialize(&tx.version));
	msg.extend(serialize(&tx.lock_time));
	msg.push(0);
	if !acp {
		let mut outpoints = Vec::new();
		let mut amounts = Vec::new();
		let mut scripts = Vec::new();
		let mut sequences = Vec::new();
		for (vin, prevout) in tx.input.iter().zip(prevouts) {
			outpoints.extend(serialize(&vin.previous_output));
			amounts.extend(prevout.value.to_sat().to_le_bytes());
			scripts.extend(serialize(&prevout.script_pubkey));
			sequences.extend(serialize(&vin.sequence));
		}
		for bytes in [&outpoints, &amounts, &scripts, &sequences] {
			msg.extend(sha256::Hash::hash(bytes).to_byte_array());
		}
	}
	if base == 1 {
		let outputs: Vec<u8> = tx.output.iter().flat_map(serialize).collect();
		msg.extend(sha256::Hash::hash(&outputs).to_byte_array());
	}
	msg.push(exec.script_type);
	if acp {
		msg.extend(serialize(&tx.input[input].previous_output));
		msg.extend(serialize(&prevouts[input]));
		msg.extend(serialize(&tx.input[input].sequence));
	} else {
		msg.extend(u32::try_from(input).map_err(|_| Error::Input)?.to_le_bytes());
	}
	if let Some(script) = exec.script_code { msg.extend(serialize(script)); }
	if exec.script_type >= 2 {
		msg.push(u8::from(exec.annex.is_some()));
		if let Some(annex) = exec.annex {
			let mut encoded = serialize(&bitcoin::VarInt(annex.len() as u64));
			encoded.extend(annex);
			msg.extend(sha256::Hash::hash(&encoded).to_byte_array());
		}
	}
	if base == 3 {
		let output = tx.output.get(input).ok_or(Error::Single)?;
		msg.extend(sha256::Hash::hash(&serialize(output)).to_byte_array());
	}
	if let Some((leaf, separator)) = exec.leaf {
		msg.extend(leaf.to_byte_array());
		msg.push(0);
		msg.extend(separator.to_le_bytes());
	}
	let tag = sha256::Hash::hash(b"UnifiedSighash").to_byte_array();
	let mut tagged = tag.to_vec();
	tagged.extend(tag);
	tagged.extend(msg);
	Ok(TapSighash::from_byte_array(sha256::Hash::hash(&tagged).to_byte_array()))
}

/// Raw aggregate signatures remain 64 bytes; their transaction witnesses never do.
pub fn signature(sig: &schnorr::Signature) -> [u8; SIGNATURE_SIZE] {
	let mut ret = [0; SIGNATURE_SIZE];
	ret[..64].copy_from_slice(sig.as_ref());
	ret[64] = ALL;
	ret
}

pub trait UnifiedSighash {
	fn unified_taproot_signature_hash<T: Borrow<TxOut>>(
		&mut self, input: usize, prevouts: &Prevouts<T>, annex: Option<Annex<'_>>,
		leaf: Option<(TapLeafHash, u32)>, selector: TapSighashType,
	) -> Result<TapSighash, Error>;

	fn unified_taproot_key_spend_signature_hash<T: Borrow<TxOut>>(
		&mut self, input: usize, prevouts: &Prevouts<T>, selector: TapSighashType,
	) -> Result<TapSighash, Error> {
		self.unified_taproot_signature_hash(input, prevouts, None, None, selector)
	}

	fn unified_taproot_script_spend_signature_hash<T: Borrow<TxOut>>(
		&mut self, input: usize, prevouts: &Prevouts<T>, leaf: TapLeafHash,
		selector: TapSighashType,
	) -> Result<TapSighash, Error> {
		self.unified_taproot_signature_hash(input, prevouts, None, Some((leaf, u32::MAX)), selector)
	}
}

impl<R: Borrow<Transaction>> UnifiedSighash for SighashCache<R> {
	fn unified_taproot_signature_hash<T: Borrow<TxOut>>(
		&mut self, input: usize, prevouts: &Prevouts<T>, annex: Option<Annex<'_>>,
		leaf: Option<(TapLeafHash, u32)>, selector: TapSighashType,
	) -> Result<TapSighash, Error> {
		// Ark's witnesses commit to ALL. Reject other selectors rather than
		// silently producing a digest inconsistent with the witness suffix.
		if !matches!(selector, TapSighashType::Default | TapSighashType::All) {
			return Err(Error::HashType);
		}
		let prevouts = match prevouts {
			Prevouts::All(p) => p.iter().map(|p| p.borrow().clone()).collect::<Vec<_>>(),
			_ => return Err(Error::Prevouts),
		};
		digest(self.transaction(), input, &prevouts, ALL, Execution {
			script_type: if leaf.is_some() { 3 } else { 2 },
			script_code: None, annex: annex.as_ref().map(|a| a.as_bytes()), leaf,
		})
	}
}
