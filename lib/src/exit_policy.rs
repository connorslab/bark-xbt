//! Checks for a fully signed, funded recovery path under a specified relay policy.
//! These checks are admission checks, not a promise of future block inclusion.

use bitcoin::{Amount, FeeRate, Transaction};
use bitcoin_ext::{BlockDelta, BlockHeight};

use crate::{Vtxo, VtxoPolicy};
use crate::vtxo::Full;

#[derive(Debug, Clone, Copy)]
pub struct FundedExitPolicy {
	pub minimum_relay: FeeRate,
	pub dust_relay: FeeRate,
	/// Additional blocks beyond one confirmation per ancestor and the CSV delay.
	pub confirmation_margin: BlockDelta,
	/// Reserve for the final claim, deducted from the recovered output.
	pub claim_fee: Amount,
}

impl FundedExitPolicy {
	/// Check an ordinary pubkey balance before accepting it as recoverable.
	/// HTLC recovery has extra conditions and needs separate checks.
	pub fn check(
		&self,
		vtxo: &Vtxo<Full>,
		funding: &Transaction,
		tip: BlockHeight,
	) -> Result<(), String> {
		if !matches!(vtxo.policy(), VtxoPolicy::Pubkey(..)) {
			return Err("funded recovery check only supports ordinary pubkey balances".into());
		}
		if self.minimum_relay.to_sat_per_kwu() == 0 || self.confirmation_margin.to_u16() == 0
			|| self.dust_relay.to_sat_per_kwu() > 25_000_000 || self.claim_fee == Amount::ZERO {
			return Err("invalid exit policy bounds".into());
		}
		vtxo.validate(funding).map_err(|e| e.to_string())?;
		let steps = u32::try_from(vtxo.genesis.items.len()).map_err(|_| "exit depth overflow")?;
		let deadline = tip.to_u32().checked_add(steps)
			.and_then(|h| h.checked_add(u32::from(vtxo.exit_delta().to_u16())))
			.and_then(|h| h.checked_add(u32::from(self.confirmation_margin.to_u16())))
			.ok_or("exit deadline overflow")?;
		if deadline >= vtxo.expiry_height().to_u32() {
			return Err("insufficient time to complete recovery before expiry".into());
		}
		let mut prev = funding.output.get(vtxo.chain_anchor().vout as usize)
			.ok_or("missing funding output")?.clone();
		for item in vtxo.transactions() {
			let total = item.tx.output.iter().try_fold(Amount::ZERO, |sum, o| {
				if o.value < o.script_pubkey.minimal_non_dust_custom(self.dust_relay) { return None; }
				sum.checked_add(o.value)
			}).ok_or("dust output or output value overflow in recovery path")?;
			let fee = prev.value.checked_sub(total).ok_or("unfunded recovery transaction")?;
			let required = (item.tx.vsize() as u64).checked_mul(4)
				.and_then(|w| w.checked_mul(self.minimum_relay.to_sat_per_kwu()))
				.and_then(|v| v.checked_add(999)).map(|v| v / 1000)
				.ok_or("relay fee overflow")?;
			if fee.to_sat() < required { return Err("recovery parent is below its individual relay floor".into()); }
			prev = item.tx.output.get(item.output_idx).ok_or("invalid recovery output index")?.clone();
		}
		let claim_floor = prev.script_pubkey.minimal_non_dust_custom(self.dust_relay);
		if prev.value.checked_sub(self.claim_fee).is_none_or(|a| a < claim_floor) {
			return Err("insufficient balance for a non-dust final claim after fees".into());
		}
		Ok(())
	}
}
