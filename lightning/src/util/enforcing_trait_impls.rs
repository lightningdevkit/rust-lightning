use ln::chan_utils::{HTLCOutputInCommitment, TxCreationKeys, ChannelPublicKeys, LocalCommitmentTransaction};
use ln::{chan_utils, msgs};
use chain::keysinterface::{ChannelKeys, InMemoryChannelKeys};

use std::cmp;
use std::sync::{Mutex, Arc};

use bitcoin::blockdata::transaction::Transaction;
use bitcoin::util::bip143;

use bitcoin::secp256k1;
use bitcoin::secp256k1::key::{SecretKey, PublicKey};
use bitcoin::secp256k1::{Secp256k1, Signature};
use util::ser::{Writeable, Writer, Readable};
use std::io::Error;
use ln::msgs::DecodeError;

/// Enforces some rules on ChannelKeys calls. Eventually we will probably want to expose a variant
/// of this which would essentially be what you'd want to run on a hardware wallet.
#[derive(Clone)]
pub struct EnforcingChannelKeys {
	pub inner: InMemoryChannelKeys,
	commitment_number_obscure_and_last: Arc<Mutex<(Option<u64>, u64)>>,
}

impl EnforcingChannelKeys {
	pub fn new(inner: InMemoryChannelKeys) -> Self {
		Self {
			inner,
			commitment_number_obscure_and_last: Arc::new(Mutex::new((None, 0))),
		}
	}
}

impl EnforcingChannelKeys {
	fn check_keys<T: secp256k1::Signing + secp256k1::Verification>(&self, secp_ctx: &Secp256k1<T>,
	                                                               keys: &TxCreationKeys) {
		let remote_points = self.inner.remote_channel_pubkeys.as_ref().unwrap();

		let keys_expected = TxCreationKeys::new(secp_ctx,
		                                        &keys.per_commitment_point,
		                                        &remote_points.delayed_payment_basepoint,
		                                        &remote_points.htlc_basepoint,
		                                        &self.inner.pubkeys().revocation_basepoint,
		                                        &self.inner.pubkeys().htlc_basepoint).unwrap();
		if keys != &keys_expected { panic!("derived different per-tx keys") }
	}
}

impl ChannelKeys for EnforcingChannelKeys {
	fn commitment_seed(&self) -> &[u8; 32] { self.inner.commitment_seed() }
	fn pubkeys<'a>(&'a self) -> &'a ChannelPublicKeys { self.inner.pubkeys() }
	fn key_derivation_params(&self) -> (u64, u64) { self.inner.key_derivation_params() }

	fn sign_remote_commitment<T: secp256k1::Signing + secp256k1::Verification>(&self, feerate_per_kw: u64, commitment_tx: &Transaction, keys: &TxCreationKeys, htlcs: &[&HTLCOutputInCommitment], to_self_delay: u16, secp_ctx: &Secp256k1<T>) -> Result<(Signature, Vec<Signature>), ()> {
		if commitment_tx.input.len() != 1 { panic!("lightning commitment transactions have a single input"); }
		self.check_keys(secp_ctx, keys);
		let obscured_commitment_transaction_number = (commitment_tx.lock_time & 0xffffff) as u64 | ((commitment_tx.input[0].sequence as u64 & 0xffffff) << 3*8);

		{
			let mut commitment_data = self.commitment_number_obscure_and_last.lock().unwrap();
			if commitment_data.0.is_none() {
				commitment_data.0 = Some(obscured_commitment_transaction_number ^ commitment_data.1);
			}
			let commitment_number = obscured_commitment_transaction_number ^ commitment_data.0.unwrap();
			assert!(commitment_number == commitment_data.1 || commitment_number == commitment_data.1 + 1);
			commitment_data.1 = cmp::max(commitment_number, commitment_data.1)
		}

		Ok(self.inner.sign_remote_commitment(feerate_per_kw, commitment_tx, keys, htlcs, to_self_delay, secp_ctx).unwrap())
	}

	fn sign_local_commitment<T: secp256k1::Signing + secp256k1::Verification>(&self, local_commitment_tx: &LocalCommitmentTransaction, secp_ctx: &Secp256k1<T>) -> Result<Signature, ()> {
		Ok(self.inner.sign_local_commitment(local_commitment_tx, secp_ctx).unwrap())
	}

	#[cfg(test)]
	fn unsafe_sign_local_commitment<T: secp256k1::Signing + secp256k1::Verification>(&self, local_commitment_tx: &LocalCommitmentTransaction, secp_ctx: &Secp256k1<T>) -> Result<Signature, ()> {
		Ok(self.inner.unsafe_sign_local_commitment(local_commitment_tx, secp_ctx).unwrap())
	}

	fn sign_local_commitment_htlc_transactions<T: secp256k1::Signing + secp256k1::Verification>(&self, local_commitment_tx: &LocalCommitmentTransaction, local_csv: u16, secp_ctx: &Secp256k1<T>) -> Result<Vec<Option<Signature>>, ()> {
		let commitment_txid = local_commitment_tx.txid();

		for this_htlc in local_commitment_tx.per_htlc.iter() {
			if this_htlc.0.transaction_output_index.is_some() {
				let htlc_tx = chan_utils::build_htlc_transaction(&commitment_txid, local_commitment_tx.feerate_per_kw, local_csv, &this_htlc.0, &local_commitment_tx.local_keys.a_delayed_payment_key, &local_commitment_tx.local_keys.revocation_key);

				let htlc_redeemscript = chan_utils::get_htlc_redeemscript(&this_htlc.0, &local_commitment_tx.local_keys);

				let sighash = hash_to_message!(&bip143::SighashComponents::new(&htlc_tx).sighash_all(&htlc_tx.input[0], &htlc_redeemscript, this_htlc.0.amount_msat / 1000)[..]);
				secp_ctx.verify(&sighash, this_htlc.1.as_ref().unwrap(), &local_commitment_tx.local_keys.b_htlc_key).unwrap();
			}
		}

		Ok(self.inner.sign_local_commitment_htlc_transactions(local_commitment_tx, local_csv, secp_ctx).unwrap())
	}

	fn sign_justice_transaction<T: secp256k1::Signing + secp256k1::Verification>(&self, justice_tx: &Transaction, input: usize, amount: u64, per_commitment_key: &SecretKey, htlc: &Option<HTLCOutputInCommitment>, on_remote_tx_csv: u16, secp_ctx: &Secp256k1<T>) -> Result<Signature, ()> {
		Ok(self.inner.sign_justice_transaction(justice_tx, input, amount, per_commitment_key, htlc, on_remote_tx_csv, secp_ctx).unwrap())
	}

	fn sign_remote_htlc_transaction<T: secp256k1::Signing + secp256k1::Verification>(&self, htlc_tx: &Transaction, input: usize, amount: u64, per_commitment_point: &PublicKey, htlc: &HTLCOutputInCommitment, secp_ctx: &Secp256k1<T>) -> Result<Signature, ()> {
		Ok(self.inner.sign_remote_htlc_transaction(htlc_tx, input, amount, per_commitment_point, htlc, secp_ctx).unwrap())
	}

	fn sign_closing_transaction<T: secp256k1::Signing>(&self, closing_tx: &Transaction, secp_ctx: &Secp256k1<T>) -> Result<Signature, ()> {
		Ok(self.inner.sign_closing_transaction(closing_tx, secp_ctx).unwrap())
	}

	fn sign_channel_announcement<T: secp256k1::Signing>(&self, msg: &msgs::UnsignedChannelAnnouncement, secp_ctx: &Secp256k1<T>) -> Result<Signature, ()> {
		self.inner.sign_channel_announcement(msg, secp_ctx)
	}

	fn set_remote_channel_pubkeys(&mut self, channel_pubkeys: &ChannelPublicKeys) {
		self.inner.set_remote_channel_pubkeys(channel_pubkeys)
	}
}

impl Writeable for EnforcingChannelKeys {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), Error> {
		self.inner.write(writer)?;
		let (obscure, last) = *self.commitment_number_obscure_and_last.lock().unwrap();
		obscure.write(writer)?;
		last.write(writer)?;
		Ok(())
	}
}

impl Readable for EnforcingChannelKeys {
	fn read<R: ::std::io::Read>(reader: &mut R) -> Result<Self, DecodeError> {
		let inner = Readable::read(reader)?;
		let obscure_and_last = Readable::read(reader)?;
		Ok(EnforcingChannelKeys {
			inner: inner,
			commitment_number_obscure_and_last: Arc::new(Mutex::new(obscure_and_last))
		})
	}
}
