use ln::chan_utils::{HTLCOutputInCommitment, TxCreationKeys, ChannelPublicKeys};
use ln::msgs;
use chain::keysinterface::{ChannelKeys, InMemoryChannelKeys};

use std::cmp;
use std::sync::{Mutex, Arc};

use bitcoin::blockdata::transaction::Transaction;

use secp256k1;
use secp256k1::key::{SecretKey, PublicKey};
use secp256k1::{Secp256k1, Signature};
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
		let revocation_base = PublicKey::from_secret_key(secp_ctx, &self.inner.revocation_base_key());
		let payment_base = PublicKey::from_secret_key(secp_ctx, &self.inner.payment_base_key());
		let htlc_base = PublicKey::from_secret_key(secp_ctx, &self.inner.htlc_base_key());

		let remote_points = self.inner.remote_channel_pubkeys.as_ref().unwrap();

		let keys_expected = TxCreationKeys::new(secp_ctx,
		                                        &keys.per_commitment_point,
		                                        &remote_points.delayed_payment_basepoint,
		                                        &remote_points.htlc_basepoint,
		                                        &revocation_base,
		                                        &payment_base,
		                                        &htlc_base).unwrap();
		if keys != &keys_expected { panic!("derived different per-tx keys") }
	}
}

impl ChannelKeys for EnforcingChannelKeys {
	fn funding_key(&self) -> &SecretKey { self.inner.funding_key() }
	fn revocation_base_key(&self) -> &SecretKey { self.inner.revocation_base_key() }
	fn payment_base_key(&self) -> &SecretKey { self.inner.payment_base_key() }
	fn delayed_payment_base_key(&self) -> &SecretKey { self.inner.delayed_payment_base_key() }
	fn htlc_base_key(&self) -> &SecretKey { self.inner.htlc_base_key() }
	fn commitment_seed(&self) -> &[u8; 32] { self.inner.commitment_seed() }
	fn pubkeys<'a>(&'a self) -> &'a ChannelPublicKeys { self.inner.pubkeys() }

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
