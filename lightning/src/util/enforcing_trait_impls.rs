use chain::keysinterface::{ChannelKeys, InMemoryChannelKeys};

use secp256k1::key::SecretKey;

/// Enforces some rules on ChannelKeys calls. Eventually we will probably want to expose a variant
/// of this which would essentially be what you'd want to run on a hardware wallet.
pub struct EnforcingChannelKeys {
	pub inner: InMemoryChannelKeys,
}

impl EnforcingChannelKeys {
	pub fn new(inner: InMemoryChannelKeys) -> Self {
		Self {
			inner,
		}
	}
}
impl ChannelKeys for EnforcingChannelKeys {
	fn funding_key(&self) -> &SecretKey { self.inner.funding_key() }
	fn revocation_base_key(&self) -> &SecretKey { self.inner.revocation_base_key() }
	fn payment_base_key(&self) -> &SecretKey { self.inner.payment_base_key() }
	fn delayed_payment_base_key(&self) -> &SecretKey { self.inner.delayed_payment_base_key() }
	fn htlc_base_key(&self) -> &SecretKey { self.inner.htlc_base_key() }
	fn commitment_seed(&self) -> &[u8; 32] { self.inner.commitment_seed() }
}

impl_writeable!(EnforcingChannelKeys, 0, {
	inner
});
