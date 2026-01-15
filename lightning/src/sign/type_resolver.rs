use crate::sign::{ChannelSigner, SignerProvider};

pub(crate) enum ChannelSignerType<SP: SignerProvider> {
	// in practice, this will only ever be an EcdsaChannelSigner (specifically, Writeable)
	Ecdsa(SP::EcdsaSigner),
	#[cfg(taproot)]
	#[allow(unused)]
	Taproot(SP::TaprootSigner),
}

#[cfg(test)]
impl<SP: SignerProvider> std::fmt::Debug for ChannelSignerType<SP> {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.debug_struct("ChannelSignerType").finish()
	}
}

impl<SP: SignerProvider> ChannelSignerType<SP> {
	pub(crate) fn as_ref(&self) -> &dyn ChannelSigner {
		match self {
			ChannelSignerType::Ecdsa(ecs) => ecs,
			#[cfg(taproot)]
			#[allow(unused)]
			ChannelSignerType::Taproot(tcs) => tcs,
		}
	}

	#[allow(unused)]
	pub(crate) fn as_ecdsa(&self) -> Option<&SP::EcdsaSigner> {
		match self {
			ChannelSignerType::Ecdsa(ecs) => Some(ecs),
			_ => None,
		}
	}

	#[allow(unused)]
	pub(crate) fn as_mut_ecdsa(&mut self) -> Option<&mut SP::EcdsaSigner> {
		match self {
			ChannelSignerType::Ecdsa(ecs) => Some(ecs),
			_ => None,
		}
	}
}
