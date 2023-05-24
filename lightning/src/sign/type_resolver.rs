use crate::sign::{ChannelSigner, EcdsaChannelSigner};

pub(crate) enum ChannelSignerType<ECS: ChannelSigner> {
	// in practice, this will only ever be an EcdsaChannelSigner
	Ecdsa(ECS)
}

impl<ECS: EcdsaChannelSigner> ChannelSignerType<ECS> {
	pub(crate) fn as_ref(&self) -> &dyn ChannelSigner {
		match self {
			ChannelSignerType::Ecdsa(cs) => cs.as_channel_signer()
		}
	}

	pub(crate) fn as_mut(&mut self) -> &mut dyn ChannelSigner {
		match self {
			ChannelSignerType::Ecdsa(cs) => cs.as_mut_channel_signer()
		}
	}

	pub(crate) fn as_ecdsa(&self) -> Option<&ECS> {
		match self {
			ChannelSignerType::Ecdsa(ecs) => Some(ecs),
			#[cfg(taproot)]
			_ => None
		}
	}

	pub(crate) fn as_mut_ecdsa(&mut self) -> Option<&mut ECS> {
		match self {
			ChannelSignerType::Ecdsa(ecs) => Some(ecs),
			#[cfg(taproot)]
			_ => None
		}
	}
}

/// Helper trait for accessing common channel signer methods between different implementations
pub trait AsChannelSigner {
	fn as_channel_signer(&self) -> &dyn ChannelSigner;
	fn as_mut_channel_signer(&mut self) -> &mut dyn ChannelSigner;
}

impl<CS: ChannelSigner> AsChannelSigner for CS {
	fn as_channel_signer(&self) -> &dyn ChannelSigner {
		self
	}

	fn as_mut_channel_signer(&mut self) -> &mut dyn ChannelSigner {
		self
	}
}
