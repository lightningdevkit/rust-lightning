use crate::sign::{ChannelSigner, EcdsaChannelSigner};

pub(crate) enum ChannelSignerType<ECS: EcdsaChannelSigner> {
	// in practice, this will only ever be an EcdsaChannelSigner (specifically, Writeable)
	Ecdsa(ECS)
}

impl<ECS: EcdsaChannelSigner> ChannelSignerType<ECS>{
	pub(crate) fn as_ref(&self) -> &dyn ChannelSigner {
		match self {
			ChannelSignerType::Ecdsa(ecs) => ecs
		}
	}

	pub(crate) fn as_mut(&mut self) -> &mut dyn ChannelSigner {
		match self {
			ChannelSignerType::Ecdsa(ecs) => ecs
		}
	}

	pub(crate) fn as_ecdsa(&self) -> Option<&ECS> {
		match self {
			ChannelSignerType::Ecdsa(ecs) => Some(ecs)
		}
	}

	#[allow(unused)]
	pub(crate) fn as_mut_ecdsa(&mut self) -> Option<&mut ECS> {
		match self {
			ChannelSignerType::Ecdsa(ecs) => Some(ecs)
		}
	}
}
