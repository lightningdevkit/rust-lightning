use crate::sign::{ChannelSigner, SignerProvider};
use core::ops::Deref;

pub(crate) enum ChannelSignerType<SP: Deref>
where
	SP::Target: SignerProvider,
{
	// in practice, this will only ever be an EcdsaChannelSigner (specifically, Writeable)
	Ecdsa(<SP::Target as SignerProvider>::EcdsaSigner),
	#[cfg(taproot)]
	Taproot(<SP::Target as SignerProvider>::TaprootSigner),
}

impl<SP: Deref> ChannelSignerType<SP>
where
	SP::Target: SignerProvider,
{
	pub(crate) fn as_ref(&self) -> &dyn ChannelSigner {
		match self {
			ChannelSignerType::Ecdsa(ecs) => ecs,
			#[cfg(taproot)]
			ChannelSignerType::Taproot(tcs) => tcs,
		}
	}

	pub(crate) fn as_mut(&mut self) -> &mut dyn ChannelSigner {
		match self {
			ChannelSignerType::Ecdsa(ecs) => ecs,
			#[cfg(taproot)]
			ChannelSignerType::Taproot(tcs) => tcs,
		}
	}

	#[allow(unused)]
	pub(crate) fn as_ecdsa(&self) -> Option<&<SP::Target as SignerProvider>::EcdsaSigner> {
		match self {
			ChannelSignerType::Ecdsa(ecs) => Some(ecs),
			_ => None,
		}
	}

	#[allow(unused)]
	pub(crate) fn as_mut_ecdsa(
		&mut self,
	) -> Option<&mut <SP::Target as SignerProvider>::EcdsaSigner> {
		match self {
			ChannelSignerType::Ecdsa(ecs) => Some(ecs),
			_ => None,
		}
	}
}
