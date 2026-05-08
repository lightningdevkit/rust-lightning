//! Utilities for supporting custom peer-to-peer messages in LDK.
//!
//! [BOLT 1] specifies a custom message type range for use with experimental or application-specific
//! messages. While a [`CustomMessageHandler`] can be defined to support more than one message type,
//! defining such a handler requires a significant amount of boilerplate and can be error prone.
//!
//! This crate provides the [`composite_custom_message_handler`] macro for easily composing
//! pre-defined custom message handlers into one handler. The resulting handler can be further
//! composed with other custom message handlers using the same macro.
//!
//! The following example demonstrates defining a `FooBarHandler` to compose separate handlers for
//! `Foo` and `Bar` messages, and further composing it with a handler for `Baz` messages.
//!
//!```
//! # fn main() {} // Avoid #[macro_export] generating an in-function warning
//! # extern crate bitcoin;
//! extern crate lightning;
//! #[macro_use]
//! extern crate lightning_custom_message;
//!
//! # use bitcoin::secp256k1::PublicKey;
//! # use lightning::io;
//! # use lightning::ln::msgs::{DecodeError, Init, LightningError};
//! use lightning::ln::peer_handler::CustomMessageHandler;
//! use lightning::ln::wire::{CustomMessageReader, self};
//! # use lightning::types::features::{InitFeatures, NodeFeatures};
//! use lightning::util::ser::{LengthLimitedRead, Writeable};
//! # use lightning::util::ser::Writer;
//!
//! // Assume that `FooHandler` and `BarHandler` are defined in one crate and `BazHandler` is
//! // defined in another crate, handling messages `Foo`, `Bar`, and `Baz`, respectively.
//!
//! #[derive(Debug)]
//! pub struct Foo;
//!
//! macro_rules! foo_type_id {
//!     () => { 32768 }
//! }
//!
//! impl wire::Type for Foo {
//!     fn type_id(&self) -> u16 { foo_type_id!() }
//! }
//! impl Writeable for Foo {
//!     // ...
//! #     fn write<W: Writer>(&self, _: &mut W) -> Result<(), io::Error> {
//! #         unimplemented!()
//! #     }
//! }
//!
//! pub struct FooHandler;
//!
//! impl CustomMessageReader for FooHandler {
//!     // ...
//! #     type CustomMessage = Foo;
//! #     fn read<R: LengthLimitedRead>(
//! #         &self, _message_type: u16, _buffer: &mut R
//! #     ) -> Result<Option<Self::CustomMessage>, DecodeError> {
//! #         unimplemented!()
//! #     }
//! }
//! impl CustomMessageHandler for FooHandler {
//!     // ...
//! #     fn handle_custom_message(
//! #         &self, _msg: Self::CustomMessage, _sender_node_id: PublicKey
//! #     ) -> Result<(), LightningError> {
//! #         unimplemented!()
//! #     }
//! #     fn get_and_clear_pending_msg(&self) -> Vec<(PublicKey, Self::CustomMessage)> {
//! #         unimplemented!()
//! #     }
//! #     fn peer_disconnected(&self, _their_node_id: PublicKey) {
//! #         unimplemented!()
//! #     }
//! #     fn peer_connected(&self, _their_node_id: PublicKey, _msg: &Init, _inbound: bool) -> Result<(), ()> {
//! #         unimplemented!()
//! #     }
//! #     fn provided_node_features(&self) -> NodeFeatures {
//! #         unimplemented!()
//! #     }
//! #     fn provided_init_features(&self, _their_node_id: PublicKey) -> InitFeatures {
//! #         unimplemented!()
//! #     }
//! }
//!
//! #[derive(Debug)]
//! pub struct Bar;
//!
//! macro_rules! bar_type_id {
//!     () => { 32769 }
//! }
//!
//! impl wire::Type for Bar {
//!     fn type_id(&self) -> u16 { bar_type_id!() }
//! }
//! impl Writeable for Bar {
//!     // ...
//! #     fn write<W: Writer>(&self, _: &mut W) -> Result<(), io::Error> {
//! #         unimplemented!()
//! #     }
//! }
//!
//! pub struct BarHandler;
//!
//! impl CustomMessageReader for BarHandler {
//!     // ...
//! #     type CustomMessage = Bar;
//! #     fn read<R: LengthLimitedRead>(
//! #         &self, _message_type: u16, _buffer: &mut R
//! #     ) -> Result<Option<Self::CustomMessage>, DecodeError> {
//! #         unimplemented!()
//! #     }
//! }
//! impl CustomMessageHandler for BarHandler {
//!     // ...
//! #     fn handle_custom_message(
//! #         &self, _msg: Self::CustomMessage, _sender_node_id: PublicKey
//! #     ) -> Result<(), LightningError> {
//! #         unimplemented!()
//! #     }
//! #     fn get_and_clear_pending_msg(&self) -> Vec<(PublicKey, Self::CustomMessage)> {
//! #         unimplemented!()
//! #     }
//! #     fn peer_disconnected(&self, _their_node_id: PublicKey) {
//! #         unimplemented!()
//! #     }
//! #     fn peer_connected(&self, _their_node_id: PublicKey, _msg: &Init, _inbound: bool) -> Result<(), ()> {
//! #         unimplemented!()
//! #     }
//! #     fn provided_node_features(&self) -> NodeFeatures {
//! #         unimplemented!()
//! #     }
//! #     fn provided_init_features(&self, _their_node_id: PublicKey) -> InitFeatures {
//! #         unimplemented!()
//! #     }
//! }
//!
//! #[derive(Debug)]
//! pub struct Baz;
//!
//! macro_rules! baz_type_id {
//!     () => { 32770 }
//! }
//!
//! impl wire::Type for Baz {
//!     fn type_id(&self) -> u16 { baz_type_id!() }
//! }
//! impl Writeable for Baz {
//!     // ...
//! #     fn write<W: Writer>(&self, _: &mut W) -> Result<(), io::Error> {
//! #         unimplemented!()
//! #     }
//! }
//!
//! pub struct BazHandler;
//!
//! impl CustomMessageReader for BazHandler {
//!     // ...
//! #     type CustomMessage = Baz;
//! #     fn read<R: LengthLimitedRead>(
//! #         &self, _message_type: u16, _buffer: &mut R
//! #     ) -> Result<Option<Self::CustomMessage>, DecodeError> {
//! #         unimplemented!()
//! #     }
//! }
//! impl CustomMessageHandler for BazHandler {
//!     // ...
//! #     fn handle_custom_message(
//! #         &self, _msg: Self::CustomMessage, _sender_node_id: PublicKey
//! #     ) -> Result<(), LightningError> {
//! #         unimplemented!()
//! #     }
//! #     fn get_and_clear_pending_msg(&self) -> Vec<(PublicKey, Self::CustomMessage)> {
//! #         unimplemented!()
//! #     }
//! #     fn peer_disconnected(&self, _their_node_id: PublicKey) {
//! #         unimplemented!()
//! #     }
//! #     fn peer_connected(&self, _their_node_id: PublicKey, _msg: &Init, _inbound: bool) -> Result<(), ()> {
//! #         unimplemented!()
//! #     }
//! #     fn provided_node_features(&self) -> NodeFeatures {
//! #         unimplemented!()
//! #     }
//! #     fn provided_init_features(&self, _their_node_id: PublicKey) -> InitFeatures {
//! #         unimplemented!()
//! #     }
//! }
//!
//! // The first crate may define a handler composing `FooHandler` and `BarHandler` and export the
//! // corresponding message type ids as a macro to use in further composition.
//!
//! composite_custom_message_handler!(
//!     pub struct FooBarHandler {
//!         foo: FooHandler,
//!         bar: BarHandler,
//!     }
//!
//!     pub enum FooBarMessage {
//!         Foo(foo_type_id!()),
//!         Bar(bar_type_id!()),
//!     }
//! );
//!
//! #[macro_export]
//! macro_rules! foo_bar_type_ids {
//!     () => { foo_type_id!() | bar_type_id!() }
//! }
//!
//! // Another crate can then define a handler further composing `FooBarHandler` with `BazHandler`
//! // and similarly export the composition of message type ids as a macro.
//!
//! composite_custom_message_handler!(
//!     pub struct FooBarBazHandler {
//!         foo_bar: FooBarHandler,
//!         baz: BazHandler,
//!     }
//!
//!     pub enum FooBarBazMessage {
//!         FooBar(foo_bar_type_ids!()),
//!         Baz(baz_type_id!()),
//!     }
//! );
//!
//! #[macro_export]
//! macro_rules! foo_bar_baz_type_ids {
//!     () => { foo_bar_type_ids!() | baz_type_id!() }
//! }
//!```
//!
//! [BOLT 1]: https://github.com/lightning/bolts/blob/master/01-messaging.md
//! [`CustomMessageHandler`]: crate::lightning::ln::peer_handler::CustomMessageHandler

#![doc(test(no_crate_inject, attr(deny(warnings))))]

pub extern crate bitcoin;
pub extern crate lightning;

/// Defines a composite type implementing [`CustomMessageHandler`] (and therefore also implementing
/// [`CustomMessageReader`]), along with a corresponding enumerated custom message [`Type`], from
/// one or more previously defined custom message handlers.
///
/// Useful for parameterizing [`PeerManager`] with custom message handling for one or more sets of
/// custom messages. Message type ids may be given as a valid `match` pattern, including ranges,
/// though using OR-ed literal patterns is preferred in order to catch unreachable code for
/// conflicting handlers.
///
/// See [crate documentation] for example usage.
///
/// [`CustomMessageHandler`]: crate::lightning::ln::peer_handler::CustomMessageHandler
/// [`CustomMessageReader`]: crate::lightning::ln::wire::CustomMessageReader
/// [`Type`]: crate::lightning::ln::wire::Type
/// [`PeerManager`]: crate::lightning::ln::peer_handler::PeerManager
/// [crate documentation]: self
#[macro_export]
macro_rules! composite_custom_message_handler {
	(
		$handler_visibility:vis struct $handler:ident {
			$($field_visibility:vis $field:ident: $type:ty),* $(,)*
		}

		$message_visibility:vis enum $message:ident {
			$($variant:ident($pattern:pat)),* $(,)*
		}
	) => {
		#[allow(missing_docs)]
		$handler_visibility struct $handler {
			$(
				$field_visibility $field: $type,
			)*
		}

		#[allow(missing_docs)]
		#[derive(Debug)]
		$message_visibility enum $message {
			$(
				$variant(<$type as $crate::lightning::ln::wire::CustomMessageReader>::CustomMessage),
			)*
		}

		impl $crate::lightning::ln::peer_handler::CustomMessageHandler for $handler {
			fn handle_custom_message(
				&self, msg: Self::CustomMessage, sender_node_id: $crate::bitcoin::secp256k1::PublicKey
			) -> Result<(), $crate::lightning::ln::msgs::LightningError> {
				match msg {
					$(
						$message::$variant(message) => {
							$crate::lightning::ln::peer_handler::CustomMessageHandler::handle_custom_message(
								&self.$field, message, sender_node_id
							)
						},
					)*
				}
			}

			fn get_and_clear_pending_msg(&self) -> Vec<($crate::bitcoin::secp256k1::PublicKey, Self::CustomMessage)> {
				vec![].into_iter()
					$(
						.chain(
							self.$field
								.get_and_clear_pending_msg()
								.into_iter()
								.map(|(pubkey, message)| (pubkey, $message::$variant(message)))
						)
					)*
					.collect()
			}

			fn peer_disconnected(&self, their_node_id: $crate::bitcoin::secp256k1::PublicKey) {
				$(
					self.$field.peer_disconnected(their_node_id);
				)*
			}

			fn peer_connected(&self, their_node_id: $crate::bitcoin::secp256k1::PublicKey, msg: &$crate::lightning::ln::msgs::Init, inbound: bool) -> Result<(), ()> {
				// Per the `CustomMessageHandler::peer_connected` contract, `peer_disconnected`
				// will not be called by `PeerManager` if we return `Err`. To avoid leaking
				// per-peer state in sub-handlers that already returned `Ok` when a later one
				// errors, record each sub-handler's result and roll back the successful ones
				// ourselves before propagating the failure.
				$(
					let $field = self.$field.peer_connected(their_node_id, msg, inbound);
				)*
				let any_err = false $( || $field.is_err() )*;
				if any_err {
					$(
						if $field.is_ok() {
							self.$field.peer_disconnected(their_node_id);
						}
					)*
					Err(())
				} else {
					Ok(())
				}
			}

			fn provided_node_features(&self) -> $crate::lightning::types::features::NodeFeatures {
				$crate::lightning::types::features::NodeFeatures::empty()
					$(
						| self.$field.provided_node_features()
					)*
			}

			fn provided_init_features(
				&self, their_node_id: $crate::bitcoin::secp256k1::PublicKey
			) -> $crate::lightning::types::features::InitFeatures {
				$crate::lightning::types::features::InitFeatures::empty()
					$(
						| self.$field.provided_init_features(their_node_id)
					)*
			}
		}

		impl $crate::lightning::ln::wire::CustomMessageReader for $handler {
			type CustomMessage = $message;
			fn read<R: $crate::lightning::util::ser::LengthLimitedRead>(
				&self, message_type: u16, buffer: &mut R
			) -> Result<Option<Self::CustomMessage>, $crate::lightning::ln::msgs::DecodeError> {
				match message_type {
					$(
						$pattern => match <$type>::read(&self.$field, message_type, buffer)? {
							None => unreachable!(),
							Some(message) => Ok(Some($message::$variant(message))),
						},
					)*
					_ => Ok(None),
				}
			}
		}

		impl $crate::lightning::ln::wire::Type for $message {
			fn type_id(&self) -> u16 {
				match self {
					$(
						Self::$variant(message) => message.type_id(),
					)*
				}
			}
		}

		impl $crate::lightning::util::ser::Writeable for $message {
			fn write<W: $crate::lightning::util::ser::Writer>(&self, writer: &mut W) -> Result<(), $crate::lightning::io::Error> {
				match self {
					$(
						Self::$variant(message) => message.write(writer),
					)*
				}
			}
		}
	}
}

#[cfg(test)]
mod tests {
	use bitcoin::secp256k1::PublicKey;
	use core::sync::atomic::{AtomicUsize, Ordering};
	use lightning::io;
	use lightning::ln::msgs::{DecodeError, Init, LightningError};
	use lightning::ln::peer_handler::CustomMessageHandler;
	use lightning::ln::wire::{CustomMessageReader, Type};
	use lightning::types::features::{InitFeatures, NodeFeatures};
	use lightning::util::ser::{LengthLimitedRead, Writeable, Writer};

	#[derive(Debug)]
	pub struct Foo;
	impl Type for Foo {
		fn type_id(&self) -> u16 {
			32768
		}
	}
	impl Writeable for Foo {
		fn write<W: Writer>(&self, _: &mut W) -> Result<(), io::Error> {
			Ok(())
		}
	}

	pub struct CountingHandler {
		pub connect_count: AtomicUsize,
	}
	impl CustomMessageReader for CountingHandler {
		type CustomMessage = Foo;
		fn read<R: LengthLimitedRead>(
			&self, _t: u16, _b: &mut R,
		) -> Result<Option<Foo>, DecodeError> {
			Ok(None)
		}
	}
	impl CustomMessageHandler for CountingHandler {
		fn handle_custom_message(&self, _msg: Foo, _: PublicKey) -> Result<(), LightningError> {
			Ok(())
		}
		fn get_and_clear_pending_msg(&self) -> Vec<(PublicKey, Foo)> {
			vec![]
		}
		fn peer_disconnected(&self, _: PublicKey) {
			self.connect_count.fetch_sub(1, Ordering::SeqCst);
		}
		fn peer_connected(&self, _: PublicKey, _: &Init, _: bool) -> Result<(), ()> {
			self.connect_count.fetch_add(1, Ordering::SeqCst);
			Ok(())
		}
		fn provided_node_features(&self) -> NodeFeatures {
			NodeFeatures::empty()
		}
		fn provided_init_features(&self, _: PublicKey) -> InitFeatures {
			InitFeatures::empty()
		}
	}

	#[derive(Debug)]
	pub struct Bar;
	impl Type for Bar {
		fn type_id(&self) -> u16 {
			32769
		}
	}
	impl Writeable for Bar {
		fn write<W: Writer>(&self, _: &mut W) -> Result<(), io::Error> {
			Ok(())
		}
	}

	pub struct ErroringHandler;
	impl CustomMessageReader for ErroringHandler {
		type CustomMessage = Bar;
		fn read<R: LengthLimitedRead>(
			&self, _t: u16, _b: &mut R,
		) -> Result<Option<Bar>, DecodeError> {
			Ok(None)
		}
	}
	impl CustomMessageHandler for ErroringHandler {
		fn handle_custom_message(&self, _msg: Bar, _: PublicKey) -> Result<(), LightningError> {
			Ok(())
		}
		fn get_and_clear_pending_msg(&self) -> Vec<(PublicKey, Bar)> {
			vec![]
		}
		fn peer_disconnected(&self, _: PublicKey) {
			debug_assert!(false);
		}
		fn peer_connected(&self, _: PublicKey, _: &Init, _: bool) -> Result<(), ()> {
			Err(())
		}
		fn provided_node_features(&self) -> NodeFeatures {
			NodeFeatures::empty()
		}
		fn provided_init_features(&self, _: PublicKey) -> InitFeatures {
			InitFeatures::empty()
		}
	}

	composite_custom_message_handler!(
		pub struct CompositeHandler {
			counting: CountingHandler,
			erroring: ErroringHandler,
		}

		pub enum CompositeMessage {
			Foo(32768),
			Bar(32769),
		}
	);

	#[test]
	fn peer_connected_failure_does_not_leak_subhandler_state() {
		let composite = CompositeHandler {
			counting: CountingHandler { connect_count: AtomicUsize::new(0) },
			erroring: ErroringHandler,
		};
		let pk_bytes = [
			0x02, 0x79, 0xBE, 0x66, 0x7E, 0xF9, 0xDC, 0xBB, 0xAC, 0x55, 0xA0, 0x62, 0x95, 0xCE,
			0x87, 0x0B, 0x07, 0x02, 0x9B, 0xFC, 0xDB, 0x2D, 0xCE, 0x28, 0xD9, 0x59, 0xF2, 0x81,
			0x5B, 0x16, 0xF8, 0x17, 0x98,
		];
		let pk = PublicKey::from_slice(&pk_bytes).unwrap();
		let init =
			Init { features: InitFeatures::empty(), networks: None, remote_network_address: None };

		let result = composite.peer_connected(pk, &init, true);
		assert!(result.is_err(), "Composite must propagate the inner Err");

		let leaked = composite.counting.connect_count.load(Ordering::SeqCst);
		assert_eq!(
			leaked, 0,
			"CountingHandler tracked {leaked} connected peer(s) after the composite \
			 returned Err; this state will never be cleaned up because per the trait \
			 contract peer_disconnected won't be called when peer_connected returns Err.",
		);
	}
}
