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
//! # extern crate bitcoin;
//! extern crate lightning;
//! #[macro_use]
//! extern crate lightning_custom_message;
//!
//! # use bitcoin::secp256k1::PublicKey;
//! # use lightning::io;
//! # use lightning::ln::msgs::{DecodeError, LightningError};
//! use lightning::ln::peer_handler::CustomMessageHandler;
//! use lightning::ln::wire::{CustomMessageReader, self};
//! use lightning::util::ser::Writeable;
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
//! #     fn read<R: io::Read>(
//! #         &self, _message_type: u16, _buffer: &mut R
//! #     ) -> Result<Option<Self::CustomMessage>, DecodeError> {
//! #         unimplemented!()
//! #     }
//! }
//! impl CustomMessageHandler for FooHandler {
//!     // ...
//! #     fn handle_custom_message(
//! #         &self, _msg: Self::CustomMessage, _sender_node_id: &PublicKey
//! #     ) -> Result<(), LightningError> {
//! #         unimplemented!()
//! #     }
//! #     fn get_and_clear_pending_msg(&self) -> Vec<(PublicKey, Self::CustomMessage)> {
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
//! #     fn read<R: io::Read>(
//! #         &self, _message_type: u16, _buffer: &mut R
//! #     ) -> Result<Option<Self::CustomMessage>, DecodeError> {
//! #         unimplemented!()
//! #     }
//! }
//! impl CustomMessageHandler for BarHandler {
//!     // ...
//! #     fn handle_custom_message(
//! #         &self, _msg: Self::CustomMessage, _sender_node_id: &PublicKey
//! #     ) -> Result<(), LightningError> {
//! #         unimplemented!()
//! #     }
//! #     fn get_and_clear_pending_msg(&self) -> Vec<(PublicKey, Self::CustomMessage)> {
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
//! #     fn read<R: io::Read>(
//! #         &self, _message_type: u16, _buffer: &mut R
//! #     ) -> Result<Option<Self::CustomMessage>, DecodeError> {
//! #         unimplemented!()
//! #     }
//! }
//! impl CustomMessageHandler for BazHandler {
//!     // ...
//! #     fn handle_custom_message(
//! #         &self, _msg: Self::CustomMessage, _sender_node_id: &PublicKey
//! #     ) -> Result<(), LightningError> {
//! #         unimplemented!()
//! #     }
//! #     fn get_and_clear_pending_msg(&self) -> Vec<(PublicKey, Self::CustomMessage)> {
//! #         unimplemented!()
//! #     }
//! }
//!
//! # fn main() {
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
//! # }
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
				&self, msg: Self::CustomMessage, sender_node_id: &$crate::bitcoin::secp256k1::PublicKey
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
		}

		impl $crate::lightning::ln::wire::CustomMessageReader for $handler {
			type CustomMessage = $message;
			fn read<R: $crate::lightning::io::Read>(
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
