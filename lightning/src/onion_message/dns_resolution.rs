// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! This module defines message handling for DNSSEC proof fetching using [bLIP 32].
//!
//! It contains [`DNSResolverMessage`]s as well as a [`DNSResolverMessageHandler`] trait to handle
//! such messages using an [`OnionMessenger`].
//!
//! [bLIP 32]: https://github.com/lightning/blips/blob/master/blip-0032.md
//! [`OnionMessenger`]: super::messenger::OnionMessenger

use dnssec_prover::rr::Name;

use crate::blinded_path::message::DNSResolverContext;
use crate::io;
use crate::ln::msgs::DecodeError;
use crate::onion_message::messenger::{MessageSendInstructions, Responder, ResponseInstruction};
use crate::onion_message::packet::OnionMessageContents;
use crate::prelude::*;
use crate::util::ser::{Hostname, Readable, ReadableArgs, Writeable, Writer};

/// A handler for an [`OnionMessage`] containing a DNS(SEC) query or a DNSSEC proof
///
/// [`OnionMessage`]: crate::ln::msgs::OnionMessage
pub trait DNSResolverMessageHandler {
	/// Handle a [`DNSSECQuery`] message.
	///
	/// If we provide DNS resolution services to third parties, we should respond with a
	/// [`DNSSECProof`] message.
	fn handle_dnssec_query(
		&self, message: DNSSECQuery, responder: Option<Responder>,
	) -> Option<(DNSResolverMessage, ResponseInstruction)>;

	/// Handle a [`DNSSECProof`] message (in response to a [`DNSSECQuery`] we presumably sent).
	///
	/// With this, we should be able to validate the DNS record we requested.
	fn handle_dnssec_proof(&self, message: DNSSECProof, context: DNSResolverContext);

	/// Release any [`DNSResolverMessage`]s that need to be sent.
	fn release_pending_messages(&self) -> Vec<(DNSResolverMessage, MessageSendInstructions)> {
		vec![]
	}
}

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
/// An enum containing the possible onion messages which are used uses to request and receive
/// DNSSEC proofs.
pub enum DNSResolverMessage {
	/// A query requesting a DNSSEC proof
	DNSSECQuery(DNSSECQuery),
	/// A response containing a DNSSEC proof
	DNSSECProof(DNSSECProof),
}

const DNSSEC_QUERY_TYPE: u64 = 65536;
const DNSSEC_PROOF_TYPE: u64 = 65538;

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
/// A message which is sent to a DNSSEC prover requesting a DNSSEC proof for the given name.
pub struct DNSSECQuery(pub Name);

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
/// A message which is sent in response to [`DNSSECQuery`] containing a DNSSEC proof.
pub struct DNSSECProof {
	/// The name which the query was for. The proof may not contain a DNS RR for exactly this name
	/// if it contains a wildcard RR which contains this name instead.
	pub name: Name,
	/// An [RFC 9102 DNSSEC AuthenticationChain] providing a DNSSEC proof.
	///
	/// [RFC 9102 DNSSEC AuthenticationChain]: https://www.rfc-editor.org/rfc/rfc9102.html#name-dnssec-authentication-chain
	pub proof: Vec<u8>,
}

impl DNSResolverMessage {
	/// Returns whether `tlv_type` corresponds to a TLV record for DNS Resolvers.
	pub fn is_known_type(tlv_type: u64) -> bool {
		match tlv_type {
			DNSSEC_QUERY_TYPE | DNSSEC_PROOF_TYPE => true,
			_ => false,
		}
	}
}

impl Writeable for DNSResolverMessage {
	fn write<W: Writer>(&self, w: &mut W) -> Result<(), io::Error> {
		match self {
			Self::DNSSECQuery(DNSSECQuery(q)) => {
				(q.as_str().len() as u8).write(w)?;
				w.write_all(&q.as_str().as_bytes())
			},
			Self::DNSSECProof(DNSSECProof { name, proof }) => {
				(name.as_str().len() as u8).write(w)?;
				w.write_all(&name.as_str().as_bytes())?;
				proof.write(w)
			},
		}
	}
}

impl ReadableArgs<u64> for DNSResolverMessage {
	fn read<R: io::Read>(r: &mut R, message_type: u64) -> Result<Self, DecodeError> {
		match message_type {
			DNSSEC_QUERY_TYPE => {
				let s = Hostname::read(r)?;
				let name = s.try_into().map_err(|_| DecodeError::InvalidValue)?;
				Ok(DNSResolverMessage::DNSSECQuery(DNSSECQuery(name)))
			},
			DNSSEC_PROOF_TYPE => {
				let s = Hostname::read(r)?;
				let name = s.try_into().map_err(|_| DecodeError::InvalidValue)?;
				let proof = Readable::read(r)?;
				Ok(DNSResolverMessage::DNSSECProof(DNSSECProof { name, proof }))
			},
			_ => Err(DecodeError::InvalidValue),
		}
	}
}

impl OnionMessageContents for DNSResolverMessage {
	#[cfg(c_bindings)]
	fn msg_type(&self) -> String {
		match self {
			DNSResolverMessage::DNSSECQuery(_) => "DNS(SEC) Query".to_string(),
			DNSResolverMessage::DNSSECProof(_) => "DNSSEC Proof".to_string(),
		}
	}
	#[cfg(not(c_bindings))]
	fn msg_type(&self) -> &'static str {
		match self {
			DNSResolverMessage::DNSSECQuery(_) => "DNS(SEC) Query",
			DNSResolverMessage::DNSSECProof(_) => "DNSSEC Proof",
		}
	}
	fn tlv_type(&self) -> u64 {
		match self {
			DNSResolverMessage::DNSSECQuery(_) => DNSSEC_QUERY_TYPE,
			DNSResolverMessage::DNSSECProof(_) => DNSSEC_PROOF_TYPE,
		}
	}
}
