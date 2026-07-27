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
//! With the `dnssec` feature enabled, it also contains `OMNameResolver`, which does all the work
//! required to resolve BIP 353 [`HumanReadableName`]s using [bLIP 32] - sending onion messages to
//! a DNS resolver, validating the proofs, and ultimately surfacing validated data back to the
//! caller.
//!
//! [bLIP 32]: https://github.com/lightning/blips/blob/master/blip-0032.md
//! [`OnionMessenger`]: super::messenger::OnionMessenger

#[cfg(feature = "dnssec")]
use core::str::FromStr;
#[cfg(feature = "dnssec")]
use core::sync::atomic::{AtomicUsize, Ordering};

#[cfg(feature = "dnssec")]
use dnssec_prover::rr::RR;
#[cfg(feature = "dnssec")]
use dnssec_prover::ser::parse_rr_stream;
#[cfg(feature = "dnssec")]
use dnssec_prover::validation::verify_rr_stream;

use dnssec_prover::rr::Name;

use lightning_types::features::NodeFeatures;

use core::fmt;
use core::ops::Deref;

use crate::blinded_path::message::DNSResolverContext;
#[cfg(feature = "dnssec")]
use crate::blinded_path::message::MessageContext;
use crate::io;
#[cfg(feature = "dnssec")]
use crate::ln::channelmanager::PaymentId;
use crate::ln::msgs::DecodeError;
#[cfg(feature = "dnssec")]
use crate::offers::offer::Offer;
#[cfg(feature = "dnssec")]
use crate::onion_message::messenger::Destination;
use crate::onion_message::messenger::{MessageSendInstructions, Responder, ResponseInstruction};
use crate::onion_message::packet::OnionMessageContents;
use crate::prelude::*;
#[cfg(feature = "dnssec")]
use crate::sign::EntropySource;
#[cfg(feature = "dnssec")]
use crate::sync::Mutex;
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
	/// The provided [`DNSResolverContext`] was authenticated by the [`OnionMessenger`] as coming from
	/// a blinded path that we created.
	///
	/// With this, we should be able to validate the DNS record we requested.
	///
	/// [`OnionMessenger`]: crate::onion_message::messenger::OnionMessenger
	fn handle_dnssec_proof(&self, message: DNSSECProof, context: DNSResolverContext);

	/// Handle a [`DNSSECError`] message (in response to a [`DNSSECQuery`] we presumably sent),
	/// indicating that the resolver was unable to resolve the requested name.
	///
	/// The provided [`DNSResolverContext`] was authenticated by the [`OnionMessenger`] as coming from
	/// a blinded path that we created.
	///
	/// Receiving this lets us avoid waiting for a [`DNSSECProof`] which will never come, failing the
	/// pending operation early instead (at least if the name is
	/// [definitely unresolvable](DNSSECError::definitely_unresolvable)).
	///
	/// [`OnionMessenger`]: crate::onion_message::messenger::OnionMessenger
	fn handle_dnssec_error(&self, message: DNSSECError, context: DNSResolverContext);

	/// Gets the node feature flags which this handler itself supports. Useful for setting the
	/// `dns_resolver` flag if this handler supports returning [`DNSSECProof`] messages in response
	/// to [`DNSSECQuery`] messages.
	fn provided_node_features(&self) -> NodeFeatures {
		NodeFeatures::empty()
	}

	/// Release any [`DNSResolverMessage`]s that need to be sent.
	fn release_pending_messages(&self) -> Vec<(DNSResolverMessage, MessageSendInstructions)> {
		vec![]
	}
}

impl<T: DNSResolverMessageHandler + ?Sized, D: Deref<Target = T>> DNSResolverMessageHandler for D {
	fn handle_dnssec_query(
		&self, message: DNSSECQuery, responder: Option<Responder>,
	) -> Option<(DNSResolverMessage, ResponseInstruction)> {
		self.deref().handle_dnssec_query(message, responder)
	}
	fn handle_dnssec_proof(&self, message: DNSSECProof, context: DNSResolverContext) {
		self.deref().handle_dnssec_proof(message, context)
	}
	fn handle_dnssec_error(&self, message: DNSSECError, context: DNSResolverContext) {
		self.deref().handle_dnssec_error(message, context)
	}
	fn provided_node_features(&self) -> NodeFeatures {
		self.deref().provided_node_features()
	}
	fn release_pending_messages(&self) -> Vec<(DNSResolverMessage, MessageSendInstructions)> {
		self.deref().release_pending_messages()
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
	/// An error in response to a [`DNSSECQuery`], indicating that the requested name could not be
	/// resolved into a [`DNSSECProof`].
	DNSSECError(DNSSECError),
}

const DNSSEC_QUERY_TYPE: u64 = 65536;
const DNSSEC_PROOF_TYPE: u64 = 65538;
const DNSSEC_ERROR_TYPE: u64 = 65550;

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

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
/// A message which is sent in response to a [`DNSSECQuery`] when the resolver was unable to build a
/// [`DNSSECProof`] for the requested name.
///
/// This lets the recipient stop waiting for a [`DNSSECProof`] which will not be forthcoming.
pub struct DNSSECError {
	/// The name which the [`DNSSECQuery`] was for and which we were unable to resolve.
	pub name: Name,
	/// Whether the name is known to be permanently unresolvable, as opposed to having failed due to
	/// some transient error.
	///
	/// This is set if the requested name does not exist (i.e. the resolver received an NXDOMAIN
	/// response) or if the name is not in a DNSSEC-signed zone, in which case retrying or querying a
	/// different resolver will not help. It is not set for transient failures (e.g. a timeout
	/// communicating with an upstream DNS server), where a retry or a different resolver may yet
	/// succeed.
	pub definitely_unresolvable: bool,
}

impl DNSResolverMessage {
	/// Returns whether `tlv_type` corresponds to a TLV record for DNS Resolvers.
	pub fn is_known_type(tlv_type: u64) -> bool {
		match tlv_type {
			DNSSEC_QUERY_TYPE | DNSSEC_PROOF_TYPE | DNSSEC_ERROR_TYPE => true,
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
			Self::DNSSECError(DNSSECError { name, definitely_unresolvable }) => {
				(name.as_str().len() as u8).write(w)?;
				w.write_all(&name.as_str().as_bytes())?;
				definitely_unresolvable.write(w)
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
			DNSSEC_ERROR_TYPE => {
				let s = Hostname::read(r)?;
				let name = s.try_into().map_err(|_| DecodeError::InvalidValue)?;
				let definitely_unresolvable = Readable::read(r)?;
				Ok(DNSResolverMessage::DNSSECError(DNSSECError { name, definitely_unresolvable }))
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
			DNSResolverMessage::DNSSECError(_) => "DNSSEC Error".to_string(),
		}
	}
	#[cfg(not(c_bindings))]
	fn msg_type(&self) -> &'static str {
		match self {
			DNSResolverMessage::DNSSECQuery(_) => "DNS(SEC) Query",
			DNSResolverMessage::DNSSECProof(_) => "DNSSEC Proof",
			DNSResolverMessage::DNSSECError(_) => "DNSSEC Error",
		}
	}
	fn tlv_type(&self) -> u64 {
		match self {
			DNSResolverMessage::DNSSECQuery(_) => DNSSEC_QUERY_TYPE,
			DNSResolverMessage::DNSSECProof(_) => DNSSEC_PROOF_TYPE,
			DNSResolverMessage::DNSSECError(_) => DNSSEC_ERROR_TYPE,
		}
	}
}

// Note that `REQUIRED_EXTRA_LEN` includes the (implicit) trailing `.`
const REQUIRED_EXTRA_LEN: usize = ".user._bitcoin-payment.".len() + 1;

/// A struct containing the two parts of a BIP 353 Human Readable Name - the user and domain parts.
///
/// The `user` and `domain` parts combined cannot exceed 231 bytes in length;
/// each DNS label within them must be non-empty and no longer than 63 bytes.
///
/// If you intend to handle non-ASCII `user` or `domain` parts, you must handle [Homograph Attacks]
/// and do punycode en-/de-coding yourself. This struct will always handle only plain ASCII `user`
/// and `domain` parts.
///
/// This struct can also be used for LN-Address recipients.
///
/// [Homograph Attacks]: https://en.wikipedia.org/wiki/IDN_homograph_attack
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub struct HumanReadableName {
	contents: [u8; 255 - REQUIRED_EXTRA_LEN],
	user_len: u8,
	domain_len: u8,
}

impl HumanReadableName {
	/// Constructs a new [`HumanReadableName`] from the `user` and `domain` parts. See the
	/// struct-level documentation for more on the requirements on each.
	pub fn new(user: &str, domain: &str) -> Result<Self, ()> {
		// First normalize domain and remove the optional trailing `.`
		let domain = domain.strip_suffix('.').unwrap_or(domain);
		if user.len() + domain.len() + REQUIRED_EXTRA_LEN > 255 {
			return Err(());
		}
		for label in user.split('.') {
			if label.is_empty() || label.len() > 63 {
				return Err(());
			}
		}
		for label in domain.split('.') {
			if label.is_empty() || label.len() > 63 {
				return Err(());
			}
		}
		if !Hostname::str_is_valid_hostname(&user) || !Hostname::str_is_valid_hostname(&domain) {
			return Err(());
		}
		let mut contents = [0; 255 - REQUIRED_EXTRA_LEN];
		contents[..user.len()].copy_from_slice(user.as_bytes());
		contents[user.len()..user.len() + domain.len()].copy_from_slice(domain.as_bytes());
		Ok(Self { contents, user_len: user.len() as u8, domain_len: domain.len() as u8 })
	}

	/// Constructs a new [`HumanReadableName`] from the standard encoding - `user`@`domain`.
	///
	/// If `user` includes the standard BIP 353 ₿ prefix it is automatically removed as required by
	/// BIP 353.
	pub fn from_encoded(encoded: &str) -> Result<Self, ()> {
		let encoded = encoded.strip_prefix('₿').unwrap_or(encoded);
		let (user, domain) = encoded.split_once('@').ok_or(())?;
		Self::new(user, domain)
	}

	/// Gets the `user` part of this Human Readable Name
	pub fn user(&self) -> &str {
		let bytes = &self.contents[..self.user_len as usize];
		core::str::from_utf8(bytes).expect("Checked in constructor")
	}

	/// Gets the `domain` part of this Human Readable Name
	pub fn domain(&self) -> &str {
		let user_len = self.user_len as usize;
		let bytes = &self.contents[user_len..user_len + self.domain_len as usize];
		core::str::from_utf8(bytes).expect("Checked in constructor")
	}
}

// Serialized per the requirements for inclusion in a BOLT 12 `invoice_request`
impl Writeable for HumanReadableName {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), io::Error> {
		(self.user().len() as u8).write(writer)?;
		writer.write_all(&self.user().as_bytes())?;
		(self.domain().len() as u8).write(writer)?;
		writer.write_all(&self.domain().as_bytes())
	}
}

impl Readable for HumanReadableName {
	fn read<R: io::Read>(reader: &mut R) -> Result<Self, DecodeError> {
		let mut user_bytes = [0; 255];
		let user_len: u8 = Readable::read(reader)?;
		reader.read_exact(&mut user_bytes[..user_len as usize])?;
		let user = match core::str::from_utf8(&user_bytes[..user_len as usize]) {
			Ok(user) => user,
			Err(_) => return Err(DecodeError::InvalidValue),
		};

		let mut domain_bytes = [0; 255];
		let domain_len: u8 = Readable::read(reader)?;
		reader.read_exact(&mut domain_bytes[..domain_len as usize])?;
		let domain = match core::str::from_utf8(&domain_bytes[..domain_len as usize]) {
			Ok(domain) => domain,
			Err(_) => return Err(DecodeError::InvalidValue),
		};

		HumanReadableName::new(user, domain).map_err(|()| DecodeError::InvalidValue)
	}
}

impl fmt::Display for HumanReadableName {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		write!(f, "₿{}@{}", self.user(), self.domain())
	}
}

#[cfg(feature = "dnssec")]
struct PendingResolution {
	start_height: u32,
	pending_query_contexts: Vec<DNSResolverContext>,
	name: HumanReadableName,
	payment_id: PaymentId,
}

/// A stateful resolver which maps BIP 353 Human Readable Names to URIs and BOLT12 [`Offer`]s.
///
/// It does not directly implement [`DNSResolverMessageHandler`] but implements all the core logic
/// which is required in a client which intends to.
///
/// It relies on being made aware of the passage of time with regular calls to
/// [`Self::new_best_block`] in order to time out existing queries. Queries time out after two
/// blocks.
#[cfg(feature = "dnssec")]
pub struct OMNameResolver {
	pending_resolves: Mutex<HashMap<Name, Vec<PendingResolution>>>,
	latest_block_time: AtomicUsize,
	latest_block_height: AtomicUsize,
}

#[cfg(feature = "dnssec")]
impl OMNameResolver {
	/// Builds a new [`OMNameResolver`].
	pub fn new(latest_block_time: u32, latest_block_height: u32) -> Self {
		Self {
			pending_resolves: Mutex::new(new_hash_map()),
			latest_block_time: AtomicUsize::new(latest_block_time as usize),
			latest_block_height: AtomicUsize::new(latest_block_height as usize),
		}
	}

	/// Builds a new [`OMNameResolver`] which will not validate the time limits on DNSSEC proofs
	/// (for builds without the "std" feature and until [`Self::new_best_block`] is called).
	///
	/// If possible, you should prefer [`Self::new`] so that providing stale proofs is not
	/// possible, however in no-std environments where there is some trust in the resolver used and
	/// no time source is available, this may be acceptable.
	///
	/// Note that not calling [`Self::new_best_block`] will result in requests not timing out and
	/// unresolved requests leaking memory. You must instead call
	/// [`Self::expire_pending_resolution`] as unresolved requests expire.
	pub fn new_without_no_std_expiry_validation() -> Self {
		Self {
			pending_resolves: Mutex::new(new_hash_map()),
			latest_block_time: AtomicUsize::new(0),
			latest_block_height: AtomicUsize::new(0),
		}
	}

	/// Informs the [`OMNameResolver`] of the passage of time in the form of a new best Bitcoin
	/// block.
	///
	/// This is used to prune stale requests (by block height) and keep track of the current time
	/// to validate that DNSSEC proofs are current.
	pub fn new_best_block(&self, height: u32, time: u32) {
		self.latest_block_time.store(time as usize, Ordering::Release);
		self.latest_block_height.store(height as usize, Ordering::Release);
		let mut resolves = self.pending_resolves.lock().unwrap();
		resolves.retain(|_, queries| {
			queries.retain(|query| query.start_height >= height - 1);
			!queries.is_empty()
		});
	}

	/// Removes any pending resolutions for the given `name` and `payment_id`.
	///
	/// Any future calls to [`Self::handle_dnssec_proof_for_offer`] or
	/// [`Self::handle_dnssec_proof_for_uri`] will no longer return a result for the given
	/// resolution.
	pub fn expire_pending_resolution(&self, name: &HumanReadableName, payment_id: PaymentId) {
		let dns_name =
			Name::try_from(format!("{}.user._bitcoin-payment.{}.", name.user(), name.domain()));
		debug_assert!(
			dns_name.is_ok(),
			"The HumanReadableName constructor shouldn't allow names which are too long"
		);
		if let Ok(name) = dns_name {
			let mut pending_resolves = self.pending_resolves.lock().unwrap();
			if let hash_map::Entry::Occupied(mut entry) = pending_resolves.entry(name) {
				let resolutions = entry.get_mut();
				resolutions.retain(|resolution| resolution.payment_id != payment_id);
				if resolutions.is_empty() {
					entry.remove();
				}
			}
		}
	}

	/// Begins the process of resolving a BIP 353 Human Readable Name.
	///
	/// Sets up the state to handle query responses and returns a list of [`DNSSECQuery`] onion
	/// messages and the [`MessageSendInstructions`] over which each should be sent - one entry per
	/// provided `destination`.
	pub fn initiate_resolution<ES: EntropySource + ?Sized>(
		&self, payment_id: PaymentId, name: HumanReadableName, destinations: Vec<Destination>,
		entropy_source: &ES,
	) -> Result<Vec<(DNSResolverMessage, MessageSendInstructions)>, ()> {
		if destinations.is_empty() {
			return Err(());
		}

		let dns_name =
			Name::try_from(format!("{}.user._bitcoin-payment.{}.", name.user(), name.domain()));
		debug_assert!(
			dns_name.is_ok(),
			"The HumanReadableName constructor shouldn't allow names which are too long"
		);
		if let Ok(dns_name) = dns_name {
			let start_height = self.latest_block_height.load(Ordering::Acquire) as u32;
			let query = DNSResolverMessage::DNSSECQuery(DNSSECQuery(dns_name.clone()));
			let mut pending_query_contexts = Vec::with_capacity(destinations.len());
			let messages = destinations
				.into_iter()
				.map(|destination| {
					let mut context = DNSResolverContext { nonce: [0; 16] };
					context.nonce.copy_from_slice(&entropy_source.get_secure_random_bytes()[..16]);
					pending_query_contexts.push(context.clone());
					let instructions = MessageSendInstructions::WithReplyPath {
						destination,
						context: MessageContext::DNSResolver(context),
					};
					(query.clone(), instructions)
				})
				.collect();
			let mut pending_resolves = self.pending_resolves.lock().unwrap();
			let resolution =
				PendingResolution { start_height, pending_query_contexts, name, payment_id };
			pending_resolves.entry(dns_name).or_insert_with(Vec::new).push(resolution);
			Ok(messages)
		} else {
			Err(())
		}
	}

	/// Handles a [`DNSSECProof`] message, attempting to verify it and match it against a pending
	/// query.
	///
	/// If verification succeeds, the resulting bitcoin: URI is parsed to find a contained
	/// [`Offer`].
	///
	/// Note that a single proof for a wildcard DNS entry may complete several requests for
	/// different [`HumanReadableName`]s.
	///
	/// If an [`Offer`] is found, it, as well as the [`PaymentId`] and original `name` passed to
	/// [`Self::initiate_resolution`] are returned.
	///
	/// If the proof is invalid and there are no remaining queries for this name, or if the proof is
	/// valid and does not contain a valid BIP 353 entry or BOLT 12 [`Offer`], `Err` will be
	/// returned with the set of [`HumanReadableName`] and [`PaymentId`] requests which should be
	/// considered failed.
	pub fn handle_dnssec_proof_for_offer(
		&self, msg: DNSSECProof, context: DNSResolverContext,
	) -> Result<(Vec<(HumanReadableName, PaymentId)>, Offer), Vec<(HumanReadableName, PaymentId)>> {
		let (completed_requests, uri) = self.handle_dnssec_proof_for_uri(msg, context)?;
		if let Some((_onchain, params)) = uri.split_once('?') {
			for param in params.split('&') {
				let (k, v) = if let Some(split) = param.split_once('=') {
					split
				} else {
					continue;
				};
				if k.eq_ignore_ascii_case("lno") {
					if let Ok(offer) = Offer::from_str(v) {
						return Ok((completed_requests, offer));
					}
					return Err(completed_requests);
				}
			}
		}
		Err(completed_requests)
	}

	/// Handles a [`DNSSECProof`] message, attempting to verify it and match it against any pending
	/// queries.
	///
	/// If verification succeeds, all matching [`PaymentId`] and [`HumanReadableName`]s passed to
	/// [`Self::initiate_resolution`], as well as the resolved bitcoin: URI are returned.
	///
	/// Note that a single proof for a wildcard DNS entry may complete several requests for
	/// different [`HumanReadableName`]s.
	///
	/// If the proof is invalid and there are no remaining queries for this name, or if the proof is
	/// valid and does not contain a valid BIP 353 entry, `Err` will be returned with the set of
	/// [`HumanReadableName`] and [`PaymentId`] requests which should be considered failed.
	///
	/// This method is useful for those who handle bitcoin: URIs already, handling more than just
	/// BOLT12 [`Offer`]s.
	pub fn handle_dnssec_proof_for_uri(
		&self, msg: DNSSECProof, context: DNSResolverContext,
	) -> Result<(Vec<(HumanReadableName, PaymentId)>, String), Vec<(HumanReadableName, PaymentId)>>
	{
		let DNSSECProof { name: answer_name, proof } = msg;
		let mut pending_resolves = self.pending_resolves.lock().unwrap();
		if let hash_map::Entry::Occupied(mut entry) = pending_resolves.entry(answer_name) {
			if !entry.get().iter().any(|query| query.pending_query_contexts.contains(&context)) {
				// If we don't have any pending queries with the context included in the blinded
				// path (implying someone sent us this response not using the blinded path we gave
				// when making the query), return immediately to avoid the extra time for the proof
				// validation giving away that we were the node that made the query.
				//
				// If there was at least one query with the same context, we go ahead and complete
				// all queries for the same name, as there's no point in waiting for another proof
				// for the same name.
				return Err(Vec::new());
			}
			let mut valid_resolution = false;
			let res = parse_rr_stream(&proof).and_then(|rrs| {
				if let Some(verified_rrs) = self.verify_dnssec_proof_for_rrs(entry.key(), &rrs) {
					valid_resolution = true;
					self.map_rrs_to_uri(verified_rrs).ok_or(())
				} else {
					Err(())
				}
			});
			if valid_resolution {
				let requests =
					entry.remove_entry().1.into_iter().map(|r| (r.name, r.payment_id)).collect();
				match res {
					Ok(txt) => Ok((requests, txt)),
					Err(()) => Err(requests),
				}
			} else {
				// Note that because each context has a unique random nonce, at most one resolution
				// can run out of pending queries here. Still, the API returns a Vec as we may join
				// multiple queries for the same name in the future.
				let mut failed_resolutions = Vec::new();
				entry.get_mut().retain_mut(|query| {
					query.pending_query_contexts.retain(|c| *c != context);
					if query.pending_query_contexts.is_empty() {
						failed_resolutions.push((query.name, query.payment_id));
						false
					} else {
						true
					}
				});

				if entry.get().is_empty() {
					entry.remove_entry();
				}
				Err(failed_resolutions)
			}
		} else {
			Err(Vec::new())
		}
	}

	fn verify_dnssec_proof_for_rrs<'a>(
		&self, resolved_name: &Name, rrs: &'a [RR],
	) -> Option<Vec<&'a RR>> {
		let validated_rrs = verify_rr_stream(rrs);
		if let Ok(validated_rrs) = validated_rrs {
			#[allow(unused_assignments, unused_mut)]
			let mut time = self.latest_block_time.load(Ordering::Acquire) as u64;
			#[cfg(all(feature = "std", not(fuzzing)))]
			{
				use std::time::{SystemTime, UNIX_EPOCH};
				let now = SystemTime::now().duration_since(UNIX_EPOCH);
				time = now.expect("Time must be > 1970").as_secs();
			}
			if time != 0 {
				// Block times may be up to two hours in the future and some time into the past
				// (we assume no more than two hours, though the actual limits are rather
				// complicated).
				// Thus, we have to let the proof times be rather fuzzy.
				let max_time_offset =
					if cfg!(all(feature = "std", not(fuzzing))) { 0 } else { 60 * 60 * 2 };
				if validated_rrs.valid_from > time + max_time_offset {
					return None;
				}
				if validated_rrs.expires < time - max_time_offset {
					return None;
				}
			}
			let resolved_rrs = validated_rrs.resolve_name(resolved_name);
			if resolved_rrs.is_empty() {
				return None;
			}

			Some(resolved_rrs)
		} else {
			None
		}
	}

	fn map_rrs_to_uri(&self, resolved_rrs: Vec<&RR>) -> Option<String> {
		const URI_PREFIX: &str = "bitcoin:";
		let mut candidate_records = resolved_rrs
			.iter()
			.filter_map(|rr| if let RR::Txt(txt) = rr { Some(txt.data.as_vec()) } else { None })
			.filter_map(|data| String::from_utf8(data).ok())
			.filter(|data_string| data_string.len() > URI_PREFIX.len())
			.filter(|data_string| {
				let pfx = &data_string.as_bytes()[..URI_PREFIX.len()];
				pfx.eq_ignore_ascii_case(URI_PREFIX.as_bytes())
			});
		// Check that there is exactly one TXT record that begins with
		// bitcoin: as required by BIP 353 (and is valid UTF-8).
		match (candidate_records.next(), candidate_records.next()) {
			(Some(txt), None) => Some(txt),
			_ => None,
		}
	}

	/// Handles a [`DNSSECError`] message, indicating that one of the resolvers we sent a
	/// [`DNSSECQuery`] to was unable to provide a [`DNSSECProof`] for the requested name.
	///
	/// A resolution will be considered failed once we have received a [`DNSSECError`] for all the
	/// queries we made for it, as a [`DNSSECProof`] may still arrive from one of the other
	/// resolvers we queried. When a resolution does fail, its [`HumanReadableName`] and
	/// [`PaymentId`] (as passed to [`Self::initiate_resolution`]) are included in the returned
	/// list.
	///
	/// As with [`Self::handle_dnssec_proof_for_uri`], the [`DNSResolverContext`] is checked against
	/// the contexts of any pending resolutions for the name to ensure the error was received over a
	/// blinded path we created when making the relevant [`DNSSECQuery`].
	pub fn handle_dnssec_error(
		&self, msg: DNSSECError, context: DNSResolverContext,
	) -> Vec<(HumanReadableName, PaymentId)> {
		let DNSSECError { name, .. } = msg;
		let mut failed_resolutions = Vec::new();
		let mut pending_resolves = self.pending_resolves.lock().unwrap();
		if let hash_map::Entry::Occupied(mut entry) = pending_resolves.entry(name) {
			entry.get_mut().retain_mut(|resolution| {
				// Drop the context matching the blinded path this error was received over, if
				// any. If no contexts match (including because a previous error already removed
				// this context), the error does not pertain to this resolution and it is left
				// untouched.
				// Note that because each context has a unique random nonce, at most one resolution
				// can run out of pending queries here. Still, the API returns a Vec as we may join
				// multiple queries for the same name in the future.
				resolution.pending_query_contexts.retain(|c| *c != context);
				if resolution.pending_query_contexts.is_empty() {
					failed_resolutions.push((resolution.name, resolution.payment_id));
					false
				} else {
					true
				}
			});
			if entry.get().is_empty() {
				entry.remove();
			}
		}
		failed_resolutions
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[cfg(feature = "dnssec")]
	use crate::util::test_utils::pubkey;

	#[cfg(feature = "dnssec")]
	fn dest(b: u8) -> Destination {
		Destination::Node(pubkey(b))
	}

	/// Extracts the DNS [`Name`] and the per-query [`DNSResolverContext`]s from the messages
	/// returned by [`OMNameResolver::initiate_resolution`].
	#[cfg(feature = "dnssec")]
	fn dns_name_and_contexts(
		messages: &[(DNSResolverMessage, MessageSendInstructions)],
	) -> (Name, Vec<DNSResolverContext>) {
		let name = match &messages[0] {
			(DNSResolverMessage::DNSSECQuery(DNSSECQuery(name)), _) => name.clone(),
			_ => panic!("Unexpected initiate_resolution output"),
		};
		let contexts = messages
			.iter()
			.map(|(_, instructions)| match instructions {
				MessageSendInstructions::WithReplyPath {
					context: MessageContext::DNSResolver(context),
					..
				} => context.clone(),
				_ => panic!("Unexpected initiate_resolution output"),
			})
			.collect();
		(name, contexts)
	}

	#[test]
	fn test_hrn_display_format() {
		let user = "user";
		let domain = "example.com";
		let hrn = HumanReadableName::new(user, domain)
			.expect("Failed to create HumanReadableName for user");

		// Assert that the formatted string matches the expected output
		let expected_display = format!("₿{}@{}", user, domain);
		assert_eq!(
			format!("{}", hrn),
			expected_display,
			"HumanReadableName display format mismatch"
		);
	}

	#[test]
	fn test_hrn_validation() {
		assert!(HumanReadableName::new("user", "example.com").is_ok());
		assert!(HumanReadableName::new("user", "example.com.").is_ok());

		assert!(HumanReadableName::new("user!", "example.com").is_err());
		assert!(HumanReadableName::new("user.", "example.com").is_err());
		assert!(HumanReadableName::new("user", "exa mple.com").is_err());
		assert!(HumanReadableName::new("", "example.com").is_err());
		assert!(HumanReadableName::new("user", "").is_err());

		let max_label = "a".repeat(63);
		assert!(HumanReadableName::new(&max_label, "example.com").is_ok());

		let long_label = "a".repeat(64);
		assert!(HumanReadableName::new(&long_label, "example.com").is_err());
		let domain_with_long_label = format!("{long_label}.com");
		assert!(HumanReadableName::new("user", &domain_with_long_label).is_err());
		let huge_domain = format!("{max_label}.{max_label}.{max_label}.{max_label}");
		assert!(HumanReadableName::new("user", &huge_domain).is_err());
	}

	#[test]
	fn test_dnssec_error_roundtrip() {
		let name = Name::try_from("test.user._bitcoin-payment.example.com.".to_owned()).unwrap();
		for definitely_unresolvable in [false, true] {
			let msg = DNSResolverMessage::DNSSECError(DNSSECError {
				name: name.clone(),
				definitely_unresolvable,
			});
			let mut buf = Vec::new();
			msg.write(&mut buf).unwrap();
			let read = DNSResolverMessage::read(&mut &buf[..], DNSSEC_ERROR_TYPE).unwrap();
			assert_eq!(msg, read);
		}
	}

	#[test]
	#[cfg(feature = "dnssec")]
	fn test_expiry() {
		let keys = crate::sign::KeysManager::new(&[33; 32], 0, 0, true);
		let resolver = OMNameResolver::new(42, 42);
		let name = HumanReadableName::new("user", "example.com").unwrap();

		// Queue up a resolution
		resolver
			.initiate_resolution(PaymentId([0; 32]), name.clone(), vec![dest(42)], &keys)
			.unwrap();
		assert_eq!(resolver.pending_resolves.lock().unwrap().len(), 1);
		// and check that it expires after two blocks
		resolver.new_best_block(44, 42);
		assert_eq!(resolver.pending_resolves.lock().unwrap().len(), 0);

		// Queue up another resolution
		resolver
			.initiate_resolution(PaymentId([1; 32]), name.clone(), vec![dest(42)], &keys)
			.unwrap();
		assert_eq!(resolver.pending_resolves.lock().unwrap().len(), 1);
		// it won't expire after one block
		resolver.new_best_block(45, 42);
		assert_eq!(resolver.pending_resolves.lock().unwrap().len(), 1);
		assert_eq!(resolver.pending_resolves.lock().unwrap().iter().next().unwrap().1.len(), 1);
		// and queue up a second and third resolution of the same name
		resolver
			.initiate_resolution(PaymentId([2; 32]), name.clone(), vec![dest(42)], &keys)
			.unwrap();
		resolver
			.initiate_resolution(PaymentId([3; 32]), name.clone(), vec![dest(42)], &keys)
			.unwrap();
		assert_eq!(resolver.pending_resolves.lock().unwrap().len(), 1);
		assert_eq!(resolver.pending_resolves.lock().unwrap().iter().next().unwrap().1.len(), 3);
		// after another block the first will expire, but the second and third won't
		resolver.new_best_block(46, 42);
		assert_eq!(resolver.pending_resolves.lock().unwrap().len(), 1);
		assert_eq!(resolver.pending_resolves.lock().unwrap().iter().next().unwrap().1.len(), 2);
		// Check manual expiry
		resolver.expire_pending_resolution(&name, PaymentId([3; 32]));
		assert_eq!(resolver.pending_resolves.lock().unwrap().len(), 1);
		assert_eq!(resolver.pending_resolves.lock().unwrap().iter().next().unwrap().1.len(), 1);
		// after one more block all the requests will have expired
		resolver.new_best_block(47, 42);
		assert_eq!(resolver.pending_resolves.lock().unwrap().len(), 0);
	}

	#[test]
	#[cfg(feature = "dnssec")]
	fn test_dnssec_error() {
		let keys = crate::sign::KeysManager::new(&[33; 32], 0, 0, true);
		let resolver = OMNameResolver::new(42, 42);
		let name = HumanReadableName::new("user", "example.com").unwrap();

		// Resolve a name, sending the query to two resolvers. Each query gets its own unique
		// context in its reply path.
		let messages = resolver
			.initiate_resolution(PaymentId([0; 32]), name.clone(), vec![dest(1), dest(2)], &keys)
			.unwrap();
		assert_eq!(messages.len(), 2);
		let (dns_name, contexts) = dns_name_and_contexts(&messages);
		assert_ne!(contexts[0], contexts[1]);
		assert_eq!(resolver.pending_resolves.lock().unwrap().len(), 1);

		// An error whose context doesn't match any pending query is ignored entirely, even if it
		// claims the name is unresolvable.
		let mut wrong_context = contexts[0].clone();
		wrong_context.nonce[0] ^= 0x01;
		let wrong = DNSSECError { name: dns_name.clone(), definitely_unresolvable: true };
		assert!(resolver.handle_dnssec_error(wrong, wrong_context).is_empty());
		assert_eq!(resolver.pending_resolves.lock().unwrap().len(), 1);

		// An error over the first query's reply path fails that query but not the resolution
		// itself - even though `definitely_unresolvable` is set - as a proof may yet arrive from
		// the other query.
		let err = DNSSECError { name: dns_name.clone(), definitely_unresolvable: true };
		assert!(resolver.handle_dnssec_error(err, contexts[0].clone()).is_empty());
		assert_eq!(resolver.pending_resolves.lock().unwrap().len(), 1);

		// A duplicate error over the same reply path is ignored - the first query's context was
		// already dropped, so a single misbehaving resolver cannot fail the whole resolution.
		let dup = DNSSECError { name: dns_name.clone(), definitely_unresolvable: true };
		assert!(resolver.handle_dnssec_error(dup, contexts[0].clone()).is_empty());
		assert_eq!(resolver.pending_resolves.lock().unwrap().len(), 1);

		// An error over the second query's reply path fails the last outstanding query, so the
		// resolution now fails - even though this error only indicates a transient failure.
		let err = DNSSECError { name: dns_name, definitely_unresolvable: false };
		let failed = resolver.handle_dnssec_error(err, contexts[1].clone());
		assert_eq!(failed, vec![(name, PaymentId([0; 32]))]);
		assert_eq!(resolver.pending_resolves.lock().unwrap().len(), 0);
	}

	#[test]
	#[cfg(feature = "dnssec")]
	fn test_dnssec_error_only_fails_matching_resolution() {
		// An error only counts against the resolution whose blinded path (context) it was received
		// over; other resolutions for the same name (queued with a different `PaymentId`, and thus a
		// different context) are left untouched.
		let keys = crate::sign::KeysManager::new(&[33; 32], 0, 0, true);
		let resolver = OMNameResolver::new(42, 42);
		let name = HumanReadableName::new("user", "example.com").unwrap();

		let messages = resolver
			.initiate_resolution(PaymentId([0; 32]), name.clone(), vec![dest(1)], &keys)
			.unwrap();
		let (dns_name, contexts_a) = dns_name_and_contexts(&messages);
		resolver
			.initiate_resolution(PaymentId([1; 32]), name.clone(), vec![dest(2)], &keys)
			.unwrap();
		{
			let pending_resolves = resolver.pending_resolves.lock().unwrap();
			let pending_queries_for_name = &pending_resolves.iter().next().unwrap().1;
			assert_eq!(pending_queries_for_name.len(), 2);
		}

		// A single error over payment 0's reply path fails only its (single-query) resolution.
		let err = DNSSECError { name: dns_name, definitely_unresolvable: false };
		let failed = resolver.handle_dnssec_error(err, contexts_a[0].clone());
		assert_eq!(failed, vec![(name, PaymentId([0; 32]))]);

		// Payment 1's resolution is still pending.
		let pending_resolves = resolver.pending_resolves.lock().unwrap();
		let pending_queries_for_name = &pending_resolves.iter().next().unwrap().1;
		assert_eq!(pending_queries_for_name.len(), 1);
		assert_eq!(pending_queries_for_name[0].payment_id, PaymentId([1; 32]));
	}
}
