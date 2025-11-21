// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Data structures and utilities for managing Lightning Network contacts.
//!
//! Contacts are trusted people to which we may want to reveal our identity when paying them.
//! We're also able to figure out when incoming payments have been made by one of our contacts.
//! See [bLIP 42](https://github.com/lightning/blips/blob/master/blip-0042.md) for more details.

use crate::offers::offer::Offer;
use bitcoin::hashes::{sha256, Hash, HashEngine};
use bitcoin::secp256k1::Scalar;
use bitcoin::secp256k1::{Secp256k1, SecretKey};
use core::fmt;

#[allow(unused_imports)]
use crate::prelude::*;

/// BIP 353 human-readable address of a contact.
///
/// This represents an address in the form `name@domain` that can be used to identify
/// a contact in a human-readable way.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ContactAddress {
	name: String,
	domain: String,
}

impl ContactAddress {
	/// Creates a new [`ContactAddress`] with the given name and domain.
	///
	/// Returns `None` if either the name or domain exceeds 255 characters.
	pub fn new(name: String, domain: String) -> Result<Self, ()> {
		if name.len() >= 256 || domain.len() >= 256 {
			// TODO: return a better error string in here!
			return Err(());
		}
		Ok(Self { name, domain })
	}

	/// Returns the name part of the contact address.
	pub fn name(&self) -> &str {
		&self.name
	}

	/// Returns the domain part of the contact address.
	pub fn domain(&self) -> &str {
		&self.domain
	}

	/// Parses a contact address from a string in the format `name@domain`.
	///
	/// The Bitcoin symbol (₿) is stripped if present.
	/// Returns `None` if the format is invalid or if name/domain exceed 255 characters.
	pub fn from_str(address: &str) -> Result<Self, ()> {
		let address = address.replace("₿", "");
		let parts: Vec<&str> = address.split('@').collect();

		if parts.len() != 2 {
			return Err(());
		}

		if parts[0].len() > 255 || parts[1].len() > 255 {
			return Err(());
		}

		Self::new(parts[0].to_string(), parts[1].to_string())
	}
}

impl fmt::Display for ContactAddress {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		write!(f, "{}@{}", self.name, self.domain)
	}
}



/// Contact secrets are used to mutually authenticate payments.
///
/// The first node to add the other to its contacts list will generate the `primary_secret` and
/// send it when paying. If the second node adds the first node to its contacts list from the
/// received payment, it will use the same `primary_secret` and both nodes are able to identify
/// payments from each other.
///
/// But if the second node independently added the first node to its contacts list, it may have
/// generated a different `primary_secret`. Each node has a different `primary_secret`, but they
/// will store the other node's `primary_secret` in their `additional_remote_secrets`, which lets
/// them correctly identify payments.
///
/// When sending a payment, we must always send the `primary_secret`.
/// When receiving payments, we must check if the received contact_secret matches either the
/// `primary_secret` or any of the `additional_remote_secrets`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContactSecrets {
	primary_secret: [u8; 32],
	additional_remote_secrets: Vec<[u8; 32]>,
}

impl ContactSecrets {
	/// Creates a new [`ContactSecrets`] with the given primary secret.
	pub fn new(primary_secret: [u8; 32]) -> Self {
		Self { primary_secret, additional_remote_secrets: Vec::new() }
	}

	/// Creates a new [`ContactSecrets`] with the given primary secret and additional remote secrets.
	pub fn with_additional_secrets(
		primary_secret: [u8; 32], additional_remote_secrets: Vec<[u8; 32]>,
	) -> Self {
		Self { primary_secret, additional_remote_secrets }
	}

	/// Returns the primary secret.
	pub fn primary_secret(&self) -> &[u8; 32] {
		&self.primary_secret
	}

	/// Returns the additional remote secrets.
	pub fn additional_remote_secrets(&self) -> &[[u8; 32]] {
		&self.additional_remote_secrets
	}

	/// This function should be used when we attribute an incoming payment to an existing contact.
	///
	/// This can be necessary when:
	///  - our contact added us without using the contact_secret we initially sent them
	///  - our contact is using a different wallet from the one(s) we have already stored
	pub fn add_remote_secret(&mut self, remote_secret: [u8; 32]) {
		if !self.additional_remote_secrets.contains(&remote_secret) {
			self.additional_remote_secrets.push(remote_secret);
		}
	}

	/// Checks if the given secret matches either the primary secret or any additional remote secret.
	pub fn matches(&self, secret: &[u8; 32]) -> bool {
		&self.primary_secret == secret || self.additional_remote_secrets.contains(secret)
	}
}

/// We derive our contact secret deterministically based on our offer and our contact's offer.
///
/// This provides a few interesting properties:
///  - if we remove a contact and re-add it using the same offer, we will generate the same
///    contact secret
///  - if our contact is using the same deterministic algorithm with a single static offer, they
///    will also generate the same contact secret
///
/// Note that this function must only be used when adding a contact that hasn't paid us before.
/// If we're adding a contact that paid us before, we must use the contact_secret they sent us,
/// which ensures that when we pay them, they'll be able to know it was coming from us (see
/// [`from_remote_secret`]).
///
/// # Arguments
/// * `our_private_key` - The private key associated with our node identity
/// * `their_public_key` - The public key of the contact's node identity
pub fn compute_contact_secret(our_private_key: &SecretKey, their_offer: &Offer) -> ContactSecrets {
	let offer_node_id = if let Some(issuer) = their_offer.issuer_signing_pubkey() {
		// If the offer has an issuer signing key, use it
		issuer
	} else {
		// Otherwise, use the last node in the first blinded path (if any)
		let node_ids = their_offer
			.paths()
			.iter()
			.filter_map(|path| path.blinded_hops().last())
			.map(|hop| hop.blinded_node_id)
			.collect::<Vec<_>>();
		if node_ids.is_empty() {
			// FIXME: do not panic but return a proper error!
			panic!("Offer must have either an issuer signing key or a blinded path");
		}
		node_ids[0]
	};
	// Compute ECDH shared secret (multiply their public key by our private key)
	let scalar: Scalar = our_private_key.clone().into();
	let secp = Secp256k1::new();
	let ecdh = offer_node_id.mul_tweak(&secp, &scalar).expect("Multiply");
	// Hash the shared secret with the bLIP 42 tag
	let mut engine = sha256::Hash::engine();
	engine.input(b"blip42_contact_secret");
	engine.input(&ecdh.serialize());
	let primary_secret = sha256::Hash::from_engine(engine).to_byte_array();

	ContactSecrets::new(primary_secret)
}

/// When adding a contact from which we've received a payment, we must use the contact_secret
/// they sent us: this ensures that they'll be able to identify payments coming from us.
pub fn from_remote_secret(remote_secret: [u8; 32]) -> ContactSecrets {
	ContactSecrets::new(remote_secret)
}

#[cfg(test)]
mod tests {
	use super::*;
	use bitcoin::{hex::DisplayHex, secp256k1::Secp256k1};
	use core::str::FromStr;

	// FIXME: there is a better way to have test vectors? Loading them from
	// the json file for instance?

	// derive deterministic contact_secret when both offers use blinded paths only
	#[test]
	fn test_compute_contact_secret_test_vector_blinded_paths() {
		let alice_offer_str = "lno1qgsqvgnwgcg35z6ee2h3yczraddm72xrfua9uve2rlrm9deu7xyfzrcsesp0grlulxv3jygx83h7tghy3233sqd6xlcccvpar2l8jshxrtwvtcsrejlwh4vyz70s46r62vtakl4sxztqj6gxjged0wx0ly8qtrygufcsyq5agaes6v605af5rr9ydnj9srneudvrmc73n7evp72tzpqcnd28puqr8a3wmcff9wfjwgk32650vl747m2ev4zsjagzucntctlmcpc6vhmdnxlywneg5caqz0ansr45z2faxq7unegzsnyuduzys7kzyugpwcmhdqqj0h70zy92p75pseunclwsrwhaelvsqy9zsejcytxulndppmykcznn7y5h";
		let alice_priv_key =
			SecretKey::from_str("4ed1a01dae275f7b7ba503dbae23dddd774a8d5f64788ef7a768ed647dd0e1eb")
				.unwrap();
		let alice_offer = Offer::from_str(alice_offer_str).unwrap();

		assert!(alice_offer.issuer_signing_pubkey().is_none());
		assert_eq!(alice_offer.paths().len(), 1);

		let alice_offer_node_id = alice_offer
			.paths()
			.iter()
			.filter_map(|path| path.blinded_hops().last())
			.map(|hop| hop.blinded_node_id)
			.collect::<Vec<_>>();
		let alice_offer_node_id = alice_offer_node_id.first().unwrap();
		assert_eq!(
			alice_offer_node_id.to_string(),
			"0284c9c6f04487ac22710176377680127dfcf110aa0fa8186793c7dd01bafdcfd9"
		);

		let bob_offer_str = "lno1qgsqvgnwgcg35z6ee2h3yczraddm72xrfua9uve2rlrm9deu7xyfzrcsesp0grlulxv3jygx83h7tghy3233sqd6xlcccvpar2l8jshxrtwvtcsz4n88s74qhussxsu0vs3c4unck4yelk67zdc29ree3sztvjn7pc9qyqlcpj54jnj67aa9rd2n5dhjlxyfmv3vgqymrks2nf7gnf5u200mn5qrxfrxh9d0ug43j5egklhwgyrfv3n84gyjd2aajhwqxa0cc7zn37sncrwptz4uhlp523l83xpjx9dw72spzecrtex3ku3h3xpepeuend5rtmurekfmnqsq6kva9yr4k3dtplku9v6qqyxr5ep6lls3hvrqyt9y7htaz9qj";
		let bob_priv_key =
			SecretKey::from_str("12afb8248c7336e6aea5fe247bc4bac5dcabfb6017bd67b32c8195a6c56b8333")
				.unwrap();
		let bob_offer = Offer::from_str(bob_offer_str).unwrap();
		assert!(bob_offer.issuer_signing_pubkey().is_none());
		assert_eq!(bob_offer.paths().len(), 1);

		let bob_offer_node_id = bob_offer
			.paths()
			.iter()
			.filter_map(|path| path.blinded_hops().last())
			.map(|hop| hop.blinded_node_id)
			.collect::<Vec<_>>();
		let bob_offer_node_id = bob_offer_node_id.first().unwrap();
		assert_eq!(
			bob_offer_node_id.to_string(),
			"035e4d1b7237898390e7999b6835ef83cd93b98200d599d29075b45ab0fedc2b34"
		);

		let alice_computed = compute_contact_secret(&alice_priv_key, &bob_offer);
		let bob_computed = compute_contact_secret(&bob_priv_key, &alice_offer);

		assert_eq!(
			alice_computed.primary_secret().to_hex_string(bitcoin::hex::Case::Lower),
			"810641fab614f8bc1441131dc50b132fd4d1e2ccd36f84b887bbab3a6d8cc3d8".to_owned()
		);
		assert_eq!(alice_computed, bob_computed);
	}

	// derive deterministic contact_secret when one offer uses both blinded paths and issuer_id
	#[test]
	fn test_compute_contact_secret_test_vector_blinded_paths_and_issuer_id() {
		let alice_offer_str = "lno1qgsqvgnwgcg35z6ee2h3yczraddm72xrfua9uve2rlrm9deu7xyfzrcsesp0grlulxv3jygx83h7tghy3233sqd6xlcccvpar2l8jshxrtwvtcsrejlwh4vyz70s46r62vtakl4sxztqj6gxjged0wx0ly8qtrygufcsyq5agaes6v605af5rr9ydnj9srneudvrmc73n7evp72tzpqcnd28puqr8a3wmcff9wfjwgk32650vl747m2ev4zsjagzucntctlmcpc6vhmdnxlywneg5caqz0ansr45z2faxq7unegzsnyuduzys7kzyugpwcmhdqqj0h70zy92p75pseunclwsrwhaelvsqy9zsejcytxulndppmykcznn7y5h";
		let alice_priv_key =
			SecretKey::from_str("4ed1a01dae275f7b7ba503dbae23dddd774a8d5f64788ef7a768ed647dd0e1eb")
				.unwrap();
		let alice_offer = Offer::from_str(alice_offer_str).unwrap();

		assert!(alice_offer.issuer_signing_pubkey().is_none());
		assert_eq!(alice_offer.paths().len(), 1);

		let alice_offer_node_id = alice_offer
			.paths()
			.iter()
			.filter_map(|path| path.blinded_hops().last())
			.map(|hop| hop.blinded_node_id)
			.collect::<Vec<_>>();
		let alice_offer_node_id = alice_offer_node_id.first().unwrap();
		assert_eq!(
			alice_offer_node_id.to_string(),
			"0284c9c6f04487ac22710176377680127dfcf110aa0fa8186793c7dd01bafdcfd9"
		);

		let bob_offer_str = "lno1qgsqvgnwgcg35z6ee2h3yczraddm72xrfua9uve2rlrm9deu7xyfzrcsesp0grlulxv3jygx83h7tghy3233sqd6xlcccvpar2l8jshxrtwvtcsz4n88s74qhussxsu0vs3c4unck4yelk67zdc29ree3sztvjn7pc9qyqlcpj54jnj67aa9rd2n5dhjlxyfmv3vgqymrks2nf7gnf5u200mn5qrxfrxh9d0ug43j5egklhwgyrfv3n84gyjd2aajhwqxa0cc7zn37sncrwptz4uhlp523l83xpjx9dw72spzecrtex3ku3h3xpepeuend5rtmurekfmnqsq6kva9yr4k3dtplku9v6qqyxr5ep6lls3hvrqyt9y7htaz9qjzcssy065ctv38c5h03lu0hlvq2t4p5fg6u668y6pmzcg64hmdm050jxx";
		let bob_priv_key =
			SecretKey::from_str("bcaafa8ed73da11437ce58c7b3458567a870168c0da325a40292fed126b97845")
				.unwrap();
		let bob_offer = Offer::from_str(bob_offer_str).unwrap();
		let bob_offer_node_id = bob_offer.issuer_signing_pubkey().unwrap();
		assert_eq!(
			bob_offer_node_id.to_string(),
			"023f54c2d913e2977c7fc7dfec029750d128d735a39341d8b08d56fb6edf47c8c6"
		);

		let alice_computed = compute_contact_secret(&alice_priv_key, &bob_offer);
		let bob_computed = compute_contact_secret(&bob_priv_key, &alice_offer);

		assert_eq!(
			alice_computed.primary_secret().to_hex_string(bitcoin::hex::Case::Lower),
			"4e0aa72cc42eae9f8dc7c6d2975bbe655683ada2e9abfdfe9f299d391ed9736c".to_owned()
		);
		assert_eq!(alice_computed, bob_computed);
	}
}
