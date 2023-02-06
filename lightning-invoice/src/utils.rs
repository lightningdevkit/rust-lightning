//! Convenient utilities to create an invoice.

use crate::{CreationError, Currency, Invoice, InvoiceBuilder, SignOrCreationError};

use crate::{prelude::*, Description, InvoiceDescription, Sha256};
use bech32::ToBase32;
use bitcoin_hashes::Hash;
use lightning::chain;
use lightning::chain::chaininterface::{BroadcasterInterface, FeeEstimator};
use lightning::chain::keysinterface::{Recipient, NodeSigner, SignerProvider, EntropySource};
use lightning::ln::{PaymentHash, PaymentSecret};
use lightning::ln::channelmanager::{ChannelDetails, ChannelManager, MIN_FINAL_CLTV_EXPIRY_DELTA};
use lightning::ln::channelmanager::{PhantomRouteHints, MIN_CLTV_EXPIRY_DELTA};
use lightning::ln::inbound_payment::{create, create_from_hash, ExpandedKey};
use lightning::routing::gossip::RoutingFees;
use lightning::routing::router::{RouteHint, RouteHintHop, Router};
use lightning::util::logger::Logger;
use secp256k1::PublicKey;
use core::ops::Deref;
use core::time::Duration;

/// Utility to create an invoice that can be paid to one of multiple nodes, or a "phantom invoice."
/// See [`PhantomKeysManager`] for more information on phantom node payments.
///
/// `phantom_route_hints` parameter:
/// * Contains channel info for all nodes participating in the phantom invoice
/// * Entries are retrieved from a call to [`ChannelManager::get_phantom_route_hints`] on each
///   participating node
/// * It is fine to cache `phantom_route_hints` and reuse it across invoices, as long as the data is
///   updated when a channel becomes disabled or closes
/// * Note that if too many channels are included in [`PhantomRouteHints::channels`], the invoice
///   may be too long for QR code scanning. To fix this, `PhantomRouteHints::channels` may be pared
///   down
///
/// `payment_hash` can be specified if you have a specific need for a custom payment hash (see the difference
/// between [`ChannelManager::create_inbound_payment`] and [`ChannelManager::create_inbound_payment_for_hash`]).
/// If `None` is provided for `payment_hash`, then one will be created.
///
/// `invoice_expiry_delta_secs` describes the number of seconds that the invoice is valid for
/// in excess of the current time.
/// 
/// `duration_since_epoch` is the current time since epoch in seconds.
///
/// You can specify a custom `min_final_cltv_expiry_delta`, or let LDK default it to
/// [`MIN_FINAL_CLTV_EXPIRY_DELTA`]. The provided expiry must be at least [`MIN_FINAL_CLTV_EXPIRY_DELTA`] - 3.
/// Note that LDK will add a buffer of 3 blocks to the delta to allow for up to a few new block
/// confirmations during routing.
///
/// Note that the provided `keys_manager`'s `NodeSigner` implementation must support phantom
/// invoices in its `sign_invoice` implementation ([`PhantomKeysManager`] satisfies this
/// requirement).
///
/// [`PhantomKeysManager`]: lightning::chain::keysinterface::PhantomKeysManager
/// [`ChannelManager::get_phantom_route_hints`]: lightning::ln::channelmanager::ChannelManager::get_phantom_route_hints
/// [`ChannelManager::create_inbound_payment`]: lightning::ln::channelmanager::ChannelManager::create_inbound_payment
/// [`ChannelManager::create_inbound_payment_for_hash`]: lightning::ln::channelmanager::ChannelManager::create_inbound_payment_for_hash
/// [`PhantomRouteHints::channels`]: lightning::ln::channelmanager::PhantomRouteHints::channels
/// [`MIN_FINAL_CLTV_EXPIRY_DETLA`]: lightning::ln::channelmanager::MIN_FINAL_CLTV_EXPIRY_DELTA
/// 
/// This can be used in a `no_std` environment, where [`std::time::SystemTime`] is not
/// available and the current time is supplied by the caller.
pub fn create_phantom_invoice<ES: Deref, NS: Deref, L: Deref>(
	amt_msat: Option<u64>, payment_hash: Option<PaymentHash>, description: String,
	invoice_expiry_delta_secs: u32, phantom_route_hints: Vec<PhantomRouteHints>, entropy_source: ES,
	node_signer: NS, logger: L, network: Currency, min_final_cltv_expiry_delta: Option<u16>, duration_since_epoch: Duration,
) -> Result<Invoice, SignOrCreationError<()>>
where
	ES::Target: EntropySource,
	NS::Target: NodeSigner,
	L::Target: Logger,
{
	let description = Description::new(description).map_err(SignOrCreationError::CreationError)?;
	let description = InvoiceDescription::Direct(&description,);
	_create_phantom_invoice::<ES, NS, L>(
		amt_msat, payment_hash, description, invoice_expiry_delta_secs, phantom_route_hints,
		entropy_source, node_signer, logger, network, min_final_cltv_expiry_delta, duration_since_epoch,
	)
}

/// Utility to create an invoice that can be paid to one of multiple nodes, or a "phantom invoice."
/// See [`PhantomKeysManager`] for more information on phantom node payments.
///
/// `phantom_route_hints` parameter:
/// * Contains channel info for all nodes participating in the phantom invoice
/// * Entries are retrieved from a call to [`ChannelManager::get_phantom_route_hints`] on each
///   participating node
/// * It is fine to cache `phantom_route_hints` and reuse it across invoices, as long as the data is
///   updated when a channel becomes disabled or closes
/// * Note that if too many channels are included in [`PhantomRouteHints::channels`], the invoice
///   may be too long for QR code scanning. To fix this, `PhantomRouteHints::channels` may be pared
///   down
///
/// `description_hash` is a SHA-256 hash of the description text
///
/// `payment_hash` can be specified if you have a specific need for a custom payment hash (see the difference
/// between [`ChannelManager::create_inbound_payment`] and [`ChannelManager::create_inbound_payment_for_hash`]).
/// If `None` is provided for `payment_hash`, then one will be created.
///
/// `invoice_expiry_delta_secs` describes the number of seconds that the invoice is valid for
/// in excess of the current time.
/// 
/// `duration_since_epoch` is the current time since epoch in seconds.
///
/// Note that the provided `keys_manager`'s `NodeSigner` implementation must support phantom
/// invoices in its `sign_invoice` implementation ([`PhantomKeysManager`] satisfies this
/// requirement).
///
/// [`PhantomKeysManager`]: lightning::chain::keysinterface::PhantomKeysManager
/// [`ChannelManager::get_phantom_route_hints`]: lightning::ln::channelmanager::ChannelManager::get_phantom_route_hints
/// [`ChannelManager::create_inbound_payment`]: lightning::ln::channelmanager::ChannelManager::create_inbound_payment
/// [`ChannelManager::create_inbound_payment_for_hash`]: lightning::ln::channelmanager::ChannelManager::create_inbound_payment_for_hash
/// [`PhantomRouteHints::channels`]: lightning::ln::channelmanager::PhantomRouteHints::channels
/// 
/// This can be used in a `no_std` environment, where [`std::time::SystemTime`] is not
/// available and the current time is supplied by the caller.
pub fn create_phantom_invoice_with_description_hash<ES: Deref, NS: Deref, L: Deref>(
	amt_msat: Option<u64>, payment_hash: Option<PaymentHash>, invoice_expiry_delta_secs: u32,
	description_hash: Sha256, phantom_route_hints: Vec<PhantomRouteHints>, entropy_source: ES,
	node_signer: NS, logger: L, network: Currency, min_final_cltv_expiry_delta: Option<u16>, duration_since_epoch: Duration,
) -> Result<Invoice, SignOrCreationError<()>>
where
	ES::Target: EntropySource,
	NS::Target: NodeSigner,
	L::Target: Logger,
{
	_create_phantom_invoice::<ES, NS, L>(
		amt_msat, payment_hash, InvoiceDescription::Hash(&description_hash),
		invoice_expiry_delta_secs, phantom_route_hints, entropy_source, node_signer, logger, network,
		min_final_cltv_expiry_delta, duration_since_epoch,
	)
}

fn _create_phantom_invoice<ES: Deref, NS: Deref, L: Deref>(
	amt_msat: Option<u64>, payment_hash: Option<PaymentHash>, description: InvoiceDescription,
	invoice_expiry_delta_secs: u32, phantom_route_hints: Vec<PhantomRouteHints>, entropy_source: ES,
	node_signer: NS, logger: L, network: Currency, min_final_cltv_expiry_delta: Option<u16>, duration_since_epoch: Duration,
) -> Result<Invoice, SignOrCreationError<()>>
where
	ES::Target: EntropySource,
	NS::Target: NodeSigner,
	L::Target: Logger,
{

	if phantom_route_hints.len() == 0 {
		return Err(SignOrCreationError::CreationError(
			CreationError::MissingRouteHints,
		));
	}

	if min_final_cltv_expiry_delta.is_some() && min_final_cltv_expiry_delta.unwrap().saturating_add(3) < MIN_FINAL_CLTV_EXPIRY_DELTA {
		return Err(SignOrCreationError::CreationError(CreationError::MinFinalCltvExpiryDeltaTooShort));
	}

	let invoice = match description {
		InvoiceDescription::Direct(description) => {
			InvoiceBuilder::new(network).description(description.0.clone())
		}
		InvoiceDescription::Hash(hash) => InvoiceBuilder::new(network).description_hash(hash.0),
	};

	// If we ever see performance here being too slow then we should probably take this ExpandedKey as a parameter instead.
	let keys = ExpandedKey::new(&node_signer.get_inbound_payment_key_material());
	let (payment_hash, payment_secret) = if let Some(payment_hash) = payment_hash {
		let payment_secret = create_from_hash(
			&keys,
			amt_msat,
			payment_hash,
			invoice_expiry_delta_secs,
			duration_since_epoch
				.as_secs(),
			min_final_cltv_expiry_delta,
		)
		.map_err(|_| SignOrCreationError::CreationError(CreationError::InvalidAmount))?;
		(payment_hash, payment_secret)
	} else {
		create(
			&keys,
			amt_msat,
			invoice_expiry_delta_secs,
			&entropy_source,
			duration_since_epoch
				.as_secs(),
			min_final_cltv_expiry_delta,
		)
		.map_err(|_| SignOrCreationError::CreationError(CreationError::InvalidAmount))?
	};

	log_trace!(logger, "Creating phantom invoice from {} participating nodes with payment hash {}",
		phantom_route_hints.len(), log_bytes!(payment_hash.0));

	let mut invoice = invoice
		.duration_since_epoch(duration_since_epoch)
		.payment_hash(Hash::from_slice(&payment_hash.0).unwrap())
		.payment_secret(payment_secret)
		.min_final_cltv_expiry_delta(
			// Add a buffer of 3 to the delta if present, otherwise use LDK's minimum.
			min_final_cltv_expiry_delta.map(|x| x.saturating_add(3)).unwrap_or(MIN_FINAL_CLTV_EXPIRY_DELTA).into())
		.expiry_time(Duration::from_secs(invoice_expiry_delta_secs.into()));
	if let Some(amt) = amt_msat {
		invoice = invoice.amount_milli_satoshis(amt);
	}

	for PhantomRouteHints { channels, phantom_scid, real_node_pubkey } in phantom_route_hints {
		log_trace!(logger, "Generating phantom route hints for node {}",
			log_pubkey!(real_node_pubkey));
		let mut route_hints = filter_channels(channels, amt_msat, &logger);

		// If we have any public channel, the route hints from `filter_channels` will be empty.
		// In that case we create a RouteHint on which we will push a single hop with the phantom
		// route into the invoice, and let the sender find the path to the `real_node_pubkey`
		// node by looking at our public channels.
		if route_hints.is_empty() {
			route_hints.push(RouteHint(vec![]))
		}
		for mut route_hint in route_hints {
			route_hint.0.push(RouteHintHop {
				src_node_id: real_node_pubkey,
				short_channel_id: phantom_scid,
				fees: RoutingFees {
					base_msat: 0,
					proportional_millionths: 0,
				},
				cltv_expiry_delta: MIN_CLTV_EXPIRY_DELTA,
				htlc_minimum_msat: None,
				htlc_maximum_msat: None,});
			invoice = invoice.private_route(route_hint.clone());
		}
	}

	let raw_invoice = match invoice.build_raw() {
		Ok(inv) => inv,
		Err(e) => return Err(SignOrCreationError::CreationError(e))
	};
	let hrp_str = raw_invoice.hrp.to_string();
	let hrp_bytes = hrp_str.as_bytes();
	let data_without_signature = raw_invoice.data.to_base32();
	let signed_raw_invoice = raw_invoice.sign(|_| node_signer.sign_invoice(hrp_bytes, &data_without_signature, Recipient::PhantomNode));
	match signed_raw_invoice {
		Ok(inv) => Ok(Invoice::from_signed(inv).unwrap()),
		Err(e) => Err(SignOrCreationError::SignError(e))
	}
}

#[cfg(feature = "std")]
/// Utility to construct an invoice. Generally, unless you want to do something like a custom
/// cltv_expiry, this is what you should be using to create an invoice. The reason being, this
/// method stores the invoice's payment secret and preimage in `ChannelManager`, so (a) the user
/// doesn't have to store preimage/payment secret information and (b) `ChannelManager` can verify
/// that the payment secret is valid when the invoice is paid.
///
/// `invoice_expiry_delta_secs` describes the number of seconds that the invoice is valid for
/// in excess of the current time.
///
/// You can specify a custom `min_final_cltv_expiry_delta`, or let LDK default it to
/// [`MIN_FINAL_CLTV_EXPIRY_DELTA`]. The provided expiry must be at least [`MIN_FINAL_CLTV_EXPIRY_DELTA`].
/// Note that LDK will add a buffer of 3 blocks to the delta to allow for up to a few new block
/// confirmations during routing.
///
/// [`MIN_FINAL_CLTV_EXPIRY_DETLA`]: lightning::ln::channelmanager::MIN_FINAL_CLTV_EXPIRY_DELTA
pub fn create_invoice_from_channelmanager<M: Deref, T: Deref, ES: Deref, NS: Deref, SP: Deref, F: Deref, R: Deref, L: Deref>(
	channelmanager: &ChannelManager<M, T, ES, NS, SP, F, R, L>, node_signer: NS, logger: L,
	network: Currency, amt_msat: Option<u64>, description: String, invoice_expiry_delta_secs: u32,
	min_final_cltv_expiry_delta: Option<u16>,
) -> Result<Invoice, SignOrCreationError<()>>
where
	M::Target: chain::Watch<<SP::Target as SignerProvider>::Signer>,
	T::Target: BroadcasterInterface,
	ES::Target: EntropySource,
	NS::Target: NodeSigner,
	SP::Target: SignerProvider,
	F::Target: FeeEstimator,
	R::Target: Router,
	L::Target: Logger,
{
	use std::time::SystemTime;
	let duration = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH)
		.expect("for the foreseeable future this shouldn't happen");
	create_invoice_from_channelmanager_and_duration_since_epoch(
		channelmanager, node_signer, logger, network, amt_msat,
		description, duration, invoice_expiry_delta_secs, min_final_cltv_expiry_delta,
	)
}

#[cfg(feature = "std")]
/// Utility to construct an invoice. Generally, unless you want to do something like a custom
/// cltv_expiry, this is what you should be using to create an invoice. The reason being, this
/// method stores the invoice's payment secret and preimage in `ChannelManager`, so (a) the user
/// doesn't have to store preimage/payment secret information and (b) `ChannelManager` can verify
/// that the payment secret is valid when the invoice is paid.
/// Use this variant if you want to pass the `description_hash` to the invoice.
///
/// `invoice_expiry_delta_secs` describes the number of seconds that the invoice is valid for
/// in excess of the current time.
///
/// You can specify a custom `min_final_cltv_expiry_delta`, or let LDK default it to
/// [`MIN_FINAL_CLTV_EXPIRY_DELTA`]. The provided expiry must be at least [`MIN_FINAL_CLTV_EXPIRY_DELTA`].
/// Note that LDK will add a buffer of 3 blocks to the delta to allow for up to a few new block
/// confirmations during routing.
///
/// [`MIN_FINAL_CLTV_EXPIRY_DETLA`]: lightning::ln::channelmanager::MIN_FINAL_CLTV_EXPIRY_DELTA
pub fn create_invoice_from_channelmanager_with_description_hash<M: Deref, T: Deref, ES: Deref, NS: Deref, SP: Deref, F: Deref, R: Deref, L: Deref>(
	channelmanager: &ChannelManager<M, T, ES, NS, SP, F, R, L>, node_signer: NS, logger: L,
	network: Currency, amt_msat: Option<u64>, description_hash: Sha256,
	invoice_expiry_delta_secs: u32, min_final_cltv_expiry_delta: Option<u16>,
) -> Result<Invoice, SignOrCreationError<()>>
where
	M::Target: chain::Watch<<SP::Target as SignerProvider>::Signer>,
	T::Target: BroadcasterInterface,
	ES::Target: EntropySource,
	NS::Target: NodeSigner,
	SP::Target: SignerProvider,
	F::Target: FeeEstimator,
	R::Target: Router,
	L::Target: Logger,
{
	use std::time::SystemTime;

	let duration = SystemTime::now()
		.duration_since(SystemTime::UNIX_EPOCH)
		.expect("for the foreseeable future this shouldn't happen");

	create_invoice_from_channelmanager_with_description_hash_and_duration_since_epoch(
		channelmanager, node_signer, logger, network, amt_msat,
		description_hash, duration, invoice_expiry_delta_secs, min_final_cltv_expiry_delta,
	)
}

/// See [`create_invoice_from_channelmanager_with_description_hash`]
/// This version can be used in a `no_std` environment, where [`std::time::SystemTime`] is not
/// available and the current time is supplied by the caller.
pub fn create_invoice_from_channelmanager_with_description_hash_and_duration_since_epoch<M: Deref, T: Deref, ES: Deref, NS: Deref, SP: Deref, F: Deref, R: Deref, L: Deref>(
	channelmanager: &ChannelManager<M, T, ES, NS, SP, F, R, L>, node_signer: NS, logger: L,
	network: Currency, amt_msat: Option<u64>, description_hash: Sha256,
	duration_since_epoch: Duration, invoice_expiry_delta_secs: u32, min_final_cltv_expiry_delta: Option<u16>,
) -> Result<Invoice, SignOrCreationError<()>>
		where
			M::Target: chain::Watch<<SP::Target as SignerProvider>::Signer>,
			T::Target: BroadcasterInterface,
			ES::Target: EntropySource,
			NS::Target: NodeSigner,
			SP::Target: SignerProvider,
			F::Target: FeeEstimator,
			R::Target: Router,
			L::Target: Logger,
{
	_create_invoice_from_channelmanager_and_duration_since_epoch(
		channelmanager, node_signer, logger, network, amt_msat,
		InvoiceDescription::Hash(&description_hash),
		duration_since_epoch, invoice_expiry_delta_secs, min_final_cltv_expiry_delta,
	)
}

/// See [`create_invoice_from_channelmanager`]
/// This version can be used in a `no_std` environment, where [`std::time::SystemTime`] is not
/// available and the current time is supplied by the caller.
pub fn create_invoice_from_channelmanager_and_duration_since_epoch<M: Deref, T: Deref, ES: Deref, NS: Deref, SP: Deref, F: Deref, R: Deref, L: Deref>(
	channelmanager: &ChannelManager<M, T, ES, NS, SP, F, R, L>, node_signer: NS, logger: L,
	network: Currency, amt_msat: Option<u64>, description: String, duration_since_epoch: Duration,
	invoice_expiry_delta_secs: u32, min_final_cltv_expiry_delta: Option<u16>,
) -> Result<Invoice, SignOrCreationError<()>>
		where
			M::Target: chain::Watch<<SP::Target as SignerProvider>::Signer>,
			T::Target: BroadcasterInterface,
			ES::Target: EntropySource,
			NS::Target: NodeSigner,
			SP::Target: SignerProvider,
			F::Target: FeeEstimator,
			R::Target: Router,
			L::Target: Logger,
{
	_create_invoice_from_channelmanager_and_duration_since_epoch(
		channelmanager, node_signer, logger, network, amt_msat,
		InvoiceDescription::Direct(
			&Description::new(description).map_err(SignOrCreationError::CreationError)?,
		),
		duration_since_epoch, invoice_expiry_delta_secs, min_final_cltv_expiry_delta,
	)
}

fn _create_invoice_from_channelmanager_and_duration_since_epoch<M: Deref, T: Deref, ES: Deref, NS: Deref, SP: Deref, F: Deref, R: Deref, L: Deref>(
	channelmanager: &ChannelManager<M, T, ES, NS, SP, F, R, L>, node_signer: NS, logger: L,
	network: Currency, amt_msat: Option<u64>, description: InvoiceDescription,
	duration_since_epoch: Duration, invoice_expiry_delta_secs: u32, min_final_cltv_expiry_delta: Option<u16>,
) -> Result<Invoice, SignOrCreationError<()>>
		where
			M::Target: chain::Watch<<SP::Target as SignerProvider>::Signer>,
			T::Target: BroadcasterInterface,
			ES::Target: EntropySource,
			NS::Target: NodeSigner,
			SP::Target: SignerProvider,
			F::Target: FeeEstimator,
			R::Target: Router,
			L::Target: Logger,
{
	if min_final_cltv_expiry_delta.is_some() && min_final_cltv_expiry_delta.unwrap().saturating_add(3) < MIN_FINAL_CLTV_EXPIRY_DELTA {
		return Err(SignOrCreationError::CreationError(CreationError::MinFinalCltvExpiryDeltaTooShort));
	}

	// `create_inbound_payment` only returns an error if the amount is greater than the total bitcoin
	// supply.
	let (payment_hash, payment_secret) = channelmanager
		.create_inbound_payment(amt_msat, invoice_expiry_delta_secs, min_final_cltv_expiry_delta)
		.map_err(|()| SignOrCreationError::CreationError(CreationError::InvalidAmount))?;
	_create_invoice_from_channelmanager_and_duration_since_epoch_with_payment_hash(
		channelmanager, node_signer, logger, network, amt_msat, description, duration_since_epoch,
		invoice_expiry_delta_secs, payment_hash, payment_secret, min_final_cltv_expiry_delta)
}

/// See [`create_invoice_from_channelmanager_and_duration_since_epoch`]
/// This version allows for providing a custom [`PaymentHash`] for the invoice.
/// This may be useful if you're building an on-chain swap or involving another protocol where
/// the payment hash is also involved outside the scope of lightning.
pub fn create_invoice_from_channelmanager_and_duration_since_epoch_with_payment_hash<M: Deref, T: Deref, ES: Deref, NS: Deref, SP: Deref, F: Deref, R: Deref, L: Deref>(
	channelmanager: &ChannelManager<M, T, ES, NS, SP, F, R, L>, node_signer: NS, logger: L,
	network: Currency, amt_msat: Option<u64>, description: String, duration_since_epoch: Duration,
	invoice_expiry_delta_secs: u32, payment_hash: PaymentHash, min_final_cltv_expiry_delta: Option<u16>,
) -> Result<Invoice, SignOrCreationError<()>>
	where
		M::Target: chain::Watch<<SP::Target as SignerProvider>::Signer>,
		T::Target: BroadcasterInterface,
		ES::Target: EntropySource,
		NS::Target: NodeSigner,
		SP::Target: SignerProvider,
		F::Target: FeeEstimator,
		R::Target: Router,
		L::Target: Logger,
{
	let payment_secret = channelmanager
		.create_inbound_payment_for_hash(payment_hash, amt_msat, invoice_expiry_delta_secs,
			min_final_cltv_expiry_delta)
		.map_err(|()| SignOrCreationError::CreationError(CreationError::InvalidAmount))?;
	_create_invoice_from_channelmanager_and_duration_since_epoch_with_payment_hash(
		channelmanager, node_signer, logger, network, amt_msat,
		InvoiceDescription::Direct(
			&Description::new(description).map_err(SignOrCreationError::CreationError)?,
		),
		duration_since_epoch, invoice_expiry_delta_secs, payment_hash, payment_secret,
		min_final_cltv_expiry_delta,
	)
}

fn _create_invoice_from_channelmanager_and_duration_since_epoch_with_payment_hash<M: Deref, T: Deref, ES: Deref, NS: Deref, SP: Deref, F: Deref, R: Deref, L: Deref>(
	channelmanager: &ChannelManager<M, T, ES, NS, SP, F, R, L>, node_signer: NS, logger: L,
	network: Currency, amt_msat: Option<u64>, description: InvoiceDescription, duration_since_epoch: Duration,
	invoice_expiry_delta_secs: u32, payment_hash: PaymentHash, payment_secret: PaymentSecret,
	min_final_cltv_expiry_delta: Option<u16>,
) -> Result<Invoice, SignOrCreationError<()>>
	where
		M::Target: chain::Watch<<SP::Target as SignerProvider>::Signer>,
		T::Target: BroadcasterInterface,
		ES::Target: EntropySource,
		NS::Target: NodeSigner,
		SP::Target: SignerProvider,
		F::Target: FeeEstimator,
		R::Target: Router,
		L::Target: Logger,
{
	let our_node_pubkey = channelmanager.get_our_node_id();
	let channels = channelmanager.list_channels();

	if min_final_cltv_expiry_delta.is_some() && min_final_cltv_expiry_delta.unwrap().saturating_add(3) < MIN_FINAL_CLTV_EXPIRY_DELTA {
		return Err(SignOrCreationError::CreationError(CreationError::MinFinalCltvExpiryDeltaTooShort));
	}

	log_trace!(logger, "Creating invoice with payment hash {}", log_bytes!(payment_hash.0));

	let invoice = match description {
		InvoiceDescription::Direct(description) => {
			InvoiceBuilder::new(network).description(description.0.clone())
		}
		InvoiceDescription::Hash(hash) => InvoiceBuilder::new(network).description_hash(hash.0),
	};

	let mut invoice = invoice
		.duration_since_epoch(duration_since_epoch)
		.payee_pub_key(our_node_pubkey)
		.payment_hash(Hash::from_slice(&payment_hash.0).unwrap())
		.payment_secret(payment_secret)
		.basic_mpp()
		.min_final_cltv_expiry_delta(
			// Add a buffer of 3 to the delta if present, otherwise use LDK's minimum.
			min_final_cltv_expiry_delta.map(|x| x.saturating_add(3)).unwrap_or(MIN_FINAL_CLTV_EXPIRY_DELTA).into())
		.expiry_time(Duration::from_secs(invoice_expiry_delta_secs.into()));
	if let Some(amt) = amt_msat {
		invoice = invoice.amount_milli_satoshis(amt);
	}

	let route_hints = filter_channels(channels, amt_msat, &logger);
	for hint in route_hints {
		invoice = invoice.private_route(hint);
	}

	let raw_invoice = match invoice.build_raw() {
		Ok(inv) => inv,
		Err(e) => return Err(SignOrCreationError::CreationError(e))
	};
	let hrp_str = raw_invoice.hrp.to_string();
	let hrp_bytes = hrp_str.as_bytes();
	let data_without_signature = raw_invoice.data.to_base32();
	let signed_raw_invoice = raw_invoice.sign(|_| node_signer.sign_invoice(hrp_bytes, &data_without_signature, Recipient::Node));
	match signed_raw_invoice {
		Ok(inv) => Ok(Invoice::from_signed(inv).unwrap()),
		Err(e) => Err(SignOrCreationError::SignError(e))
	}
}

/// Filters the `channels` for an invoice, and returns the corresponding `RouteHint`s to include
/// in the invoice.
///
/// The filtering is based on the following criteria:
/// * Only one channel per counterparty node
/// * Always select the channel with the highest inbound capacity per counterparty node
/// * Prefer channels with capacity at least `min_inbound_capacity_msat` and where the channel
///   `is_usable` (i.e. the peer is connected).
/// * If any public channel exists, the returned `RouteHint`s will be empty, and the sender will
///   need to find the path by looking at the public channels instead
fn filter_channels<L: Deref>(
	channels: Vec<ChannelDetails>, min_inbound_capacity_msat: Option<u64>, logger: &L
) -> Vec<RouteHint> where L::Target: Logger {
	let mut filtered_channels: HashMap<PublicKey, ChannelDetails> = HashMap::new();
	let min_inbound_capacity = min_inbound_capacity_msat.unwrap_or(0);
	let mut min_capacity_channel_exists = false;
	let mut online_channel_exists = false;
	let mut online_min_capacity_channel_exists = false;

	log_trace!(logger, "Considering {} channels for invoice route hints", channels.len());
	for channel in channels.into_iter().filter(|chan| chan.is_channel_ready) {
		if channel.get_inbound_payment_scid().is_none() || channel.counterparty.forwarding_info.is_none() {
			log_trace!(logger, "Ignoring channel {} for invoice route hints", log_bytes!(channel.channel_id));
			continue;
		}

		if channel.is_public {
			// If any public channel exists, return no hints and let the sender
			// look at the public channels instead.
			log_trace!(logger, "Not including channels in invoice route hints on account of public channel {}",
				log_bytes!(channel.channel_id));
			return vec![]
		}

		if channel.inbound_capacity_msat >= min_inbound_capacity {
			if !min_capacity_channel_exists {
				log_trace!(logger, "Channel with enough inbound capacity exists for invoice route hints");
				min_capacity_channel_exists = true;
			}

			if channel.is_usable {
				online_min_capacity_channel_exists = true;
			}
		}

		if channel.is_usable {
			if !online_channel_exists {
				log_trace!(logger, "Channel with connected peer exists for invoice route hints");
				online_channel_exists = true;
			}
		}

		match filtered_channels.entry(channel.counterparty.node_id) {
			hash_map::Entry::Occupied(mut entry) => {
				let current_max_capacity = entry.get().inbound_capacity_msat;
				if channel.inbound_capacity_msat < current_max_capacity {
					log_trace!(logger,
						"Preferring counterparty {} channel {} ({} msats) over {} ({} msats) for invoice route hints",
						log_pubkey!(channel.counterparty.node_id),
						log_bytes!(entry.get().channel_id), current_max_capacity,
						log_bytes!(channel.channel_id), channel.inbound_capacity_msat);
					continue;
				}
				log_trace!(logger,
					"Preferring counterparty {} channel {} ({} msats) over {} ({} msats) for invoice route hints",
					log_pubkey!(channel.counterparty.node_id),
					log_bytes!(channel.channel_id), channel.inbound_capacity_msat,
					log_bytes!(entry.get().channel_id), current_max_capacity);
				entry.insert(channel);
			}
			hash_map::Entry::Vacant(entry) => {
				entry.insert(channel);
			}
		}
	}

	let route_hint_from_channel = |channel: ChannelDetails| {
		let forwarding_info = channel.counterparty.forwarding_info.as_ref().unwrap();
		RouteHint(vec![RouteHintHop {
			src_node_id: channel.counterparty.node_id,
			short_channel_id: channel.get_inbound_payment_scid().unwrap(),
			fees: RoutingFees {
				base_msat: forwarding_info.fee_base_msat,
				proportional_millionths: forwarding_info.fee_proportional_millionths,
			},
			cltv_expiry_delta: forwarding_info.cltv_expiry_delta,
			htlc_minimum_msat: channel.inbound_htlc_minimum_msat,
			htlc_maximum_msat: channel.inbound_htlc_maximum_msat,}])
	};
	// If all channels are private, prefer to return route hints which have a higher capacity than
	// the payment value and where we're currently connected to the channel counterparty.
	// Even if we cannot satisfy both goals, always ensure we include *some* hints, preferring
	// those which meet at least one criteria.
	filtered_channels
		.into_iter()
		.map(|(_, channel)| channel)
		.filter(|channel| {
			let has_enough_capacity = channel.inbound_capacity_msat >= min_inbound_capacity;
			let include_channel = if online_min_capacity_channel_exists {
				has_enough_capacity && channel.is_usable
			} else if min_capacity_channel_exists && online_channel_exists {
				// If there are some online channels and some min_capacity channels, but no
				// online-and-min_capacity channels, just include the min capacity ones and ignore
				// online-ness.
				has_enough_capacity
			} else if min_capacity_channel_exists {
				has_enough_capacity
			} else if online_channel_exists {
				channel.is_usable
			} else { true };

			if include_channel {
				log_trace!(logger, "Including channel {} in invoice route hints",
					log_bytes!(channel.channel_id));
			} else if !has_enough_capacity {
				log_trace!(logger, "Ignoring channel {} without enough capacity for invoice route hints",
					log_bytes!(channel.channel_id));
			} else {
				debug_assert!(!channel.is_usable);
				log_trace!(logger, "Ignoring channel {} with disconnected peer",
					log_bytes!(channel.channel_id));
			}

			include_channel
		})
		.map(route_hint_from_channel)
		.collect::<Vec<RouteHint>>()
}

#[cfg(test)]
mod test {
	use core::time::Duration;
	use crate::{Currency, Description, InvoiceDescription, SignOrCreationError, CreationError};
	use bitcoin_hashes::{Hash, sha256};
	use bitcoin_hashes::sha256::Hash as Sha256;
	use lightning::chain::keysinterface::{EntropySource, PhantomKeysManager};
	use lightning::ln::{PaymentPreimage, PaymentHash};
	use lightning::ln::channelmanager::{PhantomRouteHints, MIN_FINAL_CLTV_EXPIRY_DELTA, PaymentId};
	use lightning::ln::functional_test_utils::*;
	use lightning::ln::msgs::ChannelMessageHandler;
	use lightning::routing::router::{PaymentParameters, RouteParameters, find_route};
	use lightning::util::events::{MessageSendEvent, MessageSendEventsProvider, Event};
	use lightning::util::test_utils;
	use lightning::util::config::UserConfig;
	use crate::utils::create_invoice_from_channelmanager_and_duration_since_epoch;
	use std::collections::HashSet;

	#[test]
	fn test_from_channelmanager() {
		let chanmon_cfgs = create_chanmon_cfgs(2);
		let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
		let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
		let nodes = create_network(2, &node_cfgs, &node_chanmgrs);
		create_unannounced_chan_between_nodes_with_value(&nodes, 0, 1, 100000, 10001);
		let non_default_invoice_expiry_secs = 4200;
		let invoice = create_invoice_from_channelmanager_and_duration_since_epoch(
			&nodes[1].node, nodes[1].keys_manager, nodes[1].logger, Currency::BitcoinTestnet,
			Some(10_000), "test".to_string(), Duration::from_secs(1234567),
			non_default_invoice_expiry_secs, None).unwrap();
		assert_eq!(invoice.amount_pico_btc(), Some(100_000));
		// If no `min_final_cltv_expiry_delta` is specified, then it should be `MIN_FINAL_CLTV_EXPIRY_DELTA`.
		assert_eq!(invoice.min_final_cltv_expiry_delta(), MIN_FINAL_CLTV_EXPIRY_DELTA as u64);
		assert_eq!(invoice.description(), InvoiceDescription::Direct(&Description("test".to_string())));
		assert_eq!(invoice.expiry_time(), Duration::from_secs(non_default_invoice_expiry_secs.into()));

		// Invoice SCIDs should always use inbound SCID aliases over the real channel ID, if one is
		// available.
		let chan = &nodes[1].node.list_usable_channels()[0];
		assert_eq!(invoice.route_hints().len(), 1);
		assert_eq!(invoice.route_hints()[0].0.len(), 1);
		assert_eq!(invoice.route_hints()[0].0[0].short_channel_id, chan.inbound_scid_alias.unwrap());

		assert_eq!(invoice.route_hints()[0].0[0].htlc_minimum_msat, chan.inbound_htlc_minimum_msat);
		assert_eq!(invoice.route_hints()[0].0[0].htlc_maximum_msat, chan.inbound_htlc_maximum_msat);

		let payment_params = PaymentParameters::from_node_id(invoice.recover_payee_pub_key(),
				invoice.min_final_cltv_expiry_delta() as u32)
			.with_features(invoice.features().unwrap().clone())
			.with_route_hints(invoice.route_hints());
		let route_params = RouteParameters {
			payment_params,
			final_value_msat: invoice.amount_milli_satoshis().unwrap(),
		};
		let first_hops = nodes[0].node.list_usable_channels();
		let network_graph = &node_cfgs[0].network_graph;
		let logger = test_utils::TestLogger::new();
		let scorer = test_utils::TestScorer::new();
		let random_seed_bytes = chanmon_cfgs[1].keys_manager.get_secure_random_bytes();
		let route = find_route(
			&nodes[0].node.get_our_node_id(), &route_params, &network_graph,
			Some(&first_hops.iter().collect::<Vec<_>>()), &logger, &scorer, &random_seed_bytes
		).unwrap();

		let payment_event = {
			let mut payment_hash = PaymentHash([0; 32]);
			payment_hash.0.copy_from_slice(&invoice.payment_hash().as_ref()[0..32]);
			nodes[0].node.send_payment(&route, payment_hash, &Some(invoice.payment_secret().clone()), PaymentId(payment_hash.0)).unwrap();
			let mut added_monitors = nodes[0].chain_monitor.added_monitors.lock().unwrap();
			assert_eq!(added_monitors.len(), 1);
			added_monitors.clear();

			let mut events = nodes[0].node.get_and_clear_pending_msg_events();
			assert_eq!(events.len(), 1);
			SendEvent::from_event(events.remove(0))

		};
		nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &payment_event.msgs[0]);
		nodes[1].node.handle_commitment_signed(&nodes[0].node.get_our_node_id(), &payment_event.commitment_msg);
		let mut added_monitors = nodes[1].chain_monitor.added_monitors.lock().unwrap();
		assert_eq!(added_monitors.len(), 1);
		added_monitors.clear();
		let events = nodes[1].node.get_and_clear_pending_msg_events();
		assert_eq!(events.len(), 2);
	}

	fn do_create_invoice_min_final_cltv_delta(with_custom_delta: bool) {
		let chanmon_cfgs = create_chanmon_cfgs(2);
		let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
		let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
		let nodes = create_network(2, &node_cfgs, &node_chanmgrs);
		let custom_min_final_cltv_expiry_delta = Some(50);

		let invoice = crate::utils::create_invoice_from_channelmanager_and_duration_since_epoch(
			&nodes[1].node, nodes[1].keys_manager, nodes[1].logger, Currency::BitcoinTestnet,
			Some(10_000), "".into(), Duration::from_secs(1234567), 3600,
			if with_custom_delta { custom_min_final_cltv_expiry_delta } else { None },
		).unwrap();
		assert_eq!(invoice.min_final_cltv_expiry_delta(), if with_custom_delta {
			custom_min_final_cltv_expiry_delta.unwrap() + 3 /* Buffer */} else { MIN_FINAL_CLTV_EXPIRY_DELTA } as u64);
	}

	#[test]
	fn test_create_invoice_custom_min_final_cltv_delta() {
		do_create_invoice_min_final_cltv_delta(true);
		do_create_invoice_min_final_cltv_delta(false);
	}

	#[test]
	fn create_invoice_min_final_cltv_delta_equals_htlc_fail_buffer() {
		let chanmon_cfgs = create_chanmon_cfgs(2);
		let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
		let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
		let nodes = create_network(2, &node_cfgs, &node_chanmgrs);
		let custom_min_final_cltv_expiry_delta = Some(21);

		let invoice = crate::utils::create_invoice_from_channelmanager_and_duration_since_epoch(
			&nodes[1].node, nodes[1].keys_manager, nodes[1].logger, Currency::BitcoinTestnet,
			Some(10_000), "".into(), Duration::from_secs(1234567), 3600,
			custom_min_final_cltv_expiry_delta,
		).unwrap();
		assert_eq!(invoice.min_final_cltv_expiry_delta(), MIN_FINAL_CLTV_EXPIRY_DELTA as u64);
	}

	#[test]
	fn test_create_invoice_with_description_hash() {
		let chanmon_cfgs = create_chanmon_cfgs(2);
		let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
		let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
		let nodes = create_network(2, &node_cfgs, &node_chanmgrs);
		let description_hash = crate::Sha256(Hash::hash("Testing description_hash".as_bytes()));
		let invoice = crate::utils::create_invoice_from_channelmanager_with_description_hash_and_duration_since_epoch(
			&nodes[1].node, nodes[1].keys_manager, nodes[1].logger, Currency::BitcoinTestnet,
			Some(10_000), description_hash, Duration::from_secs(1234567), 3600, None,
		).unwrap();
		assert_eq!(invoice.amount_pico_btc(), Some(100_000));
		assert_eq!(invoice.min_final_cltv_expiry_delta(), MIN_FINAL_CLTV_EXPIRY_DELTA as u64);
		assert_eq!(invoice.description(), InvoiceDescription::Hash(&crate::Sha256(Sha256::hash("Testing description_hash".as_bytes()))));
	}

	#[test]
	fn test_create_invoice_from_channelmanager_and_duration_since_epoch_with_payment_hash() {
		let chanmon_cfgs = create_chanmon_cfgs(2);
		let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
		let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
		let nodes = create_network(2, &node_cfgs, &node_chanmgrs);
		let payment_hash = PaymentHash([0; 32]);
		let invoice = crate::utils::create_invoice_from_channelmanager_and_duration_since_epoch_with_payment_hash(
			&nodes[1].node, nodes[1].keys_manager, nodes[1].logger, Currency::BitcoinTestnet,
			Some(10_000), "test".to_string(), Duration::from_secs(1234567), 3600,
			payment_hash, None,
		).unwrap();
		assert_eq!(invoice.amount_pico_btc(), Some(100_000));
		assert_eq!(invoice.min_final_cltv_expiry_delta(), MIN_FINAL_CLTV_EXPIRY_DELTA as u64);
		assert_eq!(invoice.description(), InvoiceDescription::Direct(&Description("test".to_string())));
		assert_eq!(invoice.payment_hash(), &sha256::Hash::from_slice(&payment_hash.0[..]).unwrap());
	}

	#[test]
	fn test_hints_includes_single_channels_to_nodes() {
		let chanmon_cfgs = create_chanmon_cfgs(3);
		let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
		let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &[None, None, None]);
		let nodes = create_network(3, &node_cfgs, &node_chanmgrs);

		let chan_1_0 = create_unannounced_chan_between_nodes_with_value(&nodes, 1, 0, 100000, 10001);
		let chan_2_0 = create_unannounced_chan_between_nodes_with_value(&nodes, 2, 0, 100000, 10001);

		let mut scid_aliases = HashSet::new();
		scid_aliases.insert(chan_1_0.0.short_channel_id_alias.unwrap());
		scid_aliases.insert(chan_2_0.0.short_channel_id_alias.unwrap());

		match_invoice_routes(Some(5000), &nodes[0], scid_aliases);
	}

	#[test]
	fn test_hints_has_only_highest_inbound_capacity_channel() {
		let chanmon_cfgs = create_chanmon_cfgs(2);
		let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
		let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
		let nodes = create_network(2, &node_cfgs, &node_chanmgrs);
		let _chan_1_0_low_inbound_capacity = create_unannounced_chan_between_nodes_with_value(&nodes, 1, 0, 100_000, 0);
		let chan_1_0_high_inbound_capacity = create_unannounced_chan_between_nodes_with_value(&nodes, 1, 0, 10_000_000, 0);
		let _chan_1_0_medium_inbound_capacity = create_unannounced_chan_between_nodes_with_value(&nodes, 1, 0, 1_000_000, 0);
		let mut scid_aliases = HashSet::new();
		scid_aliases.insert(chan_1_0_high_inbound_capacity.0.short_channel_id_alias.unwrap());
		match_invoice_routes(Some(5000), &nodes[0], scid_aliases);
	}

	#[test]
	fn test_hints_has_only_online_channels() {
		let chanmon_cfgs = create_chanmon_cfgs(4);
		let node_cfgs = create_node_cfgs(4, &chanmon_cfgs);
		let node_chanmgrs = create_node_chanmgrs(4, &node_cfgs, &[None, None, None, None]);
		let nodes = create_network(4, &node_cfgs, &node_chanmgrs);
		let chan_a = create_unannounced_chan_between_nodes_with_value(&nodes, 1, 0, 10_000_000, 0);
		let chan_b = create_unannounced_chan_between_nodes_with_value(&nodes, 2, 0, 10_000_000, 0);
		let _chan_c = create_unannounced_chan_between_nodes_with_value(&nodes, 3, 0, 1_000_000, 0);

		// With all peers connected we should get all hints that have sufficient value
		let mut scid_aliases = HashSet::new();
		scid_aliases.insert(chan_a.0.short_channel_id_alias.unwrap());
		scid_aliases.insert(chan_b.0.short_channel_id_alias.unwrap());

		match_invoice_routes(Some(1_000_000_000), &nodes[0], scid_aliases.clone());

		// With only one sufficient-value peer connected we should only get its hint
		scid_aliases.remove(&chan_b.0.short_channel_id_alias.unwrap());
		nodes[0].node.peer_disconnected(&nodes[2].node.get_our_node_id());
		match_invoice_routes(Some(1_000_000_000), &nodes[0], scid_aliases.clone());

		// If we don't have any sufficient-value peers connected we should get all hints with
		// sufficient value, even though there is a connected insufficient-value peer.
		scid_aliases.insert(chan_b.0.short_channel_id_alias.unwrap());
		nodes[0].node.peer_disconnected(&nodes[1].node.get_our_node_id());
		match_invoice_routes(Some(1_000_000_000), &nodes[0], scid_aliases);
	}

	#[test]
	fn test_forwarding_info_not_assigned_channel_excluded_from_hints() {
		let chanmon_cfgs = create_chanmon_cfgs(3);
		let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
		let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &[None, None, None]);
		let nodes = create_network(3, &node_cfgs, &node_chanmgrs);
		let chan_1_0 = create_unannounced_chan_between_nodes_with_value(&nodes, 1, 0, 100000, 10001);

		// Create an unannonced channel between `nodes[2]` and `nodes[0]`, for which the
		// `msgs::ChannelUpdate` is never handled for the node(s). As the `msgs::ChannelUpdate`
		// is never handled, the `channel.counterparty.forwarding_info` is never assigned.
		let mut private_chan_cfg = UserConfig::default();
		private_chan_cfg.channel_handshake_config.announced_channel = false;
		let temporary_channel_id = nodes[2].node.create_channel(nodes[0].node.get_our_node_id(), 1_000_000, 500_000_000, 42, Some(private_chan_cfg)).unwrap();
		let open_channel = get_event_msg!(nodes[2], MessageSendEvent::SendOpenChannel, nodes[0].node.get_our_node_id());
		nodes[0].node.handle_open_channel(&nodes[2].node.get_our_node_id(), &open_channel);
		let accept_channel = get_event_msg!(nodes[0], MessageSendEvent::SendAcceptChannel, nodes[2].node.get_our_node_id());
		nodes[2].node.handle_accept_channel(&nodes[0].node.get_our_node_id(), &accept_channel);

		let tx = sign_funding_transaction(&nodes[2], &nodes[0], 1_000_000, temporary_channel_id);

		let conf_height = core::cmp::max(nodes[2].best_block_info().1 + 1, nodes[0].best_block_info().1 + 1);
		confirm_transaction_at(&nodes[2], &tx, conf_height);
		connect_blocks(&nodes[2], CHAN_CONFIRM_DEPTH - 1);
		confirm_transaction_at(&nodes[0], &tx, conf_height);
		connect_blocks(&nodes[0], CHAN_CONFIRM_DEPTH - 1);
		let as_channel_ready = get_event_msg!(nodes[2], MessageSendEvent::SendChannelReady, nodes[0].node.get_our_node_id());
		nodes[2].node.handle_channel_ready(&nodes[0].node.get_our_node_id(), &get_event_msg!(nodes[0], MessageSendEvent::SendChannelReady, nodes[2].node.get_our_node_id()));
		get_event_msg!(nodes[2], MessageSendEvent::SendChannelUpdate, nodes[0].node.get_our_node_id());
		nodes[0].node.handle_channel_ready(&nodes[2].node.get_our_node_id(), &as_channel_ready);
		get_event_msg!(nodes[0], MessageSendEvent::SendChannelUpdate, nodes[2].node.get_our_node_id());
		expect_channel_ready_event(&nodes[0], &nodes[2].node.get_our_node_id());
		expect_channel_ready_event(&nodes[2], &nodes[0].node.get_our_node_id());

		// As `msgs::ChannelUpdate` was never handled for the participating node(s) of the second
		// channel, the channel will never be assigned any `counterparty.forwarding_info`.
		// Therefore only `chan_1_0` should be included in the hints.
		let mut scid_aliases = HashSet::new();
		scid_aliases.insert(chan_1_0.0.short_channel_id_alias.unwrap());
		match_invoice_routes(Some(5000), &nodes[0], scid_aliases);
	}

	#[test]
	fn test_no_hints_if_a_mix_between_public_and_private_channel_exists() {
		let chanmon_cfgs = create_chanmon_cfgs(3);
		let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
		let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &[None, None, None]);
		let nodes = create_network(3, &node_cfgs, &node_chanmgrs);
		let _chan_1_0 = create_unannounced_chan_between_nodes_with_value(&nodes, 1, 0, 100000, 10001);

		let chan_2_0 = create_announced_chan_between_nodes_with_value(&nodes, 2, 0, 100000, 10001);
		nodes[2].node.handle_channel_update(&nodes[0].node.get_our_node_id(), &chan_2_0.1);
		nodes[0].node.handle_channel_update(&nodes[2].node.get_our_node_id(), &chan_2_0.0);

		// Ensure that the invoice doesn't include any route hints for any of `nodes[0]` channels,
		// even though all channels between `nodes[1]` and `nodes[0]` are private, as there is a
		// public channel between `nodes[2]` and `nodes[0]`
		match_invoice_routes(Some(5000), &nodes[0], HashSet::new());
	}

	#[test]
	fn test_only_public_channels_includes_no_channels_in_hints() {
		let chanmon_cfgs = create_chanmon_cfgs(3);
		let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
		let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &[None, None, None]);
		let nodes = create_network(3, &node_cfgs, &node_chanmgrs);
		let chan_1_0 = create_announced_chan_between_nodes_with_value(&nodes, 1, 0, 100000, 10001);
		nodes[0].node.handle_channel_update(&nodes[1].node.get_our_node_id(), &chan_1_0.0);
		nodes[1].node.handle_channel_update(&nodes[0].node.get_our_node_id(), &chan_1_0.1);

		let chan_2_0 = create_announced_chan_between_nodes_with_value(&nodes, 2, 0, 100000, 10001);
		nodes[2].node.handle_channel_update(&nodes[0].node.get_our_node_id(), &chan_2_0.1);
		nodes[0].node.handle_channel_update(&nodes[2].node.get_our_node_id(), &chan_2_0.0);

		// As all of `nodes[0]` channels are public, no channels should be included in the hints
		match_invoice_routes(Some(5000), &nodes[0], HashSet::new());
	}

	#[test]
	fn test_channels_with_lower_inbound_capacity_than_invoice_amt_hints_filtering() {
		let chanmon_cfgs = create_chanmon_cfgs(3);
		let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
		let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &[None, None, None]);
		let nodes = create_network(3, &node_cfgs, &node_chanmgrs);
		let chan_1_0 = create_unannounced_chan_between_nodes_with_value(&nodes, 1, 0, 100_000, 0);
		let chan_2_0 = create_unannounced_chan_between_nodes_with_value(&nodes, 2, 0, 1_000_000, 0);

		// As the invoice amt is 1 msat above chan_1_0's inbound capacity, it shouldn't be included
		let mut scid_aliases_99_000_001_msat = HashSet::new();
		scid_aliases_99_000_001_msat.insert(chan_2_0.0.short_channel_id_alias.unwrap());

		match_invoice_routes(Some(99_000_001), &nodes[0], scid_aliases_99_000_001_msat);

		// As the invoice amt is exactly at chan_1_0's inbound capacity, it should be included
		let mut scid_aliases_99_000_000_msat = HashSet::new();
		scid_aliases_99_000_000_msat.insert(chan_1_0.0.short_channel_id_alias.unwrap());
		scid_aliases_99_000_000_msat.insert(chan_2_0.0.short_channel_id_alias.unwrap());

		match_invoice_routes(Some(99_000_000), &nodes[0], scid_aliases_99_000_000_msat);

		// As the invoice amt is above all channels' inbound capacity, they will still be included
		let mut scid_aliases_2_000_000_000_msat = HashSet::new();
		scid_aliases_2_000_000_000_msat.insert(chan_1_0.0.short_channel_id_alias.unwrap());
		scid_aliases_2_000_000_000_msat.insert(chan_2_0.0.short_channel_id_alias.unwrap());

		match_invoice_routes(Some(2_000_000_000), &nodes[0], scid_aliases_2_000_000_000_msat);

		// An invoice with no specified amount should include all channels in the route hints.
		let mut scid_aliases_no_specified_amount = HashSet::new();
		scid_aliases_no_specified_amount.insert(chan_1_0.0.short_channel_id_alias.unwrap());
		scid_aliases_no_specified_amount.insert(chan_2_0.0.short_channel_id_alias.unwrap());

		match_invoice_routes(None, &nodes[0], scid_aliases_no_specified_amount);
	}

	fn match_invoice_routes<'a, 'b: 'a, 'c: 'b>(
		invoice_amt: Option<u64>,
		invoice_node: &Node<'a, 'b, 'c>,
		mut chan_ids_to_match: HashSet<u64>
	) {
		let invoice = create_invoice_from_channelmanager_and_duration_since_epoch(
			&invoice_node.node, invoice_node.keys_manager, invoice_node.logger,
			Currency::BitcoinTestnet, invoice_amt, "test".to_string(), Duration::from_secs(1234567),
			3600, None).unwrap();
		let hints = invoice.private_routes();

		for hint in hints {
			let hint_short_chan_id = (hint.0).0[0].short_channel_id;
			assert!(chan_ids_to_match.remove(&hint_short_chan_id));
		}
		assert!(chan_ids_to_match.is_empty(), "Unmatched short channel ids: {:?}", chan_ids_to_match);
	}

	#[test]
	#[cfg(feature = "std")]
	fn test_multi_node_receive() {
		do_test_multi_node_receive(true);
		do_test_multi_node_receive(false);
	}

	#[cfg(feature = "std")]
	fn do_test_multi_node_receive(user_generated_pmt_hash: bool) {
		let mut chanmon_cfgs = create_chanmon_cfgs(3);
		let seed_1 = [42 as u8; 32];
		let seed_2 = [43 as u8; 32];
		let cross_node_seed = [44 as u8; 32];
		chanmon_cfgs[1].keys_manager.backing = PhantomKeysManager::new(&seed_1, 43, 44, &cross_node_seed);
		chanmon_cfgs[2].keys_manager.backing = PhantomKeysManager::new(&seed_2, 43, 44, &cross_node_seed);
		let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
		let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &[None, None, None]);
		let nodes = create_network(3, &node_cfgs, &node_chanmgrs);
		let chan_0_1 = create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 100000, 10001);
		nodes[0].node.handle_channel_update(&nodes[1].node.get_our_node_id(), &chan_0_1.1);
		nodes[1].node.handle_channel_update(&nodes[0].node.get_our_node_id(), &chan_0_1.0);
		let chan_0_2 = create_announced_chan_between_nodes_with_value(&nodes, 0, 2, 100000, 10001);
		nodes[0].node.handle_channel_update(&nodes[2].node.get_our_node_id(), &chan_0_2.1);
		nodes[2].node.handle_channel_update(&nodes[0].node.get_our_node_id(), &chan_0_2.0);

		let payment_amt = 10_000;
		let route_hints = vec![
			nodes[1].node.get_phantom_route_hints(),
			nodes[2].node.get_phantom_route_hints(),
		];

		let user_payment_preimage = PaymentPreimage([1; 32]);
		let payment_hash = if user_generated_pmt_hash {
			Some(PaymentHash(Sha256::hash(&user_payment_preimage.0[..]).into_inner()))
		} else {
			None
		};
		let non_default_invoice_expiry_secs = 4200;

		let invoice =
			crate::utils::create_phantom_invoice::<&test_utils::TestKeysInterface, &test_utils::TestKeysInterface, &test_utils::TestLogger>(
				Some(payment_amt), payment_hash, "test".to_string(), non_default_invoice_expiry_secs,
				route_hints, &nodes[1].keys_manager, &nodes[1].keys_manager, &nodes[1].logger,
				Currency::BitcoinTestnet, None, Duration::from_secs(1234567)
			).unwrap();
		let (payment_hash, payment_secret) = (PaymentHash(invoice.payment_hash().into_inner()), *invoice.payment_secret());
		let payment_preimage = if user_generated_pmt_hash {
			user_payment_preimage
		} else {
			nodes[1].node.get_payment_preimage(payment_hash, payment_secret).unwrap()
		};

		assert_eq!(invoice.min_final_cltv_expiry_delta(), MIN_FINAL_CLTV_EXPIRY_DELTA as u64);
		assert_eq!(invoice.description(), InvoiceDescription::Direct(&Description("test".to_string())));
		assert_eq!(invoice.route_hints().len(), 2);
		assert_eq!(invoice.expiry_time(), Duration::from_secs(non_default_invoice_expiry_secs.into()));
		assert!(!invoice.features().unwrap().supports_basic_mpp());

		let payment_params = PaymentParameters::from_node_id(invoice.recover_payee_pub_key(),
				invoice.min_final_cltv_expiry_delta() as u32)
			.with_features(invoice.features().unwrap().clone())
			.with_route_hints(invoice.route_hints());
		let params = RouteParameters {
			payment_params,
			final_value_msat: invoice.amount_milli_satoshis().unwrap(),
		};
		let first_hops = nodes[0].node.list_usable_channels();
		let network_graph = &node_cfgs[0].network_graph;
		let logger = test_utils::TestLogger::new();
		let scorer = test_utils::TestScorer::new();
		let random_seed_bytes = chanmon_cfgs[1].keys_manager.get_secure_random_bytes();
		let route = find_route(
			&nodes[0].node.get_our_node_id(), &params, &network_graph,
			Some(&first_hops.iter().collect::<Vec<_>>()), &logger, &scorer, &random_seed_bytes
		).unwrap();
		let (payment_event, fwd_idx) = {
			let mut payment_hash = PaymentHash([0; 32]);
			payment_hash.0.copy_from_slice(&invoice.payment_hash().as_ref()[0..32]);
			nodes[0].node.send_payment(&route, payment_hash, &Some(invoice.payment_secret().clone()), PaymentId(payment_hash.0)).unwrap();
			let mut added_monitors = nodes[0].chain_monitor.added_monitors.lock().unwrap();
			assert_eq!(added_monitors.len(), 1);
			added_monitors.clear();

			let mut events = nodes[0].node.get_and_clear_pending_msg_events();
			assert_eq!(events.len(), 1);
			let fwd_idx = match events[0] {
				MessageSendEvent::UpdateHTLCs { node_id, .. } => {
					if node_id == nodes[1].node.get_our_node_id() {
						1
					} else { 2 }
				},
				_ => panic!("Unexpected event")
			};
			(SendEvent::from_event(events.remove(0)), fwd_idx)
		};
		nodes[fwd_idx].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &payment_event.msgs[0]);
		commitment_signed_dance!(nodes[fwd_idx], nodes[0], &payment_event.commitment_msg, false, true);

		// Note that we have to "forward pending HTLCs" twice before we see the PaymentClaimable as
		// this "emulates" the payment taking two hops, providing some privacy to make phantom node
		// payments "look real" by taking more time.
		expect_pending_htlcs_forwardable_ignore!(nodes[fwd_idx]);
		nodes[fwd_idx].node.process_pending_htlc_forwards();
		expect_pending_htlcs_forwardable_ignore!(nodes[fwd_idx]);
		nodes[fwd_idx].node.process_pending_htlc_forwards();

		let payment_preimage_opt = if user_generated_pmt_hash { None } else { Some(payment_preimage) };
		expect_payment_claimable!(&nodes[fwd_idx], payment_hash, payment_secret, payment_amt, payment_preimage_opt, route.paths[0].last().unwrap().pubkey);
		do_claim_payment_along_route(&nodes[0], &vec!(&vec!(&nodes[fwd_idx])[..]), false, payment_preimage);
		let events = nodes[0].node.get_and_clear_pending_events();
		assert_eq!(events.len(), 2);
		match events[0] {
			Event::PaymentSent { payment_preimage: ref ev_preimage, payment_hash: ref ev_hash, ref fee_paid_msat, .. } => {
				assert_eq!(payment_preimage, *ev_preimage);
				assert_eq!(payment_hash, *ev_hash);
				assert_eq!(fee_paid_msat, &Some(0));
			},
			_ => panic!("Unexpected event")
		}
		match events[1] {
			Event::PaymentPathSuccessful { payment_hash: hash, .. } => {
				assert_eq!(hash, Some(payment_hash));
			},
			_ => panic!("Unexpected event")
		}
	}

	#[test]
	#[cfg(feature = "std")]
	fn test_multi_node_hints_has_htlc_min_max_values() {
		let mut chanmon_cfgs = create_chanmon_cfgs(3);
		let seed_1 = [42 as u8; 32];
		let seed_2 = [43 as u8; 32];
		let cross_node_seed = [44 as u8; 32];
		chanmon_cfgs[1].keys_manager.backing = PhantomKeysManager::new(&seed_1, 43, 44, &cross_node_seed);
		chanmon_cfgs[2].keys_manager.backing = PhantomKeysManager::new(&seed_2, 43, 44, &cross_node_seed);
		let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
		let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &[None, None, None]);
		let nodes = create_network(3, &node_cfgs, &node_chanmgrs);

		create_unannounced_chan_between_nodes_with_value(&nodes, 0, 1, 100000, 10001);
		create_unannounced_chan_between_nodes_with_value(&nodes, 0, 2, 100000, 10001);

		let payment_amt = 20_000;
		let (payment_hash, _payment_secret) = nodes[1].node.create_inbound_payment(Some(payment_amt), 3600, None).unwrap();
		let route_hints = vec![
			nodes[1].node.get_phantom_route_hints(),
			nodes[2].node.get_phantom_route_hints(),
		];

		let invoice = crate::utils::create_phantom_invoice::<&test_utils::TestKeysInterface,
			&test_utils::TestKeysInterface, &test_utils::TestLogger>(Some(payment_amt), Some(payment_hash),
				"test".to_string(), 3600, route_hints, &nodes[1].keys_manager, &nodes[1].keys_manager,
				&nodes[1].logger, Currency::BitcoinTestnet, None, Duration::from_secs(1234567)).unwrap();

		let chan_0_1 = &nodes[1].node.list_usable_channels()[0];
		assert_eq!(invoice.route_hints()[0].0[0].htlc_minimum_msat, chan_0_1.inbound_htlc_minimum_msat);
		assert_eq!(invoice.route_hints()[0].0[0].htlc_maximum_msat, chan_0_1.inbound_htlc_maximum_msat);

		let chan_0_2 = &nodes[2].node.list_usable_channels()[0];
		assert_eq!(invoice.route_hints()[1].0[0].htlc_minimum_msat, chan_0_2.inbound_htlc_minimum_msat);
		assert_eq!(invoice.route_hints()[1].0[0].htlc_maximum_msat, chan_0_2.inbound_htlc_maximum_msat);
	}

	#[test]
	#[cfg(feature = "std")]
	fn create_phantom_invoice_with_description_hash() {
		let chanmon_cfgs = create_chanmon_cfgs(3);
		let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
		let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &[None, None, None]);
		let nodes = create_network(3, &node_cfgs, &node_chanmgrs);

		let payment_amt = 20_000;
		let route_hints = vec![
			nodes[1].node.get_phantom_route_hints(),
			nodes[2].node.get_phantom_route_hints(),
		];

		let description_hash = crate::Sha256(Hash::hash("Description hash phantom invoice".as_bytes()));
		let non_default_invoice_expiry_secs = 4200;
		let invoice = crate::utils::create_phantom_invoice_with_description_hash::<
			&test_utils::TestKeysInterface, &test_utils::TestKeysInterface, &test_utils::TestLogger,
		>(
			Some(payment_amt), None, non_default_invoice_expiry_secs, description_hash,
			route_hints, &nodes[1].keys_manager, &nodes[1].keys_manager, &nodes[1].logger,
			Currency::BitcoinTestnet, None, Duration::from_secs(1234567),
		)
		.unwrap();
		assert_eq!(invoice.amount_pico_btc(), Some(200_000));
		assert_eq!(invoice.min_final_cltv_expiry_delta(), MIN_FINAL_CLTV_EXPIRY_DELTA as u64);
		assert_eq!(invoice.expiry_time(), Duration::from_secs(non_default_invoice_expiry_secs.into()));
		assert_eq!(invoice.description(), InvoiceDescription::Hash(&crate::Sha256(Sha256::hash("Description hash phantom invoice".as_bytes()))));
	}

	#[test]
	#[cfg(feature = "std")]
	fn create_phantom_invoice_with_custom_payment_hash_and_custom_min_final_cltv_delta() {
		let chanmon_cfgs = create_chanmon_cfgs(3);
		let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
		let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &[None, None, None]);
		let nodes = create_network(3, &node_cfgs, &node_chanmgrs);

		let payment_amt = 20_000;
		let route_hints = vec![
			nodes[1].node.get_phantom_route_hints(),
			nodes[2].node.get_phantom_route_hints(),
		];
		let user_payment_preimage = PaymentPreimage([1; 32]);
		let payment_hash = Some(PaymentHash(Sha256::hash(&user_payment_preimage.0[..]).into_inner()));
		let non_default_invoice_expiry_secs = 4200;
		let min_final_cltv_expiry_delta = Some(100);
		let duration_since_epoch = Duration::from_secs(1234567);
		let invoice = crate::utils::create_phantom_invoice::<&test_utils::TestKeysInterface,
			&test_utils::TestKeysInterface, &test_utils::TestLogger>(Some(payment_amt), payment_hash,
				"".to_string(), non_default_invoice_expiry_secs, route_hints, &nodes[1].keys_manager, &nodes[1].keys_manager,
				&nodes[1].logger, Currency::BitcoinTestnet, min_final_cltv_expiry_delta, duration_since_epoch).unwrap();
		assert_eq!(invoice.amount_pico_btc(), Some(200_000));
		assert_eq!(invoice.min_final_cltv_expiry_delta(), (min_final_cltv_expiry_delta.unwrap() + 3) as u64);
		assert_eq!(invoice.expiry_time(), Duration::from_secs(non_default_invoice_expiry_secs.into()));
	}

	#[test]
	#[cfg(feature = "std")]
	fn test_multi_node_hints_includes_single_channels_to_participating_nodes() {
		let mut chanmon_cfgs = create_chanmon_cfgs(3);
		let seed_1 = [42 as u8; 32];
		let seed_2 = [43 as u8; 32];
		let cross_node_seed = [44 as u8; 32];
		chanmon_cfgs[1].keys_manager.backing = PhantomKeysManager::new(&seed_1, 43, 44, &cross_node_seed);
		chanmon_cfgs[2].keys_manager.backing = PhantomKeysManager::new(&seed_2, 43, 44, &cross_node_seed);
		let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
		let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &[None, None, None]);
		let nodes = create_network(3, &node_cfgs, &node_chanmgrs);

		let chan_0_1 = create_unannounced_chan_between_nodes_with_value(&nodes, 0, 1, 100000, 10001);
		let chan_0_2 = create_unannounced_chan_between_nodes_with_value(&nodes, 0, 2, 100000, 10001);

		let mut scid_aliases = HashSet::new();
		scid_aliases.insert(chan_0_1.0.short_channel_id_alias.unwrap());
		scid_aliases.insert(chan_0_2.0.short_channel_id_alias.unwrap());

		match_multi_node_invoice_routes(
			Some(10_000),
			&nodes[1],
			vec![&nodes[1], &nodes[2],],
			scid_aliases,
			false
		);
	}

	#[test]
	#[cfg(feature = "std")]
	fn test_multi_node_hints_includes_one_channel_of_each_counterparty_nodes_per_participating_node() {
		let mut chanmon_cfgs = create_chanmon_cfgs(4);
		let seed_1 = [42 as u8; 32];
		let seed_2 = [43 as u8; 32];
		let cross_node_seed = [44 as u8; 32];
		chanmon_cfgs[2].keys_manager.backing = PhantomKeysManager::new(&seed_1, 43, 44, &cross_node_seed);
		chanmon_cfgs[3].keys_manager.backing = PhantomKeysManager::new(&seed_2, 43, 44, &cross_node_seed);
		let node_cfgs = create_node_cfgs(4, &chanmon_cfgs);
		let node_chanmgrs = create_node_chanmgrs(4, &node_cfgs, &[None, None, None, None]);
		let nodes = create_network(4, &node_cfgs, &node_chanmgrs);

		let chan_0_2 = create_unannounced_chan_between_nodes_with_value(&nodes, 0, 2, 100000, 10001);
		let chan_0_3 = create_unannounced_chan_between_nodes_with_value(&nodes, 0, 3, 1000000, 10001);
		let chan_1_3 = create_unannounced_chan_between_nodes_with_value(&nodes, 1, 3, 3_000_000, 10005);

		let mut scid_aliases = HashSet::new();
		scid_aliases.insert(chan_0_2.0.short_channel_id_alias.unwrap());
		scid_aliases.insert(chan_0_3.0.short_channel_id_alias.unwrap());
		scid_aliases.insert(chan_1_3.0.short_channel_id_alias.unwrap());

		match_multi_node_invoice_routes(
			Some(10_000),
			&nodes[2],
			vec![&nodes[2], &nodes[3],],
			scid_aliases,
			false
		);
	}

	#[test]
	#[cfg(feature = "std")]
	fn test_multi_node_forwarding_info_not_assigned_channel_excluded_from_hints() {
		let mut chanmon_cfgs = create_chanmon_cfgs(4);
		let seed_1 = [42 as u8; 32];
		let seed_2 = [43 as u8; 32];
		let cross_node_seed = [44 as u8; 32];
		chanmon_cfgs[2].keys_manager.backing = PhantomKeysManager::new(&seed_1, 43, 44, &cross_node_seed);
		chanmon_cfgs[3].keys_manager.backing = PhantomKeysManager::new(&seed_2, 43, 44, &cross_node_seed);
		let node_cfgs = create_node_cfgs(4, &chanmon_cfgs);
		let node_chanmgrs = create_node_chanmgrs(4, &node_cfgs, &[None, None, None, None]);
		let nodes = create_network(4, &node_cfgs, &node_chanmgrs);

		let chan_0_2 = create_unannounced_chan_between_nodes_with_value(&nodes, 0, 2, 100000, 10001);
		let chan_0_3 = create_unannounced_chan_between_nodes_with_value(&nodes, 0, 3, 1000000, 10001);

		// Create an unannonced channel between `nodes[1]` and `nodes[3]`, for which the
		// `msgs::ChannelUpdate` is never handled for the node(s). As the `msgs::ChannelUpdate`
		// is never handled, the `channel.counterparty.forwarding_info` is never assigned.
		let mut private_chan_cfg = UserConfig::default();
		private_chan_cfg.channel_handshake_config.announced_channel = false;
		let temporary_channel_id = nodes[1].node.create_channel(nodes[3].node.get_our_node_id(), 1_000_000, 500_000_000, 42, Some(private_chan_cfg)).unwrap();
		let open_channel = get_event_msg!(nodes[1], MessageSendEvent::SendOpenChannel, nodes[3].node.get_our_node_id());
		nodes[3].node.handle_open_channel(&nodes[1].node.get_our_node_id(), &open_channel);
		let accept_channel = get_event_msg!(nodes[3], MessageSendEvent::SendAcceptChannel, nodes[1].node.get_our_node_id());
		nodes[1].node.handle_accept_channel(&nodes[3].node.get_our_node_id(), &accept_channel);

		let tx = sign_funding_transaction(&nodes[1], &nodes[3], 1_000_000, temporary_channel_id);

		let conf_height = core::cmp::max(nodes[1].best_block_info().1 + 1, nodes[3].best_block_info().1 + 1);
		confirm_transaction_at(&nodes[1], &tx, conf_height);
		connect_blocks(&nodes[1], CHAN_CONFIRM_DEPTH - 1);
		confirm_transaction_at(&nodes[3], &tx, conf_height);
		connect_blocks(&nodes[3], CHAN_CONFIRM_DEPTH - 1);
		let as_channel_ready = get_event_msg!(nodes[1], MessageSendEvent::SendChannelReady, nodes[3].node.get_our_node_id());
		nodes[1].node.handle_channel_ready(&nodes[3].node.get_our_node_id(), &get_event_msg!(nodes[3], MessageSendEvent::SendChannelReady, nodes[1].node.get_our_node_id()));
		get_event_msg!(nodes[1], MessageSendEvent::SendChannelUpdate, nodes[3].node.get_our_node_id());
		nodes[3].node.handle_channel_ready(&nodes[1].node.get_our_node_id(), &as_channel_ready);
		get_event_msg!(nodes[3], MessageSendEvent::SendChannelUpdate, nodes[1].node.get_our_node_id());
		expect_channel_ready_event(&nodes[1], &nodes[3].node.get_our_node_id());
		expect_channel_ready_event(&nodes[3], &nodes[1].node.get_our_node_id());

		// As `msgs::ChannelUpdate` was never handled for the participating node(s) of the third
		// channel, the channel will never be assigned any `counterparty.forwarding_info`.
		// Therefore only `chan_0_3` should be included in the hints for `nodes[3]`.
		let mut scid_aliases = HashSet::new();
		scid_aliases.insert(chan_0_2.0.short_channel_id_alias.unwrap());
		scid_aliases.insert(chan_0_3.0.short_channel_id_alias.unwrap());

		match_multi_node_invoice_routes(
			Some(10_000),
			&nodes[2],
			vec![&nodes[2], &nodes[3],],
			scid_aliases,
			false
		);
	}

	#[test]
	#[cfg(feature = "std")]
	fn test_multi_node_with_only_public_channels_hints_includes_only_phantom_route() {
		let mut chanmon_cfgs = create_chanmon_cfgs(3);
		let seed_1 = [42 as u8; 32];
		let seed_2 = [43 as u8; 32];
		let cross_node_seed = [44 as u8; 32];
		chanmon_cfgs[1].keys_manager.backing = PhantomKeysManager::new(&seed_1, 43, 44, &cross_node_seed);
		chanmon_cfgs[2].keys_manager.backing = PhantomKeysManager::new(&seed_2, 43, 44, &cross_node_seed);
		let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
		let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &[None, None, None]);
		let nodes = create_network(3, &node_cfgs, &node_chanmgrs);

		let chan_0_1 = create_unannounced_chan_between_nodes_with_value(&nodes, 0, 1, 100000, 10001);

		let chan_2_0 = create_announced_chan_between_nodes_with_value(&nodes, 2, 0, 100000, 10001);
		nodes[2].node.handle_channel_update(&nodes[0].node.get_our_node_id(), &chan_2_0.1);
		nodes[0].node.handle_channel_update(&nodes[2].node.get_our_node_id(), &chan_2_0.0);

		// Hints should include `chan_0_1` from as `nodes[1]` only have private channels, but not
		// `chan_0_2` as `nodes[2]` only has public channels.
		let mut scid_aliases = HashSet::new();
		scid_aliases.insert(chan_0_1.0.short_channel_id_alias.unwrap());

		match_multi_node_invoice_routes(
			Some(10_000),
			&nodes[1],
			vec![&nodes[1], &nodes[2],],
			scid_aliases,
			true
		);
	}

	#[test]
	#[cfg(feature = "std")]
	fn test_multi_node_with_mixed_public_and_private_channel_hints_includes_only_phantom_route() {
		let mut chanmon_cfgs = create_chanmon_cfgs(4);
		let seed_1 = [42 as u8; 32];
		let seed_2 = [43 as u8; 32];
		let cross_node_seed = [44 as u8; 32];
		chanmon_cfgs[1].keys_manager.backing = PhantomKeysManager::new(&seed_1, 43, 44, &cross_node_seed);
		chanmon_cfgs[2].keys_manager.backing = PhantomKeysManager::new(&seed_2, 43, 44, &cross_node_seed);
		let node_cfgs = create_node_cfgs(4, &chanmon_cfgs);
		let node_chanmgrs = create_node_chanmgrs(4, &node_cfgs, &[None, None, None, None]);
		let nodes = create_network(4, &node_cfgs, &node_chanmgrs);

		let chan_0_2 = create_announced_chan_between_nodes_with_value(&nodes, 0, 2, 100000, 10001);
		nodes[0].node.handle_channel_update(&nodes[2].node.get_our_node_id(), &chan_0_2.1);
		nodes[2].node.handle_channel_update(&nodes[0].node.get_our_node_id(), &chan_0_2.0);
		let _chan_1_2 = create_unannounced_chan_between_nodes_with_value(&nodes, 1, 2, 100000, 10001);

		let chan_0_3 = create_unannounced_chan_between_nodes_with_value(&nodes, 0, 3, 100000, 10001);

		// Hints should include `chan_0_3` from as `nodes[3]` only have private channels, and no
		// channels for `nodes[2]` as it contains a mix of public and private channels.
		let mut scid_aliases = HashSet::new();
		scid_aliases.insert(chan_0_3.0.short_channel_id_alias.unwrap());

		match_multi_node_invoice_routes(
			Some(10_000),
			&nodes[2],
			vec![&nodes[2], &nodes[3],],
			scid_aliases,
			true
		);
	}

	#[test]
	#[cfg(feature = "std")]
	fn test_multi_node_hints_has_only_highest_inbound_capacity_channel() {
		let mut chanmon_cfgs = create_chanmon_cfgs(3);
		let seed_1 = [42 as u8; 32];
		let seed_2 = [43 as u8; 32];
		let cross_node_seed = [44 as u8; 32];
		chanmon_cfgs[1].keys_manager.backing = PhantomKeysManager::new(&seed_1, 43, 44, &cross_node_seed);
		chanmon_cfgs[2].keys_manager.backing = PhantomKeysManager::new(&seed_2, 43, 44, &cross_node_seed);
		let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
		let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &[None, None, None]);
		let nodes = create_network(3, &node_cfgs, &node_chanmgrs);

		let _chan_0_1_low_inbound_capacity = create_unannounced_chan_between_nodes_with_value(&nodes, 0, 1, 100_000, 0);
		let chan_0_1_high_inbound_capacity = create_unannounced_chan_between_nodes_with_value(&nodes, 0, 1, 10_000_000, 0);
		let _chan_0_1_medium_inbound_capacity = create_unannounced_chan_between_nodes_with_value(&nodes, 0, 1, 1_000_000, 0);
		let chan_0_2 = create_unannounced_chan_between_nodes_with_value(&nodes, 0, 2, 100000, 10001);

		let mut scid_aliases = HashSet::new();
		scid_aliases.insert(chan_0_1_high_inbound_capacity.0.short_channel_id_alias.unwrap());
		scid_aliases.insert(chan_0_2.0.short_channel_id_alias.unwrap());

		match_multi_node_invoice_routes(
			Some(10_000),
			&nodes[1],
			vec![&nodes[1], &nodes[2],],
			scid_aliases,
			false
		);
	}

	#[test]
	#[cfg(feature = "std")]
	fn test_multi_node_channels_inbound_capacity_lower_than_invoice_amt_filtering() {
		let mut chanmon_cfgs = create_chanmon_cfgs(4);
		let seed_1 = [42 as u8; 32];
		let seed_2 = [43 as u8; 32];
		let cross_node_seed = [44 as u8; 32];
		chanmon_cfgs[1].keys_manager.backing = PhantomKeysManager::new(&seed_1, 43, 44, &cross_node_seed);
		chanmon_cfgs[2].keys_manager.backing = PhantomKeysManager::new(&seed_2, 43, 44, &cross_node_seed);
		let node_cfgs = create_node_cfgs(4, &chanmon_cfgs);
		let node_chanmgrs = create_node_chanmgrs(4, &node_cfgs, &[None, None, None, None]);
		let nodes = create_network(4, &node_cfgs, &node_chanmgrs);

		let chan_0_2 = create_unannounced_chan_between_nodes_with_value(&nodes, 0, 2, 1_000_000, 0);
		let chan_0_3 = create_unannounced_chan_between_nodes_with_value(&nodes, 0, 3, 100_000, 0);
		let chan_1_3 = create_unannounced_chan_between_nodes_with_value(&nodes, 1, 3, 200_000, 0);

		// Since the invoice 1 msat above chan_0_3's inbound capacity, it should be filtered out.
		let mut scid_aliases_99_000_001_msat = HashSet::new();
		scid_aliases_99_000_001_msat.insert(chan_0_2.0.short_channel_id_alias.unwrap());
		scid_aliases_99_000_001_msat.insert(chan_1_3.0.short_channel_id_alias.unwrap());

		match_multi_node_invoice_routes(
			Some(99_000_001),
			&nodes[2],
			vec![&nodes[2], &nodes[3],],
			scid_aliases_99_000_001_msat,
			false
		);

		// Since the invoice is exactly at chan_0_3's inbound capacity, it should be included.
		let mut scid_aliases_99_000_000_msat = HashSet::new();
		scid_aliases_99_000_000_msat.insert(chan_0_2.0.short_channel_id_alias.unwrap());
		scid_aliases_99_000_000_msat.insert(chan_0_3.0.short_channel_id_alias.unwrap());
		scid_aliases_99_000_000_msat.insert(chan_1_3.0.short_channel_id_alias.unwrap());

		match_multi_node_invoice_routes(
			Some(99_000_000),
			&nodes[2],
			vec![&nodes[2], &nodes[3],],
			scid_aliases_99_000_000_msat,
			false
		);

		// Since the invoice is above all of `nodes[2]` channels' inbound capacity, all of
		// `nodes[2]` them should be included.
		let mut scid_aliases_300_000_000_msat = HashSet::new();
		scid_aliases_300_000_000_msat.insert(chan_0_2.0.short_channel_id_alias.unwrap());
		scid_aliases_300_000_000_msat.insert(chan_0_3.0.short_channel_id_alias.unwrap());
		scid_aliases_300_000_000_msat.insert(chan_1_3.0.short_channel_id_alias.unwrap());

		match_multi_node_invoice_routes(
			Some(300_000_000),
			&nodes[2],
			vec![&nodes[2], &nodes[3],],
			scid_aliases_300_000_000_msat,
			false
		);

		// Since the no specified amount, all channels should included.
		let mut scid_aliases_no_specified_amount = HashSet::new();
		scid_aliases_no_specified_amount.insert(chan_0_2.0.short_channel_id_alias.unwrap());
		scid_aliases_no_specified_amount.insert(chan_0_3.0.short_channel_id_alias.unwrap());
		scid_aliases_no_specified_amount.insert(chan_1_3.0.short_channel_id_alias.unwrap());

		match_multi_node_invoice_routes(
			None,
			&nodes[2],
			vec![&nodes[2], &nodes[3],],
			scid_aliases_no_specified_amount,
			false
		);
	}

	#[cfg(feature = "std")]
	fn match_multi_node_invoice_routes<'a, 'b: 'a, 'c: 'b>(
		invoice_amt: Option<u64>,
		invoice_node: &Node<'a, 'b, 'c>,
		network_multi_nodes: Vec<&Node<'a, 'b, 'c>>,
		mut chan_ids_to_match: HashSet<u64>,
		nodes_contains_public_channels: bool
	){
		let phantom_route_hints = network_multi_nodes.iter()
			.map(|node| node.node.get_phantom_route_hints())
			.collect::<Vec<PhantomRouteHints>>();
		let phantom_scids = phantom_route_hints.iter()
			.map(|route_hint| route_hint.phantom_scid)
			.collect::<HashSet<u64>>();

		let invoice = crate::utils::create_phantom_invoice::<&test_utils::TestKeysInterface,
			&test_utils::TestKeysInterface, &test_utils::TestLogger>(invoice_amt, None, "test".to_string(),
				3600, phantom_route_hints, &invoice_node.keys_manager, &invoice_node.keys_manager,
				&invoice_node.logger, Currency::BitcoinTestnet, None, Duration::from_secs(1234567)).unwrap();

		let invoice_hints = invoice.private_routes();

		for hint in invoice_hints {
			let hints = &(hint.0).0;
			match hints.len() {
				1 => {
					assert!(nodes_contains_public_channels);
					let phantom_scid = hints[0].short_channel_id;
					assert!(phantom_scids.contains(&phantom_scid));
				},
				2 => {
					let hint_short_chan_id = hints[0].short_channel_id;
					assert!(chan_ids_to_match.remove(&hint_short_chan_id));
					let phantom_scid = hints[1].short_channel_id;
					assert!(phantom_scids.contains(&phantom_scid));
				},
				_ => panic!("Incorrect hint length generated")
			}
		}
		assert!(chan_ids_to_match.is_empty(), "Unmatched short channel ids: {:?}", chan_ids_to_match);
	}

	#[test]
	fn test_create_invoice_fails_with_invalid_custom_min_final_cltv_expiry_delta() {
		let chanmon_cfgs = create_chanmon_cfgs(2);
		let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
		let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
		let nodes = create_network(2, &node_cfgs, &node_chanmgrs);
		let result = crate::utils::create_invoice_from_channelmanager_and_duration_since_epoch(
			&nodes[1].node, nodes[1].keys_manager, nodes[1].logger, Currency::BitcoinTestnet,
			Some(10_000), "Some description".into(), Duration::from_secs(1234567), 3600, Some(MIN_FINAL_CLTV_EXPIRY_DELTA - 4),
		);
		match result {
			Err(SignOrCreationError::CreationError(CreationError::MinFinalCltvExpiryDeltaTooShort)) => {},
			_ => panic!(),
		}
	}
}
