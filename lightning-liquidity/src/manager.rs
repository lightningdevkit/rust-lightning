use alloc::string::ToString;
use alloc::vec::Vec;

use crate::events::{EventQueue, LiquidityEvent};
use crate::lsps0::client::LSPS0ClientHandler;
use crate::lsps0::msgs::LSPS0Message;
use crate::lsps0::ser::{
	LSPSMessage, LSPSMethod, LSPSProtocolMessageHandler, LSPSRequestId, LSPSResponseError,
	RawLSPSMessage, JSONRPC_INVALID_MESSAGE_ERROR_CODE, JSONRPC_INVALID_MESSAGE_ERROR_MESSAGE,
	LSPS_MESSAGE_TYPE_ID,
};
use crate::lsps0::service::LSPS0ServiceHandler;
use crate::lsps5::client::{LSPS5ClientConfig, LSPS5ClientHandler};
use crate::lsps5::msgs::LSPS5Message;
#[cfg(feature = "time")]
use crate::lsps5::service::DefaultTimeProvider;
use crate::lsps5::service::{LSPS5ServiceConfig, LSPS5ServiceHandler, TimeProvider};
use crate::message_queue::MessageQueue;

use crate::lsps1::client::{LSPS1ClientConfig, LSPS1ClientHandler};
use crate::lsps1::msgs::LSPS1Message;
#[cfg(lsps1_service)]
use crate::lsps1::service::{LSPS1ServiceConfig, LSPS1ServiceHandler};

use crate::lsps2::client::{LSPS2ClientConfig, LSPS2ClientHandler};
use crate::lsps2::msgs::LSPS2Message;
use crate::lsps2::service::{LSPS2ServiceConfig, LSPS2ServiceHandler};
use crate::prelude::{new_hash_map, new_hash_set, HashMap, HashSet};
use crate::sync::{Arc, Mutex, RwLock};

use lightning::chain::{self, BestBlock, Confirm, Filter, Listen};
use lightning::ln::channelmanager::{AChannelManager, ChainParameters};
use lightning::ln::msgs::{ErrorAction, LightningError};
use lightning::ln::peer_handler::CustomMessageHandler;
use lightning::ln::wire::CustomMessageReader;
use lightning::sign::EntropySource;
use lightning::util::logger::Level;
use lightning::util::ser::{LengthLimitedRead, LengthReadable};
use lightning::util::wakers::Future;

use lightning_types::features::{InitFeatures, NodeFeatures};

use bitcoin::secp256k1::PublicKey;

use core::ops::Deref;

const LSPS_FEATURE_BIT: usize = 729;

/// A server-side configuration for [`LiquidityManager`].
///
/// Allows end-users to configure options when using the [`LiquidityManager`]
/// to provide liquidity services to clients.
pub struct LiquidityServiceConfig {
	/// Optional server-side configuration for LSPS1 channel requests.
	#[cfg(lsps1_service)]
	pub lsps1_service_config: Option<LSPS1ServiceConfig>,
	/// Optional server-side configuration for JIT channels
	/// should you want to support them.
	pub lsps2_service_config: Option<LSPS2ServiceConfig>,
	/// Optional server-side configuration for LSPS5 webhook service.
	pub lsps5_service_config: Option<LSPS5ServiceConfig>,
	/// Controls whether the liquidity service should be advertised via setting the feature bit in
	/// node announcment and the init message.
	pub advertise_service: bool,
}

/// A client-side configuration for [`LiquidityManager`].
///
/// Allows end-user to configure options when using the [`LiquidityManager`]
/// to access liquidity services from a provider.
pub struct LiquidityClientConfig {
	/// Optional client-side configuration for LSPS1 channel requests.
	pub lsps1_client_config: Option<LSPS1ClientConfig>,
	/// Optional client-side configuration for JIT channels.
	pub lsps2_client_config: Option<LSPS2ClientConfig>,
	/// Optional client-side configuration for LSPS5 webhook service.
	pub lsps5_client_config: Option<LSPS5ClientConfig>,
}

/// A trivial trait which describes any [`LiquidityManager`].
///
/// This is not exported to bindings users as general cover traits aren't useful in other
/// languages.
pub trait ALiquidityManager {
	/// A type implementing [`EntropySource`]
	type EntropySource: EntropySource + ?Sized;
	/// A type that may be dereferenced to [`Self::EntropySource`].
	type ES: Deref<Target = Self::EntropySource> + Clone;
	/// A type implementing [`AChannelManager`]
	type AChannelManager: AChannelManager + ?Sized;
	/// A type that may be dereferenced to [`Self::AChannelManager`].
	type CM: Deref<Target = Self::AChannelManager> + Clone;
	/// A type implementing [`Filter`].
	type Filter: Filter + ?Sized;
	/// A type that may be dereferenced to [`Self::Filter`].
	type C: Deref<Target = Self::Filter> + Clone;
	/// A type implementing [`TimeProvider`].
	type TimeProvider: TimeProvider + ?Sized;
	/// A type that may be dereferenced to [`Self::TimeProvider`].
	type TP: Deref<Target = Self::TimeProvider> + Clone;
	/// Returns a reference to the actual [`LiquidityManager`] object.
	fn get_lm(&self) -> &LiquidityManager<Self::ES, Self::CM, Self::C, Self::TP>;
}

impl<ES: Deref + Clone, CM: Deref + Clone, C: Deref + Clone, TP: Deref + Clone> ALiquidityManager
	for LiquidityManager<ES, CM, C, TP>
where
	ES::Target: EntropySource,
	CM::Target: AChannelManager,
	C::Target: Filter,
	TP::Target: TimeProvider,
{
	type EntropySource = ES::Target;
	type ES = ES;
	type AChannelManager = CM::Target;
	type CM = CM;
	type Filter = C::Target;
	type C = C;
	type TimeProvider = TP::Target;
	type TP = TP;
	fn get_lm(&self) -> &LiquidityManager<ES, CM, C, TP> {
		self
	}
}

/// The main interface into LSP functionality.
///
/// Should be used as a [`CustomMessageHandler`] for your [`PeerManager`]'s [`MessageHandler`].
///
/// Users need to continually poll [`LiquidityManager::get_and_clear_pending_events`] in order to surface
/// [`LiquidityEvent`]'s that likely need to be handled.
///
/// If the LSPS2 service is configured, users must forward the following parameters from LDK events:
/// - [`Event::HTLCIntercepted`] to [`LSPS2ServiceHandler::htlc_intercepted`]
/// - [`Event::ChannelReady`] to [`LSPS2ServiceHandler::channel_ready`]
/// - [`Event::HTLCHandlingFailed`] to [`LSPS2ServiceHandler::htlc_handling_failed`]
/// - [`Event::PaymentForwarded`] to [`LSPS2ServiceHandler::payment_forwarded`]
///
/// [`PeerManager`]: lightning::ln::peer_handler::PeerManager
/// [`MessageHandler`]: lightning::ln::peer_handler::MessageHandler
/// [`Event::HTLCIntercepted`]: lightning::events::Event::HTLCIntercepted
/// [`Event::ChannelReady`]: lightning::events::Event::ChannelReady
/// [`Event::HTLCHandlingFailed`]: lightning::events::Event::HTLCHandlingFailed
/// [`Event::PaymentForwarded`]: lightning::events::Event::PaymentForwarded
pub struct LiquidityManager<
	ES: Deref + Clone,
	CM: Deref + Clone,
	C: Deref + Clone,
	TP: Deref + Clone,
> where
	ES::Target: EntropySource,
	CM::Target: AChannelManager,
	C::Target: Filter,
	TP::Target: TimeProvider,
{
	pending_messages: Arc<MessageQueue>,
	pending_events: Arc<EventQueue>,
	request_id_to_method_map: Mutex<HashMap<LSPSRequestId, LSPSMethod>>,
	// We ignore peers if they send us bogus data.
	ignored_peers: RwLock<HashSet<PublicKey>>,
	lsps0_client_handler: LSPS0ClientHandler<ES>,
	lsps0_service_handler: Option<LSPS0ServiceHandler>,
	#[cfg(lsps1_service)]
	lsps1_service_handler: Option<LSPS1ServiceHandler<ES, CM, C>>,
	lsps1_client_handler: Option<LSPS1ClientHandler<ES>>,
	lsps2_service_handler: Option<LSPS2ServiceHandler<CM>>,
	lsps2_client_handler: Option<LSPS2ClientHandler<ES>>,
	lsps5_service_handler: Option<LSPS5ServiceHandler<CM, TP>>,
	lsps5_client_handler: Option<LSPS5ClientHandler<ES, TP>>,
	service_config: Option<LiquidityServiceConfig>,
	_client_config: Option<LiquidityClientConfig>,
	best_block: RwLock<Option<BestBlock>>,
	_chain_source: Option<C>,
}

#[cfg(feature = "time")]
impl<ES: Deref + Clone, CM: Deref + Clone, C: Deref + Clone>
	LiquidityManager<ES, CM, C, Arc<DefaultTimeProvider>>
where
	ES::Target: EntropySource,
	CM::Target: AChannelManager,
	C::Target: Filter,
{
	/// Constructor for the [`LiquidityManager`] using the default system clock
	pub fn new(
		entropy_source: ES, channel_manager: CM, chain_source: Option<C>,
		chain_params: Option<ChainParameters>, service_config: Option<LiquidityServiceConfig>,
		client_config: Option<LiquidityClientConfig>,
	) -> Self {
		let time_provider = Arc::new(DefaultTimeProvider);
		Self::new_with_custom_time_provider(
			entropy_source,
			channel_manager,
			chain_source,
			chain_params,
			service_config,
			client_config,
			time_provider,
		)
	}
}

impl<ES: Deref + Clone, CM: Deref + Clone, C: Deref + Clone, TP: Deref + Clone>
	LiquidityManager<ES, CM, C, TP>
where
	ES::Target: EntropySource,
	CM::Target: AChannelManager,
	C::Target: Filter,
	TP::Target: TimeProvider,
{
	/// Constructor for the [`LiquidityManager`] with a custom time provider.
	///
	/// This should be used on non-std platforms where access to the system time is not
	/// available.
	/// Sets up the required protocol message handlers based on the given
	/// [`LiquidityClientConfig`] and [`LiquidityServiceConfig`].
	pub fn new_with_custom_time_provider(
		entropy_source: ES, channel_manager: CM, chain_source: Option<C>,
		chain_params: Option<ChainParameters>, service_config: Option<LiquidityServiceConfig>,
		client_config: Option<LiquidityClientConfig>, time_provider: TP,
	) -> Self {
		let pending_messages = Arc::new(MessageQueue::new());
		let pending_events = Arc::new(EventQueue::new());
		let ignored_peers = RwLock::new(new_hash_set());

		let mut supported_protocols = Vec::new();

		let lsps2_client_handler = client_config.as_ref().and_then(|config| {
			config.lsps2_client_config.map(|config| {
				LSPS2ClientHandler::new(
					entropy_source.clone(),
					Arc::clone(&pending_messages),
					Arc::clone(&pending_events),
					config.clone(),
				)
			})
		});
		let lsps2_service_handler = service_config.as_ref().and_then(|config| {
			config.lsps2_service_config.as_ref().map(|config| {
				if let Some(number) =
					<LSPS2ServiceHandler<CM> as LSPSProtocolMessageHandler>::PROTOCOL_NUMBER
				{
					supported_protocols.push(number);
				}
				LSPS2ServiceHandler::new(
					Arc::clone(&pending_messages),
					Arc::clone(&pending_events),
					channel_manager.clone(),
					config.clone(),
				)
			})
		});

		let lsps5_client_handler = client_config.as_ref().and_then(|config| {
			config.lsps5_client_config.as_ref().map(|config| {
				LSPS5ClientHandler::new(
					entropy_source.clone(),
					Arc::clone(&pending_messages),
					Arc::clone(&pending_events),
					config.clone(),
					time_provider.clone(),
				)
			})
		});

		let lsps5_service_handler = service_config.as_ref().and_then(|config| {
			config.lsps5_service_config.as_ref().map(|config| {
				if let Some(number) =
					<LSPS5ServiceHandler<CM, TP> as LSPSProtocolMessageHandler>::PROTOCOL_NUMBER
				{
					supported_protocols.push(number);
				}

				return LSPS5ServiceHandler::new(
					Arc::clone(&pending_events),
					Arc::clone(&pending_messages),
					channel_manager.clone(),
					config.clone(),
					time_provider,
				);
			})
		});

		let lsps1_client_handler = client_config.as_ref().and_then(|config| {
			config.lsps1_client_config.as_ref().map(|config| {
				LSPS1ClientHandler::new(
					entropy_source.clone(),
					Arc::clone(&pending_messages),
					Arc::clone(&pending_events),
					config.clone(),
				)
			})
		});

		#[cfg(lsps1_service)]
		let lsps1_service_handler = service_config.as_ref().and_then(|config| {
			if let Some(number) =
				<LSPS1ServiceHandler<ES, CM, C> as LSPSProtocolMessageHandler>::PROTOCOL_NUMBER
			{
				supported_protocols.push(number);
			}
			config.lsps1_service_config.as_ref().map(|config| {
				LSPS1ServiceHandler::new(
					entropy_source.clone(),
					Arc::clone(&pending_messages),
					Arc::clone(&pending_events),
					channel_manager.clone(),
					chain_source.clone(),
					config.clone(),
				)
			})
		});

		let lsps0_client_handler = LSPS0ClientHandler::new(
			entropy_source.clone(),
			Arc::clone(&pending_messages),
			Arc::clone(&pending_events),
		);

		let lsps0_service_handler = if service_config.is_some() {
			Some(LSPS0ServiceHandler::new(supported_protocols, Arc::clone(&pending_messages)))
		} else {
			None
		};

		Self {
			pending_messages,
			pending_events,
			request_id_to_method_map: Mutex::new(new_hash_map()),
			ignored_peers,
			lsps0_client_handler,
			lsps0_service_handler,
			lsps1_client_handler,
			#[cfg(lsps1_service)]
			lsps1_service_handler,
			lsps2_client_handler,
			lsps2_service_handler,
			lsps5_client_handler,
			lsps5_service_handler,
			service_config,
			_client_config: client_config,
			best_block: RwLock::new(chain_params.map(|chain_params| chain_params.best_block)),
			_chain_source: chain_source,
		}
	}

	/// Returns a reference to the LSPS0 client-side handler.
	pub fn lsps0_client_handler(&self) -> &LSPS0ClientHandler<ES> {
		&self.lsps0_client_handler
	}

	/// Returns a reference to the LSPS0 server-side handler.
	pub fn lsps0_service_handler(&self) -> Option<&LSPS0ServiceHandler> {
		self.lsps0_service_handler.as_ref()
	}

	/// Returns a reference to the LSPS1 client-side handler.
	///
	/// The returned hendler allows to initiate the LSPS1 client-side flow, i.e., allows to request
	/// channels from the configured LSP.
	pub fn lsps1_client_handler(&self) -> Option<&LSPS1ClientHandler<ES>> {
		self.lsps1_client_handler.as_ref()
	}

	/// Returns a reference to the LSPS1 server-side handler.
	#[cfg(lsps1_service)]
	pub fn lsps1_service_handler(&self) -> Option<&LSPS1ServiceHandler<ES, CM, C>> {
		self.lsps1_service_handler.as_ref()
	}

	/// Returns a reference to the LSPS2 client-side handler.
	///
	/// The returned hendler allows to initiate the LSPS2 client-side flow. That is, it allows to
	/// retrieve all necessary data to create 'just-in-time' invoices that, when paid, will have
	/// the configured LSP open a 'just-in-time' channel.
	pub fn lsps2_client_handler(&self) -> Option<&LSPS2ClientHandler<ES>> {
		self.lsps2_client_handler.as_ref()
	}

	/// Returns a reference to the LSPS2 server-side handler.
	///
	/// The returned hendler allows to initiate the LSPS2 service-side flow.
	pub fn lsps2_service_handler(&self) -> Option<&LSPS2ServiceHandler<CM>> {
		self.lsps2_service_handler.as_ref()
	}

	/// Returns a reference to the LSPS5 client-side handler.
	///
	/// The returned hendler allows to initiate the LSPS5 client-side flow. That is, it allows to
	pub fn lsps5_client_handler(&self) -> Option<&LSPS5ClientHandler<ES, TP>> {
		self.lsps5_client_handler.as_ref()
	}

	/// Returns a reference to the LSPS5 server-side handler.
	///
	/// The returned hendler allows to initiate the LSPS5 service-side flow.
	pub fn lsps5_service_handler(&self) -> Option<&LSPS5ServiceHandler<CM, TP>> {
		self.lsps5_service_handler.as_ref()
	}

	/// Returns a [`Future`] that will complete when the next batch of pending messages is ready to
	/// be processed.
	///
	/// Note that callbacks registered on the [`Future`] MUST NOT call back into this
	/// [`LiquidityManager`] and should instead register actions to be taken later.
	pub fn get_pending_msgs_future(&self) -> Future {
		self.pending_messages.get_pending_msgs_future()
	}

	/// Blocks the current thread until next event is ready and returns it.
	///
	/// Typically you would spawn a thread or task that calls this in a loop.
	///
	/// **Note**: Users must handle events as soon as possible to avoid an increased event queue
	/// memory footprint. We will start dropping any generated events after
	/// [`MAX_EVENT_QUEUE_SIZE`] has been reached.
	///
	/// [`MAX_EVENT_QUEUE_SIZE`]: crate::events::MAX_EVENT_QUEUE_SIZE
	#[cfg(feature = "std")]
	pub fn wait_next_event(&self) -> LiquidityEvent {
		self.pending_events.wait_next_event()
	}

	/// Returns `Some` if an event is ready.
	///
	/// Typically you would spawn a thread or task that calls this in a loop.
	///
	/// **Note**: Users must handle events as soon as possible to avoid an increased event queue
	/// memory footprint. We will start dropping any generated events after
	/// [`MAX_EVENT_QUEUE_SIZE`] has been reached.
	///
	/// [`MAX_EVENT_QUEUE_SIZE`]: crate::events::MAX_EVENT_QUEUE_SIZE
	pub fn next_event(&self) -> Option<LiquidityEvent> {
		self.pending_events.next_event()
	}

	/// Asynchronously polls the event queue and returns once the next event is ready.
	///
	/// Typically you would spawn a thread or task that calls this in a loop.
	///
	/// **Note**: Users must handle events as soon as possible to avoid an increased event queue
	/// memory footprint. We will start dropping any generated events after
	/// [`MAX_EVENT_QUEUE_SIZE`] has been reached.
	///
	/// [`MAX_EVENT_QUEUE_SIZE`]: crate::events::MAX_EVENT_QUEUE_SIZE
	pub async fn next_event_async(&self) -> LiquidityEvent {
		self.pending_events.next_event_async().await
	}

	/// Returns and clears all events without blocking.
	///
	/// Typically you would spawn a thread or task that calls this in a loop.
	///
	/// **Note**: Users must handle events as soon as possible to avoid an increased event queue
	/// memory footprint. We will start dropping any generated events after
	/// [`MAX_EVENT_QUEUE_SIZE`] has been reached.
	///
	/// [`MAX_EVENT_QUEUE_SIZE`]: crate::events::MAX_EVENT_QUEUE_SIZE
	pub fn get_and_clear_pending_events(&self) -> Vec<LiquidityEvent> {
		self.pending_events.get_and_clear_pending_events()
	}

	fn handle_lsps_message(
		&self, msg: LSPSMessage, sender_node_id: &PublicKey,
	) -> Result<(), lightning::ln::msgs::LightningError> {
		match msg {
			LSPSMessage::Invalid(_error) => {
				return Err(LightningError { err: format!("{} did not understand a message we previously sent, maybe they don't support a protocol we are trying to use?", sender_node_id), action: ErrorAction::IgnoreAndLog(Level::Error)});
			},
			LSPSMessage::LSPS0(msg @ LSPS0Message::Response(..)) => {
				self.lsps0_client_handler.handle_message(msg, sender_node_id)?;
			},
			LSPSMessage::LSPS0(msg @ LSPS0Message::Request(..)) => {
				match &self.lsps0_service_handler {
					Some(lsps0_service_handler) => {
						lsps0_service_handler.handle_message(msg, sender_node_id)?;
					},
					None => {
						return Err(LightningError { err: format!("Received LSPS0 request message without LSPS0 service handler configured. From node = {:?}", sender_node_id), action: ErrorAction::IgnoreAndLog(Level::Info)});
					},
				}
			},
			LSPSMessage::LSPS1(msg @ LSPS1Message::Response(..)) => {
				match &self.lsps1_client_handler {
					Some(lsps1_client_handler) => {
						lsps1_client_handler.handle_message(msg, sender_node_id)?;
					},
					None => {
						return Err(LightningError { err: format!("Received LSPS1 response message without LSPS1 client handler configured. From node = {:?}", sender_node_id), action: ErrorAction::IgnoreAndLog(Level::Info)});
					},
				}
			},
			LSPSMessage::LSPS1(_msg @ LSPS1Message::Request(..)) => {
				#[cfg(lsps1_service)]
				match &self.lsps1_service_handler {
					Some(lsps1_service_handler) => {
						lsps1_service_handler.handle_message(_msg, sender_node_id)?;
					},
					None => {
						return Err(LightningError { err: format!("Received LSPS1 request message without LSPS1 service handler configured. From node = {:?}", sender_node_id), action: ErrorAction::IgnoreAndLog(Level::Info)});
					},
				}
				#[cfg(not(lsps1_service))]
				return Err(LightningError { err: format!("Received LSPS1 request message without LSPS1 service handler configured. From node = {:?}", sender_node_id), action: ErrorAction::IgnoreAndLog(Level::Info)});
			},
			LSPSMessage::LSPS2(msg @ LSPS2Message::Response(..)) => {
				match &self.lsps2_client_handler {
					Some(lsps2_client_handler) => {
						lsps2_client_handler.handle_message(msg, sender_node_id)?;
					},
					None => {
						return Err(LightningError { err: format!("Received LSPS2 response message without LSPS2 client handler configured. From node = {:?}", sender_node_id), action: ErrorAction::IgnoreAndLog(Level::Info)});
					},
				}
			},
			LSPSMessage::LSPS2(msg @ LSPS2Message::Request(..)) => {
				match &self.lsps2_service_handler {
					Some(lsps2_service_handler) => {
						lsps2_service_handler.handle_message(msg, sender_node_id)?;
					},
					None => {
						return Err(LightningError { err: format!("Received LSPS2 request message without LSPS2 service handler configured. From node = {:?}", sender_node_id), action: ErrorAction::IgnoreAndLog(Level::Info)});
					},
				}
			},
			LSPSMessage::LSPS5(msg @ LSPS5Message::Response(..)) => {
				match &self.lsps5_client_handler {
					Some(lsps5_client_handler) => {
						lsps5_client_handler.handle_message(msg, sender_node_id)?;
					},
					None => {
						return Err(LightningError { err: format!("Received LSPS5 response message without LSPS5 client handler configured. From node = {:?}", sender_node_id), action: ErrorAction::IgnoreAndLog(Level::Info)});
					},
				}
			},
			LSPSMessage::LSPS5(msg @ LSPS5Message::Request(..)) => {
				match &self.lsps5_service_handler {
					Some(lsps5_service_handler) => {
						lsps5_service_handler.handle_message(msg, sender_node_id)?;
					},
					None => {
						return Err(LightningError { err: format!("Received LSPS5 request message without LSPS5 service handler configured. From node = {:?}", sender_node_id), action: ErrorAction::IgnoreAndLog(Level::Info)});
					},
				}
			},
		}
		Ok(())
	}
}

impl<ES: Deref + Clone, CM: Deref + Clone, C: Deref + Clone, TP: Deref + Clone> CustomMessageReader
	for LiquidityManager<ES, CM, C, TP>
where
	ES::Target: EntropySource,
	CM::Target: AChannelManager,
	C::Target: Filter,
	TP::Target: TimeProvider,
{
	type CustomMessage = RawLSPSMessage;

	fn read<RD: LengthLimitedRead>(
		&self, message_type: u16, buffer: &mut RD,
	) -> Result<Option<Self::CustomMessage>, lightning::ln::msgs::DecodeError> {
		match message_type {
			LSPS_MESSAGE_TYPE_ID => {
				Ok(Some(RawLSPSMessage::read_from_fixed_length_buffer(buffer)?))
			},
			_ => Ok(None),
		}
	}
}

impl<ES: Deref + Clone, CM: Deref + Clone, C: Deref + Clone, TP: Deref + Clone> CustomMessageHandler
	for LiquidityManager<ES, CM, C, TP>
where
	ES::Target: EntropySource,
	CM::Target: AChannelManager,
	C::Target: Filter,
	TP::Target: TimeProvider,
{
	fn handle_custom_message(
		&self, msg: Self::CustomMessage, sender_node_id: PublicKey,
	) -> Result<(), lightning::ln::msgs::LightningError> {
		{
			if self.ignored_peers.read().unwrap().contains(&sender_node_id) {
				let err = format!("Ignoring message from peer {}.", sender_node_id);
				return Err(LightningError {
					err,
					action: ErrorAction::IgnoreAndLog(Level::Trace),
				});
			}
		}

		let message = {
			{
				let mut request_id_to_method_map = self.request_id_to_method_map.lock().unwrap();
				LSPSMessage::from_str_with_id_map(&msg.payload, &mut request_id_to_method_map)
			}
			.map_err(|_| {
				let error = LSPSResponseError {
					code: JSONRPC_INVALID_MESSAGE_ERROR_CODE,
					message: JSONRPC_INVALID_MESSAGE_ERROR_MESSAGE.to_string(),
					data: None,
				};

				self.pending_messages.enqueue(&sender_node_id, LSPSMessage::Invalid(error));
				self.ignored_peers.write().unwrap().insert(sender_node_id);
				let err = format!(
					"Failed to deserialize invalid LSPS message. Ignoring peer {} from now on.",
					sender_node_id
				);
				LightningError { err, action: ErrorAction::IgnoreAndLog(Level::Info) }
			})?
		};

		self.handle_lsps_message(message, &sender_node_id)
	}

	fn get_and_clear_pending_msg(&self) -> Vec<(PublicKey, Self::CustomMessage)> {
		let pending_messages = self.pending_messages.get_and_clear_pending_msgs();

		let mut request_ids_and_methods = pending_messages
			.iter()
			.filter_map(|(_, msg)| msg.get_request_id_and_method())
			.peekable();

		if request_ids_and_methods.peek().is_some() {
			let mut request_id_to_method_map_lock = self.request_id_to_method_map.lock().unwrap();
			for (request_id, method) in request_ids_and_methods {
				request_id_to_method_map_lock.insert(request_id, method);
			}
		}

		pending_messages
			.into_iter()
			.filter_map(|(public_key, msg)| {
				serde_json::to_string(&msg)
					.ok()
					.map(|payload| (public_key, RawLSPSMessage { payload }))
			})
			.collect()
	}

	fn provided_node_features(&self) -> NodeFeatures {
		let mut features = NodeFeatures::empty();

		let advertise_service = self.service_config.as_ref().map_or(false, |c| c.advertise_service);

		if advertise_service {
			features
				.set_optional_custom_bit(LSPS_FEATURE_BIT)
				.expect("Failed to set LSPS feature bit");
		}

		features
	}

	fn provided_init_features(&self, _their_node_id: PublicKey) -> InitFeatures {
		let mut features = InitFeatures::empty();

		let advertise_service = self.service_config.as_ref().map_or(false, |c| c.advertise_service);
		if advertise_service {
			features
				.set_optional_custom_bit(LSPS_FEATURE_BIT)
				.expect("Failed to set LSPS feature bit");
		}

		features
	}

	fn peer_disconnected(&self, counterparty_node_id: bitcoin::secp256k1::PublicKey) {
		// If the peer was misbehaving, drop it from the ignored list to cleanup the kept state.
		self.ignored_peers.write().unwrap().remove(&counterparty_node_id);

		if let Some(lsps2_service_handler) = self.lsps2_service_handler.as_ref() {
			lsps2_service_handler.peer_disconnected(counterparty_node_id);
		}
	}
	fn peer_connected(
		&self, _: bitcoin::secp256k1::PublicKey, _: &lightning::ln::msgs::Init, _: bool,
	) -> Result<(), ()> {
		Ok(())
	}
}

impl<ES: Deref + Clone, CM: Deref + Clone, C: Deref + Clone, TP: Deref + Clone> Listen
	for LiquidityManager<ES, CM, C, TP>
where
	ES::Target: EntropySource,
	CM::Target: AChannelManager,
	C::Target: Filter,
	TP::Target: TimeProvider,
{
	fn filtered_block_connected(
		&self, header: &bitcoin::block::Header, txdata: &chain::transaction::TransactionData,
		height: u32,
	) {
		if let Some(best_block) = self.best_block.read().unwrap().as_ref() {
			assert_eq!(best_block.block_hash, header.prev_blockhash,
			"Blocks must be connected in chain-order - the connected header must build on the last connected header");
			assert_eq!(best_block.height, height - 1,
			"Blocks must be connected in chain-order - the connected block height must be one greater than the previous height");
		}

		self.transactions_confirmed(header, txdata, height);
		self.best_block_updated(header, height);
	}

	fn block_disconnected(&self, header: &bitcoin::block::Header, height: u32) {
		let new_height = height - 1;
		if let Some(best_block) = self.best_block.write().unwrap().as_mut() {
			assert_eq!(best_block.block_hash, header.block_hash(),
				"Blocks must be disconnected in chain-order - the disconnected header must be the last connected header");
			assert_eq!(best_block.height, height,
				"Blocks must be disconnected in chain-order - the disconnected block must have the correct height");
			*best_block = BestBlock::new(header.prev_blockhash, new_height)
		}

		// TODO: Call block_disconnected on all sub-modules that require it, e.g., LSPS1MessageHandler.
		// Internally this should call transaction_unconfirmed for all transactions that were
		// confirmed at a height <= the one we now disconnected.
	}
}

impl<ES: Deref + Clone, CM: Deref + Clone, C: Deref + Clone, TP: Deref + Clone> Confirm
	for LiquidityManager<ES, CM, C, TP>
where
	ES::Target: EntropySource,
	CM::Target: AChannelManager,
	C::Target: Filter,
	TP::Target: TimeProvider,
{
	fn transactions_confirmed(
		&self, _header: &bitcoin::block::Header, _txdata: &chain::transaction::TransactionData,
		_height: u32,
	) {
		// TODO: Call transactions_confirmed on all sub-modules that require it, e.g., LSPS1MessageHandler.
	}

	fn transaction_unconfirmed(&self, _txid: &bitcoin::Txid) {
		// TODO: Call transaction_unconfirmed on all sub-modules that require it, e.g., LSPS1MessageHandler.
		// Internally this should call transaction_unconfirmed for all transactions that were
		// confirmed at a height <= the one we now unconfirmed.
	}

	fn best_block_updated(&self, header: &bitcoin::block::Header, height: u32) {
		let new_best_block = BestBlock::new(header.block_hash(), height);
		*self.best_block.write().unwrap() = Some(new_best_block);

		// TODO: Call best_block_updated on all sub-modules that require it, e.g., LSPS1MessageHandler.
		if let Some(lsps2_service_handler) = self.lsps2_service_handler.as_ref() {
			lsps2_service_handler.prune_peer_state();
		}
	}

	fn get_relevant_txids(&self) -> Vec<(bitcoin::Txid, u32, Option<bitcoin::BlockHash>)> {
		// TODO: Collect relevant txids from all sub-modules that, e.g., LSPS1MessageHandler.
		Vec::new()
	}
}
