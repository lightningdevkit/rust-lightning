# 0.0.105 - 2022-02-28

## API Updates
 * `Phantom node` payments are now supported, allowing receipt of a payment on
   any one of multiple nodes without any coordination across the nodes being
   required. See the new `PhantomKeysManager`'s docs for more, as well as
   requirements on `KeysInterface::get_inbound_payment_key_material` and
   `lightning_invoice::utils::create_phantom_invoice` (#1199).
 * In order to support phantom node payments, several `KeysInterface` methods
   now accept a `Recipient` parameter to select between the local `node_id` and
   a phantom-specific one.
 * `ProbabilisticScorer`, a `Score` based on learning the current balances of
   channels in the network, was added. It attempts to better capture payment
   success probability than the existing `Scorer`, though may underperform on
   nodes with low payment volume. We welcome feedback on performance (#1227).
 * `Score::channel_penalty_msat` now always takes the channel value, instead of
   an `Option` (#1227).
 * `UserConfig::manually_accept_inbound_channels` was added which, when set,
   generates a new `Event::OpenChannelRequest`, which allows manual acceptance
   or rejection of incoming channels on a per-channel basis (#1281).
 * `Payee` has been renamed to `PaymentParameters` (#1271).
 * `PaymentParameters` now has a `max_total_cltv_expiry_delta` field. This
   defaults to 1008 and limits the maximum amount of time an HTLC can be pending
   before it will either fail or be claimed (#1234).
 * The `lightning-invoice` crate now supports no-std environments. This required
   numerous API changes around timestamp handling and std+no-std versions of
   several methods that previously assumed knowledge of the time (#1223, #1230).
 * `lightning-invoice` now supports parsing invoices with expiry times of more
   than one year. This required changing the semantics of `ExpiryTime` (#1273).
 * The `CounterpartyCommitmentSecrets` is now public, allowing external uses of
   the `BOLT 3` secret storage scheme (#1299).
 * Several `Sign` methods now receive HTLC preimages as proof of state
   transition, see new documentation for more (#1251).
 * `KeysInterface::sign_invoice` now provides the HRP and other invoice data
   separately to make it simpler for external signers to parse (#1272).
 * `Sign::sign_channel_announcement` now returns both the node's signature and
   the per-channel signature. `InMemorySigner` now requires the node's secret
   key in order to implement this (#1179).
 * `ChannelManager` deserialization will now fail if the `KeysInterface` used
   has a different `node_id` than the `ChannelManager` expects (#1250).
 * A new `ErrorAction` variant was added to send `warning` messages (#1013).
 * Several references to `chain::Listen` objects in `lightning-block-sync` no
   longer require a mutable reference (#1304).

## Bug Fixes
 * Fixed a regression introduced in 0.0.104 where `ChannelManager`'s internal
   locks could have an order violation leading to a deadlock (#1238).
 * Fixed cases where slow code (including user I/O) could cause us to
   disconnect peers with ping timeouts in `BackgroundProcessor` (#1269).
 * Now persist the `ChannelManager` prior to `BackgroundProcessor` stopping,
   preventing race conditions where channels are closed on startup even with a
   clean shutdown. This requires that users stop network processing and
   disconnect peers prior to `BackgroundProcessor` shutdown (#1253).
 * Fields in `ChannelHandshakeLimits` provided via the `override_config` to
   `create_channel` are now applied instead of the default config (#1292).
 * Fixed the generation of documentation on docs.rs to include API surfaces
   which are hidden behind feature flags (#1303).
 * Added the `channel_type` field to `accept_channel` messages we send, which
   may avoid some future compatibility issues with other nodes (#1314).
 * Fixed a bug where, if a previous LDK run using `lightning-persister` crashed
   while persisting updated data, we may have failed to initialize (#1332).
 * Fixed a rare bug where having both pending inbound and outbound HTLCs on a
   just-opened inbound channel could cause `ChannelDetails::balance_msat` to
   underflow and be reported as large, or cause panics in debug mode (#1268).
 * Moved more instances of verbose gossip logging from the `Trace` level to the
   `Gossip` level (#1220).
 * Delayed `announcement_signatures` until the channel has six confirmations,
   slightly improving propagation of channel announcements (#1179).
 * Several fixes in script and transaction weight calculations when anchor
   outputs are enabled (#1229).

## Serialization Compatibility
 * Using `ChannelManager` data written by versions prior to 0.0.105 will result
   in preimages for HTLCs that were pending at startup to be missing in calls
   to `KeysInterface` methods (#1251).
 * Any phantom invoice payments received on a node that is not upgraded to
   0.0.105 will fail with an "unknown channel" error. Further, downgrading to
   0.0.104 or before and then upgrading again will invalidate existing phantom
   SCIDs which may be included in invoices (#1199).

In total, this release features 108 files changed, 6914 insertions, 2095
deletions in 102 commits from 15 authors, in alphabetical order:
 * Conor Okus
 * Devrandom
 * Elias Rohrer
 * Jeffrey Czyz
 * Jurvis Tan
 * Ken Sedgwick
 * Matt Corallo
 * Naveen
 * Tibo-lg
 * Valentine Wallace
 * Viktor Tigerström
 * dependabot[bot]
 * hackerrdave
 * naveen
 * vss96


# 0.0.104 - 2021-12-17

## API Updates
 * A `PaymentFailed` event is now provided to indicate a payment has failed
   fully. This event is generated either after
   `ChannelManager::abandon_payment` is called for a given payment, or the
   payment times out, and there are no further pending HTLCs for the payment.
   This event should be used to detect payment failure instead of
   `PaymentPathFailed::all_paths_failed`, unless no payment retries occur via
   `ChannelManager::retry_payment` (#1202).
 * Payment secrets are now generated deterministically using material from
   the new `KeysInterface::get_inbound_payment_key_material` (#1177).
 * A `PaymentPathSuccessful` event has been added to ease passing success info
   to a scorer, along with a `Score::payment_path_successful` method to accept
   such info (#1178, #1197).
 * `Score::channel_penalty_msat` has additional arguments describing the
   channel's capacity and the HTLC amount being sent over the channel (#1166).
 * A new log level `Gossip` has been added, which is used for verbose
   information generated during network graph sync. Enabling the
   `max_level_trace` feature or ignoring `Gossip` log entries reduces log
   growth during initial start up from many GiB to several MiB (#1145).
 * The `allow_wallclock_use` feature has been removed in favor of only using
   the `std` and `no-std` features (#1212).
 * `NetworkGraph` can now remove channels that we haven't heard updates for in
   two weeks with `NetworkGraph::remove_stale_channels{,with_time}`. The first
   is called automatically if a `NetGraphMsgHandler` is passed to
   `BackgroundProcessor::start` (#1212).
 * `InvoicePayer::pay_pubkey` was added to enable sending "keysend" payments to
   supported recipients, using the `InvoicePayer` to handle retires (#1160).
 * `user_payment_id` has been removed from `PaymentPurpose`, and
   `ChannelManager::create_inbound_payment{,_for_hash}` (#1180).
 * Updated documentation for several `ChannelManager` functions to remove stale
   references to panics which no longer occur (#1201).
 * The `Score` and `LockableScore` objects have moved into the
   `routing::scoring` module instead of being in the `routing` module (#1166).
 * The `Time` parameter to `ScorerWithTime` is no longer longer exposed,
   instead being fixed based on the `std`/`no-std` feature (#1184).
 * `ChannelDetails::balance_msat` was added to fetch a channel's balance
   without subtracting the reserve values, lining up with on-chain claim amounts
   less on-chain fees (#1203).
 * An explicit `UserConfig::accept_inbound_channels` flag is now provided,
   removing the need to set `min_funding_satoshis` to > 21 million BTC (#1173).
 * Inbound channels that fail to see the funding transaction confirm within
   2016 blocks are automatically force-closed with
   `ClosureReason::FundingTimedOut` (#1083).
 * We now accept a channel_reserve value of 0 from counterparties, as it is
   insecure for our counterparty but not us (#1163).
 * `NetAddress::OnionV2` parsing was removed as version 2 onion services are no
   longer supported in modern Tor (#1204).
 * Generation and signing of anchor outputs is now supported in the
   `KeysInterface`, though no support for them exists in the channel itself (#1176)

## Bug Fixes
 * Fixed a race condition in `InvoicePayer` where paths may be retried after
   the retry count has been exceeded. In this case the
   `Event::PaymentPathFailed::all_paths_failed` field is not a reliable payment
   failure indicator. There was no acceptable alternative indicator,
   `Event::PaymentFailed` as been added to provide one (#1202).
 * Reduced the blocks-before-timeout we expect of outgoing HTLCs before
   refusing to forward. This check was overly strict and resulted in refusing
   to forward som HTLCs to a next hop that had a lower security threshold than
   us (#1119).
 * LDK no longer attempt to update the channel fee for outbound channels when
   we cannot afford the new fee. This could have caused force-closure by our
   channel counterparty (#1054).
 * Fixed several bugs which may have prevented the reliable broadcast of our
   own channel announcements and updates (#1169).
 * Fixed a rare bug which may have resulted in spurious route finding failures
   when using last-hop hints and MPP with large value payments (#1168).
 * `KeysManager::spend_spendable_outputs` no longer adds a change output that
   is below the dust threshold for non-standard change scripts (#1131).
 * Fixed a minor memory leak when attempting to send a payment that fails due
   to an error when updating the `ChannelMonitor` (#1143).
 * Fixed a bug where a `FeeEstimator` that returns values rounded to the next
   sat/vbyte may result in force-closures (#1208).
 * Handle MPP timeout HTLC error codes, instead of considering the recipient to
   have sent an invalid error, removing them from the network graph (#1148)

## Serialization Compatibility
 * All above new events/fields are ignored by prior clients. All above new
   events/fields are not present when reading objects serialized by prior
   versions of the library.
 * Payment secrets are now generated deterministically. This reduces the memory
   footprint for inbound payments, however, newly-generated inbound payments
   using `ChannelManager::create_inbound_payment{,_for_hash}` will not be
   receivable using versions prior to 0.0.104.
   `ChannelManager::create_inbound_payment{,_for_hash}_legacy` are provided for
   backwards compatibility (#1177).
 * `PaymentPurpose::InvoicePayment::user_payment_id` will be 0 when reading
   objects written with 0.0.104 when read by 0.0.103 and previous (#1180).

In total, this release features 51 files changed, 5356 insertions, 2238
deletions in 107 commits from 9 authors, in alphabetical order:
 * Antoine Riard
 * Conor Okus
 * Devrandom
 * Duncan Dean
 * Elias Rohrer
 * Jeffrey Czyz
 * Ken Sedgwick
 * Matt Corallo
 * Valentine Wallace


# 0.0.103 - 2021-11-02

## API Updates
 * This release is almost entirely focused on a new API in the
   `lightning-invoice` crate - the `InvoicePayer`. `InvoicePayer` is a
   struct which takes a reference to a `ChannelManager` and a `Router`
   and retries payments as paths fail. It limits retries to a configurable
   number, but is not serialized to disk and may retry additional times across
   a serialization/load. In order to learn about failed payments, it must
   receive `Event`s directly from the `ChannelManager`, wrapping a
   user-provided `EventHandler` which it provides all unhandled events to
   (#1059).
 * `get_route` has been renamed `find_route` (#1059) and now takes a
   `RouteParameters` struct in replacement of a number of its long list of
   arguments (#1134). The `Payee` in the `RouteParameters` is stored in the
   `Route` object returned and provided in the `RouteParameters` contained in
   `Event::PaymentPathFailed` (#1059).
 * `ChannelMonitor`s must now be persisted after calls that provide new block
   data, prior to `MonitorEvent`s being passed back to `ChannelManager` for
   processing. If you are using a `ChainMonitor` this is handled for you.
   The `Persist` API has been updated to `Option`ally take the
   `ChannelMonitorUpdate` as persistence events that result from chain data no
   longer have a corresponding update (#1108).
 * `routing::Score` now has a `payment_path_failed` method which it can use to
   learn which channels often fail payments. It is automatically called by
   `InvoicePayer` for failed payment paths (#1144).
 * The default `Scorer` implementation is now a type alias to a type generic
   across different clocks and supports serialization to persist scoring data
   across restarts (#1146).
 * `Event::PaymentSent` now includes the full fee which was spent across all
   payment paths which were fulfilled or pending when the payment was fulfilled
   (#1142).
 * `Event::PaymentSent` and `Event::PaymentPathFailed` now include the
   `PaymentId` which matches the `PaymentId` returned from
   `ChannelManager::send_payment` or `InvoicePayer::pay_invoice` (#1059).
 * `NetGraphMsgHandler` now takes a `Deref` to the `NetworkGraph`, allowing for
   shared references to the graph data to make serialization and references to
   the graph data in the `InvoicePayer`'s `Router` simpler (#1149).
 * `routing::Score::channel_penalty_msat` has been updated to provide the
   `NodeId` of both the source and destination nodes of a channel (#1133).

## Bug Fixes
 * Previous versions would often disconnect peers during initial graph sync due
   to ping timeouts while processing large numbers of gossip messages. We now
   delay disconnecting peers if we receive messages from them even if it takes
   a while to receive a pong from them. Further, we avoid sending too many
   gossip messages between pings to ensure we should always receive pongs in a
   timely manner (#1137).
 * If a payment was sent, creating an outbound HTLC and sending it to our
   counterparty (implying the `ChannelMonitor` was persisted on disk), but the
   `ChannelManager` was not persisted prior to shutdown/crash, no
   `Event::PaymentPathFailed` event was generated if the HTLC was eventually
   failed on chain. Events are now consistent irrespective of `ChannelManager`
   persistence or non-persistence (#1104).

## Serialization Compatibility
 * All above new Events/fields are ignored by prior clients. All above new
   Events/fields are not present when reading objects serialized by prior
   versions of the library.
 * Payments for which a `Route` was generated using a previous version or for
   which the payment was originally sent by a previous version of the library
   will not be retried by an `InvoicePayer`.

This release was singularly focused and some contributions by third parties
were delayed.
In total, this release features 38 files changed, 4414 insertions, and 969
deletions in 71 commits from 2 authors, in alphabetical order:

 * Jeffrey Czyz
 * Matt Corallo


# 0.0.102 - 2021-10-18

## API Updates
 * `get_route` now takes a `Score` as an argument. `Score` is queried during
   the route-finding process, returning the absolute amounts which you are
   willing to pay to avoid routing over a given channel. As a default, a
   `Scorer` is provided which returns a constant amount, with a suggested
   default of 500 msat. This translates to a willingness to pay up to 500 msat
   in additional fees per hop in order to avoid additional hops (#1124).
 * `Event::PaymentPathFailed` now contains a `short_channel_id` field which may
   be filled in with a channel that can be "blamed" for the payment failure.
   Payment retries should likely avoid the given channel for some time (#1077).
 * `PublicKey`s in `NetworkGraph` have been replaced with a `NodeId` struct
   which contains only a simple `[u8; 33]`, substantially improving
   `NetworkGraph` deserialization performance (#1107).
 * `ChainMonitor`'s `HashMap` of `ChannelMonitor`s is now private, exposed via
   `Chainmonitor::get_monitor` and `ChainMonitor::list_monitors` instead
   (#1112).
 * When an outbound channel is closed prior to the broadcasting of its funding
   transaction, but after you call
   `ChannelManager::funding_transaction_generated`, a new event type,
   `Event::DiscardFunding`, is generated, informing you the transaction was not
   broadcasted and that you can spend the same inputs again elsewhere (#1098).
 * `ChannelManager::create_channel` now returns the temporary channel ID which
   may later appear in `Event::ChannelClosed` or `ChannelDetails` prior to the
   channel being funded (#1121).
 * `Event::PaymentSent` now contains the payment hash as well as the payment
   preimage (#1062).
 * `ReadOnlyNetworkGraph::get_addresses` now returns owned `NetAddress` rather
   than references. As a side-effect this method is now exposed in foreign
   language bindings (#1115).
 * The `Persist` and `ChannelMonitorUpdateErr` types have moved to the
   `lightning::chain::chainmonitor` and `lightning::chain` modules,
   respectively (#1112).
 * `ChannelManager::send_payment` now returns a `PaymentId` which identifies a
   payment (whether MPP or not) and can be used to retry the full payment or
   MPP parts through `retry_payment` (#1096). Note that doing so is currently
   *not* crash safe, and you may find yourself sending twice. It is recommended
   that you *not* use the `retry_payment` API until the next release.

## Bug Fixes
 * Due to an earlier fix for the Lightning dust inflation vulnerability tracked
   in CVE-2021-41591/CVE-2021-41592/CVE-2021-41593 in 0.0.100, we required
   counterparties to accept a dust limit slightly lower than the dust limit now
   required by other implementations. This appeared as, at least, latest lnd
   always refusing to accept channels opened by LDK clients (#1065).
 * If there are multiple channels available to the same counterparty,
   `get_route` would only consider the channel listed last as available for
   sending (#1100).
 * `Persist` implementations returning
   `ChannelMonitorUpdateErr::TemporaryFailure` from `watch_channel` previously
   resulted in the `ChannelMonitor` not being stored at all, resulting in a
   panic after monitor updating is complete (#1112).
 * If payments are pending awaiting forwarding at startup, an
   `Event::PendingHTLCsForwardable` event will always be provided. This ensures
   user code calls `ChannelManager::process_pending_htlc_fowards` even if it
   shut down while awaiting the batching timer during the previous run (#1076).
 * If a call to `ChannelManager::send_payment` failed due to lack of
   availability of funds locally, LDK would store the payment as pending
   forever, with no ability to retry or fail it, leaking memory (#1109).

## Serialization Compatibility
 * All above new Events/fields are ignored by prior clients. All above new
   Events/fields, except for `Event::PaymentSent::payment_hash` are not present
   when reading objects serialized by prior versions of the library.

In total, this release features 32 files changed, 2248 insertions, and 1483
deletions in 51 commits from 7 authors, in alphabetical order:

 * 1nF0rmed
 * Duncan Dean
 * Elias Rohrer
 * Galder Zamarreño
 * Jeffrey Czyz
 * Matt Corallo
 * Valentine Wallace


# 0.0.101 - 2021-09-23

## API Updates
 * Custom message types are now supported directly in the `PeerManager`,
   allowing you to send and receive messages of any type that is not natively
   understood by LDK. This requires a new type bound on `PeerManager`, a
   `CustomMessageHandler`. `IgnoringMessageHandler` provides a simple default
   for this new bound for ignoring unknown messages (#1031, #1074).
 * Route graph updates as a result of failed payments are no longer provided as
   `MessageSendEvent::PaymentFailureNetworkUpdate` but instead included in a
   new field in the `Event::PaymentFailed` events. Generally, this means route
   graph updates are no longer handled as a part of the `PeerManager` but
   instead through the new `EventHandler` implementation for
   `NetGraphMsgHandler`. To make this easy, a new parameter to
   `lightning-background-processor::BackgroundProcessor::start` is added, which
   contains an `Option`al `NetGraphmsgHandler`. If provided as `Some`, relevant
   events will be processed by the `NetGraphMsgHandler` prior to normal event
   handling (#1043).
 * `NetworkGraph` is now, itself, thread-safe. Accordingly, most functions now
   take `&self` instead of `&mut self` and the graph data can be accessed
   through `NetworkGraph.read_only` (#1043).
 * The balances available on-chain to claim after a channel has been closed are
   now exposed via `ChannelMonitor::get_claimable_balances` and
   `ChainMonitor::get_claimable_balances`. The second can be used to get
   information about all closed channels which still have on-chain balances
   associated with them. See enum variants of `ln::channelmonitor::Balance` and
   method documentation for the above methods for more information on the types
   of balances exposed (#1034).
 * When one HTLC of a multi-path payment fails, the new field `all_paths_failed`
   in `Event::PaymentFailed` is set to `false`. This implies that the payment
   has not failed, but only one part. Payment resolution is only indicated by an
   `Event::PaymentSent` event or an `Event::PaymentFailed` with
   `all_paths_failed` set to `true`, which is also set for the last remaining
   part of a multi-path payment (#1053).
 * To better capture the context described above, `Event::PaymentFailed` has
   been renamed to `Event::PaymentPathFailed` (#1084).
 * A new event, `ChannelClosed`, is provided by `ChannelManager` when a channel
   is closed, including a reason and error message (if relevant, #997).
 * `lightning-invoice` now considers invoices with sub-millisatoshi precision
   to be invalid, and requires millisatoshi values during construction (thus
   you must call `amount_milli_satoshis` instead of `amount_pico_btc`, #1057).
 * The `BaseSign` interface now includes two new hooks which provide additional
   information about commitment transaction signatures and revocation secrets
   provided by our counterparty, allowing additional verification (#1039).
 * The `BaseSign` interface now includes additional information for cooperative
   close transactions, making it easier for a signer to verify requests (#1064).
 * `Route` has two additional helper methods to get fees and amounts (#1063).
 * `Txid` and `Transaction` objects can now be deserialized from responses when
   using the HTTP client in the `lightning-block-sync` crate (#1037, #1061).

## Bug Fixes
 * Fix a panic when reading a lightning invoice with a non-recoverable
   signature. Further, restrict lightning invoice parsing to require payment
   secrets and better handle a few edge cases as required by BOLT 11 (#1057).
 * Fix a panic when receiving multiple messages (such as HTLC fulfill messages)
   after a call to `chain::Watch::update_channel` returned
   `Err(ChannelMonitorUpdateErr::TemporaryFailure)` with no
   `ChannelManager::channel_monitor_updated` call in between (#1066).
 * For multi-path payments, `Event::PaymentSent` is no longer generated
   multiple times, once for each independent part (#1053).
 * Multi-hop route hints in invoices are now considered in the default router
   provided via `get_route` (#1040).
 * The time peers have to respond to pings has been increased when building
   with debug assertions enabled. This avoids peer disconnections on slow hosts
   when running in debug mode (#1051).
 * The timeout for the first byte of a response for requests from the
   `lightning-block-sync` crate has been increased to 300 seconds to better
   handle the long hangs in Bitcoin Core when it syncs to disk (#1090).

## Serialization Compatibility
 * Due to a bug in 0.0.100, `Event`s written by 0.0.101 which are of a type not
   understood by 0.0.100 may lead to `Err(DecodeError::InvalidValue)` or corrupt
   deserialized objects in 0.100. Such `Event`s will lead to an
   `Err(DecodeError::InvalidValue)` in versions prior to 0.0.100. The only such
   new event written by 0.0.101 is `Event::ChannelClosed` (#1087).
 * Payments that were initiated in versions prior to 0.0.101 may still
   generate duplicate `PaymentSent` `Event`s or may have spurious values for
   `Event::PaymentPathFailed::all_paths_failed` (#1053).
 * The return values of `ChannelMonitor::get_claimable_balances` (and, thus,
   `ChainMonitor::get_claimable_balances`) may be spurious for channels where
   the spend of the funding transaction appeared on chain while running a
   version prior to 0.0.101. `Balance` information should only be relied upon
   for channels that were closed while running 0.0.101+ (#1034).
 * Payments failed while running versions prior to 0.0.101 will never have a
   `Some` for the `network_update` field (#1043).

In total, this release features 67 files changed, 4980 insertions, 1888
deletions in 89 commits from 12 authors, in alphabetical order:
 * Antoine Riard
 * Devrandom
 * Galder Zamarreño
 * Giles Cope
 * Jeffrey Czyz
 * Joseph Goulden
 * Matt Corallo
 * Sergi Delgado Segura
 * Tibo-lg
 * Valentine Wallace
 * abhik-99
 * vss96


# 0.0.100 - 2021-08-17

## API Updates
 * The `lightning` crate can now be built in no_std mode, making it easy to
   target embedded hardware for rust users. Note that mutexes are replaced with
   no-ops for such builds (#1008, #1028).
 * LDK now supports sending and receiving "keysend" payments. This includes
   modifications to `lightning::util::events::Event::PaymentReceived` to
   indicate the type of payment (#967).
 * A new variant, `lightning::util::events::Event::PaymentForwarded` has been
   added which indicates a forwarded payment has been successfully claimed and
   we've received a forwarding fee (#1004).
 * `lightning::chain::keysinterface::KeysInterface::get_shutdown_pubkey` has
   been renamed to `get_shutdown_scriptpubkey`, returns a script, and is now
   called on channel open only if
   `lightning::util::config::ChannelConfig::commit_upfront_shutdown_pubkey` is
   set (#1019).
 * Closing-signed negotiation is now more configurable, with an explicit
   `lightning::util::config::ChannelConfig::force_close_avoidance_max_fee_satoshis`
   field allowing you to select the maximum amount you are willing to pay to
   avoid a force-closure. Further, we are now less restrictive on the fee
   placed on the closing transaction when we are not the party paying it. To
   control the feerate paid on a channel at close-time, use
   `ChannelManager::close_channel_with_target_feerate` instead of
   `close_channel` (#1011).
 * `lightning_background_processor::BackgroundProcessor` now stops the
   background thread when dropped (#1007). It is marked `#[must_use]` so that
   Rust users will receive a compile-time warning when it is immediately
   dropped after construction (#1029).
 * Total potential funds burn on force-close due to dust outputs is now limited
   to `lightning::util::config::ChannelConfig::max_dust_htlc_exposure_msat` per
   channel (#1009).
 * The interval on which
   `lightning::ln::peer_handler::PeerManager::timer_tick_occurred` should be
   called has been reduced to once every five seconds (#1035) and
   `lightning::ln::channelmanager::ChannelManager::timer_tick_occurred` should
   now be called on startup in addition to once per minute (#985).
 * The rust-bitcoin and bech32 dependencies have been updated to their
   respective latest versions (0.27 and 0.8, #1012).

## Bug Fixes
 * Fix panic when reading invoices generated by some versions of c-lightning
   (#1002 and #1003).
 * Fix panic when attempting to validate a signed message of incorrect length
   (#1010).
 * Do not ignore the route hints in invoices when the invoice is over 250k
   sats (#986).
 * Fees are automatically updated on outbound channels to ensure commitment
   transactions are always broadcastable (#985).
 * Fixes a rare case where a `lightning::util::events::Event::SpendableOutputs`
   event is not generated after a counterparty commitment transaction is
   confirmed in a reorg when a conflicting local commitment transaction is
   removed in the same reorg (#1022).
 * Fixes a remotely-triggerable force-closure of an origin channel after an
   HTLC was forwarded over a next-hop channel and the next-hop channel was
   force-closed by our counterparty (#1025).
 * Fixes a rare force-closure case when sending a payment as a channel fundee
   when overdrawing our remaining balance. Instead the send will fail (#998).
 * Fixes a rare force-closure case when a payment was claimed prior to a
   peer disconnection or restart, and later failed (#977).

## Serialization Compatibility
 * Pending inbound keysend payments which have neither been failed nor claimed
   when serialized will result in a `ChannelManager` which is not readable on
   pre-0.0.100 clients (#967).
 * Because
   `lightning::chain::keysinterface::KeysInterface::get_shutdown_scriptpubkey`
   has been updated to return a script instead of only a `PublicKey`,
   `ChannelManager`s constructed with custom `KeysInterface` implementations on
   0.0.100 and later versions will not be readable on previous versions.
   `ChannelManager`s created with 0.0.99 and prior versions will remain readable
   even after the a serialization roundtrip on 0.0.100, as long as no new
   channels are opened. Further, users using a
   `lightning::chain::keysinterface::KeysManager` as their `KeysInterface` will
   have `ChannelManager`s which are readable on prior versions as well (#1019).
 * `ChannelMonitorUpdate`s created by 0.0.100 and later for channels when
   `lightning::util::config::ChannelConfig::commit_upfront_shutdown_pubkey` is
   not set may not be readable by versions prior to 0.0.100 (#1019).
 * HTLCs which were in the process of being claimed on-chain when a pre-0.0.100
   `ChannelMonitor` was serialized may generate `PaymentForwarded` events with
   spurious `fee_earned_msat` values. This only applies to payments which were
   unresolved at the time of the upgrade (#1004).
 * 0.0.100 clients with pending `Event::PaymentForwarded` events at
   serialization-time will generate serialized `ChannelManager` objects which
   0.0.99 and earlier clients cannot read. The likelihood of this can be reduced
   by ensuring you process all pending events immediately before serialization
   (as is done by the `lightning-background-processor` crate, #1004).


In total, this release features 59 files changed, 5861 insertions, and 2082
deletions in 95 commits from 6 authors.


# 0.0.99 - 2021-07-09

## API Updates

 * `lightning_block_sync::poll::Validate` is now public, allowing you to
   implement the `lightning_block_sync::poll::Poll` trait without
   `lightning_block_sync::poll::ChainPoller` (#956).
 * `lightning::ln::peer_handler::PeerManager` no longer requires that no calls
   are made to referencing the same `SocketDescriptor` after
   `disconnect_socket` returns. This makes the API significantly less
   deadlock-prone and simplifies `SocketDescriptor` implementations
   significantly. The relevant changes have been made to `lightning_net_tokio`
   and `PeerManager` documentation has been substantially rewritten (#957).
 * `lightning::util::message_signing`'s `sign` and `verify` methods now take
   secret and public keys by reference instead of value (#974).
 * Substantially more information is now exposed about channels in
   `ChannelDetails`. See documentation for more info (#984 and #988).
 * The latest best block seen is now exposed in
   `ChannelManager::current_best_block` and
   `ChannelMonitor::current_best_block` (#984).
 * Feerates charged when forwarding payments over channels is now set in
   `ChannelConfig::fee_base_msat` when the channel is opened. For existing
   channels, the value is set to the value provided in
   `ChannelManagerReadArgs::default_config::channel_options` the first time the
   `ChannelManager` is loaded in 0.0.99 (#975).
 * We now reject HTLCs which are received to be forwarded over private channels
   unless `UserConfig::accept_forwards_to_priv_channels` is set. Note that
   `UserConfig` is never serialized and must be provided via
   `ChannelManagerReadArgs::default_config` at each start (#975).

## Bug Fixes

 * We now forward gossip messages to peers instead of only relaying
   locally-generated gossip or sending gossip messages during initial sync
   (#948).
 * Correctly send `channel_update` messages to direct peers on private channels
   (#949). Without this, a private node connected to an LDK node over a private
   channel cannot receive funds as it does not know which fees the LDK node
   will charge.
 * `lightning::ln::channelmanager::ChannelManager` no longer expects to be
   persisted spuriously after we receive a `channel_update` message about any
   channel in the routing gossip (#972).
 * Asynchronous `ChannelMonitor` updates (using the
   `ChannelMonitorUpdateErr::TemporaryFailure` return variant) no longer cause
   spurious HTLC forwarding failures (#954).
 * Transaction provided via `ChannelMonitor::transactions_confirmed`
   after `ChannelMonitor::best_block_updated` was called for a much later
   block now trigger all relevant actions as of the later block. Previously
   some transaction broadcasts or other responses required an additional
   block be provided via `ChannelMonitor::best_block_updated` (#970).
 * We no longer panic in rare cases when an invoice contained last-hop route
   hints which were unusable (#958).

## Node Compatibility

 * We now accept spurious `funding_locked` messages sent prior to
   `channel_reestablish` messages after reconnect. This is a
   [known, long-standing bug in lnd](https://github.com/lightningnetwork/lnd/issues/4006)
   (#966).
 * We now set the `first_blocknum` and `number_of_blocks` fields in
   `reply_channel_range` messages to values which c-lightning versions prior to
   0.10 accepted. This avoids spurious force-closes from such nodes (#961).

## Serialization Compatibility

 * Due to a bug discovered in 0.0.98, if a `ChannelManager` is serialized on
   version 0.0.98 while an `Event::PaymentSent` is pending processing, the
   `ChannelManager` will fail to deserialize both on version 0.0.98 and later
   versions. If you have such a `ChannelManager` available, a simple patch will
   allow it to deserialize. Please file an issue if you need assistance (#973).

# 0.0.98 - 2021-06-11

0.0.98 should be considered a release candidate to the first alpha release of
Rust-Lightning and the broader LDK. It represents several years of work
designing and fine-tuning a flexible API for integrating lightning into any
application. LDK should make it easy to build a lightning node or client which
meets specific requirements that other lightning node software cannot. As
lightning continues to evolve, and new use-cases for lightning develop, the API
of LDK will continue to change and expand. However, starting with version 0.1,
objects serialized with prior versions will be readable with the latest LDK.
While Rust-Lightning is approaching the 0.1 milestone, language bindings
components of LDK available at https://github.com/lightningdevkit are still of
varying quality. Some are also approaching an 0.1 release, while others are
still much more experimental. Please note that, at 0.0.98, using Rust-Lightning
on mainnet is *strongly* discouraged.
