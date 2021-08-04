# 0.0.100 - WIP

## Serialization Compatibility
 * HTLCs which were in the process of being claimed on-chain when a pre-0.0.100
   `ChannelMonitor` was serialized may generate `PaymentForwarded` events with
   spurious `fee_earned_msat` values. This only applies to payments which were
   unresolved at the time of the upgrade.
 * 0.0.100 clients with pending PaymentForwarded events at serialization-time
   will generate serialized `ChannelManager` objects which 0.0.99 and earlier
   clients cannot read. The likelihood of this can be reduced by ensuring you
   process all pending events immediately before serialization (as is done by
   the `lightning-background-processor` crate).


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
