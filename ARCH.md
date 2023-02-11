Rust-Lightning is broken into a number of high-level structures with APIs to hook them
together, as well as APIs for you, the user, to provide external data.

The two most important structures which nearly every application of Rust-Lightning will
need to use are `ChannelManager` and `ChannelMonitor`. `ChannelManager` holds multiple
channels, routes payments between them, and exposes a simple API to make and receive
payments. Individual `ChannelMonitor`s monitor the on-chain state of a channel, punish
counterparties if they misbehave, and force-close channels if they contain unresolved
HTLCs which are near expiration. The `chain::Watch` interface provides a way for you to
receive `ChannelMonitorUpdate`s from `ChannelManager` and persist them to disk before the
channel steps forward.

There are two additional important structures that you may use either on the same device
as the `ChannelManager` or on a separate one. `P2PGossipSync` handles receiving channel
and node announcements, which are then used to calculate routes by `find_route` for sending
payments. `PeerManager` handles the authenticated and encrypted communication protocol,
monitoring for liveness of peers, routing messages to `ChannelManager` and `P2PGossipSync`
instances directly, and receiving messages from them via the `EventsProvider` interface.

These structs communicate with each other using a public API, so that you can easily add
a proxy in between for special handling. Further, APIs for key generation, transaction
broadcasting, block fetching, and fee estimation must be implemented and the data
provided by you, the user.

The library does not rely on the presence of a runtime environment outside of access to
heap, atomic integers, and basic Mutex primitives. This means the library will never
spawn threads or take any action whatsoever except when you call into it. Thus,
`ChannelManager` and `PeerManager` have public functions which you should call on a timer,
network reads and writes are external and provided by you, and the library relies only on
block time for current time knowledge.

At a high level, some of the common interfaces fit together as follows:


```

                     -----------------
                     | KeysInterface |  --------------
                     -----------------  | UserConfig |
         --------------------       ^   --------------
   ------| MessageSendEvent |       |   ^     ----------------
  /      --------------------       |   |     | FeeEstimator | <-----------------------
 |   (as MessageSendEventsProvider) |   |     ----------------                         \
 |                         ^        |   |    ^                ------------------------  |
 |                          \       |   |   /      ---------> | BroadcasterInterface |  |
 |                           \      |   |  /      /           ------------------------  |
 |                            \     |   | /      /                          ^           |
 |    (as                      ------------------       ----------------    |           |
 |    ChannelMessageHandler)-> | ChannelManager | ----> | chain::Watch |    |           |
 v               /             ------------------       ----------------    |           |
--------------- /                  (as EventsProvider)         ^            |           |
| PeerManager |-                             \                 |            |           |
---------------                               \                | (is-a)     |           |
 |                    --------------           \       _----------------   /           /
 |                    | UtxoLookup |            \     / | ChainMonitor |---------------
 |                    --------------             \   /  ----------------
 |                            ^                   \ /          |
(as RoutingMessageHandler)    |                    v           v
  \                   -----------------        ---------   -----------------
   -----------------> | P2PGossipSync |        | Event |   | chain::Filter |
                      -----------------        ---------   -----------------
```
