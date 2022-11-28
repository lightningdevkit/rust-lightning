Rust-Lightning
==============

[![Crate](https://img.shields.io/crates/v/lightning.svg?logo=rust)](https://crates.io/crates/lightning)
[![Documentation](https://img.shields.io/static/v1?logo=read-the-docs&label=docs.rs&message=lightning&color=informational)](https://docs.rs/lightning/)
[![Safety Dance](https://img.shields.io/badge/unsafe-forbidden-success.svg)](https://github.com/rust-secure-code/safety-dance/)

[LDK](https://lightningdevkit.org)/`rust-lightning` is a highly performant and flexible 
implementation of the Lightning Network protocol.

The primary crate, `lightning`, is runtime-agnostic. Data persistence, chain interactions,
and networking can be provided by LDK's [sample modules](#crates), or you may provide your
own custom implementations.
More information is available in the [`About`](#about) section.

Status
------
The project implements all of the [BOLT specifications](https://github.com/lightning/bolts),
and has been in production use since 2021. As with any Lightning implementation, care and attention
to detail is important for safe deployment.

Communications for `rust-lightning` and Lightning Development Kit happen through
our LDK [Discord](https://discord.gg/5AcknnMfBw) channels.

Crates
-----------
1. [lightning](./lightning)
  The core of the LDK library, implements the Lightning protocol, channel state machine,
  and on-chain logic. Supports `no-std` and exposes only relatively low-level interfaces.
2. [lightning-background-processor](./lightning-background-processor)
  Utilities to perform required background tasks for Rust Lightning.
3. [lightning-block-sync](./lightning-block-sync)
  Utilities to fetch the chain data from a block source and feed them into Rust Lightning.
4. [lightning-invoice](./lightning-invoice)
  Data structures to parse and serialize
  [BOLT #11](https://github.com/lightning/bolts/blob/master/11-payment-encoding.md)
  Lightning invoices.
5. [lightning-net-tokio](./lightning-net-tokio)
  Implementation of the `rust-lightning` network stack using the
  [Tokio](https://github.com/tokio-rs/tokio) `async` runtime. For `rust-lightning`
  clients which wish to make direct connections to Lightning P2P nodes, this is
  a simple alternative to implementing the required network stack, especially
  for those already using Tokio.
6. [lightning-persister](./lightning-persister)
  Implements utilities to manage `rust-lightning` channel data persistence and retrieval.
  Persisting channel data is crucial to avoiding loss of channel funds.
7. [lightning-rapid-gossip-sync](./lightning-rapid-gossip-sync)
  Client for rapid gossip graph syncing, aimed primarily at mobile clients.

About
-----------
LDK/`rust-lightning` is a generic library that allows you to build a Lightning
node without needing to worry about getting all of the Lightning state machine,
routing, and on-chain punishment code (and other chain interactions) exactly
correct. Note that LDK isn't, in itself, a node. For an out-of-the-box Lightning
node based on LDK, see [Sensei](https://l2.technology/sensei). However, if you
want to integrate Lightning with custom features such as your own chain sync,
key management, data storage/backup logic, etc., LDK is likely your best option.
Some `rust-lightning` utilities such as those in
[`chan_utils`](./lightning/src/ln/chan_utils.rs) are also suitable for use in
non-LN Bitcoin applications such as Discreet Log Contracts (DLCs) and bulletin boards.

A sample node which fetches blockchain data and manages on-chain funds via the
Bitcoin Core RPC/REST interface is available
[here](https://github.com/lightningdevkit/ldk-sample/). The individual pieces of
that demo are composable, so you can pick the off-the-shelf parts you want
and replace the rest.

In general, `rust-lightning` does not provide (but LDK has implementations of):
* on-disk storage - you can store the channel state any way you want - whether
  Google Drive/iCloud, a local disk, any key-value store/database/a remote
  server, or any combination of them - we provide a clean API that provides
  objects which can be serialized into simple binary blobs, and stored in any
  way you wish.
* blockchain data - we provide a simple `block_connected`/`block_disconnected`
  API which you provide block headers and transaction information to. We also
  provide an API for getting information about transactions we wish to be
  informed of, which is compatible with Electrum server requests/neutrino
  filtering/etc.
* UTXO management - RL/LDK owns on-chain funds as long as they are claimable as
  part of a Lightning output which can be contested - once a channel is closed
  and all on-chain outputs are spendable only by the user, we provide users
  notifications that a UTXO is "theirs" again and it is up to them to spend it
  as they wish. Additionally, channel funding is accomplished with a generic API
  which notifies users of the output which needs to appear on-chain, which they
  can then create a transaction for. Once a transaction is created, we handle
  the rest. This is a large part of our API's goals - making it easier to
  integrate Lightning into existing on-chain wallets which have their own
  on-chain logic - without needing to move funds in and out of a separate
  Lightning wallet with on-chain transactions and a separate private key system.
* networking - to enable a user to run a full Lightning node on an embedded
  machine, we don't specify exactly how to connect to another node at all! We
  provide a default implementation which uses TCP sockets, but, e.g., if you
  wanted to run your full Lightning node on a hardware wallet, you could, by
  piping the Lightning network messages over USB/serial and then sending them in
  a TCP socket from another machine.
* private keys - again we have "default implementations", but users can chose to
  provide private keys to RL/LDK in any way they wish following a simple API. We
  even support a generic API for signing transactions, allowing users to run
  RL/LDK without any private keys in memory/putting private keys only on
  hardware wallets.

LDK's customizability was presented about at Advancing Bitcoin in February 2020:
https://vimeo.com/showcase/8372504/video/412818125

Design Goal
-----------
The goal is to provide a fully-featured and incredibly flexible Lightning
implementation, allowing users to decide how they wish to use it. With that
in mind, everything should be exposed via simple, composable APIs. More
information about `rust-lightning`'s flexibility is provided in the `About`
section above.

For security reasons, do not add new dependencies. Really do not add new
non-optional/non-test/non-library dependencies. Really really do not add
dependencies with dependencies. Do convince Andrew to cut down dependency usage
in `rust-bitcoin`.

Rust-Lightning vs. LDK (Lightning Development Kit)
-------------
`rust-lightning` refers to the core `lightning` crate within this repo, whereas
LDK encompasses `rust-lightning` and all of its sample modules and crates (e.g.
the `lightning-persister` crate), language bindings, sample node
implementation(s), and other tools built around using `rust-lightning` for
Lightning integration or building a Lightning node.

Tagline
-------

*"Rust-Lightning, not Rusty's Lightning!"*

Contributing
------------

Contributors are warmly welcome, see [CONTRIBUTING.md](CONTRIBUTING.md).

Project Architecture
---------------------

For a `rust-lightning` high-level API introduction, see [ARCH.md](ARCH.md).

License is either Apache-2.0 or MIT, at the option of the user (ie dual-license
Apache-2.0 and MIT).
