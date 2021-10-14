Rust-Lightning
==============

[![Crate](https://img.shields.io/crates/v/lightning.svg?logo=rust)](https://crates.io/crates/lightning)
[![Documentation](https://img.shields.io/static/v1?logo=read-the-docs&label=docs.rs&message=lightning&color=informational)](https://docs.rs/lightning/)
[![Safety Dance](https://img.shields.io/badge/unsafe-forbidden-success.svg)](https://github.com/rust-secure-code/safety-dance/)

Rust-Lightning is a Bitcoin Lightning library written in Rust. The main crate,
`lightning`, does not handle networking, persistence, or any other I/O. Thus,
it is runtime-agnostic, but users must implement basic networking logic, chain
interactions, and disk storage. More information is available in the `About`
section.

The `lightning-net-tokio` crate implements Lightning networking using the
[Tokio](https://github.com/tokio-rs/tokio) async runtime.

The `lightning-persister` crate implements persistence for channel data that
is crucial to avoiding loss of channel funds. Sample modules for persistence of
other Rust-Lightning data is coming soon.

Status
------

The project implements all of the BOLT specifications in the 1.0 spec. The
implementation has pretty good test coverage that is expected to continue to
improve. It is also anticipated that as developers begin using the API, the
lessons from that will result in changes to the API, so any developer using this
API at this stage should be prepared to embrace that. The current state is
sufficient for a developer or project to experiment with it. Recent increased
contribution rate to the project is expected to lead to a high quality, stable,
production-worthy implementation in 2021.

Communications for Rust-Lightning and Lightning Development Kit happens through
[LDK slack](http://lightningdevkit.org/).

About
-----------
LDK/Rust-Lightning is a generic library which allows you to build a lightning
node without needing to worry about getting all of the lightning state machine,
routing, and on-chain punishment code (and other chain interactions) exactly
correct. Note that Rust-Lightning isn't, in itself, a node. There are various
working/in progress demos which could be used as a node today, but if you "just"
want a generic lightning node, you're almost certainly better off with
`c-lightning`/`lnd` - if, on the other hand, you want to integrate lightning
with custom features such as your own chain sync, your own key management, your
own data storage/backup logic, etc., LDK is likely your only option. Some
Rust-Lightning utilities such as those in `chan_utils` are also suitable for use
in non-LN Bitcoin applications such as DLCs and bulletin boards.

We are currently working on a demo node which fetches blockchain data and
on-chain funds via Bitcoin Core RPC/REST. The individual pieces of that demo
are/will be composable, so you can pick the off-the-shelf parts you want and
replace the rest.

In general, Rust-Lightning does not provide (but LDK has implementations of):
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
  a part of a lightning output which can be contested - once a channel is closed
  and all on-chain outputs are spendable only by the user, we provide users
  notifications that a UTXO is "theirs" again and it is up to them to spend it
  as they wish. Additionally, channel funding is accomplished with a generic API
  which notifies users of the output which needs to appear on-chain, which they
  can then create a transaction for. Once a transaction is created, we handle
  the rest. This is a large part of our API's goals - making it easier to
  integrate lightning into existing on-chain wallets which have their own
  on-chain logic - without needing to move funds in and out of a separate
  lightning wallet with on-chain transactions and a separate private key system.
* networking - to enable a user to run a full lightning node on an embedded
  machine, we don't specify exactly how to connect to another node at all! We
  provide a default implementation which uses TCP sockets, but, e.g., if you
  wanted to run your full lightning node on a hardware wallet, you could, by
  piping the lightning network messages over USB/serial and then sending them in
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

The goal is to provide a full-featured but also incredibly flexible lightning
implementation, allowing the user to decide how they wish to use it. With that
in mind, everything should be exposed via simple, composable APIs. More
information about Rust-Lightning's flexibility is provided in the `About`
section above.

For security reasons, do not add new dependencies. Really do not add new
non-optional/non-test/non-library dependencies. Really really do not add
dependencies with dependencies. Do convince Andrew to cut down dependency usage
in rust-bitcoin.

Rust-Lightning vs. LDK (Lightning Development Kit)
-------------
Rust-Lightning refers to the core `lightning` crate within this repo, whereas
LDK encompasses Rust-Lightning and all of its sample modules and crates (e.g.
the `lightning-persister` crate), language bindings, sample node
implementation(s), and other tools built around using Rust-Lightning for
lightning integration or building a lightning node.

Tagline
-------

*"Rust-Lightning, not Rusty's Lightning!"*

Contributing
------------

Contributors are warmly welcome, see [CONTRIBUTING.md](CONTRIBUTING.md).

Project Architecture
---------------------

For a Rust-Lightning high-level API introduction, see [ARCH.md](ARCH.md).

License is either Apache-2.0 or MIT, at the option of the user (ie dual-license
Apache-2.0 and MIT).
