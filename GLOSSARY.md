# Glossary

This document gathers the canonical Lightning nomenclature used by LDK contributors. Note, they may diverge from the BOLT specs or the ones used by the wider Lightning community; the test of time has revealed that it can be hard to agree on terminology. The following terms are employed with a best effort across the codebase aiming to reduce confusion.

### Channel Initiator

The channel initiator is the entity who is taking the decision to open a channel. Finalization relies upon the counterparty's channel acceptance policy. Within current protocol version, the initiator has the burden of paying channel onchain fees.

### Holder/Counterparty

Inspired by financial cryptography, a holder is an owner of a given digital value. In Lightning, the holder is the entity operating the current node, of which the interests are served by the implementation during channel operations. The counterparty is the entity participating in the channel operation as a peer, but of whom the interests are not of concern by the implementation.

Used across the `Channel` data structure, part of the channel-management subsystem.

### Broadcaster/Countersignatory

In Lightning, states are symmetric but punishment is asymmetric, which forces channel parties to hold different commitment transactions. At transaction construction, the broadcaster designates the entity that has the unilateral capability to broadcast the transaction. The countersignatory is the entity providing signatures for the broadcastable transaction and thus verifying it encodes the off-chain states. At any point in time, there should be two "latest" commitment transactions that have been processed by each party's implementation, one where the holder is the broadcaster and the counterparty is countersignatory, and one where the holder is the countersignatory and the counterparty is the broadcaster.

Used across the channel-utils library (`chan_utils.rs`).

### Watchtower

A watchtower is an external untrusted service that can only publish justice transactions. The security property of watchtowers is that if you subscribe to *N* of them, you will be safe if at least 1 does the right thing.

A (future) deployment configuration of the monitoring (`ChainMonitor`) subsystem.

### Monitor Replicas

An instance of a highly available distributed channel-monitor. It must have a correctly working HSM, because they have sensitive keys that can cause loss of all funds in the channel.

A deployment configuration of the monitoring (`ChainMonitor`) subsystem.
