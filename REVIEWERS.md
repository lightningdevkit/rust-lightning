# Reviewer Guidance

In general, if you're looking for security issues in LDK, please consider the worst case attack a given threat model can accomplish before reporting a specific instance of it. For example, if an attacker has access to our database they can delete important context and make us lose funds - do not report issues where an attacker can accomplish less severe outcomes by modifying our database.

## Sensitive Information in Logs

Logs may generally contain payment-identifying information, but must not contain information that can be used to steal our funds on-chain. For example, our revocation secrets before we send them to peers and payment preimages before we claim a payment must not be logged. Payment preimages which have been or are about to be sent to or received from peers may be logged.

Note that the ephemeral onion keys and payment secret values are not, in fact, secret, and are only "payment-identifying" information.

## Trusted Data Sources

Blockchain data sources are very strongly trusted - no matter what we do they can decline to provide the latest blockchain information and as a result we'd miss broadcasts of revoked state or HTLC preimages, leading to loss-of-funds. While we should generally protect against trivial DoS issues from buggy blockchain data source providers, a blockchain data source that outright and maliciously lies to us is not in our threat model.

## Corrupted Objects

In general, objects which have been corrupted on disk are not considered part of the security model - anyone with control of a node's storage may make it lose its money trivially by simply deleting all stored contents. However, such objects should not be able to result in a trivial panic in LDK and we should try to do basic validation when decoding to protect against unintentional corruption. There are some exceptions to this rule - for example, RGS (see below) decodes data from untrusted sources.

Relatedly, when evaluating "maliciously crafted objects", consider the general worst-case attack with those objects before reporting more minor issues. For example, a malicious `Router` can provide `Route`s that redirect payments and donate substantial fees to their own node, allowing for funds theft - don't report cases where a malicious `Router` can do more trivial attacks.

## RGS Threat Model

Rapid Gossip Sync servers are assumed to be able to limit what gossip a client discovers or include bogus data for channels. Such clients aren't expected to be able to "correct" issues in their gossip introduced by the RGS server just by doing a P2P sync. RGS servers are also assumed to be able to bloat clients with bogus gossip, though their ability to do so should be limited such that a client with several GiB of available memory will not fall over immediately from a malicious RGS server.
