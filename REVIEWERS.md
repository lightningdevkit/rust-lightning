# Reviewer Guidance

## Sensitive Information in Logs

Logs may generally contain payment-identifying information, but must not contain information that can be used to steal our funds on-chain. For example, our revocation secrets before we send them to peers and payment preimages before we claim a payment must not be logged. Payment preimages already sent to or received from peers may be logged.
