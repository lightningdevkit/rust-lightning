# lightning-payer-proof-uniffi

UniFFI bindings for [`lightning-payer-proof`](../), exposing `verify`, `verify_bytes` and
`pays_offers_recipient` to Kotlin, Swift, Python and the other languages uniffi targets.

## Building

This is its own workspace rather than a member of the one at the repository root: `uniffi` pulls in
a dependency tree well above LDK's 1.75 MSRV, so it is built with a current toolchain and is not
covered by the MSRV or `no_std` CI jobs.

```
cargo build --release
cargo run --bin uniffi-bindgen -- generate src/interface.udl --language kotlin --out-dir bindings
```

Substitute `swift`, `python` or `ruby` for `kotlin`. The generated code loads
`libuniffi_lightning_payer_proof.{so,dylib,dll}` from alongside itself, so copy the built library
into the output directory before running it.

## Shape of the API

`VerifiedPayerProof` is a flat record of owned plain values rather than a struct with accessors,
which is what uniffi can carry across the FFI. Keys, hashes and signatures are byte arrays in their
usual wire encodings: 33 bytes for a compressed public key, 32 for a hash or preimage, 64 for a
BIP 340 signature. Fields the payer withheld are absent rather than empty.

`VerifyError` mirrors the Rust crate's rather than re-exporting it, so that a check the Rust crate
learns to distinguish later arrives as `Unknown` instead of changing what an existing variant means.

`pays_offers_recipient` takes an already-verified proof and an `lno1...` offer string and returns
a `bool`. It is not a `Result`: a failed verification is a separate call, and a proof paid to
someone else is `false`. A `true` identifies the recipient, not the offer.

What a successful verification does and does not prove is documented on the Rust crate and applies
here unchanged. In short: it proves someone paid the invoice the proof covers, not that they paid
*yours*.
