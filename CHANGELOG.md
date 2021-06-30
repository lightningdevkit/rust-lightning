# 0.0.99 - WIP

## Serialization Compatibility

 * Due to a bug discovered in 0.0.98, if a `ChannelManager` is serialized on
   version 0.0.98 while an `Event::PaymentSent` is pending processing, the
   `ChannelManager` will fail to deserialize both on version 0.0.98 and later
   versions. If you have such a `ChannelManager` available, a simple patch will
   allow it to deserialize, please file an issue if you need assistance.

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
