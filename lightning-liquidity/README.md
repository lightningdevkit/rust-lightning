# lightning-liquidity

The goal of this crate is to provide types and primitives to integrate a spec-compliant LSP with an LDK-based node. To this end, this crate provides client-side as well as service-side logic to implement the [LSP specifications].

Currently the following specifications are supported:
- [LSPS0] defines the transport protocol with the LSP over which the other protocols communicate.
- [LSPS1] allows to order Lightning channels from an LSP. This is useful when the client needs
inbound Lightning liquidity for which they are willing and able to pay in bitcoin.
- [LSPS2] allows to generate a special invoice for which, when paid, an LSP
  will open a "just-in-time" channel. This is useful for the initial
  on-boarding of clients as the channel opening fees are deducted from the
  incoming payment, i.e., no funds are required client-side to initiate this
  flow.

To get started, you'll want to setup a `LiquidityManager` and configure it to be the `CustomMessageHandler` of your LDK node. You can then call `LiquidityManager::lsps1_client_handler` / `LiquidityManager::lsps2_client_handler`, or `LiquidityManager::lsps2_service_handler`, to access the respective client-side or service-side handlers.

`LiquidityManager` uses an eventing system to notify the user about important updates to the protocol flow. To this end, you will need to handle events emitted via one of the event handling methods provided by `LiquidityManager`, e.g., `LiquidityManager::next_event`.

[LSP specifications]: https://github.com/BitcoinAndLightningLayerSpecs/lsp
[LSPS0]: https://github.com/BitcoinAndLightningLayerSpecs/lsp/tree/main/LSPS0
[LSPS1]: https://github.com/BitcoinAndLightningLayerSpecs/lsp/tree/main/LSPS1
[LSPS2]: https://github.com/BitcoinAndLightningLayerSpecs/lsp/tree/main/LSPS2
