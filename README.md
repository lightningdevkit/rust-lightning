Rust-Lightning, not Rusty's Lightning!

Currently somewhere near 5% towards usable, published to see if there is any
real interest from folks in either contributing to or using a lightning rust
library.

The goal is to provide a full-featured but also incredibly flexible lightning
implementation, allowing the user to decide how they wish to use it. With that
in mind, everything should be exposed via simple, composable APIs. The user
should be able to decide whether they wish to use their own threading/execution
models, allowing usage inside of existing library architectures, or allow us to
handle that for them. Same goes with network connections - if the user wishes
to use their own networking stack, they should be able to do so! This all means
that we should provide simple external interfaces which allow the user to drive
all execution, while implementing sample execution drivers that create a
full-featured lightning daemon by default.

For security reasons, do not add new dependencies. Really do not add new
non-optional/non-test/non-library dependencies. Really really do not add
dependencies with dependencies. Do convince Andrew to cut down dependency usage
in rust-bitcoin.

Assorted random TODOs:

 * Create a general timer interface - this should be passed around in reference
   form to most objects to allow them to register functions which are called on
   a timer. By default we should provide an implementation of this which uses
   some newfangled rusty promise-y library, but should generally ensure a
   client can simply integrate this into whatever existing timer interface
   they use.

 * Networking...having a simple bytes-in-bytes-out interface which does message
   handling and calls our encryption layer is probably the right approach. We
   should then also probably use the same promise-y library we use for timers
   to do socket selection and reading/writing.

 * Figure out how to expose when-to-connect and who-to-connect-to.

 * Implement when-to-connect and who-to-connect-to based on route/node rumoring
   and channelmanager state.

 * Some kind of serialization format for on-disk storage of things like
   channels, channelmonitors, routing db, etc.

 * BOLT 10/network bootstrapping implementation.

 * Some kind of DoS thing including ban tracking and putting that info in
   HandleError (and also rename HandleError) to be propagated up...and then
   handled.

 * All the random TODOs and unimplemented!()s across the codebase.

 * BOLT 11 (invoice/address creation/generation) implementation

 * Type-ify our somewhat random usage of Uint256/[u8; 32]. Use Sha256dHash
   where appropriate, create our own types for everything else.

 * Some kind of logging subsystem/API.

Notes on coding style:
 * Use tabs. If you want to align lines, use spaces. Any desired alignment
   should display fine at any tab-length display setting.

License is AGPL, but with agreement that Matt can relicense under any other
OSI-approved license at will (and likely will with sufficient motivation).
