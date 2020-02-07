[![Safety Dance](https://img.shields.io/badge/unsafe-forbidden-success.svg)](https://github.com/rust-secure-code/safety-dance/)

Rust-Lightning, not Rusty's Lightning!
=====

Documentation can be found at [docs.rs](https://docs.rs/lightning/)

The project implements all of the BOLT specifications except for X, Y, Z. The
implementation has pretty good test coverage that is expected to continue to
improve. There are no known production uses of the library though. The current
state is sufficient for a developer or project to experiment with it. Recent
increased contribution rate to the project is expected to lead to a high quality,
stable, production-worthy implementation in 2020.

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

Notes on coding style:
 * Use tabs. If you want to align lines, use spaces. Any desired alignment
   should display fine at any tab-length display setting.

License is Apache-2.0.
