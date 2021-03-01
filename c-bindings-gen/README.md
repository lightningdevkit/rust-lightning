LDK C Bindings Generator
========================

This program parses a Rust crate's AST from a single lib.rs passed in on stdin and generates a
second crate which is C-callable (and carries appropriate annotations for cbindgen). It is usually
invoked via the `genbindings.sh` script in the top-level directory, which converts the lightning
crate into a single file with a call to
`RUSTC_BOOTSTRAP=1 cargo rustc --profile=check -- -Zunstable-options --pretty=expanded`.

`genbindings.sh` requires that you have a rustc installed with the `wasm32-wasi` target available
(eg via the `libstd-rust-dev-wasm32` package on Debian or `rustup target add wasm32-wasi` for those
using rustup), cbindgen installed via `cargo install cbindgen` and in your `PATH`, and `clang`,
`clang++`, `gcc`, and `g++` available in your `PATH`. It uses `valgrind` if it is available to test
the generated bindings thoroughly for memory management issues.
