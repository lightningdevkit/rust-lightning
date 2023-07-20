This crate uses criterion to benchmark various LDK functions.

It can be run as `RUSTFLAGS=--cfg=ldk_bench cargo bench --features=criterion`.

For routing or other HashMap-bottlenecked functions, the `hashbrown` feature
should also be benchmarked.
