# Fuzzing

Fuzz tests generate a ton of random parameter arguments to the program and then validate that none
cause it to crash.

## How does it work?

Typically, CI will run `ci-fuzz.sh` on one of the environments the automated tests are
configured for. Fuzzing is further only effective with a lot of CPU time, indicating that if crash
scenarios are discovered on CI with its low runtime constraints, the crash is caused relatively
easily.

## How do I run fuzz tests locally?

We support multiple fuzzing engines such as `honggfuzz`, `libFuzzer` and `AFL`. You typically won't
need to run the entire suite of different fuzzing tools. For local execution, `honggfuzz`should be
more than sufficient.
> MacOS users should prefer using `libFuzzer` since `honggfuzz` is not actively maintained for MacOS based systems

### Setup
#### Honggfuzz
To install `honggfuzz`, simply run

```shell
cargo update
cargo install --force honggfuzz
```

In some environments, you may want to pin the honggfuzz version to `0.5.52`:

```shell
cargo update -p honggfuzz --precise "0.5.52"
cargo install --force honggfuzz --version "0.5.52"
```

#### cargo-fuzz / libFuzzer
To install `cargo-fuzz`, simply run

```shell
cargo update
cargo install --force cargo-fuzz
```

### Execution

#### Honggfuzz
To run fuzzing using `honggfuzz`, do

```shell
export CPU_COUNT=1 # replace as needed
export HFUZZ_BUILD_ARGS="--features honggfuzz_fuzz"
export HFUZZ_RUN_ARGS="-n $CPU_COUNT --exit_upon_crash"

export TARGET="msg_ping_target" # replace with the target to be fuzzed
cargo hfuzz run $TARGET
```

(Or, for a prettier output, replace the last line with `cargo --color always hfuzz run $TARGET`.)

#### cargo-fuzz / libFuzzer
To run fuzzing using `cargo-fuzz / libFuzzer`, run

```shell
rustup install nightly # Note: libFuzzer requires a nightly version of rust.
export RUSTFLAGS="--cfg=fuzzing --cfg=secp256k1_fuzz --cfg=hashes_fuzz"
cargo +nightly fuzz run --features "libfuzzer_fuzz" msg_ping_target
```
Note: If you encounter a `SIGKILL` during run/build check for OOM in kernel logs and consider
increasing RAM size for VM.

##### Fast builds for development

The default build uses LTO and single codegen unit, which is slow. For faster iteration during
development, use the `-D` (dev) flag:

```shell
cargo +nightly fuzz run --features "libfuzzer_fuzz" -D msg_ping_target
```

The `-D` flag builds in development mode with faster compilation (still has optimizations via
`opt-level = 1`). The first build will be slow as it rebuilds the standard library with
sanitizer instrumentation, but subsequent builds will be fast.

If you wish to just generate fuzzing binary executables for `libFuzzer` and not run them:
```shell
cargo +nightly fuzz build --features "libfuzzer_fuzz" msg_ping_target
# Generates binary artifact in path ./target/aarch64-unknown-linux-gnu/release/msg_ping_target
# Exact path depends on your system architecture.
```
You can upload the build artifact generated above to `ClusterFuzz` for distributed fuzzing.

### List Fuzzing Targets
To see a list of available fuzzing targets, run:

```shell
ls ./src/bin/
```

## A fuzz test failed, what do I do?

You're trying to create a PR, but need to find the underlying cause of that pesky fuzz failure
blocking the merge?

Worry not, for this is easily traced.

If your output log looks like this:

```
Size:639 (i,b,hw,ed,ip,cmp): 0/0/0/0/0/1, Tot:0/0/0/2036/5/28604
Seen a crash. Terminating all fuzzing threads

… # a lot of lines in between

<0x0000555555565559> [func:UNKNOWN file: line:0 module:./rust-lightning/fuzz/hfuzz_target/x86_64-unknown-linux-gnu/release/full_stack_target]
<0x0000000000000000> [func:UNKNOWN file: line:0 module:UNKNOWN]
=====================================================================
2d3136383734090101010101010101010101010101010101010101010101
010101010100040101010101010101010101010103010101010100010101
0069d07c319a4961
The command "if [ "$(rustup show | grep default | grep stable)" != "" ]; then cd fuzz && cargo test --verbose && ./ci-fuzz.sh; fi" exited with 1.
```

Note that the penultimate stack trace line ends in `release/full_stack_target]`. That indicates that
the failing target was `full_stack`. To reproduce the error locally, simply copy the hex,
and run the following from the `fuzz` directory:

```shell
export TARGET="full_stack" # adjust for your output
export HEX="2d3136383734090101010101010101010101010101010101010101010101\
010101010100040101010101010101010101010103010101010100010101\
0069d07c319a4961" # adjust for your output

mkdir -p ./test_cases/$TARGET
echo $HEX | xxd -r -p > ./test_cases/$TARGET/any_filename_works

export RUST_BACKTRACE=1
export RUSTFLAGS="--cfg=fuzzing --cfg=secp256k1_fuzz --cfg=hashes_fuzz"
cargo test
```

Note that if the fuzz test failed locally, moving the offending run's trace
to the `test_cases` folder should also do the trick; simply replace the `echo $HEX |` line above
with (the trace file name is of course a bit longer than in the example):

```shell
mv hfuzz_workspace/fuzz_target/SIGABRT.PC.7ffff7e21ce1.STACK.[…].fuzz ./test_cases/$TARGET/
```

This will reproduce the failing fuzz input and yield a usable stack trace.

Alternatively, you can use the `stdin_fuzz` feature to pipe the crash input directly without
creating test case files on disk:

```shell
echo -ne '\x2d\x31\x36\x38\x37\x34\x09\x01...' | RUSTFLAGS="--cfg=fuzzing --cfg=secp256k1_fuzz --cfg=hashes_fuzz" cargo run --features stdin_fuzz --bin full_stack_target
```

This is useful for reproducing crashes during `git bisect` or when working with AI agents that can
construct and pipe byte sequences directly.

## How do I add a new fuzz test?

1. The easiest approach is to take one of the files in `fuzz/src/`, such as
`process_network_graph.rs`, and duplicate it, renaming the new file to something more
suitable. For the sake of example, let's call the new fuzz target we're creating
`my_fuzzy_experiment`.

2. In the newly created file `fuzz/src/my_fuzzy_experiment.rs`, run a string substitution
of `process_network_graph` to `my_fuzzy_experiment`, such that the three methods in the
file are `do_test`, `my_fuzzy_experiment_test`, and `my_fuzzy_experiment_run`.

3. Adjust the body (not the signature!) of `do_test` as necessary for the new fuzz test.

4. In `fuzz/src/bin/gen_target.sh`, add a line reading `GEN_TEST my_fuzzy_experiment` to the
first group of `GEN_TEST` lines (starting in line 9).

5. If your test relies on a new local crate, add that crate as a dependency to `fuzz/Cargo.toml`.

6. In `fuzz/src/lib.rs`, add the line `pub mod my_fuzzy_experiment`. Additionally, if
you added a new crate dependency, add the `extern crate […]` import line.

7. Run `fuzz/src/bin/gen_target.sh`.

8. There is no step eight: happy fuzzing!
