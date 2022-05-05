# Fuzzing

Fuzz tests generate a ton of random parameter arguments to the program and then validate that none cause it to crash.

## How does it work?

Typically, Travis CI will run `travis-fuzz.sh` on one of the environments the automated tests are configured for.
This is the most time-consuming component of the continuous integration workflow, so it is recommended that you detect
issues locally, and Travis merely acts as a sanity check. Fuzzing is further only effective with
a lot of CPU time, indicating that if crash scenarios are discovered on Travis with its low
runtime constraints, the crash is caused relatively easily.

## How do I run fuzz tests locally?

You typically won't need to run the entire combination of different fuzzing tools. For local execution, `honggfuzz`
should be more than sufficient. 

### Setup

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

### Execution

To run the Hongg fuzzer, do

```shell
export CPU_COUNT=1 # replace as needed
export HFUZZ_BUILD_ARGS="--features honggfuzz_fuzz"
export HFUZZ_RUN_ARGS="-n $CPU_COUNT --exit_upon_crash"

export TARGET="msg_ping_target" # replace with the target to be fuzzed
cargo hfuzz run $TARGET
```

(Or, for a prettier output, replace the last line with `cargo --color always hfuzz run $TARGET`.)

To see a list of available fuzzing targets, run:

```shell
ls ./src/bin/
```

## A fuzz test failed on Travis, what do I do?

You're trying to create a PR, but need to find the underlying cause of that pesky fuzz failure blocking the merge?

Worry not, for this is easily traced.

If your Travis output log looks like this:

```
Size:639 (i,b,hw,ed,ip,cmp): 0/0/0/0/0/1, Tot:0/0/0/2036/5/28604
Seen a crash. Terminating all fuzzing threads

… # a lot of lines in between

<0x0000555555565559> [func:UNKNOWN file: line:0 module:/home/travis/build/rust-bitcoin/rust-lightning/fuzz/hfuzz_target/x86_64-unknown-linux-gnu/release/full_stack_target]
<0x0000000000000000> [func:UNKNOWN file: line:0 module:UNKNOWN]
=====================================================================
2d3136383734090101010101010101010101010101010101010101010101
010101010100040101010101010101010101010103010101010100010101
0069d07c319a4961
The command "if [ "$(rustup show | grep default | grep stable)" != "" ]; then cd fuzz && cargo test --verbose && ./travis-fuzz.sh; fi" exited with 1.
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
export RUSTFLAGS="--cfg=fuzzing"
cargo test
```

Note that if the fuzz test failed locally, moving the offending run's trace 
to the `test_cases` folder should also do the trick; simply replace the `echo $HEX |` line above
with (the trace file name is of course a bit longer than in the example):

```shell
mv hfuzz_workspace/fuzz_target/SIGABRT.PC.7ffff7e21ce1.STACK.[…].fuzz ./test_cases/$TARGET/
```

This will reproduce the failing fuzz input and yield a usable stack trace.


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
