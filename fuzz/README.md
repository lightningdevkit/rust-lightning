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

### Execution

To run the Hongg fuzzer, do

```shell
export CPU_COUNT=1 # replace as needed
export HFUZZ_BUILD_ARGS="--features honggfuzz_fuzz"
export HFUZZ_RUN_ARGS="-n $CPU_COUNT --exit_upon_crash"

export TARGET="msg_ping_target" # replace with the target to be fuzzed
cargo hfuzz run $TARGET 
```

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

This will reproduce the failing fuzz input and yield a usable stack trace.
