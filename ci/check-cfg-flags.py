#!/usr/bin/env python3
# Rust is fairly relaxed in checking the validity of arguments passed to #[cfg].
# While it should probably be more strict when checking features, it cannot be
# strict when checking loose cfg tags, because those can be anything and are
# simply passed to rustc via unconstrained arguments.
#
# Thus, we do it for rustc manually, but scanning all our source and checking
# that all our cfg tags match a known cfg tag.
import sys, glob, re

def check_feature(feature):
    if feature == "std":
        pass
    elif feature == "no-std":
        pass
    elif feature == "possiblyrandom":
        pass
    elif feature == "getrandom":
        pass
    elif feature == "hashbrown":
        pass
    elif feature == "backtrace":
        pass
    elif feature == "grind_signatures":
        pass
    elif feature == "unsafe_revoked_tx_signing":
        pass
    elif feature == "futures":
        pass
    elif feature == "tokio":
        pass
    elif feature == "rest-client":
        pass
    elif feature == "rpc-client":
        pass
    elif feature == "serde":
        pass
    elif feature == "esplora-blocking":
        pass
    elif feature == "esplora-async":
        pass
    elif feature == "async-interface":
        pass
    elif feature == "electrum":
        pass
    elif feature == "time":
        pass
    elif feature == "_test_utils":
        pass
    elif feature == "_test_vectors":
        pass
    elif feature == "afl":
        pass
    elif feature == "honggfuzz":
        pass
    elif feature == "libfuzzer_fuzz":
        pass
    elif feature == "stdin_fuzz":
        pass
    elif feature == "max_level_off":
        pass
    elif feature == "max_level_error":
        pass
    elif feature == "max_level_warn":
        pass
    elif feature == "max_level_info":
        pass
    elif feature == "max_level_debug":
        pass
    elif feature == "max_level_trace":
        pass
    else:
        print("Bad feature: " + feature)
        assert False

def check_target_os(os):
    if os == "windows":
        pass
    else:
        assert False

def check_cfg_tag(cfg):
    if cfg == "fuzzing":
        pass
    elif cfg == "secp256k1_fuzz":
        pass
    elif cfg == "hashes_fuzz":
        pass
    elif cfg == "test":
        pass
    elif cfg == "debug_assertions":
        pass
    elif cfg == "c_bindings":
        pass
    elif cfg == "ldk_bench":
        pass
    elif cfg == "taproot":
        pass
    elif cfg == "async_signing":
        pass
    elif cfg == "require_route_graph_test":
        pass
    elif cfg == "dual_funding":
        pass
    elif cfg == "splicing":
        pass
    elif cfg == "async_payments":
        pass
    else:
        print("Bad cfg tag: " + cfg)
        assert False

def check_cfg_args(cfg):
    if cfg.startswith("all(") or cfg.startswith("any(") or cfg.startswith("not("):
        brackets = 1
        pos = 4
        while pos < len(cfg):
            if cfg[pos] == "(":
                brackets += 1
            elif cfg[pos] == ")":
                brackets -= 1
                if brackets == 0:
                    check_cfg_args(cfg[4:pos])
                    if pos + 1 != len(cfg):
                        assert cfg[pos + 1] == ","
                        check_cfg_args(cfg[pos + 2:].strip())
                    return
            pos += 1
        assert False
        assert(cfg.endswith(")"))
        check_cfg_args(cfg[4:len(cfg)-1])
    else:
        parts = [part.strip() for part in cfg.split(",", 1)]
        if len(parts) > 1:
            for part in parts:
                check_cfg_args(part)
        elif cfg.startswith("feature") or cfg.startswith("target_os") or cfg.startswith("target_pointer_width"):
            arg = cfg
            if cfg.startswith("feature"):
                arg = arg[7:].strip()
            elif cfg.startswith("target_os"):
                arg = arg[9:].strip()
            else:
                arg = arg[20:].strip()
            assert arg.startswith("=")
            arg = arg[1:].strip()
            assert arg.startswith("\"")
            assert arg.endswith("\"")
            arg = arg[1:len(arg)-1]
            assert not "\"" in arg
            if cfg.startswith("feature"):
                check_feature(arg)
            elif cfg.startswith("target_os"):
                check_target_os(arg)
            else:
                assert arg == "32" or arg == "64"
        else:
            check_cfg_tag(cfg.strip())

cfg_regex = re.compile("#\[cfg\((.*)\)\]")
for path in glob.glob(sys.path[0] + "/../**/*.rs", recursive = True):
    with open(path, "r") as file:
        while True:
            line = file.readline()
            if not line:
                break
            if "#[cfg(" in line:
                if not line.strip().startswith("//"):
                    cfg_part = cfg_regex.match(line.strip()).group(1)
                    check_cfg_args(cfg_part)
