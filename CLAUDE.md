# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

See [CONTRIBUTING.md](CONTRIBUTING.md) for build commands, testing, code style, and development workflow.

## Workspace Structure

See [README.md](README.md) for the workspace layout and [ARCH.md](ARCH.md) for some additional remark regarding important parts of LDK's architecture.

## Development Rules

- Always ensure tests pass before committing. To this end, you should run the test suite via `./ci/ci-tests.sh`.
- Run `cargo +1.75.0 fmt --all` after every code change
- Never add new dependencies unless explicitly requested
- Please always disclose the use of any AI tools in commit messages and PR descriptions using a `Co-Authored-By:` line.
- When adding new `.rs` files, please ensure to always add the licensing header as found, e.g., in `lightning/src/lib.rs` and other files.
