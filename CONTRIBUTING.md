Contributing to Rust-Lightning
==============================

The `rust-lightning` project operates an open contributor model where anyone is
welcome to contribute towards development in the form of peer review,
documentation, testing and patches.

Anyone is invited to contribute without regard to technical experience,
"expertise", OSS experience, age, or other concern. However, the development of
cryptocurrencies demands a high-level of rigor, adversarial thinking, thorough
testing and risk-minimization. Any bug may cost users real money. That being
said, we deeply welcome people contributing for the first time to an open source
project or pick up Rust while contributing. Don't be shy, you'll learn.

For the project Code of Conduct, see our [website](https://lightningdevkit.org/code_of_conduct).

Communication Channels
-----------------------

Communication about the development of LDK and `rust-lightning` happens
primarily on the [LDK Discord](https://discord.gg/5AcknnMfBw) in the `#ldk-dev`
channel. Additionally, live LDK development meetings are held every other
Monday 17:00 UTC in the [LDK Dev Jitsi Meeting
Room](https://meet.jit.si/ldkdevmeeting). Upcoming events can be found in the
[LDK calendar](https://calendar.google.com/calendar/embed?src=c_e6fv6vlshbpoob2mmbvblkkoj4%40group.calendar.google.com).

Contributors starting out with the Rust language are welcome to discuss and ask
for help in the `#rust-101` channel on LDK Discord.

Discussion about code base improvements happens in GitHub issues and on pull
requests.

The LDK roadmap is tracked [here](https://github.com/orgs/lightningdevkit/projects/2).

Major milestones are tracked [here](https://github.com/lightningdevkit/rust-lightning/milestones?direction=asc&sort=title&state=open).

Getting Started
---------------

First and foremost, start small.

This doesn't mean don't be ambitious with the breadth and depth of your
contributions but rather understand the project culture before investing an
asymmetric number of hours on development compared to your merged work.

Browsing through the [meeting minutes](https://github.com/lightningdevkit/rust-lightning/wiki/Meeting-Notes)
is a good first step. You will learn who is working on what, how releases are
drafted, what are the pending tasks to deliver, where you can contribute review
bandwidth, etc.

Even if you have an extensive open source background or sound software
engineering skills, consider that the reviewers' comprehension of the code is as
much important as technical correctness.

It's very welcome to ask for review on LDK Discord. And also for reviewers, it's
nice to provide timelines when you hope to fulfill the request while bearing in
mind for both sides that's a "soft" commitment.

If you're eager to increase the velocity of the dev process, reviewing other
contributors work is the best you can do while waiting review on yours.

Also, getting familiar with the [glossary](GLOSSARY.md) will streamline
discussions with regular contributors.

Contribution Workflow
---------------------

The codebase is maintained using the "contributor workflow" where everyone
without exception contributes patch proposals using "pull requests". This
facilitates social contribution, easy testing and peer review.

To contribute a patch, the workflow is as follows:

  1. Fork Repository
  2. Create topic branch
  3. Commit patches

In general commits should be atomic and diffs should be easy to read.
For this reason do not mix any formatting fixes or code moves with
actual code changes. Further, each commit, individually, should compile
and pass tests, in order to ensure git bisect and other automated tools
function properly.

When adding a new feature, like implementing a BOLT spec object, thought
must be given to the long term technical debt. Every new features should
be covered by functional tests.

When refactoring, structure your PR to make it easy to review and don't
hesitate to split it into multiple small, focused PRs.

The Minimum Supported Rust Version (MSRV) currently is 1.41.1 (enforced by
our GitHub Actions). Also, the compatibility for LDK object serialization is
currently ensured back to and including crate version 0.0.99 (see the
[changelog](CHANGELOG.md)).

Commits should cover both the issue fixed and the solution's rationale. These
[guidelines](https://chris.beams.io/posts/git-commit/) should be kept in mind.

To facilitate communication with other contributors, the project is making use
of GitHub's "assignee" field. First check that no one is assigned and then
comment suggesting that you're working on it. If someone is already assigned,
don't hesitate to ask if the assigned party or previous commenters are still
working on it if it has been awhile.

Any changes that have nontrivial backwards compatibility considerations should
have an entry added in the `pending_changelog` folder which includes the
CHANGELOG entries that should be added in the next release.

Peer review
-----------

Anyone may participate in peer review which is expressed by comments in the pull
request. Typically reviewers will review the code for obvious errors, as well as
test out the patch set and opine on the technical merits of the patch. PR should
be reviewed first on the conceptual level before focusing on code style or
grammar fixes.

Coding Conventions
------------------

Use tabs. If you want to align lines, use spaces. Any desired alignment should
display fine at any tab-length display setting.

Our CI enforces [clippy's](https://github.com/rust-lang/rust-clippy) default
linting
[settings](https://rust-lang.github.io/rust-clippy/rust-1.39.0/index.html). This
includes all lint groups except for nursery, pedantic, and cargo in addition to
allowing the following lints: `erasing_op`, `never_loop`, `if_same_then_else`.

If you use rustup, feel free to lint locally, otherwise you can just push to CI
for automated linting.

```bash
rustup component add clippy
cargo clippy
```

Significant structures that users persist should always have their serialization
methods (usually `Writeable::write` and `ReadableArgs::read`) begin with
`write_ver_prefix!()`/`read_ver_prefix!()` calls, and end with calls to
`write_tlv_fields!()`/`read_tlv_fields!()`.

Updates to the serialized format which has implications for backwards or
forwards compatibility must be included in release notes.

Security
--------

Security is the primary focus of `rust-lightning`; disclosure of security
vulnerabilites helps prevent user loss of funds. If you believe a vulnerability
may affect other Lightning implementations, please inform them.

You can find further information on submitting (possible) vulnerabilities in the
[security policy](SECURITY.md).

Testing
-------

Related to the security aspect, `rust-lightning` developers take testing very
seriously. Due to the modular nature of the project, writing new functional
tests is easy and good test coverage of the codebase is an important goal.
Refactoring the project to enable fine-grained unit testing is also an ongoing
effort.

Fuzzing is heavily encouraged: you will find all related material under `fuzz/`

Mutation testing is work-in-progress; any contribution there would be warmly
welcomed.

C/C++ Bindings
--------------

You can learn more about the C/C++ bindings that are made available by reading
the [C/C++ Bindings README](https://github.com/lightningdevkit/ldk-c-bindings/blob/main/lightning-c-bindings/README.md).
If you are not using the C/C++ bindings, you likely don't need to worry about
them, and during their early experimental phase we are not requiring that pull
requests keep the bindings up to date (and, thus, pass the `bindings_check` CI
run). If you wish to ensure your PR passes the bindings generation phase, you
should run the `genbindings.sh` script in the top of the directory tree to
generate, build, and test C bindings on your local system.

Going further
-------------

You may be interested by Jon Atack's guide on [How to review Bitcoin Core PRs](https://github.com/jonatack/bitcoin-development/blob/master/how-to-review-bitcoin-core-prs.md)
and [How to make Bitcoin Core PRs](https://github.com/jonatack/bitcoin-development/blob/master/how-to-make-bitcoin-core-prs.md).
While there are differences between the projects in terms of context and
maturity, many of the suggestions offered apply to this project.

Overall, have fun :)
