Contributing to Rust-Lightning
==============================

The Rust-Lightning project operates an open contributor model where anyone is
welcome to contribute towards development in the form of peer review, documentation,
testing and patches.

Anyone is invited to contribute without regard to technical experience, "expertise", OSS
experience, age, or other concern. However, the development of cryptocurrencies demands a
high-level of rigor, adversial thinking, thorough testing and risk-minimization.
Any bug may cost users real money. That said we deeply welcome people contributing
for the first time to an open source project or pick up Rust while contributing. Don't be shy,
you'll learn.

Communications Channels
-----------------------

Communication about Rust-Lightning happens primarily on #ldk-dev on the [LDK slack](http://www.lightningdevkit.org/),
but also #rust-bitcoin on IRC Freenode.

Discussion about code base improvements happens in GitHub issues and on pull
requests.

Contribution Workflow
---------------------

The codebase is maintained using the "contributor workflow" where everyone
without exception contributes patch proposals using "pull requests". This
facilitates social contribution, easy testing and peer review.

To contribute a patch, the worflow is a as follows:

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
hestitate to split it into multiple small, focused PRs.

The Minimal Supported Rust Version is 1.22.0 (enforced by our Travis).

Commits should cover both issues fixed and solutions' rationale.
These [guidelines](https://chris.beams.io/posts/git-commit/) should be kept in mind.

Peer review
-----------

Anyone may participate in peer review which is expressed by comments in the pull
request. Typically reviewers will review the code for obvious errors, as well as
test out the patch set and opine on the technical merits of the patch. PR should
be reviewed first on the conceptual level before focusing on code style or grammar
fixes.

Coding Conventions
------------------

Use tabs. If you want to align lines, use spaces. Any desired alignment should
display fine at any tab-length display setting.

Security
--------

Security is the primary focus of Rust-Lightning; disclosure of security vulnerabilites
helps prevent user loss of funds. If you believe a vulnerability may affect other Lightning
implementations, please inform them.

Note that Rust-Lightning is currently considered "pre-production" during this time, there
is no special handling of security issues. Please simply open an issue on Github.

Testing
-------

Related to the security aspect, Rust-Lightning developers take testing
very seriously. Due to the modular nature of the project, writing new functional
tests is easy and good test coverage of the codebase is an important goal. Refactoring
the project to enable fine-grained unit testing is also an ongoing effort.

Fuzzing is heavily encouraged: you will find all related material under `fuzz/`

Mutation testing is work-in-progress; any contribution there would be warmly welcomed.

Going further
-------------

You may be interested by Jon Atack guide on [How to review Bitcoin Core PRs](https://github.com/jonatack/bitcoin-development/blob/master/how-to-review-bitcoin-core-prs.md)
and [How to make Bitcoin Core PRs](https://github.com/jonatack/bitcoin-development/blob/master/how-to-make-bitcoin-core-prs.md).
While there are differences between the projects in terms of context and maturity, many of the suggestions offered apply to this project.

Overall, have fun :)
