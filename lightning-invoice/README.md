# lightning-invoice
 [![Docs.rs](https://docs.rs/lightning-invoice/badge.svg)](https://docs.rs/lightning-invoice/)

This repo provides data structures for BOLT 11 lightning invoices and
functions to parse and serialize these from and to bech32.

**Please be sure to run the test suite since we need to check assumptions
regarding `SystemTime`'s bounds on your platform. You can also call `check_platform`
on startup or in your test suite to do so.**
