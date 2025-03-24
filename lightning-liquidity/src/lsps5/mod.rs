// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! LSPS5 Webhook Registration Protocol Implementation
//!
//! Implements bLIP-55: LSP Protocol for Notification Webhook Registration
//!
//! This module provides functionality for Lightning Service Providers to send
//! webhook notifications to their clients, and for clients to register webhooks
//! with LSPs.

pub mod client;
pub mod event;
pub mod msgs;
pub mod service;
pub mod url_utils;
pub mod validator;
