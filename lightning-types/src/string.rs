// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Utilities for strings.

use alloc::string::String;
use core::fmt;
#[cfg(feature = "serde")]
use serde::{Serialize, Deserialize};

/// Struct to `Display` fields in a safe way using `PrintableString`
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct UntrustedString(pub String);

impl fmt::Display for UntrustedString {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		PrintableString(&self.0).fmt(f)
	}
}

/// A string that displays only printable characters, replacing control characters with
/// [`core::char::REPLACEMENT_CHARACTER`].
#[derive(Debug, PartialEq)]
pub struct PrintableString<'a>(pub &'a str);

impl<'a> fmt::Display for PrintableString<'a> {
	fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
		use core::fmt::Write;
		for c in self.0.chars() {
			let c = if c.is_control() { core::char::REPLACEMENT_CHARACTER } else { c };
			f.write_char(c)?;
		}

		Ok(())
	}
}

#[cfg(test)]
mod tests {
	use super::PrintableString;

	#[test]
	fn displays_printable_string() {
		assert_eq!(
			format!("{}", PrintableString("I \u{1F496} LDK!\t\u{26A1}")),
			"I \u{1F496} LDK!\u{FFFD}\u{26A1}",
		);
	}
}
