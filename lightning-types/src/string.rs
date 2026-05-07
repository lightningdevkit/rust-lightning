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

use crate::unicode::*;

/// Struct to `Display` fields in a safe way using `PrintableString`
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
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
			let is_other = is_unicode_general_category_other(c);
			let is_unassigned = is_unicode_general_category_unassigned(c);
			let c = if c.is_control() || is_other || is_unassigned {
				core::char::REPLACEMENT_CHARACTER
			} else {
				c
			};
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

	#[test]
	fn sanitizes_unicode_bidi_override_characters() {
		// U+202E RIGHT-TO-LEFT OVERRIDE and friends are Unicode general category
		// `Cf` (Format), not `Cc` (Control). They enable "Trojan Source" /
		// bidi-spoofing attacks where an attacker-supplied string (e.g. a node
		// alias gossiped from a peer) renders to a human reader as something
		// other than its byte content. `PrintableString` is the sanitiser used
		// for exactly these untrusted strings, so it must replace them.
		let rendered = format!("{}", PrintableString("safe\u{202E}cipsxe.exe"));
		assert!(
			!rendered.contains('\u{202E}'),
			"PrintableString left a U+202E RLO override in its output: {:?}",
			rendered
		);

		// U+13440 is in the Egyptian Hieroglyph Format Controls block, but its
		// general category is `Mn`, not `Cf`, so the `Cf` range ends at U+1343F.
		assert_eq!(format!("{}", PrintableString("x\u{1343F}y\u{13440}z")), "x\u{FFFD}y\u{13440}z");
	}
}
