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
			let c = if c.is_control() || is_format_char(c) {
				core::char::REPLACEMENT_CHARACTER
			} else {
				c
			};
			f.write_char(c)?;
		}

		Ok(())
	}
}

// Codepoints in Unicode general category `Cf` (Format), per Unicode standard. These are not
// matched by `char::is_control` (which only covers `Cc`), but include the bidirectional override /
// isolate controls (e.g. U+202E RLO) and zero-width characters behind the "Trojan Source" attack
// family (CVE-2021-42574), where an attacker-supplied string renders to a human reader as
// something other than its byte content. Strip them alongside `Cc` characters when sanitising
// untrusted input.
fn is_format_char(c: char) -> bool {
	matches!(
		c as u32,
		0x00AD
			| 0x0600..=0x0605
			| 0x061C
			| 0x06DD
			| 0x070F
			| 0x0890..=0x0891
			| 0x08E2
			| 0x180E
			| 0x200B..=0x200F
			| 0x202A..=0x202E
			| 0x2060..=0x2064
			| 0x2066..=0x206F
			| 0xFEFF
			| 0xFFF9..=0xFFFB
			| 0x110BD
			| 0x110CD
			| 0x13430..=0x1343F
			| 0x1BCA0..=0x1BCA3
			| 0x1D173..=0x1D17A
			| 0xE0001
			| 0xE0020..=0xE007F
	)
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
