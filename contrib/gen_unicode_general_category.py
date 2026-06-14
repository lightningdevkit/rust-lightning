#!/usr/bin/env python3
# This file is Copyright its original authors, visible in version control
# history.
#
# This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
# or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
# <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
# You may not use this file except in accordance with one or both of these
# licenses.

"""Generate Unicode general-category predicates from `UnicodeData.txt`.

Emits two `pub(crate)` functions taking a `char`, split into two disjoint
buckets across the Unicode top-level `C` ("Other") category so callers can
compose them:

    is_unicode_general_category_other         — Cc / Cf / Cs / Co (assigned)
    is_unicode_general_category_unassigned    — Cn  (plus codepoints above
                                                    U+10FFFF, which aren't
                                                    valid codepoints at all)

`UnicodeData.txt` is the canonical machine-readable listing of every assigned
codepoint in the Unicode Character Database. Each line is `;`-separated; field
0 is the codepoint (hex), field 1 is the name, and field 2 is the two-letter
general category (e.g. `Lu`, `Cf`, `Mn`). Codepoints absent from the file have
category `Cn` (Unassigned) by convention.

Two encoding details to preserve:
  * Large blocks of contiguous same-category codepoints are written as two
    consecutive entries whose names end in `, First>` and `, Last>`. Every
    codepoint between First and Last (inclusive) shares the listed category.
  * The codepoint range is U+0000..=U+10FFFF.

Each `matches!` arm in the assigned-Other table carries an end-of-line comment
derived from the `UnicodeData.txt` name field — typically the longest common
word prefix or suffix across the names in the range, falling back to the set
of categories when the names share nothing meaningful. The unassigned table
omits per-arm comments since every range there has the same meaning by
construction.

Usage:
    contrib/gen_unicode_general_category.py UnicodeData.txt > out.rs
"""

import argparse
import sys
from pathlib import Path

MAX_CODEPOINT = 0x10FFFF

LICENSE_HEADER = """\
// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.
"""

GENERATED_NOTICE = """\
// Auto-generated from the Unicode Character Database (UnicodeData.txt) by
// contrib/gen_unicode_general_category.py. Do not edit by hand; rerun the
// generator with an updated UnicodeData.txt to refresh the table.
"""


def _normalize_name(name):
	"""Strip the `<...>` wrapping and `, First` / `, Last` range markers so
	that, e.g., `<Non Private Use High Surrogate, First>` becomes
	`Non Private Use High Surrogate` and `<control>` becomes `control`.
	"""
	if name.startswith("<") and name.endswith(">"):
		inner = name[1:-1]
		for suffix in (", First", ", Last"):
			if inner.endswith(suffix):
				inner = inner[: -len(suffix)]
		return inner
	return name


def parse_categories(path):
	"""Return `(cats, names)` mapping every codepoint listed in `path` to its
	general category and to its (normalised) name. Codepoints absent from the
	returned dicts have category `Cn` (Unassigned) and no name.
	"""
	cats = {}
	names = {}
	pending_first = None  # (first_cp, first_cat, normalised_name) once a range opens.
	with path.open() as f:
		for lineno, raw in enumerate(f, 1):
			line = raw.rstrip("\n")
			if not line:
				continue
			fields = line.split(";")
			if len(fields) < 3:
				raise ValueError(f"{path}:{lineno}: expected at least 3 fields, got {len(fields)}")
			cp = int(fields[0], 16)
			name = fields[1]
			cat = fields[2]
			if pending_first is not None:
				first_cp, first_cat, first_name = pending_first
				if not name.endswith(", Last>"):
					raise ValueError(
						f"{path}:{lineno}: expected `, Last>` to close range "
						f"opened at U+{first_cp:04X}, got name {name!r}"
					)
				if cat != first_cat:
					raise ValueError(
						f"{path}:{lineno}: range U+{first_cp:04X}..=U+{cp:04X} "
						f"has mismatched categories {first_cat!r} / {cat!r}"
					)
				for x in range(first_cp, cp + 1):
					cats[x] = cat
					names[x] = first_name
				pending_first = None
			elif name.endswith(", First>"):
				pending_first = (cp, cat, _normalize_name(name))
			else:
				cats[cp] = cat
				names[cp] = _normalize_name(name)
	if pending_first is not None:
		raise ValueError(f"{path}: dangling `, First>` entry at U+{pending_first[0]:04X}")
	return cats, names


ASSIGNED_OTHER_CATS = frozenset({"Cc", "Cf", "Cs", "Co"})


def coalesce_ranges(cats, names, target_cats, *, label):
	"""Walk U+0000..=U+10FFFF and return a list of `(start, end, label)` for
	every contiguous run of codepoints whose general category is in
	`target_cats`. Codepoints absent from `cats` are treated as `Cn`.

	If `label` is `True`, attach a comment summarising the codepoint names in
	each range; otherwise every range gets an empty label.
	"""
	ranges = []
	start = None
	for cp in range(MAX_CODEPOINT + 1):
		in_target = cats.get(cp, "Cn") in target_cats
		if in_target and start is None:
			start = cp
		elif not in_target and start is not None:
			ranges.append((start, cp - 1))
			start = None
	if start is not None:
		ranges.append((start, MAX_CODEPOINT))

	if not label:
		return [(s, e, "") for s, e in ranges]

	labelled = []
	for s, e in ranges:
		range_names = []
		range_cats = set()
		for cp in range(s, e + 1):
			range_cats.add(cats.get(cp, "Cn"))
			n = names.get(cp)
			if n is not None:
				range_names.append(n)
		labelled.append((s, e, _make_label(range_names, range_cats)))
	return labelled


def _common_word_run(names, *, from_end):
	"""Return the longest sequence of words shared by every name, taken from
	either the start (`from_end=False`) or the end (`from_end=True`) of each
	name's whitespace-split tokens.
	"""
	if not names:
		return ""
	tokenised = [n.split() for n in names]
	if from_end:
		tokenised = [list(reversed(t)) for t in tokenised]
	limit = min(len(t) for t in tokenised)
	common = []
	for i in range(limit):
		token = tokenised[0][i]
		if all(t[i] == token for t in tokenised):
			common.append(token)
		else:
			break
	if from_end:
		common.reverse()
	return " ".join(common)


def _make_label(names, cats_in_range):
	"""Build a short human-readable label for a coalesced range. Applied to
	the assigned-Other buckets only; each range there is `Cc`, `Cf`, `Cs`,
	`Co`, or some contiguous union thereof.

	Rules, in order:
	  1. All names identical              →  that name (e.g. `control`).
	  2. Common leading or trailing words →  the longer of the two.
	  3. Otherwise, list the categories present (e.g. `Co / Cs`).
	"""
	unique = list(dict.fromkeys(names))
	if len(unique) == 1:
		return unique[0]

	prefix = _common_word_run(names, from_end=False)
	suffix = _common_word_run(names, from_end=True)
	# Pick whichever is more informative; when both are non-empty, prefer the
	# longer one. A multi-word prefix beats a single-word suffix.
	label = prefix if len(prefix) >= len(suffix) else suffix
	if label:
		return label
	return " / ".join(sorted(cats_in_range))


def fmt_codepoint(cp):
	# `UnicodeData.txt` uses 4-digit hex for the BMP and wider for higher
	# planes; mirror that so the output stays readable next to the source data.
	return f"0x{cp:04X}" if cp <= 0xFFFF else f"0x{cp:X}"


def _pattern(start, end):
	if start == end:
		return fmt_codepoint(start)
	return f"{fmt_codepoint(start)}..={fmt_codepoint(end)}"


def _emit_matches_body(lines, arms):
	"""Append a `matches!(c as u32, ...)` body to `lines`, with one
	`(pattern, label)` tuple per arm. The first arm sits at the `matches!`
	argument indent and continuation `| ...` arms indent one level deeper,
	matching the rustfmt convention used elsewhere in the tree.
	"""
	lines.append("\tmatches!(")
	lines.append("\t\tc as u32,")
	for i, (pattern, label) in enumerate(arms):
		prefix = "\t\t" if i == 0 else "\t\t\t| "
		comment = f" // {label}" if label else ""
		lines.append(f"{prefix}{pattern}{comment}")
	lines.append("\t)")


def render_rust(other_ranges, unassigned_ranges):
	"""Render the final Rust source defining both `char`-taking predicates.

	`other_ranges` and `unassigned_ranges` are lists of `(start, end, label)`.
	The unassigned function additionally gets a synthetic final arm catching
	`u32` values above U+10FFFF — these aren't valid Unicode codepoints, so
	by definition they have no general category and the unassigned bucket is
	the closest match.
	"""
	lines = [LICENSE_HEADER, GENERATED_NOTICE]

	lines.append("/// Returns `true` if `c` is in Unicode general category `Cc` (Control), `Cf`")
	lines.append("/// (Format), `Cs` (Surrogate), or `Co` (Private Use) — the assigned codepoints")
	lines.append("/// in the top-level `C` (\"Other\") category. The `Cs` portion of the table is")
	lines.append("/// unreachable for `char` input (a `char` cannot hold a surrogate) but is kept")
	lines.append("/// so the table mirrors the source UCD data verbatim. The disjoint `Cn`")
	lines.append("/// (Unassigned) bucket is `is_unicode_general_category_unassigned`.")
	lines.append("#[allow(dead_code)]")
	lines.append("pub(crate) fn is_unicode_general_category_other(c: char) -> bool {")
	other_arms = [(_pattern(s, e), label) for s, e, label in other_ranges]
	_emit_matches_body(lines, other_arms)
	lines.append("}")
	lines.append("")

	lines.append("/// Returns `true` if `c` is in Unicode general category `Cn` (Unassigned), or")
	lines.append("/// strictly above U+10FFFF. The trailing `0x110000..=u32::MAX` arm is")
	lines.append("/// unreachable for `char` input (a `char` is bounded to U+10FFFF) but is kept")
	lines.append("/// for defensive coverage of the underlying `u32`. The disjoint Cc / Cf / Cs /")
	lines.append("/// Co bucket is `is_unicode_general_category_other`.")
	lines.append("#[allow(dead_code)]")
	lines.append("pub(crate) fn is_unicode_general_category_unassigned(c: char) -> bool {")
	unassigned_arms = [(_pattern(s, e), label) for s, e, label in unassigned_ranges]
	unassigned_arms.append(("0x110000..=u32::MAX", "above U+10FFFF — unreachable for `char`"))
	_emit_matches_body(lines, unassigned_arms)
	lines.append("}")
	lines.append("")

	return "\n".join(lines)


def main(argv):
	ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
	ap.add_argument("unicode_data", type=Path, help="Path to UnicodeData.txt")
	ap.add_argument(
		"-o", "--output", type=Path, default=None,
		help="Output Rust file (default: stdout)",
	)
	args = ap.parse_args(argv)

	cats, names = parse_categories(args.unicode_data)
	other = coalesce_ranges(cats, names, ASSIGNED_OTHER_CATS, label=True)
	unassigned = coalesce_ranges(cats, names, frozenset({"Cn"}), label=False)
	rust = render_rust(other, unassigned)

	if args.output is None:
		sys.stdout.write(rust)
	else:
		args.output.write_text(rust)
		print(
			f"Wrote {args.output} "
			f"({len(other)} assigned-Other ranges, "
			f"{len(unassigned)} unassigned ranges).",
			file=sys.stderr,
		)


if __name__ == "__main__":
	main(sys.argv[1:])
