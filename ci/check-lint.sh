#!/bin/sh
set -e
set -x

CLIPPY() {
	# shellcheck disable=SC2086
	RUSTFLAGS='-D warnings' cargo clippy $1 -- $2 \
		`# https://github.com/rust-lang/rust-clippy/issues/15442` \
		-A unused_imports \
		`# Things clippy defaults to allowing but we should avoid` \
		-D clippy::clone_on_ref_ptr \
		`# Things where clippy is just wrong` \
		-A clippy::unwrap-or-default \
		-A clippy::upper_case_acronyms \
		-A clippy::swap-with-temporary \
		`# Things where we do odd stuff on purpose ` \
		-A clippy::unusual_byte_groupings \
		-A clippy::unit_arg \
		`# Errors` \
		-A clippy::erasing_op \
		-A clippy::never_loop \
		`# Warnings` \
		-A renamed_and_removed_lints \
		-A clippy::blocks_in_conditions \
		-A clippy::borrow_deref_ref \
		-A clippy::clone_on_copy \
		-A clippy::collapsible_else_if \
		-A clippy::collapsible_if \
		-A clippy::collapsible_match \
		-A clippy::comparison_chain \
		-A clippy::doc_lazy_continuation \
		-A clippy::drain_collect \
		-A clippy::drop_non_drop \
		-A clippy::enum_variant_names \
		-A clippy::explicit_auto_deref \
		-A clippy::extra_unused_lifetimes \
		-A clippy::for_kv_map \
		-A clippy::from_over_into \
		-A clippy::get_first \
		-A clippy::identity_op \
		-A clippy::if_same_then_else \
		-A clippy::inconsistent_digit_grouping \
		-A clippy::iter_kv_map \
		-A clippy::iter_skip_next \
		-A clippy::large_enum_variant \
		-A clippy::legacy_numeric_constants \
		-A clippy::len_without_is_empty \
		-A clippy::len_zero \
		-A clippy::let_and_return \
		-A clippy::manual_filter \
		-A clippy::manual_map \
		-A clippy::manual_memcpy \
		-A clippy::manual_inspect \
		-A clippy::manual_range_contains \
		-A clippy::manual_range_patterns \
		-A clippy::manual_saturating_arithmetic \
		-A clippy::manual_strip \
		-A clippy::map_clone \
		-A clippy::map_flatten \
		-A clippy::match_like_matches_macro \
		-A clippy::match_ref_pats \
		-A clippy::multiple_bound_locations \
		-A clippy::mut_mutex_lock \
		-A clippy::needless_bool \
		-A clippy::needless_borrow \
		-A clippy::needless_borrowed_reference \
		-A clippy::needless_borrows_for_generic_args \
		-A clippy::needless_lifetimes \
		-A clippy::needless_question_mark \
		-A clippy::needless_range_loop \
		-A clippy::needless_return \
		-A clippy::new_without_default \
		-A clippy::non_minimal_cfg \
		-A clippy::op_ref \
		-A clippy::option_as_ref_deref \
		-A clippy::option_map_or_none \
		-A clippy::option_map_unit_fn \
		-A clippy::precedence \
		-A clippy::ptr_arg \
		-A clippy::question_mark \
		-A clippy::readonly_write_lock \
		-A clippy::redundant_closure \
		-A clippy::redundant_field_names \
		-A clippy::redundant_guards \
		-A clippy::redundant_pattern_matching \
		-A clippy::redundant_slicing \
		-A clippy::redundant_static_lifetimes \
		-A clippy::result_large_err \
		-A clippy::result_unit_err \
		-A clippy::search_is_some \
		-A clippy::single_char_pattern \
		-A clippy::single_match \
		-A clippy::slow_vector_initialization \
		-A clippy::tabs_in_doc_comments \
		-A clippy::to_string_in_format_args \
		-A clippy::too_many_arguments \
		-A clippy::toplevel_ref_arg \
		-A clippy::type_complexity \
		-A clippy::unnecessary_cast \
		-A clippy::unnecessary_get_then_check \
		-A clippy::unnecessary_lazy_evaluations \
		-A clippy::unnecessary_mut_passed \
		-A clippy::unnecessary_sort_by \
		-A clippy::unnecessary_to_owned \
		-A clippy::unnecessary_unwrap \
		-A clippy::unused_unit \
		-A clippy::useless_conversion \
		-A clippy::manual_repeat_n `# to be removed once we hit MSRV 1.86` \
		-A clippy::manual_is_multiple_of `# to be removed once we hit MSRV 1.87` \
		-A clippy::uninlined-format-args
}

CLIPPY
# We allow some additional warnings in tests which we should fix, but which aren't currently a priority
CLIPPY --tests "-A clippy::bool_assert_comparison -A clippy::assertions_on_constants -A clippy::needless-late-init -A clippy::field_reassign_with_default -A clippy::unnecessary_literal_unwrap"
