"""The expression helpers the policy checks are built on."""

from __future__ import annotations

import pytest

from rls_probe.catalog import parse_reloptions
from rls_probe.checks import (
    is_literally_true,
    normalize_expr,
    references_any_column,
    strip_outer_parens,
)


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("true", "true"),
        ("(true)", "true"),
        ("((true))", "true"),
        ("  ( true ) ", "true"),
        ("(a) AND (b)", "(a) AND (b)"),
        ("(a AND b)", "a AND b"),
        ("(tenant_id = f())", "tenant_id = f()"),
    ],
)
def test_strip_outer_parens_only_unwraps_a_single_wrapper(raw, expected):
    assert strip_outer_parens(raw) == expected


@pytest.mark.parametrize("raw", ["true", "(true)", "TRUE", " ((true)) "])
def test_is_literally_true_matches_the_constant(raw):
    assert is_literally_true(raw) is True


@pytest.mark.parametrize(
    "raw",
    [
        None,
        "false",
        "1 = 1",
        "current_user IS NOT NULL",
        "true AND tenant_id = f()",
        "truest",
    ],
)
def test_is_literally_true_claims_nothing_about_semantics(raw):
    # An expression that is merely always true is a judgement about SQL
    # semantics the tool deliberately does not make.
    assert is_literally_true(raw) is False


def test_normalize_expr_collapses_whitespace():
    assert normalize_expr("( tenant_id\n  =   f() )") == "tenant_id = f()"


def test_normalize_expr_passes_none_through():
    assert normalize_expr(None) is None


def test_references_any_column_finds_a_whole_word():
    assert references_any_column("(org_ref = f())", ["org_ref", "title"]) is True


def test_references_any_column_is_not_fooled_by_a_substring():
    # "id" must not match inside "user_id": that is the difference between a
    # row-scoped predicate and a membership test, which is what RLS006 rates on.
    assert (
        references_any_column(
            "(EXISTS ( SELECT 1 FROM memberships m "
            "WHERE (m.member_ref = current_setting('x.user_id'::text, true))))",
            ["id", "title", "body", "org_ref"],
        )
        is False
    )


def test_references_any_column_handles_no_expression():
    assert references_any_column(None, ["id"]) is False


def test_parse_reloptions_splits_on_the_first_equals():
    assert parse_reloptions(["security_invoker=true", "check_option=local"]) == {
        "security_invoker": "true",
        "check_option": "local",
    }


def test_parse_reloptions_tolerates_null():
    assert parse_reloptions(None) == {}
