"""Properties of the catalog layer that can be checked without a server."""

from __future__ import annotations

import re

import pytest

from rls_probe import catalog


def _sql_constants() -> dict[str, str]:
    return {
        name: value
        for name, value in vars(catalog).items()
        if name.startswith("SQL_") and isinstance(value, str)
    }


def test_there_is_a_query_for_every_catalog_the_checks_need():
    assert set(_sql_constants()) == {
        "SQL_SERVER_INFO",
        "SQL_SCHEMAS",
        "SQL_RELATIONS",
        "SQL_RELATIONS_BY_OID",
        "SQL_POLICIES",
        "SQL_ROUTINES",
        "SQL_COLUMNS",
        "SQL_RELATION_GRANTS",
        "SQL_EFFECTIVE_RELATION_PRIVILEGES",
        "SQL_ROUTINE_GRANTS",
        "SQL_VIEW_DEPENDENCIES",
    }


@pytest.mark.parametrize("name", sorted(_sql_constants()))
def test_every_statement_is_a_select(name):
    # The read-only promise in the README is only as good as this.
    statement = _sql_constants()[name].strip()
    first_word = re.match(r"\s*(\w+)", statement).group(1).upper()
    assert first_word in ("SELECT", "WITH")


@pytest.mark.parametrize("name", sorted(_sql_constants()))
def test_no_statement_contains_a_write_keyword(name):
    statement = _sql_constants()[name].upper()
    for keyword in (
        "INSERT ",
        "UPDATE ",
        "DELETE ",
        "DROP ",
        "ALTER ",
        "CREATE ",
        "TRUNCATE ",
        "GRANT ",
        "REVOKE ",
        "COPY ",
    ):
        assert keyword not in statement, f"{name} contains {keyword.strip()}"


@pytest.mark.parametrize("name", sorted(_sql_constants()))
def test_percent_signs_only_appear_as_named_placeholders(name):
    # A bare '%' in a statement executed with parameters makes psycopg raise
    # "only '%s', '%b', '%t' are allowed as placeholders", which is how this
    # regression test came to exist.
    statement = _sql_constants()[name]
    for match in re.finditer(r"%", statement):
        tail = statement[match.start() :]
        assert tail.startswith("%("), f"{name} has a bare % at offset {match.start()}"


def test_redact_dsn_hides_a_uri_password():
    assert (
        catalog.redact_dsn("postgresql://user:hunter2@db.example.com:5432/app")
        == "postgresql://user:***@db.example.com:5432/app"
    )


def test_redact_dsn_hides_a_keyword_password():
    assert (
        catalog.redact_dsn("host=localhost password=hunter2 dbname=app")
        == "host=localhost password=*** dbname=app"
    )


def test_redact_dsn_leaves_a_passwordless_dsn_alone():
    assert catalog.redact_dsn("postgresql:///app") == "postgresql:///app"


def test_managed_schemas_cover_the_supabase_set():
    for schema in ("auth", "storage", "realtime", "vault", "extensions"):
        assert schema in catalog.MANAGED_SCHEMAS


def test_defaults_match_a_supabase_deployment():
    assert catalog.DEFAULT_EXPOSED_SCHEMAS == ("public",)
    assert catalog.DEFAULT_EXPOSED_ROLES == ("anon", "authenticated")
    assert catalog.DEFAULT_ANONYMOUS_ROLES == ("anon",)
