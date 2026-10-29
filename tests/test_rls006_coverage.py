"""RLS006: command coverage, the WITH CHECK fallback, read/write divergence."""

from __future__ import annotations

from conftest import columns, grant, policy, snapshot, table
from rls_probe.checks import check_rls006
from rls_probe.model import Severity

PREDICATE = "(owner_ref = current_user_id())"


def _uncovered(findings):
    return {
        f.discriminator.split(":", 1)[1]
        for f in findings
        if f.discriminator.startswith("uncovered:")
    }


def test_select_only_policy_leaves_three_commands_uncovered():
    protected = table("invoices", rls_enabled=True)
    snap = snapshot(
        relations=[protected],
        policies=[policy("select_own", protected, command="r", using=PREDICATE)],
        columns=columns(protected, "owner_ref"),
    )

    findings = check_rls006(snap)

    assert _uncovered(findings) == {"INSERT", "UPDATE", "DELETE"}
    assert all(f.severity is Severity.LOW for f in findings)


def test_a_for_all_policy_covers_every_command():
    protected = table("invoices", rls_enabled=True)
    snap = snapshot(
        relations=[protected],
        policies=[policy("all_own", protected, command="*", using=PREDICATE, check=PREDICATE)],
        columns=columns(protected, "owner_ref"),
    )

    assert _uncovered(check_rls006(snap)) == set()


def test_restrictive_policies_do_not_count_towards_coverage():
    # A restrictive policy narrows access; it never grants it.
    protected = table("invoices", rls_enabled=True)
    snap = snapshot(
        relations=[protected],
        policies=[
            policy("select_own", protected, command="r", using=PREDICATE),
            policy(
                "restrict_insert",
                protected,
                command="a",
                permissive=False,
                check=PREDICATE,
            ),
        ],
        columns=columns(protected, "owner_ref"),
    )

    assert "INSERT" in _uncovered(check_rls006(snap))


def test_a_table_with_no_policies_at_all_is_left_to_rls004():
    protected = table("feature_flags", rls_enabled=True)
    snap = snapshot(relations=[protected])

    assert check_rls006(snap) == []


def test_privilege_held_but_no_applicable_policy_is_reported():
    protected = table("invoices", rls_enabled=True)
    snap = snapshot(
        relations=[protected],
        policies=[
            policy("admin_select", protected, command="r", roles=("admin",), using=PREDICATE)
        ],
        columns=columns(protected, "owner_ref"),
        relation_grants=grant(protected, "authenticated", "SELECT"),
    )

    findings = [f for f in check_rls006(snap) if f.discriminator == "uncovered-for-role:SELECT"]

    assert len(findings) == 1
    assert "authenticated" in findings[0].detail
    assert "REVOKE SELECT" in findings[0].remediation


def test_with_check_fallback_on_a_row_scoped_predicate_is_only_low():
    protected = table("invoices", rls_enabled=True)
    snap = snapshot(
        relations=[protected],
        policies=[policy("update_own", protected, command="w", using=PREDICATE)],
        columns=columns(protected, "owner_ref", "amount_cents"),
    )

    findings = [
        f for f in check_rls006(snap) if f.discriminator.startswith("with-check-fallback")
    ]

    assert len(findings) == 1
    assert findings[0].severity is Severity.LOW
    assert findings[0].evidence["using_references_table_columns"] == "true"


def test_with_check_fallback_on_a_membership_test_is_medium():
    # USING asks a question about the caller and says nothing about the row, so
    # as a WITH CHECK it accepts any post-image.
    protected = table("documents", rls_enabled=True)
    snap = snapshot(
        relations=[protected],
        policies=[
            policy(
                "all_for_members",
                protected,
                command="*",
                using=(
                    "(EXISTS ( SELECT 1 FROM memberships m "
                    "WHERE (m.member_ref = current_user_id())))"
                ),
            )
        ],
        columns=columns(protected, "doc_id", "org_ref", "title", "body"),
    )

    findings = [
        f for f in check_rls006(snap) if f.discriminator.startswith("with-check-fallback")
    ]

    assert len(findings) == 1
    assert findings[0].severity is Severity.MEDIUM
    assert "constrains the new row not at all" in findings[0].detail


def test_an_explicit_with_check_is_not_a_fallback():
    protected = table("invoices", rls_enabled=True)
    snap = snapshot(
        relations=[protected],
        policies=[
            policy("update_own", protected, command="w", using=PREDICATE, check=PREDICATE)
        ],
        columns=columns(protected, "owner_ref"),
    )

    assert [
        f for f in check_rls006(snap) if f.discriminator.startswith("with-check-fallback")
    ] == []


def test_insert_policy_has_no_fallback_case():
    # PostgreSQL rejects an INSERT policy without WITH CHECK, so the fallback
    # cannot arise there.
    protected = table("invoices", rls_enabled=True)
    snap = snapshot(
        relations=[protected],
        policies=[policy("insert_own", protected, command="a", check=PREDICATE)],
        columns=columns(protected, "owner_ref"),
    )

    assert [
        f for f in check_rls006(snap) if f.discriminator.startswith("with-check-fallback")
    ] == []


def test_read_write_divergence_is_reported():
    protected = table("invoices", rls_enabled=True)
    snap = snapshot(
        relations=[protected],
        policies=[
            policy("select_own", protected, command="r", using=PREDICATE),
            policy("insert_any", protected, command="a", check="(paid = false)"),
        ],
        columns=columns(protected, "owner_ref", "paid"),
    )

    findings = [f for f in check_rls006(snap) if f.discriminator == "read-write-divergence"]

    assert len(findings) == 1
    assert findings[0].severity is Severity.MEDIUM
    assert findings[0].evidence["select_using"] == "owner_ref = current_user_id()"


def test_matching_read_and_write_predicates_do_not_diverge():
    protected = table("invoices", rls_enabled=True)
    snap = snapshot(
        relations=[protected],
        policies=[
            policy("select_own", protected, command="r", using=PREDICATE),
            policy("insert_own", protected, command="a", check=PREDICATE),
            policy("update_own", protected, command="w", using=PREDICATE, check=PREDICATE),
            policy("delete_own", protected, command="d", using=PREDICATE),
        ],
        columns=columns(protected, "owner_ref"),
    )

    assert check_rls006(snap) == []


def test_whitespace_differences_do_not_count_as_divergence():
    protected = table("invoices", rls_enabled=True)
    snap = snapshot(
        relations=[protected],
        policies=[
            policy("select_own", protected, command="r", using="(owner_ref  =  f())"),
            policy("insert_own", protected, command="a", check="( owner_ref = f() )"),
        ],
        columns=columns(protected, "owner_ref"),
    )

    assert [f for f in check_rls006(snap) if f.discriminator == "read-write-divergence"] == []


def test_an_update_policy_using_fallback_counts_as_the_write_predicate():
    # The fallback means the write predicate is USING, so an UPDATE policy with
    # the same USING as the SELECT policy does not diverge.
    protected = table("invoices", rls_enabled=True)
    snap = snapshot(
        relations=[protected],
        policies=[
            policy("select_own", protected, command="r", using=PREDICATE),
            policy("update_own", protected, command="w", using=PREDICATE),
        ],
        columns=columns(protected, "owner_ref"),
    )

    assert [f for f in check_rls006(snap) if f.discriminator == "read-write-divergence"] == []
