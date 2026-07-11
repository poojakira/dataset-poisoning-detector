"""Tests for role-based access control enforcement."""

import pytest

from poison_detector.rbac import (
    PERMISSION_MATRIX,
    Permission,
    RBACEnforcer,
    Role,
)


def test_admin_has_all_permissions():
    e = RBACEnforcer()
    for perm in Permission:
        assert e.check_permission("root", perm, roles=["admin"]).allowed


def test_service_role_limited_to_scoring():
    e = RBACEnforcer()
    assert e.check_permission("svc", Permission.SCORE, roles=["service"]).allowed
    assert e.check_permission("svc", Permission.BATCH_SCORE, roles=["service"]).allowed
    denied = e.check_permission("svc", Permission.MODIFY_CONFIG, roles=["service"])
    assert denied.allowed is False
    assert "does not have" in denied.reason


def test_no_role_is_default_deny():
    e = RBACEnforcer()
    decision = e.check_permission("nobody", Permission.SCORE)
    assert decision.allowed is False
    assert "No role assigned" in decision.reason


def test_local_role_assignment_and_revocation():
    e = RBACEnforcer()
    e.assign_role("acct", Role.ANALYST, assigned_by="tester")
    assert e.check_permission("acct", Permission.VIEW_QUARANTINE).allowed
    assert e.get_role("acct") == Role.ANALYST
    assert len(e.get_all_assignments()) == 1
    assert e.revoke_role("acct") is True
    assert e.revoke_role("acct") is False
    assert e.check_permission("acct", Permission.VIEW_QUARANTINE).allowed is False


def test_custom_permissions_grant_and_revoke():
    e = RBACEnforcer()
    # No role, but a custom grant.
    e.grant_custom_permissions("special", [Permission.EXPORT_DATA])
    assert e.check_permission("special", Permission.EXPORT_DATA).allowed
    e.revoke_custom_permissions("special")
    assert e.check_permission("special", Permission.EXPORT_DATA).allowed is False


def test_custom_permission_override_on_top_of_role():
    e = RBACEnforcer()
    e.assign_role("svc", Role.SERVICE)
    # SERVICE lacks EXPORT_DATA; grant it explicitly.
    e.grant_custom_permissions("svc", [Permission.EXPORT_DATA])
    assert e.check_permission("svc", Permission.EXPORT_DATA).allowed


def test_check_any_permission():
    e = RBACEnforcer()
    decision = e.check_any_permission(
        "u", [Permission.MODIFY_CONFIG, Permission.SCORE], roles=["service"]
    )
    assert decision.allowed  # SCORE is allowed for service
    denied = e.check_any_permission("u", [Permission.MODIFY_CONFIG], roles=["service"])
    assert denied.allowed is False


def test_highest_privilege_role_wins():
    e = RBACEnforcer()
    role = e.get_role("multi", roles=["service", "admin", "readonly"])
    assert role == Role.ADMIN


def test_unknown_role_string_ignored():
    e = RBACEnforcer()
    # "wizard" is not a real role; falls through to no valid role -> deny.
    decision = e.check_permission("u", Permission.SCORE, roles=["wizard"])
    assert decision.allowed is False


def test_get_permissions_union():
    e = RBACEnforcer()
    e.grant_custom_permissions("u", [Permission.VIEW_AUDIT])
    perms = e.get_permissions("u", roles=["service"])
    assert Permission.SCORE in perms
    assert Permission.VIEW_AUDIT in perms
    assert perms >= PERMISSION_MATRIX[Role.SERVICE]
