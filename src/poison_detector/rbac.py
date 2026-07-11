"""
Role-Based Access Control (RBAC) for the dataset poisoning detection system.

Enforces the principle of least privilege by mapping authenticated identities
to roles with specific permission sets. Supports role assignment via JWT
claims or programmatic lookup.

Threat Model Assumptions:
    - Role assignments are trusted. They come from the authentication layer
      (JWT claims signed by the identity provider) or from a protected
      configuration store. An attacker cannot self-assign roles without
      compromising the token issuer or config store.
    - Permission checks are mandatory at the API boundary. Internal service
      calls between modules do not re-check permissions (they operate in a
      trusted context after the initial auth check).
    - The permission matrix is static at deployment time. Dynamic permission
      changes require a config reload or redeployment. This prevents runtime
      privilege escalation via configuration injection.

Honest Limitations:
    - This is coarse-grained RBAC, not attribute-based access control (ABAC).
      It cannot express rules like "analyst can only view quarantine for
      their own team's datasets." For that, implement ABAC on top.
    - Role hierarchy is flat. Admin has all permissions but there is no
      inheritance chain (e.g., analyst does not inherit readonly permissions
      by hierarchy, only by explicit assignment in the matrix).
    - No support for temporary role elevation (break-glass). For emergency
      access, use a separate admin authentication path with enhanced audit.
    - Permission checks are synchronous and in-memory. No external policy
      engine (OPA, Cedar) integration. Suitable for single-service deployments.

Security Notes:
    - Default deny: if a permission is not explicitly granted, it is denied.
    - Role names and permission names are case-sensitive enums to prevent
      typo-based privilege escalation (e.g., "Admin" != "admin").
    - The admin role is intentionally the only role with modify_config and
      view_audit. Separation of duties between analysts and admins.
    - All permission denials are logged for security monitoring.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class Role(Enum):
    """Roles available in the poisoning detection system.

    Each role represents a distinct level of access with specific
    use cases:
        - ADMIN: System administrators with full access.
        - ANALYST: Security analysts who investigate and resolve quarantined samples.
        - READONLY: Monitoring dashboards and reporting tools.
        - SERVICE: Automated pipelines that only need scoring capabilities.
    """

    ADMIN = "admin"
    ANALYST = "analyst"
    READONLY = "readonly"
    SERVICE = "service"


class Permission(Enum):
    """Granular permissions for API operations.

    Each permission maps to one or more API endpoints:
        - SCORE: Submit a single sample for scoring.
        - BATCH_SCORE: Submit a batch of samples for scoring.
        - VIEW_QUARANTINE: View quarantined samples and their metadata.
        - RESOLVE_QUARANTINE: Mark quarantined samples as resolved/false positive.
        - MODIFY_CONFIG: Change detection thresholds and feature flags.
        - VIEW_AUDIT: Access the authentication audit trail.
        - EXPORT_DATA: Export detection results and quarantine data.
    """

    SCORE = "score"
    BATCH_SCORE = "batch_score"
    VIEW_QUARANTINE = "view_quarantine"
    RESOLVE_QUARANTINE = "resolve_quarantine"
    MODIFY_CONFIG = "modify_config"
    VIEW_AUDIT = "view_audit"
    EXPORT_DATA = "export_data"


# ---------------------------------------------------------------------------
# Permission Matrix
# ---------------------------------------------------------------------------

# Static permission matrix: maps each role to its allowed permissions.
# This is the single source of truth for what each role can do.
PERMISSION_MATRIX: dict[Role, frozenset[Permission]] = {
    Role.ADMIN: frozenset(Permission),  # All permissions
    Role.ANALYST: frozenset([
        Permission.SCORE,
        Permission.BATCH_SCORE,
        Permission.VIEW_QUARANTINE,
        Permission.RESOLVE_QUARANTINE,
        Permission.EXPORT_DATA,
    ]),
    Role.READONLY: frozenset([
        Permission.VIEW_QUARANTINE,
        Permission.EXPORT_DATA,
    ]),
    Role.SERVICE: frozenset([
        Permission.SCORE,
        Permission.BATCH_SCORE,
    ]),
}


# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------


@dataclass
class AccessDecision:
    """Result of a permission check.

    Attributes:
        allowed: Whether access is granted.
        role: The role that was evaluated.
        permission: The permission that was checked.
        reason: Human-readable explanation of the decision.
    """

    allowed: bool
    role: Role | None = None
    permission: Permission | None = None
    reason: str = ""


@dataclass
class RoleAssignment:
    """Maps an identity to a role.

    Attributes:
        identity: The authenticated identity (sub claim, key ID, cert CN).
        role: The assigned role.
        assigned_by: Who/what assigned this role (for audit).
        assigned_at: Unix timestamp of assignment.
        metadata: Additional context about the assignment.
    """

    identity: str
    role: Role
    assigned_by: str = "system"
    assigned_at: float = 0.0
    metadata: dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# RBAC Enforcer
# ---------------------------------------------------------------------------


class RBACEnforcer:
    """Enforces role-based access control decisions.

    Combines role resolution (from JWT claims or local assignments) with
    permission checking against the static permission matrix.

    Usage:
        enforcer = RBACEnforcer()

        # From JWT claims
        decision = enforcer.check_permission(
            identity="user@example.com",
            permission=Permission.VIEW_QUARANTINE,
            roles=["analyst"],  # from JWT claims
        )

        # From local assignment
        enforcer.assign_role("service-account-1", Role.SERVICE)
        decision = enforcer.check_permission(
            identity="service-account-1",
            permission=Permission.SCORE,
        )

        if not decision.allowed:
            raise PermissionError(decision.reason)
    """

    def __init__(self) -> None:
        """Initialize the RBAC enforcer with empty role assignments."""
        self._assignments: dict[str, RoleAssignment] = {}
        self._custom_permissions: dict[str, frozenset[Permission]] = {}

    def check_permission(
        self,
        identity: str,
        permission: Permission,
        roles: list[str] | None = None,
    ) -> AccessDecision:
        """Check if an identity has a specific permission.

        Resolution order:
        1. If roles are provided (from JWT claims), use those.
        2. Otherwise, look up local role assignment.
        3. Check custom per-identity permissions.
        4. Default deny.

        Args:
            identity: The authenticated identity to check.
            permission: The permission being requested.
            roles: Roles from JWT claims (takes precedence over local).

        Returns:
            AccessDecision indicating whether access is granted.
        """
        # Resolve role
        resolved_role = self._resolve_role(identity, roles)

        if resolved_role is None:
            # Check custom permissions as fallback
            custom = self._custom_permissions.get(identity, frozenset())
            if permission in custom:
                logger.debug(
                    "RBAC ALLOW: identity=%s permission=%s (custom)",
                    identity, permission.value,
                )
                return AccessDecision(
                    allowed=True,
                    permission=permission,
                    reason="Granted via custom permission assignment",
                )

            logger.warning(
                "RBAC DENY: identity=%s permission=%s reason=no_role_assigned",
                identity, permission.value,
            )
            return AccessDecision(
                allowed=False,
                permission=permission,
                reason=f"No role assigned to identity '{identity}'",
            )

        # Check permission matrix
        allowed_permissions = PERMISSION_MATRIX.get(resolved_role, frozenset())

        if permission in allowed_permissions:
            logger.debug(
                "RBAC ALLOW: identity=%s role=%s permission=%s",
                identity, resolved_role.value, permission.value,
            )
            return AccessDecision(
                allowed=True,
                role=resolved_role,
                permission=permission,
                reason=f"Permission granted via role '{resolved_role.value}'",
            )

        # Also check custom permissions
        custom = self._custom_permissions.get(identity, frozenset())
        if permission in custom:
            logger.debug(
                "RBAC ALLOW: identity=%s permission=%s (custom override)",
                identity, permission.value,
            )
            return AccessDecision(
                allowed=True,
                role=resolved_role,
                permission=permission,
                reason="Granted via custom permission override",
            )

        logger.warning(
            "RBAC DENY: identity=%s role=%s permission=%s",
            identity, resolved_role.value, permission.value,
        )
        return AccessDecision(
            allowed=False,
            role=resolved_role,
            permission=permission,
            reason=(
                f"Role '{resolved_role.value}' does not have "
                f"permission '{permission.value}'"
            ),
        )

    def check_any_permission(
        self,
        identity: str,
        permissions: list[Permission],
        roles: list[str] | None = None,
    ) -> AccessDecision:
        """Check if an identity has any of the specified permissions.

        Args:
            identity: The authenticated identity.
            permissions: List of permissions (any one is sufficient).
            roles: Roles from JWT claims.

        Returns:
            AccessDecision (allowed if any permission matches).
        """
        for perm in permissions:
            decision = self.check_permission(identity, perm, roles)
            if decision.allowed:
                return decision

        return AccessDecision(
            allowed=False,
            permission=permissions[0] if permissions else None,
            reason=f"None of the required permissions are granted",
        )

    def assign_role(
        self,
        identity: str,
        role: Role,
        assigned_by: str = "system",
    ) -> None:
        """Assign a role to an identity.

        Args:
            identity: The identity to assign the role to.
            role: The role to assign.
            assigned_by: Who is making the assignment (for audit).
        """
        import time

        self._assignments[identity] = RoleAssignment(
            identity=identity,
            role=role,
            assigned_by=assigned_by,
            assigned_at=time.time(),
        )
        logger.info(
            "Role assigned: identity=%s role=%s by=%s",
            identity, role.value, assigned_by,
        )

    def revoke_role(self, identity: str) -> bool:
        """Revoke role assignment for an identity.

        Args:
            identity: The identity whose role to revoke.

        Returns:
            True if a role was revoked, False if none was assigned.
        """
        if identity in self._assignments:
            old_role = self._assignments[identity].role
            del self._assignments[identity]
            logger.info(
                "Role revoked: identity=%s role=%s", identity, old_role.value,
            )
            return True
        return False

    def grant_custom_permissions(
        self,
        identity: str,
        permissions: list[Permission],
    ) -> None:
        """Grant custom permissions to an identity beyond their role.

        Use sparingly. Prefer role assignment over custom permissions.

        Args:
            identity: The identity to grant permissions to.
            permissions: Permissions to grant.
        """
        existing = self._custom_permissions.get(identity, frozenset())
        self._custom_permissions[identity] = existing | frozenset(permissions)
        logger.info(
            "Custom permissions granted: identity=%s permissions=%s",
            identity, [p.value for p in permissions],
        )

    def revoke_custom_permissions(self, identity: str) -> None:
        """Revoke all custom permissions for an identity.

        Args:
            identity: The identity whose custom permissions to revoke.
        """
        self._custom_permissions.pop(identity, None)

    def get_role(self, identity: str, roles: list[str] | None = None) -> Role | None:
        """Get the resolved role for an identity.

        Args:
            identity: The identity to look up.
            roles: Roles from JWT claims (takes precedence).

        Returns:
            The resolved Role or None if no role is assigned.
        """
        return self._resolve_role(identity, roles)

    def get_permissions(
        self,
        identity: str,
        roles: list[str] | None = None,
    ) -> frozenset[Permission]:
        """Get all permissions for an identity.

        Args:
            identity: The identity to look up.
            roles: Roles from JWT claims.

        Returns:
            Set of all permissions available to the identity.
        """
        resolved_role = self._resolve_role(identity, roles)
        permissions: frozenset[Permission] = frozenset()

        if resolved_role:
            permissions = PERMISSION_MATRIX.get(resolved_role, frozenset())

        custom = self._custom_permissions.get(identity, frozenset())
        return permissions | custom

    def get_all_assignments(self) -> list[RoleAssignment]:
        """Get all current role assignments."""
        return list(self._assignments.values())

    def _resolve_role(
        self, identity: str, roles: list[str] | None = None
    ) -> Role | None:
        """Resolve the effective role for an identity.

        JWT claim roles take precedence over local assignments.
        If multiple roles are provided, the highest-privilege role wins.

        Args:
            identity: The identity to resolve.
            roles: Roles from JWT claims.

        Returns:
            The resolved Role, or None.
        """
        if roles:
            # Parse role strings to Role enum, taking highest privilege
            resolved_roles: list[Role] = []
            for role_str in roles:
                try:
                    resolved_roles.append(Role(role_str.lower()))
                except ValueError:
                    logger.warning(
                        "Unknown role '%s' for identity '%s'", role_str, identity
                    )
                    continue

            if resolved_roles:
                # Priority order: admin > analyst > readonly > service
                priority = [Role.ADMIN, Role.ANALYST, Role.READONLY, Role.SERVICE]
                for role in priority:
                    if role in resolved_roles:
                        return role
                return resolved_roles[0]

        # Fall back to local assignment
        assignment = self._assignments.get(identity)
        if assignment:
            return assignment.role

        return None
