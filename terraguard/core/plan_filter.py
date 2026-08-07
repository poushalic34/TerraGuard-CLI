from __future__ import annotations

from typing import Any

CHANGED_ACTIONS = frozenset({"create", "update", "delete", "replace"})


def filter_changed_resources(plan: dict[str, Any]) -> dict[str, Any]:
    """Return a plan copy containing only resource_changes with mutating actions."""
    changes = plan.get("resource_changes") or []
    filtered = [change for change in changes if _is_changed(change)]
    narrowed = dict(plan)
    narrowed["resource_changes"] = filtered
    return narrowed


def changed_resource_addresses(plan: dict[str, Any]) -> tuple[str, ...]:
    return tuple(
        str(change.get("address", ""))
        for change in (plan.get("resource_changes") or [])
        if _is_changed(change) and change.get("address")
    )


def _is_changed(change: dict[str, Any]) -> bool:
    actions = set(change.get("change", {}).get("actions") or [])
    if not actions:
        # Fixtures often omit actions; treat as in-scope for evaluation.
        return True
    if actions == {"no-op"} or actions == {"read"}:
        return False
    return bool(actions & CHANGED_ACTIONS)
