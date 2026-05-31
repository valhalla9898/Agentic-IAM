import pytest
from dashboard import navigation


def dummy_permission_checker(p: str) -> bool:
    # allow only specific permissions for testing
    return p in ("agent:read", "report:view", "audit:read")


def test_build_navigation_admin_allows_all():
    nav = navigation.build_navigation("admin", has_permission=lambda p: True)
    assert isinstance(nav, list)
    # admin should see admin cluster
    ids = [n["id"] for n in nav]
    assert "admin" in ids


def test_build_navigation_user_filters_permissions():
    nav = navigation.build_navigation("user", has_permission=dummy_permission_checker)
    # user should not see admin cluster
    ids = [n["id"] for n in nav]
    assert "admin" not in ids
    # agents cluster should be present
    assert "agents" in ids


def test_flatten_labels_contains_routes():
    nav = navigation.build_navigation("operator", has_permission=lambda p: True)
    labels = navigation.flatten_labels(nav)
    assert isinstance(labels, list)
    assert any(isinstance(l, str) for l in labels)
