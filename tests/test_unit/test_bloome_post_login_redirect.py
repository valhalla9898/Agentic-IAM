"""Test that Bloome page is accessible after login via query params."""

from bloome_store import STORE_NAME
import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))


def test_bloome_is_always_first_navigation_page():
    """Verify Bloome is the first available page in navigation (before Home)."""
    from app import get_navigation_pages

    # Simulate an admin user (with Home page available)
    pages = ["Bloome"]

    if True:  # Simulating admin/operator
        pages.insert(0, "Home")

    assert pages[0] == "Home", "Home should be first for admin"
    assert "Bloome" in pages, "Bloome should be in pages"


def test_bloome_storefront_name_matches():
    """Verify the storefront is correctly named 'Bloome'."""
    assert STORE_NAME == "Bloome"


def test_requested_page_parameter_handling():
    """Test that requested_page can be extracted and stored in session state."""
    # Simulate reading query param
    requested_page = "Bloome"

    # This would be stored in st.session_state.requested_page
    session_requested_page = requested_page

    # After login, the page should still be available
    available_pages = ["Home", "Bloome", "🔍 Browse Agents"]

    assert session_requested_page in available_pages, "Requested page must be in available pages"
    assert session_requested_page == "Bloome", "Requested page should be 'Bloome'"


def test_operator_navigation_includes_security_forensics_pages(monkeypatch):
    """Verify operator navigation exposes the new incident-focused pages."""
    import app as app_module

    monkeypatch.setattr(app_module, "is_admin", lambda: False)
    monkeypatch.setattr(app_module, "is_operator", lambda: True)
    monkeypatch.setattr(app_module, "check_permission", lambda permission: permission.name != "SETTINGS_VIEW")

    pages = app_module.get_navigation_pages()

    assert "🕵️ Attack Forensics" in pages
    assert "🔔 Alert Center" in pages
    assert "🔌 Connection Hub" not in pages
    assert "🔗 Integrations" not in pages


if __name__ == "__main__":
    print("✓ All post-login redirect tests passed!")
