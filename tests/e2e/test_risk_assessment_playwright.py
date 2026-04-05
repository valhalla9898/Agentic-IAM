from playwright.sync_api import sync_playwright

from tests.e2e.helpers import login_as_admin


def test_risk_assessment_page(tmp_path):
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page()
        page.goto('http://localhost:8501')
        login_as_admin(page)
        page.wait_for_selector('text=⚠️ Risk Assessment', timeout=10000)
        page.click('text=⚠️ Risk Assessment')
        page.wait_for_selector('text=Quick agent risk assessment', timeout=5000)
        # Screenshot
        art = tmp_path / 'risk_assessment.png'
        page.screenshot(path=str(art))
        browser.close()
