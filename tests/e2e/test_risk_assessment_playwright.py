import time
from playwright.sync_api import sync_playwright


def test_risk_assessment_page(tmp_path):
    with sync_playwright() as p:
        browser = p.firefox.launch(headless=True)
        page = browser.new_page()
        page.goto('http://localhost:8501')
        page.wait_for_selector('text=Agentic-IAM Login')
        page.fill('input[placeholder="Username"]', 'operator')
        page.fill('input[type="password"]', 'operator123')
        page.click('text=🔐 Login')
        page.wait_for_selector('text=⚠️ Risk Assessment', timeout=10000)
        page.click('text=⚠️ Risk Assessment')
        page.wait_for_selector('text=Quick agent risk assessment', timeout=5000)
        # Screenshot
        art = tmp_path / 'risk_assessment.png'
        page.screenshot(path=str(art))
        browser.close()
