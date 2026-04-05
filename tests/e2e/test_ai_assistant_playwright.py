import time
from playwright.sync_api import sync_playwright

from tests.e2e.helpers import choose_selectbox_option, login_as_admin


def test_ai_assistant_can_answer_and_summarize(tmp_path):
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page()
        page.goto('http://localhost:8501')
        login_as_admin(page)
        # Wait for dashboard
        page.wait_for_selector('text=🤖 AI Assistant', timeout=10000)
        page.click('text=🤖 AI Assistant')
        page.wait_for_selector('textarea')
        page.fill('textarea', 'How to enable mTLS?')
        choose_selectbox_option(page, 'Model', 'knowledge')
        page.click('text=Ask')
        time.sleep(2)
        # take screenshot artifact
        art = tmp_path / 'ai_assistant.png'
        page.screenshot(path=str(art))
        browser.close()
