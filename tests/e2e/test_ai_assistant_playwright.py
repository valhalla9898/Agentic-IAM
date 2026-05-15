import time
from playwright.sync_api import sync_playwright

from tests.e2e.helpers import login_as_admin


def test_ai_assistant_can_answer_and_summarize(tmp_path):
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page()
        page.goto('http://localhost:8501')
        login_as_admin(page)
        # Wait for dashboard
        page.wait_for_selector('text=🤖 AI Assistant', timeout=10000)
        page.click('text=🤖 AI Assistant')
        page.wait_for_selector('text=Ask Your Question', timeout=10000)
        page.get_by_label('Type your question (English or , spelling errors are OK!)').fill(
            'How do I register an agent?'
        )
        page.get_by_role('button', name='🔍 Search for Answers').click()
        page.wait_for_selector('text=Answer Options', timeout=10000)
        time.sleep(2)
        # take screenshot artifact
        art = tmp_path / 'ai_assistant.png'
        page.screenshot(path=str(art))
        browser.close()
