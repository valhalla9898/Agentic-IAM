"""Attack simulation harness (authorized testing only).

Usage:
    python scripts/attack_simulator.py --target http://localhost:8000 --output ./attack_results

This script uses Playwright to run a set of safe, non-destructive test scenarios
(e.g., authentication fuzzing, navigation, rate-limit checks) and records a
video of the browser session. It also optionally triggers OWASP ZAP baseline
scans if a ZAP API is available.
"""

from __future__ import annotations

import argparse
import json
import os
import time
from datetime import datetime

from playwright.sync_api import sync_playwright

try:
    from zapv2 import ZAPv2

    ZAP_AVAILABLE = True
except ImportError:
    ZAP_AVAILABLE = False


def now_ts():
    return datetime.utcnow().isoformat() + "Z"


def run_playwright(target: str, output_dir: str) -> dict:
    os.makedirs(output_dir, exist_ok=True)
    events = []
    video_dir = os.path.join(output_dir, "videos")
    os.makedirs(video_dir, exist_ok=True)

    video_file = None

    with sync_playwright() as p:
        browser = p.chromium.launch()
        context = browser.new_context(record_video_dir=video_dir)
        page = context.new_page()

        try:
            events.append({"ts": now_ts(), "event": "start", "target": target})
            page.goto(target)
            events.append({"ts": now_ts(), "event": "goto", "url": target})

            # Example interaction: try to locate login form fields and attempt a few non-destructive submissions
            try:
                if page.query_selector('input[type="password"]'):
                    username_sel = page.query_selector('input[type="text"]') or page.query_selector(
                        'input[name="username"]'
                    )
                    password_sel = page.query_selector('input[type="password"]')
                    if username_sel and password_sel:
                        for attempt in range(3):
                            user_val = f"testuser_{attempt}"
                            pwd_val = "wrongpassword"
                            username_sel.fill(user_val)
                            password_sel.fill(pwd_val)
                            events.append(
                                {"ts": now_ts(), "event": "login_attempt", "username": user_val}
                            )
                            # attempt to click submit if available
                            submit = page.query_selector(
                                'button[type="submit"]'
                            ) or page.query_selector('input[type="submit"]')
                            if submit:
                                submit.click()
                                time.sleep(1)
            except Exception as e:
                import logging

                logging.getLogger(__name__).debug("login attempt interaction failed: %s", e)

            # Navigate a few pages to generate activity
            try:
                links = page.query_selector_all("a")[:5]
                for i, a in enumerate(links):
                    href = a.get_attribute("href")
                    if href:
                        try:
                            page.click(f"a:nth-of-type({i+1})")
                            events.append({"ts": now_ts(), "event": "click", "href": href})
                            time.sleep(0.5)
                        except Exception as e:
                            import logging

                            logging.getLogger(__name__).debug("link click failed: %s", e)
                            continue
            except Exception as e:
                import logging

                logging.getLogger(__name__).debug("page navigation/interactions failed: %s", e)

        finally:
            # Close context to finalize video
            page.close()
            context.close()
            browser.close()

        # Wait a moment for video file to be written
        time.sleep(1)

    # Find the most recent video file produced
    for root, _, files in os.walk(video_dir):
        for f in files:
            if f.endswith(".webm"):
                candidate = os.path.join(root, f)
                if not video_file or os.path.getmtime(candidate) > os.path.getmtime(video_file):
                    video_file = candidate

    result = {
        "ts": now_ts(),
        "video": video_file,
        "events": events,
    }

    # Save metadata
    meta_path = os.path.join(output_dir, "last_run.json")
    with open(meta_path, "w", encoding="utf-8") as fh:
        json.dump(result, fh, indent=2)

    return result


def run_zap_scan(target: str, zap_api: str = "http://zap:8090") -> dict:
    if not ZAP_AVAILABLE:
        return {"available": False}
    zap = ZAPv2(apikey=None, proxies={"http": zap_api, "https": zap_api})
    # run quick scan - baseline for authorized testing
    try:
        zap.pscan.scan(target)
        return {"available": True, "scan": True}
    except Exception as e:
        import logging

        logging.getLogger(__name__).debug("ZAP scan failed: %s", e)
        return {"available": True, "scan": False}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", required=True, help="Target base URL")
    parser.add_argument("--output", default="./attack_results", help="Output directory")
    parser.add_argument(
        "--use-zap", action="store_true", help="Trigger OWASP ZAP baseline if available"
    )
    args = parser.parse_args()

    print("Starting attack simulation (authorized only)")

    meta = run_playwright(args.target, args.output)

    if args.use_zap:
        zap_res = run_zap_scan(args.target)
        meta["zap"] = zap_res

    print("Simulation complete. Results:")
    print(json.dumps(meta, indent=2))


if __name__ == "__main__":
    main()
