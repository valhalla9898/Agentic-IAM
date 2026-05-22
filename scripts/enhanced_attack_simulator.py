"""Enhanced attack simulator - simulates realistic attacks with video recording."""

from __future__ import annotations

import argparse
import json
import os
import time
from datetime import datetime

import requests
from playwright.sync_api import sync_playwright


def now_ts():
    return datetime.utcnow().isoformat() + "Z"


def run_attack_simulation(target: str, output_dir: str, record_video: bool = True) -> dict:
    """Run comprehensive attack simulation with Playwright video recording."""
    os.makedirs(output_dir, exist_ok=True)
    events = []
    video_dir = os.path.join(output_dir, "videos")
    os.makedirs(video_dir, exist_ok=True)

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=False)  # Show browser for visibility
        context = browser.new_context(record_video_dir=video_dir if record_video else None)
        page = context.new_page()

        try:
            # 1. INITIAL ACCESS
            print("[*] Accessing target application...")
            events.append({"ts": now_ts(), "event": "target_access", "url": target})
            page.goto(target, timeout=10000)
            time.sleep(2)

            # 2. BRUTE FORCE ATTACK - Multiple failed login attempts
            print("[*] Simulating brute force attack...")
            events.append({"ts": now_ts(), "event": "attack_started", "type": "brute_force"})

            login_attempts = [
                ("admin", "password123"),
                ("admin", "password456"),
                ("admin", "password789"),
                ("admin", "admin123"),
                ("admin", "letmein"),
            ]

            for i, (user, pwd) in enumerate(login_attempts):
                # Try to find login form
                try:
                    # Fill username
                    username_input = (
                        page.query_selector('input[type="text"]')
                        or page.query_selector('input[name="username"]')
                        or page.query_selector('input[id="username"]')
                    )
                    if username_input:
                        username_input.fill(user)
                        time.sleep(0.5)

                    # Fill password
                    password_input = page.query_selector('input[type="password"]')
                    if password_input:
                        password_input.fill(pwd)
                        time.sleep(0.5)

                    # Submit form
                    submit = (
                        page.query_selector('button[type="submit"]')
                        or page.query_selector('input[type="submit"]')
                        or page.query_selector('button:has-text("Login")')
                    )

                    if submit:
                        print(f"[!] Attempt {i+1}: Sending login with {user}:{pwd}")
                        events.append(
                            {
                                "ts": now_ts(),
                                "event": "brute_force_attempt",
                                "attempt": i + 1,
                                "username": user,
                                "password": pwd,
                            }
                        )
                        submit.click()
                        time.sleep(1.5)
                except Exception as e:
                    print(f"[-] Error during attempt {i+1}: {e}")

            # 3. SQL INJECTION ATTEMPT
            print("[*] Simulating SQL Injection attack...")
            events.append({"ts": now_ts(), "event": "attack_started", "type": "sql_injection"})

            sql_payloads = [
                "' OR '1'='1",
                "admin' --",
                "1' UNION SELECT * FROM users --",
            ]

            try:
                # Try to find search/input field
                search_input = page.query_selector('input[type="text"]')
                if search_input:
                    for payload in sql_payloads:
                        print(f"[!] Sending SQL Injection: {payload}")
                        events.append(
                            {"ts": now_ts(), "event": "sql_injection_attempt", "payload": payload}
                        )
                        search_input.fill(payload)
                        search_input.press("Enter")
                        time.sleep(1)
            except Exception as e:
                print(f"[-] SQL Injection attempt failed: {e}")

            # 4. XSS ATTEMPT
            print("[*] Simulating XSS attack...")
            events.append({"ts": now_ts(), "event": "attack_started", "type": "xss"})

            xss_payloads = [
                "<script>alert('XSS')</script>",
                "<img src=x onerror=alert('XSS')>",
            ]

            try:
                xss_input = page.query_selector('input[type="text"]') or page.query_selector(
                    "textarea"
                )
                if xss_input:
                    for payload in xss_payloads:
                        print(f"[!] Sending XSS: {payload}")
                        events.append({"ts": now_ts(), "event": "xss_attempt", "payload": payload})
                        xss_input.fill(payload)
                        time.sleep(0.5)
            except Exception as e:
                print(f"[-] XSS attempt failed: {e}")

            # 5. RATE LIMIT ABUSE
            print("[*] Simulating rate limit abuse...")
            events.append({"ts": now_ts(), "event": "attack_started", "type": "rate_limit_abuse"})

            try:
                for i in range(10):
                    print(f"[!] Rapid request {i+1}/10")
                    events.append({"ts": now_ts(), "event": "rapid_request", "request_num": i + 1})
                    page.reload()
                    time.sleep(0.2)
            except Exception as e:
                print(f"[-] Rate limit abuse: {e}")

            # 6. CHECK FOR ALERTS / BLOCKING
            print("[*] Checking for security alerts...")
            events.append({"ts": now_ts(), "event": "checking_alerts"})

            # Try to call alerts API
            try:
                response = requests.get(f"{target.rstrip('/')}/alerts/active", timeout=5)
                if response.status_code == 200:
                    alerts = response.json()
                    if alerts:
                        print(f"[+] Security alerts detected: {len(alerts)} alert(s)")
                        events.append(
                            {
                                "ts": now_ts(),
                                "event": "alerts_detected",
                                "alert_count": len(alerts),
                                "alerts": alerts[:3],  # First 3 alerts
                            }
                        )
                    else:
                        print("[-] No alerts detected yet")
                        events.append({"ts": now_ts(), "event": "no_alerts_detected"})
            except Exception as e:
                print(f"[-] Failed to fetch alerts: {e}")

            # 7. CHECK FOR IP BLOCKING
            print("[*] Checking if IP is blocked...")
            events.append({"ts": now_ts(), "event": "checking_ip_block"})

            try:
                response = requests.get(f"{target.rstrip('/')}/alerts/blocked-ips", timeout=5)
                if response.status_code == 200:
                    blocked_ips = response.json()
                    print(f"[+] Blocked IPs: {blocked_ips}")
                    events.append(
                        {"ts": now_ts(), "event": "blocked_ips_check", "blocked_ips": blocked_ips}
                    )
            except Exception as e:
                print(f"[-] IP block check failed: {e}")

            # 8. FINAL STATUS
            print("[*] Simulation complete")
            events.append({"ts": now_ts(), "event": "simulation_complete"})

        finally:
            # Close browser - this finalizes video recording
            time.sleep(2)
            page.close()
            context.close()
            browser.close()
            time.sleep(2)

    # Find the recorded video
    video_file = None
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
        "total_events": len(events),
    }

    # Save metadata
    meta_path = os.path.join(output_dir, "last_run.json")
    with open(meta_path, "w", encoding="utf-8") as fh:
        json.dump(result, fh, indent=2)

    print(f"\n[+] Attack simulation saved to {meta_path}")
    if video_file:
        print(f"[+] Video recorded: {video_file}")

    return result


def main():
    parser = argparse.ArgumentParser(description="Enhanced attack simulation")
    parser.add_argument("--target", required=True, help="Target base URL")
    parser.add_argument("--output", default="./attack_results", help="Output directory")
    parser.add_argument("--no-video", action="store_true", help="Disable video recording")
    args = parser.parse_args()

    print("=" * 60)
    print("ATTACK SIMULATION - AUTHORIZED SECURITY TESTING")
    print("=" * 60)
    print(f"Target: {args.target}")
    print(f"Output: {args.output}")
    print(f"Video Recording: {'Disabled' if args.no_video else 'Enabled'}")
    print("=" * 60 + "\n")

    result = run_attack_simulation(args.target, args.output, record_video=not args.no_video)

    print("\n" + "=" * 60)
    print("SIMULATION SUMMARY")
    print("=" * 60)
    print(f"Total events: {result['total_events']}")
    print(f"Video recorded: {'Yes' if result['video'] else 'No'}")
    print(f"Results saved: {args.output}/last_run.json")
    print("=" * 60 + "\n")

    print(json.dumps(result, indent=2, default=str))


if __name__ == "__main__":
    main()
