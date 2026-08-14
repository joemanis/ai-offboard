"""Capture screenshots of the ai-offboard web UI for the README.

Run after `offboard web` is serving. Saves:
  examples/ai-offboard-landing.png   (landing page)
  examples/ai-offboard-report.png    (demand scan report page)
"""
from __future__ import annotations

from pathlib import Path

from playwright.sync_api import sync_playwright

BASE = "http://127.0.0.1:8600"
OUT_DIR = Path(__file__).resolve().parent.parent / "examples"

VIEWPORT = {"width": 1024, "height": 820}


def main() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    with sync_playwright() as p:
        browser = p.chromium.launch()
        page = browser.new_page(viewport=VIEWPORT, device_scale_factor=2)

        # Landing page
        page.goto(BASE, wait_until="networkidle")
        page.wait_for_selector("text=ai-offboard", timeout=8000)
        page.screenshot(path=str(OUT_DIR / "ai-offboard-landing.png"), full_page=True)

        # Run the demo scan and capture the report
        # The demo-scan form is the secondary one (mock=1). Click it.
        page.locator("form:has(input[value='1'][name='mock']) button").click()
        page.wait_for_url("**/scan", timeout=8000)
        page.wait_for_selector("text=AI Access Audit", timeout=8000)
        page.wait_for_timeout(600)
        page.screenshot(path=str(OUT_DIR / "ai-offboard-report.png"), full_page=True)

        browser.close()
    print("Screenshots written to", OUT_DIR)


if __name__ == "__main__":
    main()