import asyncio
import os
import sys
import subprocess
import time
from playwright.async_api import async_playwright

async def verify_dashboard():
    # Start the backend server in background
    print("Starting backend...")

    # We need to make sure we're in the right directory and using the right python
    cwd = os.getcwd()
    python_executable = sys.executable

    # Open backend process
    backend_proc = subprocess.Popen(
        [python_executable, "main.py"],
        cwd=cwd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )

    browser = None
    try:
        # Give backend some time to start up and initialize WebSocket
        print("Waiting for backend to initialize (10s)...")
        await asyncio.sleep(10)

        async with async_playwright() as p:
            print("Launching browser...")
            browser = await p.chromium.launch()
            page = await browser.new_page()

            # Load dashboard file
            dashboard_path = os.path.abspath("dashboard.html")
            url = f"file://{dashboard_path}"
            print(f"Loading dashboard: {url}")
            await page.goto(url)

            # Take initial screenshot of loaded page
            print("Taking initial screenshot...")
            await page.screenshot(path="verification_initial.png")

            # Wait for WebSocket connection confirmation
            # The JS updates status text to "MONITORING ACTIVE" (green) on connect.
            # Let's wait for that specifically.
            print("Waiting for WebSocket connection...")
            try:
                await page.wait_for_function(
                    "document.getElementById('statusText').textContent === 'MONITORING ACTIVE'",
                    timeout=5000
                )
                print("WebSocket connected successfully!")
            except Exception as e:
                print(f"WebSocket connection timed out or failed: {e}")
                # We continue anyway to see if we can get anything

            # Wait for prediction (backend sends every 5s)
            print("Waiting for AI prediction item...")
            try:
                # Wait for .prediction-item class to appear
                # The backend loop sleeps 5s, so we wait up to 15s
                await page.wait_for_selector(".prediction-item", timeout=20000)
                print("Prediction item appeared!")

                # Wait a bit more to ensure it stays and doesn't flicker away
                await asyncio.sleep(2)

                # Check if it is still there
                items = await page.query_selector_all(".prediction-item")
                count = len(items)
                if count > 0:
                    print(f"Verified: {count} prediction items present.")
                else:
                    print("ERROR: Prediction items disappeared!")

                # Check if placeholder is gone
                placeholder = await page.query_selector("#predPlaceholder")
                if placeholder:
                    print("Error: Placeholder still exists! It should have been removed.")
                else:
                    print("Verified: Placeholder removed correctly.")

                # Take final screenshot showing prediction
                print("Taking final screenshot...")
                await page.screenshot(path="verification_prediction.png")

            except Exception as e:
                print(f"Verification failed: {e}")
                print("Taking failure screenshot...")
                await page.screenshot(path="verification_failed.png")

    finally:
        if browser:
            await browser.close()

        print("Stopping backend...")
        backend_proc.terminate()
        try:
            backend_proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            backend_proc.kill()

        # Print backend output for debugging if needed
        stdout, stderr = backend_proc.communicate()
        if stdout: print(f"Backend Output:\n{stdout[-500:]}") # Last 500 chars
        if stderr: print(f"Backend Error:\n{stderr[-500:]}")

if __name__ == "__main__":
    asyncio.run(verify_dashboard())
