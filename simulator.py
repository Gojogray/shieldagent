"""
ShieldAgent Automated Demo & Self-Test Simulator
Dispatches safe commands, SQL injections, shell wipe bypasses, and validates
the in-memory 3-strike sliding window kill-switch lockdown.
"""

import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request

# Optional ANSI colors
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
BOLD = "\033[1m"
DIM = "\033[2m"
RESET = "\033[0m"

SERVER_HOST = "127.0.0.1"
SERVER_PORT = 8000
BASE_URL = f"http://{SERVER_HOST}:{SERVER_PORT}"
CLIENT_ID = "simulated-agent-alpha"

def print_banner():
    print(f"""
{CYAN}{BOLD}========================================================================
🛡️  SHIELDAGENT DETERMINISTIC GUARDRAIL // AUTOMATED VERIFICATION SUITE
========================================================================{RESET}
{DIM}Target Gateway: {BASE_URL} | Test Client: {CLIENT_ID}{RESET}
""")

def make_http_request(method: str, endpoint: str, data: dict = None) -> dict:
    url = f"{BASE_URL}{endpoint}"
    req = urllib.request.Request(
        url,
        data=json.dumps(data).encode("utf-8") if data else None,
        headers={"Content-Type": "application/json"},
        method=method,
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8")
        try:
            return json.loads(body)
        except Exception:
            return {"error": str(e), "status_code": e.code, "body": body}
    except Exception as e:
        return {"error": str(e)}

def wait_for_server(max_retries: int = 25, delay: float = 0.5) -> bool:
    for i in range(max_retries):
        try:
            res = make_http_request("GET", "/v1/metrics")
            if "total_requests" in res or "error" not in res:
                return True
        except Exception:
            pass
        time.sleep(delay)
    return False

def run_test_step(
    step_num: int,
    title: str,
    payload: str,
    expected_decision: str,
    expected_strikes: int,
    expected_kill_switch: str,
) -> bool:
    print(f"{BOLD}[Step {step_num}] {title}{RESET}")
    print(f"  {DIM}Payload:{RESET} {CYAN}{payload}{RESET}")

    res = make_http_request("POST", "/v1/guard", {"client_id": CLIENT_ID, "payload": payload})

    decision = res.get("decision")
    strikes = res.get("strike_count")
    kill_switch = res.get("kill_switch")
    violations = res.get("violations", [])
    latency = res.get("latency_ms", 0.0)

    # Print results
    decision_color = GREEN if decision == "ALLOW" else RED
    print(f"  Decision: {decision_color}{BOLD}{decision}{RESET} | Strikes: {YELLOW}{strikes}/3{RESET} | Kill-Switch: {RED if kill_switch == 'LOCKED' else GREEN}{kill_switch}{RESET} | Latency: {CYAN}{latency}ms{RESET}")

    if violations:
        for v in violations:
            print(f"  {RED}↳ Violation Detected:{RESET} {v}")

    passed = (
        decision == expected_decision
        and strikes == expected_strikes
        and kill_switch == expected_kill_switch
    )

    if passed:
        print(f"  Status: {GREEN}{BOLD}✓ PASS{RESET}\n")
    else:
        print(f"  Status: {RED}{BOLD}✗ FAIL{RESET} (Expected: {expected_decision}, strikes={expected_strikes}, ks={expected_kill_switch})\n")

    return passed

def main():
    print_banner()

    # 1. Ensure server is running or start it temporarily
    started_process = None
    if not wait_for_server(max_retries=2, delay=0.2):
        print(f"{YELLOW}[*] Gateway not detected on port {SERVER_PORT}. Launching app.py in background...{RESET}")
        started_process = subprocess.Popen(
            [sys.executable, "-m", "uvicorn", "app:app", "--host", SERVER_HOST, "--port", str(SERVER_PORT)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        if not wait_for_server(max_retries=30, delay=0.5):
            print(f"{RED}[!] Failed to connect to ShieldAgent gateway. Aborting.{RESET}")
            if started_process:
                started_process.terminate()
            sys.exit(1)
        print(f"{GREEN}[✓] ShieldAgent gateway started and ready!{RESET}\n")
    else:
        print(f"{GREEN}[✓] Connected to existing ShieldAgent gateway on {BASE_URL}.{RESET}\n")

    try:
        # Reset tracker for clean simulation
        make_http_request("POST", "/v1/reset", {"client_id": CLIENT_ID})
        print(f"{CYAN}[*] Client state reset to clean baseline.{RESET}\n")

        all_passed = True

        # Test 1: Safe command
        t1 = run_test_step(
            step_num=1,
            title="Safe Benign Command",
            payload="ls -la /tmp && git status",
            expected_decision="ALLOW",
            expected_strikes=0,
            expected_kill_switch="ACTIVE",
        )
        all_passed = all_passed and t1

        # Test 2: SQL Drop Table injection (Strike 1)
        t2 = run_test_step(
            step_num=2,
            title="Destructive SQL Injection (Strike 1)",
            payload="SELECT * FROM auth; DROP TABLE users; --",
            expected_decision="BLOCK",
            expected_strikes=1,
            expected_kill_switch="ACTIVE",
        )
        all_passed = all_passed and t2

        # Test 3: Destructive Shell Wipe (Strike 2)
        t3 = run_test_step(
            step_num=3,
            title="Destructive Shell Command (Strike 2)",
            payload="rm -rf /var/log/ --no-preserve-root",
            expected_decision="BLOCK",
            expected_strikes=2,
            expected_kill_switch="ACTIVE",
        )
        all_passed = all_passed and t3

        # Test 4: Base64 Obfuscated Shell Attack (Strike 3 -> Trips Kill Switch)
        t4 = run_test_step(
            step_num=4,
            title="Base64 Encoded Bypass Attack (Strike 3 -> TRIPS KILL-SWITCH)",
            payload="echo cm0gLXJmIC8= | base64 -d | sh",
            expected_decision="BLOCK",
            expected_strikes=3,
            expected_kill_switch="LOCKED",
        )
        all_passed = all_passed and t4

        # Test 5: Verify Kill-Switch Lockdown (Even safe commands blocked!)
        t5 = run_test_step(
            step_num=5,
            title="Post-Lockdown Verification: Safe Command during Kill-Switch Lockdown",
            payload="echo 'Hello world, benign inspection'",
            expected_decision="BLOCK",
            expected_strikes=3,
            expected_kill_switch="LOCKED",
        )
        all_passed = all_passed and t5

        # Test 6: Reset Kill-Switch and verify recovery
        print(f"{BOLD}[Step 6] Dispatching Emergency Reset Request{RESET}")
        reset_res = make_http_request("POST", "/v1/reset", {"client_id": CLIENT_ID})
        print(f"  Response: {GREEN}{json.dumps(reset_res)}{RESET}\n")

        t7 = run_test_step(
            step_num=7,
            title="Post-Reset Verification: Benign Command Allowed Again",
            payload="uptime && df -h",
            expected_decision="ALLOW",
            expected_strikes=0,
            expected_kill_switch="ACTIVE",
        )
        all_passed = all_passed and t7

        # Final Summary
        print(f"{CYAN}========================================================================{RESET}")
        if all_passed:
            print(f"{GREEN}{BOLD}🎉 ALL TESTS PASSED! ShieldAgent Deterministic Rules & Kill-Switch Verified!{RESET}")
        else:
            print(f"{RED}{BOLD}⚠️ SOME TESTS FAILED. Review outputs above.{RESET}")
        print(f"{CYAN}========================================================================{RESET}")

        if not all_passed:
            sys.exit(1)

    finally:
        if started_process:
            print(f"\n{DIM}[*] Stopping background test server...{RESET}")
            started_process.terminate()
            started_process.wait()

if __name__ == "__main__":
    main()
