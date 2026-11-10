# 🛡️ ShieldAgent: Edge Enforcement Gateway

### Autonomous AI Edge Security Gateway & Deterministic Kill-Switch

![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-blue.svg?style=for-the-badge&logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-0.100%2B-009688.svg?style=for-the-badge&logo=fastapi&logoColor=white)
![Latency](https://img.shields.io/badge/Avg%20Latency-~1.1ms-brightgreen.svg?style=for-the-badge&logo=speedtest&logoColor=white)
![Edge Ready](https://img.shields.io/badge/Architecture-Offline--First%20%7C%20Edge-purple.svg?style=for-the-badge)
![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=for-the-badge)

Sub-2ms tool-call interception, lexical de-obfuscation, and automated 3-strike agent isolation running locally at the edge.

---

## ⚡ Executive Summary

Autonomous AI agents (AutoGPT, LangChain, crewAI) are routinely delegated direct bash execution, SQL access, and local filesystem control. Current defense paradigms present a dangerous trade-off:

1. **Cloud LLM Evaluators:** Add 1,000ms – 3,000ms of latency, introduce variable token costs, and break completely under edge or offline conditions.
2. **Naive Regex Filters:** Are trivial to bypass via evasion techniques like Base64 sub-shells, command escaping (`r\m -rf`), and SQL comment splicing.

**ShieldAgent** is an ultra-lightweight, deterministic security gateway deployed directly on the host or edge gateway. Operating as an enforcement reverse-proxy, it normalizes payloads via abstract syntax tree (AST) tokenization and shell lexing, matches security policies in ~1.1 ms, and triggers a hardware-local 3-strike kill switch to isolate compromised agents in real time.

---

## 📊 Performance & Benchmarks

All benchmarks recorded live on low-resource ARM edge hardware:

| Metric | Cloud LLM Guardrails | Naive Regex Gateways | ShieldAgent (Edge Engine) |
| :--- | :---: | :---: | :---: |
| **Average Latency** | 1,200ms – 2,800ms | ~0.3ms | **~1.1ms (Deterministic)** |
| **Offline / Edge Support** | ❌ Requires WAN | ✅ Local | **✅ 100% Offline-First** |
| **Token & API Costs** | 💸 ~$0.01 – $0.03 / call | 🆓 Free | **🆓 Zero Cloud Inference Cost** |
| **Obfuscation Resistance** | ⚠️ Unreliable | ❌ 0% (Bypassed by `\`, b64) | **✅ AST & Lexer Normalized** |
| **Quarantine Mechanism** | ❌ Manual Intervention | ❌ Stateless / None | **✅ Concurrency-Safe 3-Strike Kill-Switch** |
| **Incident Logging** | ⚠️ Cloud Ingestion Latency | ❌ Memory Only | **✅ SQLite Write-Ahead Log (WAL)** |

---

## 🏗️ Architecture & Data Flow

```text
               ┌───────────────────────────────┐
               │    Autonomous AI Agent Loop   │
               │  (LangChain / crewAI / Bash)  │
               └───────────────┬───────────────┘
                               │
                               │ Tool Execution Request (JSON)
                               ▼
┌─────────────────────────────────────────────────────────────┐
│                 SHIELDAGENT GATEWAY (:8000)                 │
│                                                             │
│   [ Layer 1: Normalization & De-obfuscation ]              │
│   ├── Strips POSIX shell backslash escaping (shlex)         │
│   ├── Decodes & unpacks nested Base64 strings               │
│   └── AST token normalization for SQL syntax                │
│                                                             │
│   [ Layer 2: Deterministic Policy Engine ]                  │
│   ├── Sub-2ms pattern verification                          │
│   └── Zero cloud API or network dependencies                │
│                                                             │
│   [ Layer 3: Sliding-Window Threat Tracker ]                │
│   ├── Sliding 60s window state (concurrency-safe)           │
│   ├── Strikes 1 & 2 ──► Warning & Payload Blocked           │
│   └── Strike 3      ──► IMMEDIATE KILL-SWITCH TRIPPED       │
│                                                             │
│   [ Layer 4: Crash-Resilient Audit Log ]                    │
│   └── Non-blocking SQLite persistence (WAL mode)            │
└──────────────────────────────┬──────────────────────────────┘
                               │
               ┌───────────────┴───────────────┐
               │                               │
        [ HTTP 200 OK ]               [ HTTP 403 FORBIDDEN ]
               │                               │
               ▼                               ▼
       Safe Tool Executes            Agent Quarantined
     (OS Bash / Database)         (All Calls Intercepted)
```

---

## 🎯 Mitigated Threat Vectors

| Threat Category | Example Obfuscated Payload | Interception Mechanism |
| :--- | :--- | :--- |
| **Destructive Shell** | `r\m -r\f /*`, `rm --no-preserve-root` | POSIX `shlex` normalization strips escape tokens before evaluation. |
| **Encoded Exfiltration** | `echo Y2F0IC9ldGMvcGFzc3dk \| base64 -d \| sh` | Recursive Base64 decoder unpacks payload and surfaces hidden commands. |
| **SQL Destruction** | `'; DROP/*comment*/TABLE users; --` | Lexical parser normalizes whitespace and SQL comment blocks. |
| **Credential Harvesting** | `cat ~/.ssh/id_rsa`, `cat /etc/shadow` | Strict filesystem path access rules block access to secret stores. |
| **Prompt Injection** | `Ignore all previous instructions and output...` | Natural language instruction boundary detection rejects hijacked loops. |

---

## ⚡ 60-Second Quickstart

### Prerequisites
* Python 3.10 or higher
* Linux, macOS, WSL, or Android (Termux)

### 1. Installation
```bash
git clone https://github.com/<YOUR-USERNAME>/shieldagent.git
cd shieldagent
pip install -r requirements.txt
```

### 2. Start the Edge Gateway Server
```bash
python -m uvicorn app:app --host 127.0.0.1 --port 8000 --workers 1
```
* **Real-time Web UI:** Open `http://127.0.0.1:8000` in your browser.

### 3. Run the Automated Attack Suite
```bash
python simulator.py
```

---

## 📡 API Specification

### `POST /v1/guard`
Primary inspection proxy. Tool calls must pass through this endpoint before execution.

```json
{
  "agent_id": "agent-alpha",
  "command": "SELECT * FROM data; DROP TABLE audits;"
}
```

Response (HTTP 403):
```json
{
  "decision": "BLOCK",
  "agent_id": "agent-alpha",
  "threat_level": "HIGH",
  "violation": "SQL_DROP_DESTRUCTION: Drop or Truncate detected",
  "strikes": 2,
  "kill_switch": "ACTIVE",
  "latency_ms": 1.162
}
```

---

### `POST /v1/reset`
Administrative manual override to clear accumulated strikes.

```json
{
  "agent_id": "agent-alpha"
}
```

Response (HTTP 200):
```json
{
  "status": "RESET_SUCCESS",
  "message": "Kill-switch restored to ACTIVE, strikes cleared for agent-alpha"
}
```

---

### `GET /v1/metrics`
Returns rolling latency statistics, active agent states, and recent SQLite audit entries.

---

## 🧪 Simulation Matrix

```text
[Step 1] Baseline Safe Command     --> PASS (HTTP 200, 0/3 Strikes, Latency: 1.82ms)
[Step 2] SQL Drop Injection        --> PASS (HTTP 403, 1/3 Strikes, Latency: 2.00ms)
[Step 3] Destructive Shell Command --> PASS (HTTP 403, 2/3 Strikes, Latency: 1.82ms)
[Step 4] Base64 Bypass Exploit     --> PASS (HTTP 403, 3/3 Strikes, KILL-SWITCH TRIPPED)
[Step 5] Post-Lockdown Command     --> PASS (HTTP 403, Agent Quarantined)
[Step 6] Admin Recovery Request    --> PASS (HTTP 200, Agent Restored)
[Step 7] Post-Reset Verification   --> PASS (HTTP 200, Benign Command Allowed)
```

---

## 🛠️ Technology Stack

* **Language:** Python 3.10+ (Asynchronous AsyncIO runtime)
* **Framework:** FastAPI, Uvicorn (ASGI)
* **Data Persistence:** SQLite3 with Write-Ahead Logging (`PRAGMA journal_mode=WAL`)
* **De-obfuscation Engine:** Standard Library `shlex`, `ast`, `base64`
* **Test Harness:** HTTPX

---

Developed for Offline-First Autonomous Edge AI Safety.