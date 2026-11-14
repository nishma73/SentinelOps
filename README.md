# SentinelOps: Guarded Customer Support & Incident Triage Agent

SentinelOps is a production-grade, safety-first customer support and incident triage system demonstrating an AI Agent coupled with a Model Context Protocol (MCP) server, an isolated Independent Reviewer QA Gate, and a cryptographically locked Human-in-the-Loop (HITL) approval queue with idempotent execution.

---

## Architecture

SentinelOps enforces defense-in-depth across the entire triage lifecycle. Agents cannot take autonomous external actions; all tool outputs and proposals pass through strict schema validation, independent peer QA review, and cryptographic hash locks prior to execution.

```
 +-----------------------------------------------------------------------------+
 |                               CUSTOMER TICKET                               |
 |                (e.g., Enterprise 504 Outage / SLA Credit Claim)             |
 +-----------------------------------------------------------------------------+
                                        |
                                        v
 +-----------------------------------------------------------------------------+
 |                                AI AGENT CORE                                |
 |        Orchestrates incident analysis, runbook queries, and draft creation  |
 +-----------------------------------------------------------------------------+
               |                                               ^
     JSON-RPC  | (1) tools/call                                | Tool Results
     2.0 MCP   v                                               | (Verified Data)
 +-----------------------------------------------------------------------------+
 |                              MCP SERVER LAYER                               |
 |  - lookup_customer_account(account_id) -> Tier & SLA Entitlement            |
 |  - search_runbooks(query, category)   -> Operating Policies & Steps         |
 |  - Strict JSON Schema Validator (Strictly rejects bool for int/string)      |
 +-----------------------------------------------------------------------------+
                                        |
                         Initial Draft  | (2)
                                        v
 +-----------------------------------------------------------------------------+
 |                        INDEPENDENT REVIEWER QA GATE                         |
 |  - Enforces writer is not reviewer                                          |
 |  - Evaluates ONLY (draft, rubric, sources) -- Writer reasoning hidden       |
 |  - Scores 4 criteria (facts, policy, fit, clarity) as integers 1..10        |
 |  - Fails closed on malformed output; max 1 rewrite loop if score < 8        |
 +-----------------------------------------------------------------------------+
                                        |
                    Approved Final Draft| (3) propose_customer_reply
                                        v
 +-----------------------------------------------------------------------------+
 |                  HASH-LOCKED HUMAN APPROVAL QUEUE (HITL)                    |
 |  - Computes canonical SHA-256 payload digest: sort_keys=True                |
 |  - Human verifies and approves seen_hash                                    |
 |  - Enforces TTL expiration (e.g., 3600s)                                    |
 |  - Immutable audit trail: proposed -> approved -> executed / blocked        |
 +-----------------------------------------------------------------------------+
               |                                               |
     Tamper    | (4a) Payload Modified                         | (4b) Legitimate
     Detected  |      Post-Approval                            |      Execution
               v                                               v
 +-----------------------------+             +---------------------------------+
 |      EXECUTION BLOCKED      |             |       IDEMPOTENT EXECUTOR       |
 | Status: blocked             |             | - Enforces idempotency_key      |
 | Reason: SHA-256 mismatch    |             | - Dispatches email notification |
 | Emits security audit alert  |             | - Returns cached result on dup  |
 +-----------------------------+             +---------------------------------+
```

### Core Safety & Operational Pillars

1. **Fail-Fast Configuration & Log Redaction (`config.py`)**:
   - Refuses to start in `production` if debug mode is active, authentication tokens are missing, or CORS origins contain wildcards (`*`).
   - Built-in logging filter scrubs API keys and Bearer tokens without leaking secrets or raw error messages.

2. **JSON-RPC 2.0 MCP Server with Strict Schema Validation (`mcp_server.py`)**:
   - Adheres to JSON-RPC 2.0 error specifications: `-32600` (Invalid Request), `-32601` (Method Not Found), and `-32602` (Invalid Params).
   - Custom schema validator rejects Python's `bool` subclassing gotcha (where `isinstance(True, int)` is true), catches missing/unknown fields (`additionalProperties: False`), and returns structured `isError: true` payloads to allow model self-correction.
   - Read-only tools for runbooks and customer accounts, plus a write tool (`propose_customer_reply`) that diverts actions into the approval queue.

3. **Independent Reviewer QA Gate (`reviewer.py`)**:
   - Enforces that writer and reviewer are separate functions/entities (`ValueError` on identity match).
   - Information isolation: reviewer receives only `(draft, rubric, sources)`—writer chain-of-thought is completely hidden.
   - Evaluates 4 rubric criteria (`facts`, `policy`, `fit`, `clarity`) strictly as integers `1..10`.
   - Supports exactly one rewrite loop if Attempt 1 scores below threshold (8/10), and holds safely if Attempt 2 fails.

4. **Hash-Locked Human-in-the-Loop Approval Queue (`approval_queue.py`)**:
   - Binds human approvals to the SHA-256 digest of canonical JSON (`sort_keys=True`).
   - If payload contents are altered after approval, execution is immediately blocked and logged as a security event.
   - Enforces TTL expiration and single-dispatch idempotent execution (`idempotency_key=action_id`).

5. **Idempotent Periodic Scheduler & Pause Switch (`scheduler.py`)**:
   - Deterministic period keys (e.g., `triage:daily:YYYY-MM-DD` and `triage:hourly:YYYY-MM-DD-HH`).
   - `PAUSE` file / flag check enables instant emergency operational halts without losing state.
   - Circuit breaker with `max_attempts=3` that trips and disables failing keys while emitting alerts.

---

## Run locally

### Prerequisites
- Python 3.10+ (Python 3.11 recommended)
- `pip` package manager
- (Optional) Docker

### 1. Clone & Set Up Virtual Environment

```bash
# Clone the repository
git clone https://github.com/your-org/sentinelops.git
cd sentinelops

# Create and activate virtual environment
python -m venv .venv

# On Linux/macOS:
source .venv/bin/activate

# On Windows:
.\.venv\Scripts\activate
```

### 2. Install Dependencies

```bash
pip install -r requirements.txt
```

### 3. Configure Environment

Copy the example configuration:

```bash
cp .env.example .env
```

By default, `MOCK_MODE=true` is enabled, allowing the complete system, interactive dashboard, and MCP tools to run immediately without requiring third-party API credits.

### 4. Start the Application Server

```bash
uvicorn app:app --reload --port 8000
```

Open your browser to:
- **Interactive UI Dashboard**: [http://localhost:8000](http://localhost:8000)
- **API Documentation (Swagger)**: [http://localhost:8000/docs](http://localhost:8000/docs)
- **Health Check**: [http://localhost:8000/health](http://localhost:8000/health)

### 5. Run the Test Suite

Execute the comprehensive 48-test suite with coverage across all architectural components:

```bash
pytest -v
```

### 6. Run with Docker

```bash
# Build Docker image
docker build -t sentinelops .

# Run container on port 8000
docker run -p 8000:8000 -e APP_ENV=development sentinelops
```

---

## Configuration

SentinelOps is configured via environment variables or a `.env` file. Settings are validated at boot with strict production safeguards.

| Environment Variable | Type | Default | Production Requirement | Description |
|---|---|---|---|---|
| `APP_ENV` | `string` | `"development"` | Allowed: `"development"`, `"production"` | Operational environment mode. |
| `DEBUG` | `boolean` | `false` | **Must be false** | Verbose debugging and trace logs. |
| `MOCK_MODE` | `boolean` | `true` | Optional | When `true`, uses deterministic simulation out of the box. |
| `ANTHROPIC_API_KEY` | `string` | `""` | **Required if MOCK_MODE=false** | Claude API key for live inference. |
| `MCP_AUTH_TOKEN` | `string` | `""` | **Required and non-blank** | Bearer authentication token for `/mcp`. |
| `ALLOWED_ORIGINS` | `string` | `""` | **Required; NO wildcards (`*`)** | Comma-separated CORS allowed domains. |
| `PAUSE_FILE_PATH` | `string` | `"PAUSE"` | Optional | File path checked by the emergency pause switch. |
| `PORT` | `integer` | `8000` | Optional | Server listening port. |

### Production Startup Safeguards (`StartupError`)

In `APP_ENV=production`, SentinelOps enforces strict startup validation:
- Refuses to start if `DEBUG=true`, `1`, or `yes`.
- Refuses to start if `MCP_AUTH_TOKEN` is unset or blank.
- Refuses to start if `ALLOWED_ORIGINS` is missing, blank, or contains `*`.
- Refuses to start if `MOCK_MODE=false` and `ANTHROPIC_API_KEY` is missing.
- Gathers all misconfiguration issues into a single `StartupError` without exposing sensitive tokens in logs or stack traces.

---

## Demo

A live deployment of SentinelOps is hosted at:
👉 **[https://sentinelops-demo.onrender.com](https://sentinelops-demo.onrender.com)**

### Guided Interactive Walkthrough

Follow these steps in the interactive dashboard to experience all safety and operational controls:

1. **Inspect Operational Readiness**:
   - Check the top header badges: `GET /health: 200 OK`, `ENV: DEV`, and `MOCK MODE: ON`.
   - Click the **Pause: OFF** toggle button. Notice how creating the `PAUSE` switch immediately turns the badge into **Pause: ON (PAUSE File Active)**, gracefully suspending background work without clearing system state. Click it again to turn pause off.

2. **Ingest an Incident Scenario**:
   - Under Section 1, choose the preset **Acme Corp: 504 Outage & SLA Credit Claim**.
   - Review the prefilled ticket data: Account `ACC-101`, Issue: *504 Gateway Timeout during checkout, requesting 20% SLA credit*.
   - Click **Run Guarded Triage Pipeline**.

3. **Step 1: Inspect MCP Tool Calls & Schema Validation**:
   - In the left column, view the live JSON-RPC 2.0 tool calls made by the agent:
     - `lookup_customer_account(account_id="ACC-101")` retrieves Acme Corp's `Enterprise` tier, ARR, and SLA threshold.
     - `search_runbooks(query="...", category="sla")` matches policy runbook `RB-SLA-001`.
   - Note the **Schema Validated** badge confirming that arguments met all JSON Schema constraints.

4. **Step 2: Observe the Independent Reviewer QA Gate**:
   - In the center column, observe the scorecard for Attempt #1:
     - All 4 criteria (`Facts: 9/10`, `Policy: 9/10`, `Fit: 9/10`, `Clarity: 10/10`) meet or exceed the threshold (8/10).
     - Notice the confirmation that the reviewer evaluated only the draft and verified sources, keeping writer reasoning isolated.

5. **Test the Single-Rewrite QA Loop**:
   - Return to Section 1, check the box **Simulate Low Score (Forces 1 QA Rewrite)**, and click **Run Guarded Triage Pipeline**.
   - Watch the QA Gate execute:
     - **Attempt #1 (Rewrite Triggered)**: The reviewer notes that the initial draft violated policy (exceeded SLA credit limits and lacked an incident ID).
     - **Feedback Dispatched**: Clear notes are passed to the writer.
     - **Attempt #2 (Rewrite Approved)**: The writer generates a compliant revision referencing ticket `INC-8891` and policy `RB-SLA-001`. Reviewer scores improve to 9/10 across all criteria and approve the draft.

6. **Step 3: Hash-Locked Approval & Tamper Detection**:
   - In the right column, view the proposed customer reply in the Human Approval Queue.
   - Note the monospaced **Cryptographic Payload SHA-256 Digest** computed over canonical JSON.
   - Click **Approve (Lock Hash)**. The badge updates to **APPROVED**, locking the cryptographic digest.
   - Click **Simulate Tamper**. This directly mutates the draft body in memory post-approval.
   - Now click **Execute (Idempotent)**.
   - Notice the security banner:
     > 🛑 **EXECUTION BLOCKED:** Execution blocked: payload has been tampered with post-approval. Approved hash does not match current hash!
   - Scroll down to the **Live Cryptographic Audit Trail** to verify that a security event with `event_type: blocked` has been permanently recorded.

7. **Test Idempotent Execution**:
   - Run a new triage, click **Approve**, and click **Execute (Idempotent)** without tampering.
   - The action executes successfully.
   - Click **Execute (Idempotent)** a second time. The executor detects `idempotency_key=action_id` and immediately returns the cached result without re-dispatching.

8. **Test the Raw MCP JSON-RPC Inspector**:
   - Under Section 4, click **Bool/Int Schema Error** and click **Send JSON-RPC**.
   - Observe the MCP server's response returning `isError: true` with:
     `Schema validation failed: Field 'query': expected string, got bool`.
   - Click **-32602 Unknown Tool** to observe standard JSON-RPC 2.0 `-32602` error handling.

---

## License

This project is licensed under the terms of the [MIT License](LICENSE).
