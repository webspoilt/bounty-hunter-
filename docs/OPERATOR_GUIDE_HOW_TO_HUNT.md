# Bounty Hunter 2.6.0 — Complete Operator's Handbook
## Installation, Program Selection, Scope Gating, and Bug Hunting

This handbook is the official step-by-step operational guide for **Bounty Hunter**, a defensive, scope-gated vulnerability research and measurement platform.

---

## 1. Installation & Environment Setup

### Prerequisites
- **OS:** Windows 10/11, macOS, or Linux (Ubuntu 22.04+)
- **Python:** Python 3.11 or 3.12
- **Memory:** Minimum 8 GB RAM (16 GB recommended)
- **Disk Space:** ~5 GB free disk space

### Step 1.1: Clone the Repository
```bash
git clone https://github.com/webspoilt/bounty-hunter-.git
cd bounty-hunter-
```

### Step 1.2: Run the Automated Installer

#### On Windows (Fastest):
Double-click `install_tools.bat` or run in terminal:
```cmd
install_tools.bat
```
*(Or in Windows PowerShell: `.\install_tools.ps1`)*

#### On Linux / macOS:
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
pip install -e .
python -m bb.cli engines install
```

### Step 1.3: Verify Installation
Verify that the `bb` command is registered and test suite passes:
```bash
bb --help
bb engines list
pytest
```
* **Expected Result:** All 517 tests pass (100% offline, zero network leakage).

---

## 2. Configuration & Credentials

Bounty Hunter operates offline by default, but connecting your HackerOne API token unlocks automatic program discovery, structured scope synchronization, and policy analysis.

### Step 2.1: Initialize Environment Config
Copy the provided example file:
```bash
# Windows PowerShell
Copy-Item .env.example .env

# Linux / macOS
cp .env.example .env
```

### Step 2.2: Add Your HackerOne API Key
Generate an API token at [hackerone.com/settings/api_token](https://hackerone.com/settings/api_token) and update `.env`:
```ini
H1_USERNAME=your_hackerone_username
H1_TOKEN=your_hackerone_api_token
```
*(Or interactively configure via CLI: `bb h1 configure`)*

---

## 3. How to Select High-Yield Programs

Bounty Hunter includes continuous intelligence and ranking algorithms to find low-saturation, high-opportunity programs.

### Step 3.1: Discover Active Programs
List programs sorted by opportunity and reward thresholds:
```bash
bb h1 discover --min-bounty 1000 --limit 25
```
Or rank programs using the built-in multi-factor engine (response speed, fresh scopes, bounty density):
```bash
bb program rank
```

### Step 3.2: Inspect Program Policy & Structured Scope
Download and parse the exact program policies, guidelines, and in-scope asset lists:
```bash
bb h1 fetch --program <program_handle>
```
*Example for PortSwigger:*
```bash
bb h1 fetch --program portswigger
```

### Step 3.3: Review the Safe Harbor Brief
Generate an authorization card containing policy analysis, scope conflicts, and exclusions:
```bash
bb h1 brief --program <program_handle>
```
* **Notice:** The brief identifies policy text ambiguity, unwhitelisted subdomains, and explicit path exclusions (e.g., `/web-security`).

### Step 3.4: Human Authorization Gate (Safe Harbor Preflight)
No requests can be made until the human researcher explicitly approves a specific target:
```bash
bb h1 approve --program <program_handle> --target "https://<approved-host>"
```
* **Guardrail Guarantee:** If you approve `https://portswigger.net`, the gate automatically enforces:
  - Disputed subdomains (`ai.portswigger.net`, `collections.portswigger.net`, etc.) are blocked.
  - Excluded paths (`/web-security`) are blocked.
  - Apex-level requests and declared wildcards are strictly boundary-checked.

---

## 4. How to Hunt Bugs (Step-by-Step Pipeline)

Once a program target is approved, Bounty Hunter executes bounded, polite security measurements.

### Step 4.1: Passive & Clean Reconnaissance
Discover in-scope endpoints, sitemaps, robots.txt, and client-side JavaScript routes without aggressive fuzzing:
```bash
bb recon --program <program_handle> --url "https://<approved-host>"
```
* **Output:** Endpoints and parameters stored in `data/bountybot.db` with full scope audit logs.

### Step 4.2: Two-Role Authorization & IDOR/BOLA Hunting
The core strength of Bounty Hunter is differential authorization testing (Task P4):
1. Create a credential file `data/<program_handle>.accounts.json` with two test accounts you control (Role A and Role B).
2. Execute the dual-token differential replay engine:
```bash
bb authz run --program <program_handle> --target "https://<approved-host>" --accounts data/<program_handle>.accounts.json
```
* **Mechanism:** 
  - Requests object as Account A.
  - Replays request with Account B’s session.
  - Only alerts when Account A's private identifier/data appears in Account B's response (zero false positives).

### Step 4.3: Autonomous Specialist Scans
Run targeted engines with strict request budgets (default 3.0 req/sec rate limit):
```bash
# Run SQL injection checks via embedded SQLMap adapter:
bb engines sqlmap --target "https://<approved-host>/api/items?id=1" --program <program_handle>

# Run non-destructive XSS checks via DalFox adapter:
bb engines dalfox --target "https://<approved-host>/search?q=test" --program <program_handle>

# Run template-driven CVE checks via Nuclei:
bb engines nuclei --target "https://<approved-host>" --program <program_handle>
```

### Step 4.4: Full Autonomous Loop
To run passive recon, deterministic checks, and verification in a single controlled pass:
```bash
bb auto --program <program_handle> --target "https://<approved-host>" --budget 20
```

---

## 5. Reviewing, Verifying & Exporting Findings

**Rule of Bounty Hunter: Nothing is ever submitted automatically.** Every finding must be inspected and approved by the human operator.

### Step 5.1: View Findings & Review Queue
```bash
# List all discovered findings
bb findings --program <program_handle>

# Inspect human review queue
bb queue
```

### Step 5.2: Independent Verification & LLM Triage
Run deterministic replay to prove the finding is still live and reproducible:
```bash
bb verify --finding <finding_uuid>
```
Audit the finding against the 7-question triage gate:
```bash
bb report --finding <finding_uuid>
```

### Step 5.3: Approve or Reject the Finding
```bash
# Approve finding for report export
bb decide <queue_id> --approve

# Or reject if deemed invalid or duplicate
bb decide <queue_id> --reject
```

### Step 5.4: Export HackerOne Submission Draft
Generate the final, formatted Markdown report with redacted HTTP exchanges and reproduction steps:
```bash
bb submit --finding <finding_uuid> --team <program_handle>
```
* **Action:** Prints the complete submission payload and curl commands to your terminal and saves a draft markdown file in `data/reports/`. You copy-paste this directly into the HackerOne submission form.

---

## 6. Emergency Kill Switch

If at any point you want to immediately halt all network activity across all processes:
```bash
bb stop
```
To resume after review:
```bash
bb resume
```
