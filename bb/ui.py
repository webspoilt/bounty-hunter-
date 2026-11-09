"""Built-in Web Dashboard & Researcher Workspace server for bountybot.

Zero external dependencies: uses Python standard library `http.server`.
Provides:
  - Real-time metrics overview (findings, accepted, duplicates, bounty stats)
  - Program & Scope viewer
  - Live Triage Approval Queue with one-click Approve / Reject actions
  - Assets, Endpoints, and Routes inspector
  - Interactive Finding Detail modal with full HTTP request/response evidence
  - Kill Switch trigger and status indicator
  - P7 Researcher Workspace:
      * Discovered endpoints and applications inspection with filtering
      * HTTP exchanges inspection with status and method filtering
      * Clear classification tiers (Observation, Hypothesis, Candidate, Inconclusive, Verified Finding)
      * Dual-role account context comparison
      * One-click manual review marking and report draft generation
      * Export to Burp Suite XML
"""
from __future__ import annotations

import json
import mimetypes
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from bb import __version__, feedback, killswitch, learn, metrics
from bb.burp_api import BurpApiClient
from bb.burp_export import export_exchanges_to_burp_xml, export_finding_to_burp
from bb.gate import ApprovalGate
from bb.models import sev_rank
from bb.store import Store

DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>BountyBot Live Dashboard & Researcher Workspace</title>
  <style>
    :root {
      --bg: #0d1117;
      --card: #161b22;
      --border: #30363d;
      --text: #c9d1d9;
      --heading: #f0f6fc;
      --accent: #58a6ff;
      --green: #2ea043;
      --red: #f85149;
      --orange: #d29922;
      --purple: #bc8cff;
      --cyan: #39c5bb;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, monospace; }
    body { background: var(--bg); color: var(--text); padding: 24px; }
    header { display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid var(--border); padding-bottom: 16px; margin-bottom: 24px; }
    h1 { color: var(--heading); font-size: 22px; display: flex; align-items: center; gap: 10px; }
    .badge { font-size: 11px; padding: 3px 8px; border-radius: 12px; background: #21262d; border: 1px solid var(--border); }
    .badge-verified { background: rgba(46, 160, 67, 0.2); color: #3fb950; border-color: #238636; }
    .badge-candidate { background: rgba(210, 153, 34, 0.2); color: #d29922; border-color: #9e6a03; }
    .badge-inconclusive { background: rgba(139, 148, 158, 0.2); color: #8b949e; border-color: #484f58; }
    .status-pill { padding: 4px 10px; border-radius: 14px; font-size: 12px; font-weight: bold; }
    .status-ok { background: rgba(46, 160, 67, 0.2); color: #3fb950; border: 1px solid #238636; }
    .status-stopped { background: rgba(248, 81, 73, 0.2); color: #f85149; border: 1px solid #da3633; }
    .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 16px; margin-bottom: 24px; }
    .card { background: var(--card); border: 1px solid var(--border); border-radius: 8px; padding: 16px; margin-bottom: 16px; }
    .card-title { font-size: 12px; text-transform: uppercase; color: #8b949e; letter-spacing: 0.5px; margin-bottom: 8px; }
    .card-value { font-size: 26px; font-weight: bold; color: var(--heading); }
    .card-sub { font-size: 12px; color: #8b949e; margin-top: 4px; }
    .tabs { display: flex; gap: 8px; border-bottom: 1px solid var(--border); margin-bottom: 16px; }
    .tab { padding: 8px 16px; cursor: pointer; color: #8b949e; border-bottom: 2px solid transparent; font-size: 14px; }
    .tab.active { color: var(--accent); border-bottom-color: var(--accent); font-weight: bold; }
    table { width: 100%; border-collapse: collapse; margin-top: 8px; font-size: 13px; }
    th { text-align: left; padding: 10px; background: #21262d; color: #8b949e; font-weight: 600; border-bottom: 1px solid var(--border); }
    td { padding: 10px; border-bottom: 1px solid var(--border); }
    tr:hover { background: rgba(255, 255, 255, 0.02); }
    .sev-critical { color: #ff7b72; font-weight: bold; }
    .sev-high { color: #ffa657; font-weight: bold; }
    .sev-medium { color: #d29922; }
    .sev-low { color: #7ee787; }
    .btn { padding: 5px 10px; border-radius: 6px; font-size: 12px; border: 1px solid transparent; cursor: pointer; font-weight: 500; }
    .btn-approve { background: #238636; color: #fff; }
    .btn-approve:hover { background: #2ea043; }
    .btn-reject { background: #21262d; color: #c9d1d9; border-color: var(--border); }
    .btn-reject:hover { background: #30363d; }
    .btn-danger { background: #da3633; color: #fff; }
    .btn-danger:hover { background: #f85149; }
    .btn-burp { background: #f0883e; color: #fff; }
    .btn-burp:hover { background: #d26a1b; }
    .raw-evidence { background: #090d13; padding: 12px; border-radius: 6px; font-family: monospace; font-size: 12px; overflow-x: auto; max-height: 250px; white-space: pre-wrap; margin-top: 6px; }
    .actions { display: flex; gap: 6px; }
    .filter-bar { display: flex; gap: 10px; align-items: center; margin-bottom: 12px; }
    .input-filter { background: #090d13; border: 1px solid var(--border); color: var(--text); padding: 6px 10px; border-radius: 6px; font-size: 13px; }
    .dual-box { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; margin-top: 10px; }
    .role-box { background: #090d13; border: 1px solid var(--border); padding: 12px; border-radius: 6px; font-size: 12px; }
  </style>
</head>
<body>
  <header>
    <div>
      <h1>BountyBot Dashboard & Workspace <span class="badge">v__VERSION__</span></h1>
      <p style="color: #8b949e; font-size: 13px; margin-top: 4px;">Researcher workspace with Burp Suite interoperability & verified triage</p>
    </div>
    <div style="display: flex; gap: 12px; align-items: center;">
      <span id="burp-status" class="badge">Burp Proxy: Checking...</span>
      <span id="kill-status" class="status-pill status-ok">OPERATIONAL</span>
      <button id="kill-btn" class="btn btn-danger" onclick="toggleKillSwitch()">ARM KILL SWITCH</button>
    </div>
  </header>

  <div class="grid">
    <div class="card">
      <div class="card-title">Pending Queue</div>
      <div class="card-value" id="val-pending">0</div>
      <div class="card-sub">Awaiting human review</div>
    </div>
    <div class="card">
      <div class="card-title">Confirmed Findings</div>
      <div class="card-value" id="val-confirmed">0</div>
      <div class="card-sub">Dual-role verified</div>
    </div>
    <div class="card">
      <div class="card-title">Accepted Outcomes</div>
      <div class="card-value" id="val-accepted">0</div>
      <div class="card-sub">Recorded program approvals</div>
    </div>
    <div class="card">
      <div class="card-title">Total Bounty ($)</div>
      <div class="card-value" id="val-bounty">$0.00</div>
      <div class="card-sub">Rewarded earnings</div>
    </div>
  </div>

  <div class="tabs">
    <div class="tab active" onclick="showTab('workspace')">Researcher Workspace</div>
    <div class="tab" onclick="showTab('exchanges')">HTTP Traffic (Exchanges)</div>
    <div class="tab" onclick="showTab('queue')">Approval Queue</div>
    <div class="tab" onclick="showTab('findings')">All Findings</div>
    <div class="tab" onclick="showTab('routes')">Routes & Inventory</div>
    <div class="tab" onclick="showTab('learning')">Learning Priors</div>
  </div>

  <!-- Tab 1: Researcher Workspace -->
  <div id="tab-workspace" class="tab-pane">
    <div class="card">
      <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px;">
        <h3 style="font-size: 16px; color: var(--heading);">Candidate Vulnerabilities & Verification Inspector</h3>
        <div class="actions">
          <button class="btn btn-burp" onclick="exportBurpXmlAll()">Export Candidates to Burp XML</button>
          <button class="btn btn-reject" onclick="loadWorkspace()">Refresh</button>
        </div>
      </div>
      <p style="color: #8b949e; font-size: 13px; margin-bottom: 14px;">
        Strict evidence separation: Candidates remain unconfirmed until independently verified.
      </p>
      <div id="workspace-container">Loading workspace...</div>
    </div>
  </div>

  <!-- Tab 2: HTTP Traffic Exchanges -->
  <div id="tab-exchanges" class="tab-pane" style="display: none;">
    <div class="card">
      <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px;">
        <h3 style="font-size: 16px; color: var(--heading);">Captured HTTP Traffic (Scoped Exchanges)</h3>
        <div class="filter-bar">
          <input type="text" id="filter-exchange-host" class="input-filter" placeholder="Filter host..." oninput="loadExchanges()">
          <input type="text" id="filter-exchange-method" class="input-filter" placeholder="Method (GET/POST)..." oninput="loadExchanges()" style="width: 140px;">
        </div>
      </div>
      <div id="exchanges-container">Loading exchanges...</div>
    </div>
  </div>

  <!-- Tab 3: Queue -->
  <div id="tab-queue" class="tab-pane" style="display: none;">
    <div class="card">
      <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px;">
        <h3 style="font-size: 16px; color: var(--heading);">Pending Findings Queue</h3>
        <button class="btn btn-reject" onclick="loadAll()">Refresh</button>
      </div>
      <div id="queue-container">Loading queue...</div>
    </div>
  </div>

  <!-- Tab 4: Findings -->
  <div id="tab-findings" class="tab-pane" style="display: none;">
    <div class="card">
      <h3 style="font-size: 16px; color: var(--heading); margin-bottom: 12px;">All Recorded Findings</h3>
      <div id="findings-container">Loading findings...</div>
    </div>
  </div>

  <!-- Tab 5: Routes -->
  <div id="tab-routes" class="tab-pane" style="display: none;">
    <div class="card">
      <h3 style="font-size: 16px; color: var(--heading); margin-bottom: 12px;">Normalized Route Templates</h3>
      <div id="routes-container">Loading routes...</div>
    </div>
  </div>

  <!-- Tab 6: Learning -->
  <div id="tab-learning" class="tab-pane" style="display: none;">
    <div class="card">
      <h3 style="font-size: 16px; color: var(--heading); margin-bottom: 12px;">Feedback & Class Priors</h3>
      <div id="learning-container">Loading feedback report...</div>
    </div>
  </div>

  <script>
    let isStopped = false;

    async function loadAll() {
      try {
        const statsRes = await fetch('/api/stats');
        const stats = await statsRes.json();
        document.getElementById('val-pending').innerText = stats.pending_count || 0;
        document.getElementById('val-confirmed').innerText = stats.confirmed_count || 0;
        document.getElementById('val-accepted').innerText = stats.accepted_count || 0;
        document.getElementById('val-bounty').innerText = '$' + (stats.total_bounty || 0).toFixed(2);
        
        isStopped = stats.kill_active;
        const ks = document.getElementById('kill-status');
        const kb = document.getElementById('kill-btn');
        if (isStopped) {
          ks.innerText = 'KILL SWITCH ARMED';
          ks.className = 'status-pill status-stopped';
          kb.innerText = 'CLEAR / RESUME';
          kb.className = 'btn btn-approve';
        } else {
          ks.innerText = 'OPERATIONAL';
          ks.className = 'status-pill status-ok';
          kb.innerText = 'ARM KILL SWITCH';
          kb.className = 'btn btn-danger';
        }

        const burpStatus = document.getElementById('burp-status');
        if (stats.burp_api && stats.burp_api.available) {
          burpStatus.innerText = 'Burp Pro/Ent API Active';
          burpStatus.className = 'badge badge-verified';
        } else {
          burpStatus.innerText = 'Burp: Standalone Proxy';
          burpStatus.className = 'badge';
        }

        loadWorkspace();
        loadExchanges();
        loadQueue();
        loadFindings();
        loadRoutes();
        loadLearning();
      } catch (err) {
        console.error(err);
      }
    }

    async function loadWorkspace() {
      const res = await fetch('/api/workspace/candidates');
      const items = await res.json();
      const c = document.getElementById('workspace-container');
      if (!items || items.length === 0) {
        c.innerHTML = '<p style="color: #8b949e; padding: 12px;">No candidate vulnerabilities or investigations recorded yet.</p>';
        return;
      }
      let html = '';
      for (const item of items) {
        const sevClass = 'sev-' + (item.severity || 'low').toLowerCase();
        let statusBadge = 'badge-candidate';
        if (item.status === 'confirmed') statusBadge = 'badge-verified';
        else if (item.status === 'inconclusive') statusBadge = 'badge-inconclusive';

        html += `<div class="card" style="border-left: 4px solid var(--accent); margin-bottom: 16px;">
          <div style="display: flex; justify-content: space-between; align-items: center;">
            <div>
              <span class="${sevClass}" style="font-size: 14px;">[${(item.severity || 'UNKNOWN').toUpperCase()}]</span>
              <b style="color: var(--heading); margin-left: 6px;">${escapeHtml(item.title)}</b>
              <span class="badge ${statusBadge}" style="margin-left: 8px;">Tier: ${item.tier || item.status}</span>
            </div>
            <div class="actions">
              <button class="btn btn-burp" onclick="exportFindingBurp('${item.id}')">Export to Burp</button>
              <button class="btn btn-approve" onclick="markManualReview('${item.id}')">Mark Reviewed</button>
            </div>
          </div>
          <div style="margin-top: 8px; font-size: 13px; color: #8b949e;">
            Target URL: <code>${escapeHtml(item.url || '-')}</code> | Bug Class: <b>${escapeHtml(item.bug_class || '-')}</b>
          </div>
          ${item.dual_role ? `
            <div class="dual-box">
              <div class="role-box">
                <b style="color: var(--accent);">Account A (Owner / Baseline)</b>
                <div style="margin-top: 4px;">Status: ${item.dual_role.a_status || 200} | Identity: ${escapeHtml(item.dual_role.identity_a || 'Role A')}</div>
                <div class="raw-evidence">${escapeHtml(item.dual_role.a_excerpt || '(no excerpt)')}</div>
              </div>
              <div class="role-box">
                <b style="color: var(--orange);">Account B (Cross-Role Attacker)</b>
                <div style="margin-top: 4px;">Status: ${item.dual_role.b_status || 403} | Identity: ${escapeHtml(item.dual_role.identity_b || 'Role B')}</div>
                <div class="raw-evidence">${escapeHtml(item.dual_role.b_excerpt || '(no excerpt)')}</div>
              </div>
            </div>
          ` : ''}
          ${item.verification_note ? `<div style="margin-top: 8px; font-size: 12px; color: var(--cyan);"><b>Verification Status:</b> ${escapeHtml(item.verification_note)}</div>` : ''}
        </div>`;
      }
      c.innerHTML = html;
    }

    async function loadExchanges() {
      const host = document.getElementById('filter-exchange-host').value;
      const method = document.getElementById('filter-exchange-method').value;
      const res = await fetch(`/api/workspace/exchanges?host=${encodeURIComponent(host)}&method=${encodeURIComponent(method)}`);
      const items = await res.json();
      const c = document.getElementById('exchanges-container');
      if (!items || items.length === 0) {
        c.innerHTML = '<p style="color: #8b949e; padding: 12px;">No matching HTTP exchanges found.</p>';
        return;
      }
      let html = '<table><thead><tr><th>ID</th><th>Method</th><th>Status</th><th>URL</th><th>Duration</th><th>Action</th></tr></thead><tbody>';
      for (const ex of items) {
        html += `<tr>
          <td><code>${ex.id}</code></td>
          <td><span class="badge">${ex.method}</span></td>
          <td><code>${ex.status}</code></td>
          <td><code>${escapeHtml(ex.url)}</code></td>
          <td>${ex.duration_ms || 0} ms</td>
          <td><button class="btn btn-burp" onclick="exportSingleExchangeBurp(${ex.id})">Export XML</button></td>
        </tr>`;
      }
      html += '</tbody></table>';
      c.innerHTML = html;
    }

    async function exportFindingBurp(id) {
      window.open(`/api/workspace/export_burp?finding_id=${encodeURIComponent(id)}`, '_blank');
    }

    async function exportSingleExchangeBurp(id) {
      window.open(`/api/workspace/export_burp?exchange_id=${encodeURIComponent(id)}`, '_blank');
    }

    async function exportBurpXmlAll() {
      window.open('/api/workspace/export_burp', '_blank');
    }

    async function markManualReview(id) {
      await fetch('/api/workspace/review', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ id, review_status: 'reviewed' })
      });
      loadWorkspace();
    }

    async function loadQueue() {
      const res = await fetch('/api/queue');
      const items = await res.json();
      const c = document.getElementById('queue-container');
      if (!items || items.length === 0) {
        c.innerHTML = '<p style="color: #8b949e; padding: 12px;">No items pending approval.</p>';
        return;
      }
      let html = '<table><thead><tr><th>ID</th><th>Severity</th><th>Title</th><th>Bug Class</th><th>Target</th><th>Actions</th></tr></thead><tbody>';
      for (const it of items) {
        const f = it.finding || {};
        const sevClass = 'sev-' + (f.severity || 'low').toLowerCase();
        html += `<tr>
          <td><code>${it.id.substring(0, 8)}</code></td>
          <td class="${sevClass}">${(f.severity || 'UNKNOWN').toUpperCase()}</td>
          <td><b>${escapeHtml(f.title || it.finding_id)}</b></td>
          <td>${escapeHtml(f.bug_class || '-')}</td>
          <td><code>${escapeHtml(f.url || '-')}</code></td>
          <td class="actions">
            <button class="btn btn-approve" onclick="decide('${it.id}', true)">Approve</button>
            <button class="btn btn-reject" onclick="decide('${it.id}', false)">Reject</button>
          </td>
        </tr>`;
      }
      html += '</tbody></table>';
      c.innerHTML = html;
    }

    async function loadFindings() {
      const res = await fetch('/api/findings');
      const items = await res.json();
      const c = document.getElementById('findings-container');
      if (!items || items.length === 0) {
        c.innerHTML = '<p style="color: #8b949e; padding: 12px;">No findings recorded yet.</p>';
        return;
      }
      let html = '<table><thead><tr><th>ID</th><th>Severity</th><th>Status</th><th>Title</th><th>URL</th></tr></thead><tbody>';
      for (const f of items) {
        const sevClass = 'sev-' + (f.severity || 'low').toLowerCase();
        html += `<tr>
          <td><code>${f.id.substring(0, 8)}</code></td>
          <td class="${sevClass}">${(f.severity || '').toUpperCase()}</td>
          <td><span class="badge">${f.status || 'candidate'}</span></td>
          <td><b>${escapeHtml(f.title || '')}</b></td>
          <td><code>${escapeHtml(f.url || '')}</code></td>
        </tr>`;
      }
      html += '</tbody></table>';
      c.innerHTML = html;
    }

    async function loadRoutes() {
      const res = await fetch('/api/routes');
      const routes = await res.json();
      const c = document.getElementById('routes-container');
      if (!routes || routes.length === 0) {
        c.innerHTML = '<p style="color: #8b949e; padding: 12px;">No normalized routes in inventory.</p>';
        return;
      }
      let html = '<table><thead><tr><th>Host</th><th>Method</th><th>Route Template</th><th>Hits</th><th>Last Seen</th></tr></thead><tbody>';
      for (const r of routes) {
        html += `<tr>
          <td><code>${escapeHtml(r.host || '')}</code></td>
          <td><span class="badge">${r.method || 'GET'}</span></td>
          <td><code>${escapeHtml(r.template || '')}</code></td>
          <td>${r.hits || 1}</td>
          <td>${r.last_seen || ''}</td>
        </tr>`;
      }
      html += '</tbody></table>';
      c.innerHTML = html;
    }

    async function loadLearning() {
      const res = await fetch('/api/learning');
      const data = await res.json();
      const c = document.getElementById('learning-container');
      if (!data || !data.classes || data.classes.length === 0) {
        c.innerHTML = '<p style="color: #8b949e; padding: 12px;">No outcome feedback recorded yet.</p>';
        return;
      }
      let html = '<table><thead><tr><th>Bug Class</th><th>Decided</th><th>Accepted</th><th>Duplicate</th><th>Weight</th></tr></thead><tbody>';
      for (const row of data.classes) {
        html += `<tr>
          <td><b>${escapeHtml(row.bug_class)}</b></td>
          <td>${row.decided}</td>
          <td>${row.accepted}</td>
          <td>${row.duplicates}</td>
          <td><code>${(row.weight || 0.5).toFixed(2)}</code></td>
        </tr>`;
      }
      html += '</tbody></table>';
      c.innerHTML = html;
    }

    async function decide(id, approved) {
      await fetch('/api/queue/decide', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ id, approved })
      });
      loadAll();
    }

    async function toggleKillSwitch() {
      if (isStopped) {
        await fetch('/api/killswitch/resume', { method: 'POST' });
      } else {
        await fetch('/api/killswitch/stop', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ reason: 'Operator manual UI stop' })
        });
      }
      loadAll();
    }

    function showTab(name) {
      document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
      document.querySelectorAll('.tab-pane').forEach(p => p.style.display = 'none');
      document.getElementById('tab-' + name).style.display = 'block';
      event.target.classList.add('active');
    }

    function escapeHtml(s) {
      return (s || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
    }

    loadAll();
    setInterval(loadAll, 10000);
  </script>
</body>
</html>
""".replace("__VERSION__", __version__)


class DashboardHandler(BaseHTTPRequestHandler):
    store = Store()
    gate = ApprovalGate(store)
    burp_client = BurpApiClient()

    def log_message(self, format, *args):
        pass

    def _json(self, data, status=HTTPStatus.OK):
        body = json.dumps(data, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _html(self, html_str: str):
        body = html_str.encode("utf-8")
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _xml(self, xml_str: str, filename: str = "bountybot_burp_export.xml"):
        body = xml_str.encode("utf-8")
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "application/xml; charset=utf-8")
        self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        url = urlsplit(self.path)
        qs = parse_qs(url.query)

        if url.path in ("/", "/index.html", "/dashboard"):
            return self._html(DASHBOARD_HTML)

        if url.path == "/api/stats":
            m = metrics.collect(self.store)
            totals = m.get("totals", {})
            findings = self.store.findings()
            pending = self.gate.pending()
            burp_probe = self.burp_client.probe()
            return self._json({
                "pending_count": len(pending),
                "confirmed_count": sum(1 for f in findings if f.status == "confirmed"),
                "total_findings": len(findings),
                "accepted_count": totals.get("accepted", 0),
                "total_bounty": totals.get("bounty_total", 0.0),
                "kill_active": killswitch.active(),
                "kill_reason": killswitch.reason(),
                "burp_api": burp_probe,
            })

        # P7 Workspace APIs
        if url.path == "/api/workspace/candidates":
            findings = self.store.findings()
            out = []
            for f in findings:
                tier = "Observation"
                if f.status == "confirmed":
                    tier = "Verified Finding"
                elif f.status == "candidate":
                    tier = "Candidate"
                elif f.status == "inconclusive":
                    tier = "Inconclusive Result"

                dual_role = None
                if len(f.evidence) >= 2 and f.evidence[-2].exchange and f.evidence[-1].exchange:
                    owner_ex = f.evidence[-2].exchange
                    attacker_ex = f.evidence[-1].exchange
                    dual_role = {
                        "identity_a": f.meta.get("identity_a", "Role A"),
                        "a_status": owner_ex.status,
                        "a_excerpt": (owner_ex.response_body or "")[:300],
                        "identity_b": f.meta.get("identity_b", "Role B"),
                        "b_status": attacker_ex.status,
                        "b_excerpt": (attacker_ex.response_body or "")[:300],
                    }

                out.append({
                    "id": f.id,
                    "title": f.title,
                    "bug_class": f.bug_class,
                    "severity": f.severity,
                    "status": f.status,
                    "tier": tier,
                    "url": f.url,
                    "dual_role": dual_role,
                    "verification_note": f.meta.get("verify", {}).get("verdict") if f.meta.get("verify") else f.status,
                })
            return self._json(out)

        if url.path == "/api/workspace/exchanges":
            host_filter = qs.get("host", [""])[0].strip().lower()
            method_filter = qs.get("method", [""])[0].strip().upper()

            sql = "SELECT id, tool, method, url, status, duration_ms, created_at FROM exchanges WHERE 1=1"
            params = []
            if host_filter:
                sql += " AND url LIKE ?"
                params.append(f"%{host_filter}%")
            if method_filter:
                sql += " AND method = ?"
                params.append(method_filter)
            sql += " ORDER BY id DESC LIMIT 100"

            rows = self.store.conn.execute(sql, params).fetchall()
            return self._json([dict(r) for r in rows])

        if url.path == "/api/workspace/export_burp":
            finding_id = qs.get("finding_id", [None])[0]
            exchange_id = qs.get("exchange_id", [None])[0]

            if finding_id:
                f = self.store.get_finding(finding_id)
                if not f:
                    return self._json({"error": "finding not found"}, status=HTTPStatus.NOT_FOUND)
                xml_out = export_finding_to_burp(f)
                return self._xml(xml_out, filename=f"finding_{finding_id}_burp.xml")

            elif exchange_id:
                row = self.store.conn.execute("SELECT * FROM exchanges WHERE id = ?", (exchange_id,)).fetchone()
                if not row:
                    return self._json({"error": "exchange not found"}, status=HTTPStatus.NOT_FOUND)
                ex = Exchange(
                    method=row["method"],
                    url=row["url"],
                    status=row["status"],
                    request_headers=json.loads(row["req_headers"] or "{}"),
                    request_body=row["req_body"] or "",
                    response_headers=json.loads(row["resp_headers"] or "{}"),
                    response_body=row["resp_body"] or "",
                    duration_ms=row["duration_ms"] or 0,
                    at=row["created_at"],
                )
                xml_out = export_exchanges_to_burp_xml([ex])
                return self._xml(xml_out, filename=f"exchange_{exchange_id}_burp.xml")

            else:
                findings = self.store.findings()
                all_exchanges = []
                for f in findings:
                    for ev in f.evidence:
                        if ev.exchange:
                            all_exchanges.append(ev.exchange)
                xml_out = export_exchanges_to_burp_xml(all_exchanges)
                return self._xml(xml_out, filename="bountybot_candidates_burp.xml")

        if url.path == "/api/queue":
            pending = self.gate.pending()
            for item in pending:
                finding = self.store.get_finding(item["finding_id"])
                if finding:
                    item["finding"] = {
                        "id": finding.id,
                        "title": finding.title,
                        "bug_class": finding.bug_class,
                        "severity": finding.severity,
                        "url": finding.url,
                        "confidence": finding.confidence,
                    }
            return self._json(pending)

        if url.path == "/api/findings":
            findings = self.store.findings()
            return self._json([{
                "id": f.id,
                "title": f.title,
                "bug_class": f.bug_class,
                "severity": f.severity,
                "status": f.status,
                "url": f.url,
                "confidence": f.confidence,
            } for f in findings])

        if url.path == "/api/routes":
            routes = self.store.routes()
            return self._json(routes)

        if url.path == "/api/learning":
            report = learn.learning_report(self.store)
            return self._json(report)

        if url.path == "/api/status":
            from bb import tev1, llm
            from bb.coder.adapter import QwenCoderAdapter
            from bb.decision.evaluator import DecisionEvaluator

            tev1_client = tev1.Tev1Client()
            tev1_report = None
            try:
                tev1_report = tev1_client.probe()
            except Exception:
                tev1_report = {"endpoint_ok": False, "detail": "unavailable"}
            finally:
                tev1_client.close()

            qwen_adapter = QwenCoderAdapter()
            qwen_ok = False
            qwen_models = []
            try:
                qwen_ok = qwen_adapter.is_available()
                if qwen_ok:
                    qwen_models = qwen_adapter.get_installed_models()
            except Exception:
                pass

            latest_run = self.store.conn.execute("SELECT * FROM runs ORDER BY started_at DESC LIMIT 1").fetchone()
            run_dict = dict(latest_run) if latest_run else None
            task_counts = self.store.task_counts(run_dict["id"]) if run_dict else {}
            findings = self.store.findings(run_id=run_dict["id"]) if run_dict else []
            candidate_count = sum(1 for f in findings if f.status == "candidate")

            evaluator = DecisionEvaluator()
            eval_report = evaluator.generate_report(run_id=run_dict["id"] if run_dict else None)

            return self._json({
                "controller": {
                    "run_id": run_dict["id"] if run_dict else "none",
                    "program": run_dict["program"] if run_dict else "none",
                    "target": run_dict["target"] if run_dict else "none",
                    "started_at": run_dict["started_at"] if run_dict else None,
                },
                "models": {
                    "tev1": {
                        "model": tev1_report.get("model", "tev1:0.8b"),
                        "available": bool(tev1_report.get("endpoint_ok")),
                        "detail": tev1_report.get("detail", "unavailable"),
                        "ollama_version": tev1_report.get("ollama_version") or "unavailable",
                    },
                    "qwen": {
                        "available": qwen_ok,
                        "installed_models": qwen_models,
                        "detail": "ready" if qwen_ok else "unavailable",
                    },
                },
                "tasks": task_counts,
                "verification_backlog": candidate_count,
                "human_queue_pending": len(self.gate.pending()),
                "decision_evaluation": eval_report,
                "killswitch": {
                    "active": killswitch.active(),
                    "reason": killswitch.reason(),
                },
            })

        self.send_error(HTTPStatus.NOT_FOUND, "Not Found")

    def do_POST(self):
        url = urlsplit(self.path)
        content_len = int(self.headers.get("Content-Length", 0))
        raw_body = self.rfile.read(content_len).decode("utf-8") if content_len > 0 else "{}"
        try:
            payload = json.loads(raw_body)
        except Exception:
            payload = {}

        if url.path == "/api/queue/decide":
            queue_id = payload.get("id")
            approved = bool(payload.get("approved"))
            if not queue_id:
                return self._json({"error": "missing id"}, status=HTTPStatus.BAD_REQUEST)
            try:
                item = self.gate.decide(queue_id, approved)
                return self._json({"status": "success", "item": item})
            except Exception as e:
                return self._json({"error": str(e)}, status=HTTPStatus.INTERNAL_SERVER_ERROR)

        if url.path == "/api/workspace/review":
            finding_id = payload.get("id")
            if not finding_id:
                return self._json({"error": "missing id"}, status=HTTPStatus.BAD_REQUEST)
            finding = self.store.get_finding(finding_id)
            if not finding:
                return self._json({"error": "finding not found"}, status=HTTPStatus.NOT_FOUND)
            finding.meta["manual_review"] = "approved"
            finding.meta["reviewed_by"] = "researcher_workspace"
            self.store.update_meta(finding_id, **finding.meta)
            return self._json({"status": "success", "finding_id": finding_id})

        if url.path == "/api/killswitch/stop":
            reason = payload.get("reason", "manual stop from dashboard UI")
            killswitch.activate(reason)
            return self._json({"status": "stopped", "reason": reason})

        if url.path == "/api/killswitch/resume":
            killswitch.clear()
            return self._json({"status": "resumed"})

        self.send_error(HTTPStatus.NOT_FOUND, "Not Found")


def run_dashboard(host: str = "127.0.0.1", port: int = 8888, open_browser: bool = False):
    server = ThreadingHTTPServer((host, port), DashboardHandler)
    url = f"http://{host}:{port}/"
    print(f"[*] BountyBot Dashboard running at {url} (Ctrl+C to stop)")
    if open_browser:
        import webbrowser
        webbrowser.open(url)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Stopping dashboard...")
    finally:
        server.server_close()
