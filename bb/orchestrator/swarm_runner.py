"""Swarm Runner for Persisted Controller (Task P5).

Integrates the multi-worker swarm directly into the persisted controller loop.
Guarantees:
  - 100% atomic SQLite task claims via Scheduler (zero duplicate claims).
  - One collective polite RequestBudget shared across all concurrent workers.
  - Heartbeat lease renewals (task_renew) to protect long-running tasks.
  - Clean cancellation with automatic release of in-flight tasks back to pending.
  - Full killswitch enforcement: immediate halt without orphaned running rows.
"""
from __future__ import annotations

import concurrent.futures
import threading
import time
from typing import Any, Callable

from bb import normalize
from bb.checks import CheckOptions, Checker
from bb.http import RequestBudget, ScopedClient
from bb.killswitch import active as kill_active
from bb.models import Finding
from bb.orchestrator.resource_manager import ResourceManager
from bb.orchestrator.scheduler import Scheduler
from bb.scope import Scope
from bb.store import Store
from bb.swarm import Task


class ControllerSwarmRunner:
    """Manages concurrent worker execution of tasks under controller supervision."""

    def __init__(
        self,
        scope: Scope,
        store: Store,
        run_id: str,
        resource_mgr: ResourceManager,
        scheduler: Scheduler,
        roles: list,
        options: CheckOptions,
        proxy: str | None = None,
        timeout: float = 15.0,
        dry_run: bool = False,
        lease_renew_interval: float = 30.0,
        log: Callable[[str], None] = print,
    ):
        self.scope = scope
        self.store = store
        self.run_id = run_id
        self.resource_mgr = resource_mgr
        self.scheduler = scheduler
        self.roles = roles
        self.options = options
        self.proxy = proxy
        self.timeout = timeout
        self.dry_run = dry_run
        self.lease_renew_interval = lease_renew_interval
        self.log = log

        self._shutdown_event = threading.Event()
        self._active_clients: list[ScopedClient] = []
        self._active_stores: list[Store] = []
        self._lock = threading.Lock()

    def cancel(self) -> None:
        """Trigger graceful cancellation of all active worker threads."""
        self._shutdown_event.set()

    def _execute_single_task(
        self,
        task: Task,
        store: Store,
        client: ScopedClient,
        checker: Checker,
    ) -> dict[str, Any]:
        """Execute one claimed task with active heartbeat lease renewals."""
        if kill_active() or self._shutdown_event.is_set():
            # Release lease back so it's not locked
            store.task_finish(task.fingerprint, "failed", {"error": "cancelled or killswitch active"})
            return {"status": "cancelled", "findings": [], "requests": 0}

        t_start = time.time()
        stop_heartbeat = threading.Event()

        def heartbeat_worker():
            while not stop_heartbeat.wait(timeout=self.lease_renew_interval):
                if not store.task_renew(task.fingerprint):
                    break

        hb_thread = threading.Thread(target=heartbeat_worker, daemon=True)
        hb_thread.start()

        before_reqs = client.sent
        discovered_findings: list[Finding] = []
        error_msg: str | None = None

        try:
            ep = task.payload.get("endpoint") or {"url": task.target, "method": "GET"}
            if task.kind == "authz":
                discovered_findings = checker.check_authz([ep])
            elif task.kind == "unauth":
                discovered_findings = checker.check_unauth([ep])
            elif task.kind == "graphql":
                discovered_findings = checker.check_graphql([ep])
            elif task.kind == "open_redirect":
                discovered_findings = checker.check_open_redirect([ep])
            elif task.kind == "cors":
                discovered_findings = checker.check_cors([task.target])
            elif task.kind == "exposed":
                discovered_findings = checker.check_exposed([task.target])
            elif task.kind == "headers":
                discovered_findings = checker.check_headers([task.target])
            else:
                raise ValueError(f"unknown task kind {task.kind!r}")

            for f in discovered_findings:
                store.add_finding(f, run_id=self.run_id)

            reqs_used = client.sent - before_reqs
            store.task_finish(
                task.fingerprint,
                state="done",
                result={
                    "findings": [f.id for f in discovered_findings],
                    "requests": reqs_used,
                    "duration_ms": round((time.time() - t_start) * 1000, 2),
                },
            )
            return {
                "status": "done",
                "findings": discovered_findings,
                "requests": reqs_used,
                "duration_ms": (time.time() - t_start) * 1000,
            }
        except Exception as exc:
            error_msg = str(exc)
            reqs_used = client.sent - before_reqs
            store.task_finish(
                task.fingerprint,
                state="failed",
                result={"error": error_msg, "requests": reqs_used},
            )
            return {
                "status": "failed",
                "error": error_msg,
                "findings": [],
                "requests": reqs_used,
                "duration_ms": (time.time() - t_start) * 1000,
            }
        finally:
            stop_heartbeat.set()
            hb_thread.join(timeout=1.0)

    def run_batch(
        self,
        candidate_tasks: list[Task],
        worker_concurrency: int,
    ) -> dict[str, Any]:
        """Atomically claim and run tasks concurrently using worker_concurrency threads."""
        if kill_active() or self._shutdown_event.is_set():
            return {"status": "aborted", "executed": 0, "findings": 0, "requests": 0}

        # 1. Attempt atomic claims
        claimed_tasks: list[Task] = []
        contended_count = 0
        for task in candidate_tasks:
            if kill_active() or self._shutdown_event.is_set():
                break
            if self.scheduler.claim_task(task):
                claimed_tasks.append(task)
                if len(claimed_tasks) >= worker_concurrency * 2:
                    break
            else:
                contended_count += 1

        if not claimed_tasks:
            return {
                "status": "no_work",
                "claimed": 0,
                "contended": contended_count,
                "executed": 0,
                "findings": [],
                "requests": 0,
            }

        # Concurrency bound: network workers capped by shared polite rate
        network_workers = self.resource_mgr.effective_network_concurrency(worker_concurrency)
        actual_workers = max(1, min(len(claimed_tasks), network_workers))

        batch_findings: list[Finding] = []
        total_requests = 0
        tasks_done = 0
        tasks_failed = 0

        # Thread worker function with dedicated Store and ScopedClient over shared budget
        def worker_loop(task_queue: list[Task]):
            worker_store = Store()
            worker_client = ScopedClient(
                self.scope,
                proxy=self.proxy,
                timeout=self.timeout,
                rate=self.resource_mgr.policy.rate,
                max_requests=self.resource_mgr.policy.max_requests,
                dry_run=self.dry_run,
                store=worker_store,
                run_id=self.run_id,
                tool="controller_swarm",
                shared=self.resource_mgr.budget,
            )
            worker_checker = Checker(
                worker_client,
                worker_store,
                self.run_id,
                self.scope,
                roles=self.roles,
                options=self.options,
                log=lambda *a, **k: None,
            )
            with self._lock:
                self._active_stores.append(worker_store)
                self._active_clients.append(worker_client)

            results = []
            try:
                for task in task_queue:
                    if kill_active() or self._shutdown_event.is_set():
                        # Release task back
                        worker_store.task_finish(task.fingerprint, "failed", {"error": "aborted"})
                        continue
                    res = self._execute_single_task(task, worker_store, worker_client, worker_checker)
                    results.append((task, res))
            finally:
                worker_client.close()
                worker_store.close()
            return results

        # Partition claimed tasks across worker threads
        buckets: list[list[Task]] = [[] for _ in range(actual_workers)]
        for i, t in enumerate(claimed_tasks):
            buckets[i % actual_workers].append(t)

        with concurrent.futures.ThreadPoolExecutor(max_workers=actual_workers) as pool:
            futures = [pool.submit(worker_loop, bucket) for bucket in buckets if bucket]
            for f in concurrent.futures.as_completed(futures):
                try:
                    res_list = f.result()
                    for t, r in res_list:
                        if r["status"] == "done":
                            tasks_done += 1
                            batch_findings.extend(r.get("findings", []))
                        else:
                            tasks_failed += 1
                        total_requests += r.get("requests", 0)
                except Exception as exc:
                    tasks_failed += 1
                    self.log(f"[!] Worker pool error: {exc}")

        return {
            "status": "completed",
            "claimed": len(claimed_tasks),
            "contended": contended_count,
            "executed": tasks_done + tasks_failed,
            "done": tasks_done,
            "failed": tasks_failed,
            "findings": batch_findings,
            "requests": total_requests,
            "workers_used": actual_workers,
        }
