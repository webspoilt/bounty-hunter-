# Adaptive Swarm and Decision Evaluation (Task P5)

This document provides the operational runbook and architectural specifications for the integrated adaptive swarm, concurrency guardrails, and decision evaluation system.

---

## 1. Concurrency Separation Architecture

Concurrency in Bounty Hunter V2 is partitioned across four independent dimensions:

```
+--------------------------------------------------------------------------------+
|                             ResourceManager                                     |
|  - Owns security policy, kill-switch, scope checks, and polite rate budget     |
+--------------------------------------------------------------------------------+
       |                           |                          |
       v                           v                          v
[Logical Workers]        [Local Model Semaphores]     [Network HTTP Cap]
  Stages: 5, 10,           - Tev1: Max 2 (fast JSON)    - Shared polite rate
          20, 35, 50       - Qwen: Max 1 (heavy gen)    - effective_workers =
  (Dynamic scaling)        (No memory starvation)        min(workers, rate/0.1)
```

1. **Logical Workers**: Bounded units of work dynamically scaled across discrete stages `(5, 10, 20, 35, 50)` based on real backlog and health metrics.
2. **Tev1 Decision Concurrency**: Guarded by a dedicated bounded semaphore (max 2) to guarantee immediate response times (<50ms) for high-priority routing decisions.
3. **Qwen Generation Concurrency**: Guarded by `_CODER_SEMAPHORE` (max 1) so heavy code-generation jobs never saturate local GPU/CPU or starve Tev1 decision requests.
4. **HTTP Network Concurrency**: Bounded by `effective_workers(logical_workers, rate)` sharing **one** common polite `RequestBudget` token bucket. Concurrency expands CPU/worker throughput while strictly honoring target request limits.

---

## 2. Adaptive Scaling Policy

The `AdaptiveScalingPolicy` evaluates telemetry metrics on every planning iteration:

### Scale-Up Conditions
Scaling up from stage $S_i$ to $S_{i+1}$ requires **all** of the following:
- Eligible independent pending tasks $\ge 2 \times$ current workers.
- Shared request budget remaining $\ge 25\%$.
- Verification backlog $< 50\%$ of threshold ($< 8$ candidate findings).
- Recent task execution failure rate $< 5\%$.
- Zero claim contention or rate-limiting events.
- Zero kill-switch alerts.

### Scale-Down Conditions
Scaling down from stage $S_i$ to $S_{i-1}$ triggers immediately if **any** of the following occur:
- HTTP 429 rate-limiting or HTTP error rate $\ge 5\%$.
- Verification backlog $\ge 15$ items (backpressure protection).
- Request budget remaining $< 15\%$.
- SQLite task claim contention rate $\ge 25\%$.
- Local model memory pressure or timeout detected (>20s).
- Kill-switch activation (scales down to 0 immediately).

> [!NOTE]
> Tev1 may *recommend* a worker count, but the deterministic `ResourceManager` strictly validates, calculates, and enforces the allowed count.

---

## 3. Decision Evaluation System

Located at [`bb/decision/evaluator.py`](file:///e:/IDEAS/Bounty%20Hunter/bountybot/bb/decision/evaluator.py).

Every decision point records:
1. `decision_id`: Unique trace identifier.
2. `tev1_choice`: Option chosen by Tev1 (or deterministic fallback reason).
3. `baseline_choice`: Deterministic baseline ranking.
4. `agreed`: Boolean indicating agreement between model and baseline.
5. `execution_result`: Findings yielded, requests consumed, duration ms.
6. `verification_result`: Status from offline audit and dual-role replay (`confirmed`, `rejected`, `inconclusive`).
7. `triage_verdict`: Human or automated triage review.

The evaluator outputs comparative metrics:
- Agreement percentage with deterministic baselines.
- Yield differential: findings discovered when Tev1 diverged from the baseline.
- Request and time overhead attributed to model decisions.

---

## 4. Verification and Load Benchmarks

The full test suite validates atomic concurrency under high load (`tests/test_swarm_load.py`):
- **50-worker claim races**: 50 concurrent threads racing for the identical task fingerprint yield exactly 1 claim winner and 49 clean claim losses without database locking errors.
- **Polite request budget**: 50 concurrent workers sharing one `RequestBudget` never exceed the collective `max_requests` limit.
- **Heartbeat renewals**: In-flight tasks renew leases automatically every 30 seconds.
- **Clean cancellation**: Worker termination marks in-flight tasks as failed/releasable without orphaned locks.
