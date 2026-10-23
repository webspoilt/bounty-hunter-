"""
Telegram Gate — reviews bountybot candidates from your phone.
Watch-only + decide-only. It never submits anything to HackerOne:
approve means "moved to decided.jsonl (approved)". Submission is still manual
by design.

Setup (2 min):
  1) Telegram: talk to @BotFather -> /newbot -> copy the token.
  2) Send the bot /start from your own account.
  3) Run:  python telegram_gate.py --token <TOKEN>
     (or set TELEGRAM_BOT_TOKEN env; --chat-id optional if you know it;
      otherwise the script tells you your chat id on first message)
Hosting: runs fine on any free tier (HF Space / small VPS / laptop burst).
"""
from __future__ import annotations

import argparse
import json
import os
import time
from pathlib import Path
from urllib.parse import quote

import httpx

API = "https://api.telegram.org/bot{token}/{method}"
MAX_MSG = 3900  # leave head-room under Telegram's 4096


def _api(token: str, method: str, payload: dict | None = None, timeout: float = 60.0):
    r = httpx.post(API.format(token=token, method=method), json=payload or {}, timeout=timeout)
    r.raise_for_status()
    data = r.json()
    if not data.get("ok"):
        raise RuntimeError(f"telegram {method} -> {data}")
    return data["result"]


def format_item(seq: int, item: dict) -> str:
    ev = "\n".join(
        f"• {e.get('summary', '')[:120]}" for e in (item.get("evidence") or [])[:5]
    ).strip()
    draft = (item.get("draft_report") or "")[:900]
    text = (
        f"🟡 <b>Candidate #{seq}</b>\n"
        f"<b>Title:</b> {item.get('title', '')}\n"
        f"<b>Target:</b> <code>{item.get('target', '')}</code>\n"
        f"<b>Obs row:</b> {item.get('obs_row_id', '')}\n"
        f"<b>Evidence:</b>\n{ev or '(none listed)'}\n"
        f"<b>Draft (truncated):</b>\n<pre>{draft}</pre>\n"
        f"Approve = moves to decided.jsonl. Nothing auto-submits."
    )
    return text[:MAX_MSG]


class TelegramGate:
    """Bridges ApprovalGate.DEFAULT queue location to a Telegram chat."""

    def __init__(self, token: str, gate=None, chat_id: str | int | None = None):
        self.token = token
        self.gate = gate
        self.chat_id = chat_id  # resolved via /start on first poll if None

    # ---- outbound ----

    def send(self, chat_id, text: str, keyboard: list | None = None):
        return _api(self.token, "sendMessage", {
            "chat_id": chat_id,
            "text": text,
            "parse_mode": "HTML",
            **({"reply_markup": json.dumps(keyboard)} if keyboard else {}),
        })

    def push_pending(self, chat_id) -> int:
        """Push every still-pending candidate as a tappable card."""
        gate = self._gate_or_raise()
        n = 0
        for seq, item in enumerate(gate.pending_list(), start=1):
            kb = [[
                {"text": "✅ Approve", "callback_data": f"approve:{seq}"},
                {"text": "❌ Reject", "callback_data": f"reject:{seq}"},
            ]]
            self.send(chat_id, format_item(seq, item), kb)
            n += 1
        if not n:
            self.send(chat_id, "Queue empty. Nothing pending.")
        return n

    def _gate_or_raise(self):
        if self.gate is None:
            from approval_gate import ApprovalGate
            self.gate = ApprovalGate()
        return self.gate

    # ---- inbound loop ----

    def serve(self, poll_timeout: int = 50, quiet: bool = False):
        offset = 0
        while True:
            updates = _api(self.token, "getUpdates",
                           {"timeout": poll_timeout, "offset": offset},
                           timeout=poll_timeout + 20)
            for upd in updates:
                offset = upd["update_id"] + 1
                msg = upd.get("message") or {}
                cb = upd.get("callback_query")
                if msg:
                    self._on_message(msg, quiet)
                elif cb:
                    self._on_callback(cb)

    def _on_message(self, msg: dict, quiet: bool):
        chat = msg["chat"]["id"]
        if self.chat_id is None:
            self.chat_id = chat
        cmd = (msg.get("text") or "").split()
        if cmd and (cmd[0].startswith("/start") or cmd[0].startswith("/queue")):
            self.push_pending(chat)
        elif cmd and cmd[0] == "/help":
            self.send(chat, "Commands: /start, /queue — resend pending cards.")

    def _on_callback(self, cb: dict):
        chat_id = cb["message"]["chat"]["id"]
        data = cb.get("data", "")
        action, _, seq_s = data.partition(":")
        try:
            seq = int(seq_s)
        except ValueError:
            return
        gate = self._gate_or_raise()
        if seq > len(gate.pending_list()):
            self.answer(cb["id"], "Already gone — /queue for current state.")
            return
        approved = action == "approve"
        gate.decide(seq, approved)
        self.answer(cb["id"], "Approved ✅" if approved else "Rejected ❌")
        self.send(chat_id,
                  f"Candidate #{seq} → <b>{'APPROVED' if approved else 'REJECTED'}</b> "
                  f"(decided.jsonl updated; submission stays manual).")

    def answer(self, callback_query_id: str, text: str):
        try:
            _api(self.token, "answerCallbackQuery",
                 {"callback_query_id": callback_query_id, "text": text})
        except Exception:
            pass


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--token", default=os.environ.get("TELEGRAM_BOT_TOKEN", ""))
    ap.add_argument("--chat-id", default=os.environ.get("TELEGRAM_CHAT_ID"))
    args = ap.parse_args()
    if not args.token:
        print("set --token or TELEGRAM_BOT_TOKEN (via @BotFather)")
        return 1
    gate = TelegramGate(args.token, chat_id=args.chat_id)
    print("Telegram gate polling… (Ctrl+C to stop)")
    try:
        gate.serve()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
