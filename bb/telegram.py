"""Telegram review gate — watch/decide only, with an allow-list.

Fixes over v1: only explicitly allowed chat ids may decide; card content is HTML-escaped
(server-controlled bodies could otherwise forge a card); callback ids are queue UUIDs, so a
stale tap cannot decide a different candidate.
"""
from __future__ import annotations

import html
import json
import os
import time
from pathlib import Path

import httpx

from bb.config import OFFSET
from bb.gate import ApprovalGate

API = "https://api.telegram.org/bot{token}/{method}"
MAX_MSG = 3900


class TelegramError(RuntimeError):
    pass


class TelegramGate:
    def __init__(self, token: str, gate: ApprovalGate, allowed_chats: set[int]):
        if not allowed_chats:
            raise TelegramError("TELEGRAM_CHAT_ID must list at least one chat id")
        self.token = token
        self.gate = gate
        self.allowed = allowed_chats

    # ---------- telegram plumbing ----------

    def _api(self, method: str, payload: dict, timeout: float = 30.0):
        r = httpx.post(API.format(token=self.token, method=method), json=payload, timeout=timeout)
        r.raise_for_status()
        data = r.json()
        if not data.get("ok"):
            raise TelegramError(f"{method}: {data}")
        return data.get("result")

    def send(self, chat_id: int, text: str, keyboard: list | None = None):
        payload = {"chat_id": chat_id, "text": text[:MAX_MSG], "parse_mode": "HTML"}
        if keyboard:
            payload["reply_markup"] = json.dumps(keyboard)
        return self._api("sendMessage", payload)

    # ---------- cards ----------

    def format_item(self, item: dict) -> str:
        title = html.escape(item.get("title", ""))
        url = html.escape(item.get("url", ""))
        evidence = html.escape((item.get("summary") or "")[:600])
        return (
            f"🟡 <b>Candidate</b> <code>{html.escape(item['id'])}</code>\n"
            f"<b>{title}</b>\n"
            f"<b>Severity:</b> {html.escape(item.get('severity', ''))}  "
            f"<b>Class:</b> {html.escape(item.get('bug_class', ''))}\n"
            f"<b>Asset:</b> <code>{url}</code>\n\n{evidence}\n\n"
            "Approve = mark confirmed and export the report. Nothing is submitted."
        )

    def push_pending(self) -> int:
        pending = self.gate.pending()
        for item in pending:
            kb = [[{"text": "✅ Approve", "callback_data": f"approve:{item['id']}"},
                   {"text": "❌ Reject", "callback_data": f"reject:{item['id']}"}]]
            for chat_id in self.allowed:
                self.send(chat_id, self.format_item(item), kb)
        if not pending:
            for chat_id in self.allowed:
                self.send(chat_id, "Queue empty — nothing pending.")
        return len(pending)

    # ---------- polling ----------

    def _offset(self) -> int:
        try:
            return int(OFFSET.read_text().strip())
        except Exception:
            return 0

    def _save_offset(self, offset: int) -> None:
        OFFSET.parent.mkdir(parents=True, exist_ok=True)
        OFFSET.write_text(str(offset), encoding="utf-8")

    def serve(self, poll_timeout: int = 50) -> None:
        offset = self._offset()
        while True:
            updates = self._api("getUpdates",
                                {"timeout": poll_timeout, "offset": offset},
                                timeout=poll_timeout + 20) or []
            for upd in updates:
                offset = upd["update_id"] + 1
                self._save_offset(offset)
                if upd.get("message"):
                    self._on_message(upd["message"])
                elif upd.get("callback_query"):
                    self._on_callback(upd["callback_query"])

    def _authorised(self, chat_id: int) -> bool:
        return chat_id in self.allowed

    def _on_message(self, msg: dict) -> None:
        chat_id = msg["chat"]["id"]
        if not self._authorised(chat_id):
            self.send(chat_id, "Not authorised. Set TELEGRAM_CHAT_ID to this chat id.")
            return
        cmd = (msg.get("text") or "").split()
        if cmd and cmd[0].split("@")[0] in ("/start", "/queue"):
            self.push_pending()
        elif cmd and cmd[0].split("@")[0] == "/help":
            self.send(chat_id, "/queue — current pending findings\n/help — this message")

    def _on_callback(self, cb: dict) -> None:
        chat_id = cb["message"]["chat"]["id"]
        if not self._authorised(chat_id):
            self._api("answerCallbackQuery", {"callback_query_id": cb["id"],
                                              "text": "not authorised"})
            return
        action, _, queue_id = (cb.get("data") or "").partition(":")
        if action not in ("approve", "reject") or not queue_id:
            return
        try:
            item = self.gate.decide(queue_id, approved=(action == "approve"))
        except KeyError:
            self._api("answerCallbackQuery", {"callback_query_id": cb["id"],
                                              "text": "already gone"})
            return
        except ValueError as exc:
            self._api("answerCallbackQuery", {"callback_query_id": cb["id"], "text": str(exc)})
            return
        self._api("answerCallbackQuery", {"callback_query_id": cb["id"],
                                          "text": f"{item['state']}"})
        self.send(chat_id,
                  f"✅ <b>{item['state'].upper()}</b> — <code>{html.escape(item['id'])}</code>\n"
                  "Report exported to data/decided/. Submission stays manual.")


def gate_from_env(gate: ApprovalGate) -> TelegramGate:
    token = os.environ.get("TELEGRAM_BOT_TOKEN", "")
    chats = {int(x) for x in os.environ.get("TELEGRAM_CHAT_ID", "").replace(" ", "").split(",")
             if x.strip().lstrip("-").isdigit()}
    if not token:
        raise TelegramError("set TELEGRAM_BOT_TOKEN")
    return TelegramGate(token, gate, chats)
