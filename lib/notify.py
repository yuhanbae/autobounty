#!/usr/bin/env python3
"""Telegram notifications for the owner."""
import os, sys, time
sys.path.insert(0, os.path.dirname(__file__))

API = "https://api.telegram.org/bot{}/{}"


def _token():
    # Dedicated autobounty bot; fall back to shared token if not set.
    return (os.environ.get("AUTOBOUNTY_BOT_TOKEN")
            or os.environ.get("TELEGRAM_BOT_TOKEN"))


def send(text, chat_id=None, tries=2):
    import requests
    token = _token()
    if not token:
        return False
    cid = chat_id or os.environ.get("TELEGRAM_CHAT_ID")
    if not cid:
        return False
    for _ in range(tries):
        try:
            r = requests.post(API.format(token, "sendMessage"),
                              data={"chat_id": cid, "text": text,
                                    "parse_mode": "Markdown",
                                    "disable_web_page_preview": "true"},
                              timeout=20)
            if r.status_code == 200:
                return True
        except Exception:
            time.sleep(2)
    return False


def alert_finding(finding, report_path):
    e = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵"}.get(
        finding["severity"], "⚪")
    msg = (f"{e} *New {finding['severity'].upper()} finding*\n"
           f"*Program:* {finding['program']}\n"
           f"*Host:* `{finding['host']}`\n"
           f"*Issue:* {finding['template_name'] or finding['template_id']}\n"
           f"*Template:* `{finding['template_id']}`\n"
           f"Report: `{report_path}`")
    return send(msg)


def alert_summary(stats):
    msg = ("📊 *AutoBounty cycle complete*\n"
           f"Programs: {stats.get('programs',0)}  Hosts: {stats.get('hosts',0)}\n"
           f"Findings: " + "  ".join(
               f"{k.upper()}:{v}" for k, v in sorted(stats.items())
               if k not in ("hosts", "programs")))
    return send(msg)
