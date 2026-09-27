#!/usr/bin/env python3
"""
AutoBounty sub-agent — an LLM-backed worker that pulls jobs from the queue and
executes them. Run several of these in parallel; scanning never blocks on LLM
latency because triage/drafting happens here.

    python3 subagent.py <name> [kinds...]

Worker identity is logged so you can see which agent did what.
"""
import json, os, sys, time, traceback
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "lib"))

import jobs, triage, report, llm
from db import DB
import scope as scopelib

BASE = os.path.dirname(os.path.abspath(__file__))
CFG_PATH = os.path.join(BASE, "config.yaml")


class SubAgent:
    def __init__(self, name, kinds):
        self.name = name
        self.kinds = kinds or ["triage", "draft", "verify", "research", "enrich"]
        self.cfg = scopelib.load_config(CFG_PATH)
        self.db = DB(self.cfg["runner"]["state_db"])
        jobs.ensure(self.db)          # schema must exist before stale_running() polls it
        self.handled = 0

    # ------------------------------------------------------------- handlers
    def h_triage(self, payload):
        """Classify a finding: real / noise / severity adjustment (fast tier)."""
        f = self.db.finding(payload["finding_id"])
        if not f:
            return {"ok": False, "err": "finding gone"}
        status, note = triage.rule_triage(f)
        if status == "noise":
            self.db.set_finding_status(f["id"], "noise")
            return {"verdict": "noise", "note": note}
        llm_verdict = llm.ask_json([
            {"role": "system", "content":
             "You are a bug bounty triager. Given scanner evidence, decide if this is a REAL "
             "actionable finding or LIKELY NOISE (fingerprint, benign banner, dev/self-signed "
             "cert, harmless config). Reply with ONLY this JSON, beginning with '{': "
             '{"verdict":"real|noise","severity":"critical|high|medium|low","reason":"..."}'},
            {"role": "user", "content": json.dumps({
                "template": f["template_id"], "name": f["template_name"],
                "severity": f["severity"], "host": f["host"],
                "evidence": json.loads(f["raw"] or "{}")}, default=str)[:3000]},
        ], tier="vulkan", max_tokens=400)   # short output -> local GPU first
        out = {"rule": note, "llm": llm_verdict}
        if isinstance(llm_verdict, dict):
            if llm_verdict.get("verdict") == "noise":
                self.db.set_finding_status(f["id"], "noise")
                out["verdict"] = "noise"
            else:
                out["verdict"] = "real"
                out["severity"] = llm_verdict.get("severity", f["severity"])
        else:
            out["verdict"] = "unresolved"
        return out

    def h_draft(self, payload):
        """Write a professional report for a finding."""
        f = self.db.finding(payload["finding_id"])
        if not f:
            return {"ok": False, "err": "finding gone"}
        body = triage.draft_report(f)
        path = report.write_finding_report(self.db, self.cfg, f, body)
        self.db.set_finding_status(f["id"], "triaged", report_path=path)
        return {"report": path, "chars": len(body)}

    def h_verify(self, payload):
        """Deep verification for high/critical findings before submission."""
        f = self.db.finding(payload["finding_id"])
        if not f:
            return {"ok": False, "err": "finding gone"}
        analysis = llm.ask_json([
            {"role": "system", "content":
             "You are a senior bug bounty hunter doing final verification on a HIGH/CRITICAL "
             "candidate. Be skeptical. Reply with ONLY this JSON, beginning with '{': "
             '{"exploitable":true|false,"confidence":0-100,"duplicate_risk":"low|medium|high",'
             '"submission_advice":"...","next_steps":"..."}'},
            {"role": "user", "content": json.dumps({
                "program": f["program"], "host": f["host"], "severity": f["severity"],
                "template": f["template_id"], "name": f["template_name"],
                "evidence": json.loads(f["raw"] or "{}")}, default=str)[:3000]},
        ], tier="deep", max_tokens=700, timeout=300)
        out = {"analysis": analysis}
        if isinstance(analysis, dict) and analysis.get("exploitable") is True:
            self.db.set_finding_status(f["id"], "confirmed")
        return out

    def h_research(self, payload):
        """Suggest additional in-scope assets for a program (scope-checked later)."""
        p = payload.get("program")
        row = [x for x in self.db.programs(enabled_only=False) if x["name"] == p]
        if not row:
            return {"ok": False, "err": "unknown program"}
        row = row[0]
        ideas = llm.ask_json([
            {"role": "system", "content":
             "You are a recon specialist. Given a bug bounty program's declared scope, list "
             "likely-existing subdomains worth testing. Reply with ONLY a JSON array of "
             "hostnames, beginning with '['. Never invent hosts outside the scope."},
            {"role": "user", "content": json.dumps({
                "program": row["name"], "scope": json.loads(row["scope"]),
                "platform": row["platform"]})},
        ], tier="fast", max_tokens=700)
        added = 0
        try:
            hosts = ideas if isinstance(ideas, list) else []
            scope = json.loads(row["scope"]); excl = json.loads(row["exclusions"])
            for h in hosts:
                h = str(h).lower().strip()
                if scopelib.in_scope(h, scope, excl):
                    self.db.upsert_host(row["name"], h, "llm-research")
                    added += 1
        except Exception:
            pass
        return {"candidates_n": len(hosts) if isinstance(ideas, list) else 0,
                "added_in_scope": added}

    HANDLERS = {"triage": "h_triage", "draft": "h_draft",
                "verify": "h_verify", "research": "h_research"}

    # ------------------------------------------------------------------ run
    def run(self):
        print(f"[agent] {self.name} up  kinds={self.kinds}", flush=True)
        while True:
            try:
                jobs.stale_running(self.db)
                job = jobs.claim(self.db, self.name, self.kinds)
                if not job:
                    time.sleep(15)
                    continue
                t0 = time.time()
                handler_map = {"triage": self.h_triage, "draft": self.h_draft,
                                "verify": self.h_verify,
                                "research": self.h_research}
                fn = handler_map[job["kind"]]
                result = fn(json.loads(job["payload"]))
                jobs.complete(self.db, job["id"], result, ok=bool(result))
                self.handled += 1
                print(f"[agent] {self.name} {job['kind']}#{job['id']} "
                      f"done in {time.time()-t0:.0f}s -> "
                      f"{json.dumps(result)[:160]}", flush=True)
            except KeyboardInterrupt:
                raise
            except Exception as e:
                traceback.print_exc()
                time.sleep(20)


if __name__ == "__main__":
    name = sys.argv[1] if len(sys.argv) > 1 else "agent-1"
    kinds = sys.argv[2:] or ["triage", "draft", "verify", "research"]
    SubAgent(name, kinds).run()
