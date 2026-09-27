#!/usr/bin/env python3
"""Program loading + strict scope authorization. NO host is ever touched
unless it matches an explicit in-scope rule and no exclusion rule."""
import fnmatch, json, os, re, sys
sys.path.insert(0, os.path.dirname(__file__))
from db import DB


def load_config(path=None):
    import yaml
    p = path or os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                             "config.yaml")
    with open(p) as f:
        return yaml.safe_load(f)


def load_programs(cfg, db):
    for p in cfg.get("programs", []):
        db.upsert_program(p)
    return db.programs()


def in_scope(host, scope, exclusions):
    """host must match at least one scope rule and NO exclusion rule."""
    h = host.lower().strip().lstrip("*.")
    for ex in exclusions or []:
        if _match(h, ex):
            return False
    for rule in scope or []:
        if _match(h, rule):
            return True
    return False


def _match(host, rule):
    r = rule.lower().strip()
    if r.startswith("*."):
        suffix = r[2:]
        return host == suffix or host.endswith("." + suffix)
    return host == r


def split_host(url):
    u = re.sub(r"^[a-zA-Z]+://", "", url).split("/")[0].split(":")[0]
    return u.lower()
