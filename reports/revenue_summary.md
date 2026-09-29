# Revenue Summary

**Generated:** 2025-09-28

## Collected Revenue
- **Total collected:** $0.00
- **Payouts logged:** 0

The `revenue` table in `data/autobounty.db` is empty. No real payouts have been recorded yet. Use `/revenue <amount> <note>` via Telegram to log a collected bounty.

## Estimated Potential Value

Conservative program-median anchors from `config.yaml`:
- critical: $5,000
- high: $1,500
- medium: $400
- low: $100

Findings with status `triaged` or `confirmed`:

| severity | count | anchor | estimated |
|----------|-------|--------|-----------|
| high     | 1     | 1,500  | $1,500 |
| medium   | 1     | 400    | $400 |
| **Total**| **2**| —      | **$1,900** |

Current triaged findings:
1. HIGH — SelfTest / 127.0.0.1 — Generic Env File Disclosure — report: ./reports/HIGH_127.0.0.1_generic-env.md
2. MEDIUM — SelfTest / 127.0.0.1 — Git Configuration - Detect — report: ./reports/MEDIUM_127.0.0.1_git-config.md

*Note:* Estimated potential is not collected revenue. It is used only for prioritization and is conservative per-program medians.

## Next Steps
- Review triaged findings and submit to in-scope programs.
- When a payout is confirmed, log it: `/revenue 1500 Tesla high generic-env`
- Collected revenue will then appear in the ledger and progress reports.
