<!--
AutoBounty finding report
Program : SelfTest
Host    : 127.0.0.1
Template: generic-env
Severity: high
First seen: 2026-09-27 10:23:06 UTC
Status  : new
NOTE: Verify manually before submitting to the program. This draft was generated
from scanner evidence only.
-->

## Title
High‑Severity .env File Exposure Disclosing AWS, Database, and Stripe Secrets on localhost:8899

## Summary
An unauthenticated GET request to `/.env` on the target host returns a plain‑text environment file containing AWS access keys, a database connection string with credentials, and a live Stripe secret key. Exposure of these secrets allows an attacker to impersonate cloud services, compromise the database, and perform fraudulent payments, leading to data breach, financial loss, and service disruption.

## Affected Asset
- Host: `127.0.0.1`
- Port: `8899`
- Scheme: `http`
- Vulnerable path: `/.env`

## Severity Rationale
The scanner assigned a CVSS 3.0 vector of `AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:L` with a base score of 8.3 (High). This reflects a network‑reachable, low‑complexity vulnerability requiring no privileges or user interaction, with confidentiality, integrity, and availability impacts each rated Low but scoped to a Changed Security Authority (S:C). Translating to CVSS 3.1 yields a High severity rating, aligning with the reported `high` severity.

## Reproduction Steps
1. Send an unauthenticated GET request to the exposed `.env` file:
   ```bash
   curl -X 'GET' \
        -H 'Accept: */*' \
        -H 'Accept-Language: en' \
        -H 'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/112.0' \
        'http://127.0.0.1:8899/.env'
   ```
2. Observe the response body containing lines such as:
   ```
   AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
   AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
   DATABASE_URL=postgres://admin:SuperSecret123@db.internal:5432/prod
   STRIPE_SECRET_KEY=sk_live_51Hb...
   ```

## Impact
An attacker who retrieves the `.env` file can:
- Use the AWS keys to create, read, modify, or delete resources in the associated AWS account (e.g., S3 buckets, EC2 instances).
- Connect to the PostgreSQL database using the disclosed credentials, potentially exfiltrating or altering sensitive data.
- Perform unauthorized transactions or retrieve customer data via the live Stripe secret key.
These actions can lead to financial theft, data breaches, service abuse, and reputational damage.

## Remediation
- Immediately rotate all exposed secrets (AWS keys, database passwords, Stripe keys) and audit any unauthorized usage.
- Move environment files outside of the web‑servable directory or rename them to prevent direct HTTP access.
- Configure the web server (e.g., nginx, Apache, or the Python BaseHTTP server) to block requests for `.env` and similar dot‑files (e.g., `location ~ /\. { deny all; }` in nginx).
- Implement a security header or middleware that returns 404/403 for sensitive file patterns.
- Conduct a broader scan for other exposed configuration files and enforce least‑privilege principles for all services.

## References
- CWE‑552: Files or Directories Accessible to External Parties – https://cwe.mitre.org/data/definitions/552.html
- OWASP Top 10 2021 – A01:2021 Broken Access Control – https://owasp.org/Top10/A01_2021-Broken_Access_Control/
- OWASP Security Misconfiguration – https://owasp.org/www-community/vulnerabilities/Security_Misconfiguration
- ProjectDiscovery Nuclei generic‑env template – https://cloud.projectdiscovery.io/public/generic-env.yaml
