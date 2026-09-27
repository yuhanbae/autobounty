<!--
AutoBounty finding report
Program : SelfTest
Host    : 127.0.0.1
Template: git-config
Severity: medium
First seen: 2026-09-27 10:21:21 UTC
Status  : noise
NOTE: Verify manually before submitting to the program. This draft was generated
from scanner evidence only.
-->

## Title
Exposure of Git Configuration File (.git/config) Revealing Repository Metadata

## Summary
The target application exposes the Git configuration file at `/.git/config`, allowing unauthenticated users to retrieve repository metadata. This disclosure reveals the origin remote URL, indicating a link to a private GitHub repository. While direct source code is not exposed via this endpoint, it significantly lowers the barrier for an attacker to perform targeted reconnaissance against the development environment or associated private infrastructure.

## Affected Asset
`127.0.0.1:8899`

## Severity Rationale
The vulnerability is rated **Medium** (CVSS 3.1: 5.3). The attack vector is network, complexity is low, and no privileges are required. The impact is limited to Information Disclosure (Confidentiality: Low), as the exposure primarily reveals configuration details (remote URLs, repository settings) rather than full source code or sensitive credentials in this specific evidence. It does not allow for Integrity or Availability compromise.

## Reproduction Steps
1.  Send an HTTP GET request to the exposed `.git/config` path on the target host.
2.  Execute the following command:
    ```bash
    curl -X 'GET' -d '' -H 'Accept: */*' -H 'Accept-Language: en' -H 'User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36' 'http://127.0.0.1:8899/.git/config'
    ```
3.  Observe the response body which returns the Git configuration file:
    ```text
    [core]
        repositoryformatversion = 0
        filemode = true
        bare = false
        logallrefupdates = true
    [remote "origin"]
        url = https://github.com/owner/private-repo.git
        fetch = +refs/heads/*:refs/remotes/origin/*
    ```

## Impact
An attacker gains visibility into the development workflow and infrastructure. The exposure of `https://github.com/owner/private-repo.git` confirms the project is a private repository and identifies the hosting platform. This information facilitates social engineering attacks against developers or enables specific targeting of the GitHub account or organization. While this single file does not expose source code, it strongly suggests that other `.git` artifacts (such as `HEAD`, `refs`, or `objects`) may also be accessible, potentially leading to full source code disclosure if those paths are probed.

## Remediation
1.  **Exclude `.git` from Web Roots:** Ensure that the `.git` directory is not deployed or accessible within the web server's document root. Build processes should exclude VCS metadata.
2.  **Server Configuration:** Configure the web server (e.g., Apache, Nginx, Python HTTP server) to explicitly deny access to files and directories starting with `.`.
    *   *Nginx:* `location ~ /\.git { deny all; }`
    *   *Apache:* `FilesMatch "\.(git)" Require all denied`
3.  **WAF Rules:** Implement Web Application Firewall rules to block requests containing `/.git/` in the URI.
4.  **CI/CD Hygiene:** Audit deployment pipelines to ensure that `.git` directories are stripped before artifacts are served by static file servers or application containers.

## References
*   [CWE-200: Exposure of Sensitive Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/200.html)
*   [OWASP Top 10: Security Misconfiguration (A05:2021)](https://owasp.org/Top10/A05_Security_Misconfiguration/2021/)
*   [Nuclei Template: git-config](https://cloud.projectdiscovery.io/public/git-config)
