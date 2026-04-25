# IntraPanel Semgrep Rules

This package contains Semgrep rules for the uploaded `IntraPanel` Flask/SQLite sample application.

## Layout

- `rules/critical-high.yml`: rules for the reported Critical/High classes: SQL injection, command injection, path traversal, hardcoded credentials, unsafe YAML loading, and high-confidence XSS/SSTI patterns.
- `rules/jinja-template-review.yml`: Jinja2 template review rules. The INFO rule intentionally flags template variables for manual review only; Flask/Jinja2 autoescaping makes many of these safe by default.
- `rules/additional-high-risk.yml`: extra high-impact findings observed in the repository: exposed Flask debug mode, SSRF risk, weak password hashing, predictable token generation, Paramiko host-key bypass, POST routes needing CSRF review, and old pinned dependencies.
- `docs/findings.md`: concise repository findings and expected rule hits.

## Run

```bash
semgrep --config rules/critical-high.yml /path/to/code-repo
semgrep --config rules/additional-high-risk.yml /path/to/code-repo
semgrep --config rules/jinja-template-review.yml /path/to/code-repo

# Or run everything:
semgrep --config rules /path/to/code-repo
```

## Notes

These rules are project-focused and intentionally tuned to this repository. For production CI, combine them with Semgrep's maintained registry rules, `pip-audit`/`osv-scanner`, Bandit, and tests that exercise security controls.
