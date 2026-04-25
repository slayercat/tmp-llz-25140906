# IntraPanel Findings Summary

## Confirmed Critical / High Findings

| Severity | File | Finding | Why it matters | Rule file |
|---|---|---|---|---|
| Critical | `db.py` | SQL query construction with `%`, f-string, and `.format()` before `execute()` | User-controlled username/email can alter SQL semantics | `rules/critical-high.yml` |
| Critical | `app.py` | `subprocess.*(..., shell=True)` with request-controlled `host` / filename-derived path | Allows shell metacharacter injection if attacker controls input | `rules/critical-high.yml` |
| High | `app.py` | Path traversal in download and upload paths | Client filenames/request params are joined into `uploads` without safe basename or commonpath checks | `rules/critical-high.yml` |
| High | `app.py`, `db.py` | Hardcoded secret key, API key, admin password, DB password | Source disclosure compromises sessions and credentials | `rules/critical-high.yml` |
| High | `app.py` | `yaml.load(f)` without SafeLoader | Unsafe deserialization if config file is attacker-controlled | `rules/critical-high.yml` |
| Needs correction | `templates/*.html` | Plain `{{ var }}` output | In Flask `.html` templates, Jinja2 autoescaping is normally enabled. Treat as high only if autoescape is disabled, `|safe`/Markup is used, or the value enters JS/CSS/URL contexts unsafely. | `rules/jinja-template-review.yml` |

## Additional High-Impact Findings

| Severity | File | Finding | Why it may be high risk | Rule file |
|---|---|---|---|---|
| High/Critical in deployment | `app.py` | `app.run(debug=True, host="0.0.0.0")` | Exposed debug console and sensitive stack traces in deployed environments | `rules/additional-high-risk.yml` |
| High if config is writable | `app.py` | Config-controlled `requests.get(upstream)` in `/health` | Can become SSRF against internal metadata/admin services | `rules/additional-high-risk.yml` |
| High | `utils.py` | Passwords hashed with unsalted MD5 | Fast offline cracking after DB leak | `rules/additional-high-risk.yml` |
| High | `utils.py` + `app.py` | API tokens generated with `random.choice` and stored as bearer-like tokens | Predictable tokens are authentication bypass material | `rules/additional-high-risk.yml` |
| Medium/High | `app.py` | Paramiko `AutoAddPolicy()` | SSH MITM accepted silently | `rules/additional-high-risk.yml` |
| Medium/High | `app.py` | POST routes without visible CSRF protection | Login/register/upload/diagnostic actions can be cross-site triggered | `rules/additional-high-risk.yml` |
| Medium/High | `requirements.txt` | Old pinned dependencies | Need confirmation with SCA tooling; several listed versions are historically vulnerable or unsupported | `rules/additional-high-risk.yml` |

## Priority Fix Order

1. Replace SQL string construction with parameterized queries.
2. Remove `shell=True`; pass command arguments as arrays and validate hostnames/IPs.
3. Use `secure_filename`, absolute base paths, and `os.path.commonpath`/`Path.resolve()` containment checks for file operations.
4. Rotate hardcoded secrets and load secrets from environment/secret manager.
5. Replace `yaml.load` with `yaml.safe_load`.
6. Disable debug mode and do not bind the development server to `0.0.0.0` in production.
7. Replace MD5 and `random` token generation with password KDFs and `secrets`.
8. Add authorization checks for `/users`, `/diag`, and file routes; not every logged-in user should reach admin/diagnostic functions.
9. Add CSRF protection and upload size/type enforcement.
10. Run dependency SCA (`pip-audit`, `osv-scanner`, or Dependabot/Safety) and upgrade pinned versions.
