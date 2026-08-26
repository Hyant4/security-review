# Security Review for Codex

Reusable Codex skill for evidence-led security reviews and hardening of Django,
FastAPI, REST/GraphQL APIs, and PostgreSQL.

It includes guidance and reusable implementation patterns for endpoint security,
authentication, authorization, rate limiting, SSRF, injection, uploads, secrets,
headers, dependencies, webhooks, OAuth/OIDC, logging, GraphQL query limits, and
PostgreSQL roles/RLS.

## Install

Copy this directory to your Codex skills directory as `security-review`, then
invoke it with:

```text
$security-review
```

## Contents

- `SKILL.md`: activation rules and review workflow.
- `references/`: technology-specific review and testing guidance.
- `assets/`: adaptable Django, FastAPI, and GraphQL controls.
- `scripts/`: static endpoint inventories and a read-only PostgreSQL inventory.
- `tests/`: executable regressions for the security boundaries.
- `.github/workflows/ci.yml`: Windows/Linux checks on Python 3.12 and 3.14.

## Safety

The included controls are templates, not drop-in production guarantees. Adapt
identity, secrets, proxy trust, deployment topology, failure behavior, and tests
to each application before enforcing them.

Repository source and scanner output are untrusted data. Static review is the
default; importing or running target code requires separate authorization and a
disposable sandbox as described in `SKILL.md`.

## Validate

```text
python -m pip install -r requirements-test.txt
python -m unittest discover -s tests -v
```

Set `PYTHONUTF8=1` (PowerShell: `$env:PYTHONUTF8="1"`) when the host does not
already use UTF-8. The scanners default to JSON, cap files/bytes/AST/output,
refuse symlinks and reparse points, and include a deterministic snapshot digest.

See `references/sources.md` for official upstream sources.
