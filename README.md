# Security Review for Codex

Reusable Codex skill for evidence-led security reviews and hardening of Django,
FastAPI, REST/GraphQL APIs, and PostgreSQL.

It includes guidance and reusable implementation patterns for endpoint security,
authentication, authorization, rate limiting, SSRF, injection, uploads, secrets,
headers, dependencies, webhooks, OAuth/OIDC, logging, GraphQL query limits, and
PostgreSQL roles/RLS.

## Install

Requirements for the skill itself: a supported Codex installation and Python
3.12 or 3.14 for the bundled static scanners. Review the checked-out revision
before copying it into your trusted skills directory.

Copy this directory to `$CODEX_HOME/skills/security-review`, then invoke it
with:

```text
$security-review
```

Only Codex installation is documented and tested here. Compatibility with
other agents is not claimed. Framework packages in `requirements-test.txt` are
development and test dependencies; target applications keep their own runtime
dependencies.

`pglast` is GPL-3.0-or-later and is used only to parse the PostgreSQL audit SQL
in tests. Do not bundle the test environment into a commercial runtime package
without reviewing all third-party license obligations and required notices.

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
python -m compileall -q assets scripts tests
python -m unittest discover -s tests -v
```

Set `PYTHONUTF8=1` (PowerShell: `$env:PYTHONUTF8="1"`) when the host does not
already use UTF-8. The scanners default to JSON, cap files/bytes/AST/output,
refuse symlinks and reparse points, and include a deterministic snapshot digest.

See `references/sources.md` for official upstream sources.

## Known limits

- Endpoint inventories are static review aids. Dynamic routing, inherited
  policy, generated GraphQL schemas, and deployment behavior need separate
  validation in an authorized disposable sandbox.
- Rate-limit and GraphQL modules are adaptable templates, not drop-in
  production controls.
- PostgreSQL inventory is read-only but may expose sensitive role, policy, and
  configuration metadata. Store and share its output as sensitive review data.

## License status

This repository does not currently grant an open-source or commercial license.
Public visibility alone does not authorize copying, redistribution, resale,
modification, or commercial use beyond rights supplied by applicable law or
platform terms. Obtain permission from the applicable copyright holder or
holders before distribution. No marketplace compatibility is claimed.
