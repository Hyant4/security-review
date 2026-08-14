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

## Safety

The included controls are templates, not drop-in production guarantees. Adapt
identity, secrets, proxy trust, deployment topology, failure behavior, and tests
to each application before enforcing them.

See `references/sources.md` for official upstream sources.
