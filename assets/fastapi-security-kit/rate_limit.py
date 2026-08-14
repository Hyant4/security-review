"""Adaptable FastAPI rate-limit dependency backed by atomic Redis Lua.

Copy this module into the target project and adapt identity, scopes, failure
policy, Redis lifecycle, and tests. Add an edge limit for hostile traffic.
"""

from __future__ import annotations

import hashlib
import hmac
import inspect
from collections.abc import Awaitable, Callable, Iterable
from dataclasses import dataclass
from typing import Any, Protocol

from fastapi import HTTPException, Request, Response, status


class CounterStore(Protocol):
    async def hit(self, key: str, window_seconds: int) -> tuple[int, int]:
        """Return (count, ttl_seconds) after atomically incrementing key."""


REDIS_FIXED_WINDOW_LUA = """
local current = redis.call('INCR', KEYS[1])
local ttl = redis.call('TTL', KEYS[1])
if current == 1 or ttl < 0 then
  redis.call('EXPIRE', KEYS[1], ARGV[1])
end
ttl = redis.call('TTL', KEYS[1])
return {current, ttl}
"""


class RedisFixedWindowStore:
    """Small adapter for a redis.asyncio-compatible client."""

    def __init__(self, redis_client: Any) -> None:
        self.redis = redis_client

    async def hit(self, key: str, window_seconds: int) -> tuple[int, int]:
        if window_seconds < 1:
            raise ValueError("window_seconds must be positive")
        result = await self.redis.eval(
            REDIS_FIXED_WINDOW_LUA,
            1,
            key,
            window_seconds,
        )
        if not isinstance(result, (list, tuple)) or len(result) != 2:
            raise RuntimeError("unexpected Redis rate-limit result")
        count, ttl = int(result[0]), int(result[1])
        if count < 1:
            raise RuntimeError("Redis rate-limit counter must be positive")
        return count, max(ttl, 1)


Identity = Callable[[Request], str | Awaitable[str]]


def direct_client_identity(request: Request) -> str:
    """Use the ASGI-normalized peer address; never parse forwarding headers here."""
    host = request.client.host if request.client else "unknown"
    return f"ip:{host}"


async def _resolve_identity(identity: Identity, request: Request) -> str:
    value = identity(request)
    if inspect.isawaitable(value):
        value = await value  # type: ignore[misc]
    if not isinstance(value, str) or not value:
        raise RuntimeError("rate-limit identity must be a non-empty string")
    return value


def _key(prefix: str, scope: str, identity: str, key_secret: bytes) -> str:
    """Derive a pseudonymous key without exposing a guessable IP/user hash."""
    digest = hmac.new(key_secret, identity.encode("utf-8"), hashlib.sha256).hexdigest()[:32]
    return f"{prefix}:{scope}:{digest}"


@dataclass(frozen=True)
class RateLimitPolicy:
    scope: str
    limit: int
    window_seconds: int
    methods: frozenset[str] = frozenset({"POST"})

    def __post_init__(self) -> None:
        if not self.scope or any(char.isspace() for char in self.scope):
            raise ValueError("scope must be a non-empty token without whitespace")
        if self.limit < 1 or self.window_seconds < 1:
            raise ValueError("limit and window_seconds must be positive")
        if any(not isinstance(method, str) for method in self.methods):
            raise TypeError("methods must contain strings")
        normalized = frozenset(method.upper() for method in self.methods)
        if not normalized or any(not method or any(char.isspace() for char in method) for method in normalized):
            raise ValueError("methods must contain non-empty HTTP method tokens")
        object.__setattr__(self, "methods", normalized)


class RateLimit:
    """FastAPI dependency returning 429 when a fixed-window budget is exceeded."""

    def __init__(
        self,
        store: CounterStore,
        policy: RateLimitPolicy,
        *,
        identity: Identity = direct_client_identity,
        key_prefix: str = "security:rate-limit:v1",
        key_secret: bytes,
        fail_closed: bool = False,
    ) -> None:
        if not isinstance(key_secret, bytes) or len(key_secret) < 32:
            raise ValueError("key_secret must contain at least 32 bytes")
        if not key_prefix or any(char.isspace() for char in key_prefix):
            raise ValueError("key_prefix must be a non-empty token without whitespace")
        self.store = store
        self.policy = policy
        self.identity = identity
        self.key_prefix = key_prefix
        self.key_secret = key_secret
        self.fail_closed = fail_closed

    async def __call__(self, request: Request, response: Response) -> None:
        if request.method.upper() not in self.policy.methods:
            return
        identity = await _resolve_identity(self.identity, request)
        key = _key(self.key_prefix, self.policy.scope, identity, self.key_secret)
        try:
            count, ttl = await self.store.hit(key, self.policy.window_seconds)
            if (
                isinstance(count, bool) or not isinstance(count, int) or count < 1
                or isinstance(ttl, bool) or not isinstance(ttl, int) or ttl < 1
            ):
                raise RuntimeError("rate-limit store returned an invalid count or TTL")
        except Exception as exc:
            if self.fail_closed:
                raise HTTPException(
                    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                    detail="Request temporarily unavailable.",
                    headers={"Retry-After": "1"},
                ) from exc
            return

        remaining = max(self.policy.limit - count, 0)
        response.headers["RateLimit-Limit"] = str(self.policy.limit)
        response.headers["RateLimit-Remaining"] = str(remaining)
        response.headers["RateLimit-Reset"] = str(ttl)
        if count > self.policy.limit:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Too many requests. Try again later.",
                headers={
                    "Retry-After": str(ttl),
                    "RateLimit-Limit": str(self.policy.limit),
                    "RateLimit-Remaining": "0",
                    "RateLimit-Reset": str(ttl),
                },
            )


def methods(*values: str) -> frozenset[str]:
    """Convenience helper for an immutable normalized method set."""
    return frozenset(value.upper() for value in values)
