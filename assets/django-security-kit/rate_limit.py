"""Adaptable Django fixed-window rate-limit decorator.

Copy this module into the target project and adapt it. Production use requires
an atomic, shared cache backend and a reviewed identity/proxy model.
"""

from __future__ import annotations

import hashlib
import hmac
import time
from collections.abc import Callable, Iterable
from functools import wraps
from typing import Any

from django.conf import settings
from django.core.cache import caches
from django.http import HttpRequest, JsonResponse


Identity = Callable[[HttpRequest], str]


def default_identity(request: HttpRequest) -> str:
    """Prefer a stable account identity; otherwise use the direct peer address."""
    user = getattr(request, "user", None)
    if user is not None and getattr(user, "is_authenticated", False):
        return f"user:{user.pk}"
    # Do not trust X-Forwarded-For here. Normalize it only at a trusted proxy.
    return f"ip:{request.META.get('REMOTE_ADDR', 'unknown')}"


def _backend_has_expected_atomic_primitives(cache_alias: str) -> bool:
    backend = settings.CACHES[cache_alias].get("BACKEND", "")
    known = ("RedisCache", "PyLibMCCache", "PyMemcacheCache")
    return backend.endswith(known)


def _key(scope: str, identity: str, bucket: int, key_secret: bytes) -> str:
    """Derive a pseudonymous key without exposing a guessable IP/user hash."""
    digest = hmac.new(key_secret, identity.encode("utf-8"), hashlib.sha256).hexdigest()[:32]
    return f"security:rate-limit:v1:{scope}:{bucket}:{digest}"


def rate_limit(
    *,
    scope: str,
    limit: int,
    window_seconds: int,
    methods: Iterable[str] = ("POST",),
    identity: Identity = default_identity,
    key_secret: bytes,
    cache_alias: str = "default",
    fail_closed: bool = False,
    require_shared_cache: bool = True,
) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """Limit calls per identity in a fixed window and return HTTP 429.

    Cache `add` and `incr` must be atomic. Choose distinct scopes for distinct
    behaviors. Layer edge limits for cost- or security-critical endpoints.
    """
    if not scope or any(char.isspace() for char in scope):
        raise ValueError("scope must be a non-empty token without whitespace")
    if limit < 1 or window_seconds < 1:
        raise ValueError("limit and window_seconds must be positive")
    if not isinstance(key_secret, bytes) or len(key_secret) < 32:
        raise ValueError("key_secret must contain at least 32 bytes")
    if cache_alias not in settings.CACHES:
        raise ValueError(f"unknown cache alias: {cache_alias}")
    if require_shared_cache and not _backend_has_expected_atomic_primitives(cache_alias):
        raise ValueError(
            "rate limiting requires a verified shared cache with atomic add/incr; "
            "set require_shared_cache=False only for isolated tests or after review"
        )
    method_values = tuple(methods)
    if any(not isinstance(method, str) for method in method_values):
        raise TypeError("methods must contain strings")
    limited_methods = frozenset(method.upper() for method in method_values)
    if not limited_methods or any(
        not method or any(char.isspace() for char in method) for method in limited_methods
    ):
        raise ValueError("methods must contain non-empty HTTP method tokens")
    selected_cache = caches[cache_alias]

    def decorate(view: Callable[..., Any]) -> Callable[..., Any]:
        @wraps(view)
        def wrapped(request: HttpRequest, *args: Any, **kwargs: Any) -> Any:
            if request.method.upper() not in limited_methods:
                return view(request, *args, **kwargs)
            now = int(time.time())
            bucket = now // window_seconds
            retry_after = window_seconds - (now % window_seconds)
            resolved_identity = identity(request)
            if not isinstance(resolved_identity, str) or not resolved_identity:
                raise RuntimeError("rate-limit identity must be a non-empty string")
            cache_key = _key(scope, resolved_identity, bucket, key_secret)
            try:
                created = selected_cache.add(cache_key, 1, timeout=retry_after + 1)
                count = 1 if created else selected_cache.incr(cache_key)
            except Exception:
                if fail_closed:
                    return JsonResponse(
                        {"detail": "Request temporarily unavailable."},
                        status=503,
                        headers={"Retry-After": "1"},
                    )
                return view(request, *args, **kwargs)

            if count > limit:
                return JsonResponse(
                    {"detail": "Too many requests. Try again later."},
                    status=429,
                    headers={"Retry-After": str(retry_after)},
                )
            response = view(request, *args, **kwargs)
            response["RateLimit-Limit"] = str(limit)
            response["RateLimit-Remaining"] = str(max(limit - count, 0))
            response["RateLimit-Reset"] = str(retry_after)
            return response

        return wrapped

    return decorate
