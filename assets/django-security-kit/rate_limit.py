"""Adaptable Django fixed-window rate-limit decorator.

Copy this module into the target project and adapt it. Production use requires
an atomic, shared cache backend and a reviewed identity/proxy model.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import re
import threading
import time
from collections.abc import Callable, Iterable
from functools import wraps
from typing import Any

from django.conf import settings
from django.core.cache import caches
from django.http import HttpRequest, JsonResponse


Identity = Callable[[HttpRequest], str]
LOGGER = logging.getLogger(__name__)
HTTP_TOKEN = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")
_FAILURE_LOG_INTERVAL_SECONDS = 60.0
_FAILURE_LOG_LOCK = threading.Lock()
_LAST_FAILURE_LOG: dict[tuple[str, str, str], float] = {}


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


def _normalize_methods(methods: Iterable[str]) -> frozenset[str]:
    if isinstance(methods, (str, bytes)):
        raise TypeError("methods must be an iterable of complete HTTP method strings")
    method_values = tuple(methods)
    if any(not isinstance(method, str) for method in method_values):
        raise TypeError("methods must contain strings")
    normalized = frozenset(method.upper() for method in method_values)
    if not normalized or any(HTTP_TOKEN.fullmatch(method) is None for method in normalized):
        raise ValueError("methods must contain valid non-empty HTTP method tokens")
    return normalized


def _log_store_failure(scope: str, cache_alias: str, fail_closed: bool, exc: Exception) -> None:
    mode = "closed" if fail_closed else "open"
    signature = (scope, cache_alias, mode)
    now = time.monotonic()
    with _FAILURE_LOG_LOCK:
        last = _LAST_FAILURE_LOG.get(signature, float("-inf"))
        if now - last < _FAILURE_LOG_INTERVAL_SECONDS:
            return
        _LAST_FAILURE_LOG[signature] = now
    LOGGER.warning(
        "rate-limit store failure; scope=%s cache=%s mode=%s error=%s",
        scope,
        cache_alias,
        mode,
        type(exc).__name__,
    )


def rate_limit(
    *,
    scope: str,
    limit: int,
    window_seconds: int,
    methods: Iterable[str] = ("POST",),
    identity: Identity = default_identity,
    key_secret: bytes,
    fail_closed: bool,
    cache_alias: str = "default",
    require_shared_cache: bool = True,
) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """Limit calls per identity in a fixed window and return HTTP 429.

    Cache `add` and `incr` must be atomic. Choose distinct scopes for distinct
    behaviors. Layer edge limits for cost- or security-critical endpoints.
    """
    if not isinstance(scope, str) or not scope or any(char.isspace() for char in scope):
        raise ValueError("scope must be a non-empty token without whitespace")
    if (
        isinstance(limit, bool)
        or not isinstance(limit, int)
        or isinstance(window_seconds, bool)
        or not isinstance(window_seconds, int)
        or limit < 1
        or window_seconds < 1
    ):
        raise ValueError("limit and window_seconds must be positive")
    if not isinstance(key_secret, bytes) or len(key_secret) < 32:
        raise ValueError("key_secret must contain at least 32 bytes")
    if not isinstance(fail_closed, bool):
        raise TypeError("fail_closed must be an explicit boolean")
    if not isinstance(require_shared_cache, bool):
        raise TypeError("require_shared_cache must be a boolean")
    if not isinstance(cache_alias, str) or cache_alias not in settings.CACHES:
        raise ValueError(f"unknown cache alias: {cache_alias}")
    if require_shared_cache and not _backend_has_expected_atomic_primitives(cache_alias):
        raise ValueError(
            "rate limiting requires a verified shared cache with atomic add/incr; "
            "set require_shared_cache=False only for isolated tests or after review"
        )
    limited_methods = _normalize_methods(methods)
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
                if isinstance(count, bool) or not isinstance(count, int) or count < 1:
                    raise RuntimeError("rate-limit cache returned an invalid count")
            except Exception as exc:
                _log_store_failure(scope, cache_alias, fail_closed, exc)
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
