from __future__ import annotations

import asyncio
import unittest
from unittest.mock import patch

from _support import ROOT, SECRET, load_module


class FastAPIRateLimitTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.mod = load_module(
            "tested_fastapi_rate_limit",
            ROOT / "assets" / "fastapi-security-kit" / "rate_limit.py",
        )

    def test_method_container_and_token_validation(self) -> None:
        for invalid in ("POST", b"POST"):
            with self.subTest(invalid=invalid), self.assertRaises(TypeError):
                self.mod.RateLimitPolicy("login", 1, 60, methods=invalid)
        policy = self.mod.RateLimitPolicy(
            "login", 1, 60, methods=(value for value in ("post", "PURGE"))
        )
        self.assertEqual(policy.methods, frozenset({"POST", "PURGE"}))
        with self.assertRaises(ValueError):
            self.mod.RateLimitPolicy("login", 1, 60, methods={"BAD METHOD"})

    def test_failure_mode_is_mandatory_and_observable(self) -> None:
        from starlette.requests import Request
        from starlette.responses import Response

        class BrokenStore:
            async def hit(self, key: str, window_seconds: int):
                raise OSError("store unavailable")

        with self.assertRaises(TypeError):
            self.mod.RateLimit(
                BrokenStore(), self.mod.RateLimitPolicy("login", 1, 60), key_secret=SECRET
            )
        request = Request(
            {
                "type": "http",
                "method": "POST",
                "path": "/",
                "headers": [],
                "client": ("127.0.0.1", 1234),
            }
        )

        async def exercise() -> None:
            open_limiter = self.mod.RateLimit(
                BrokenStore(),
                self.mod.RateLimitPolicy("public", 1, 60),
                key_secret=SECRET,
                fail_closed=False,
            )
            with self.assertLogs(self.mod.LOGGER, level="WARNING") as logs:
                await open_limiter(request, Response())
            self.assertIn("mode=open", " ".join(logs.output))
            with self.assertNoLogs(self.mod.LOGGER, level="WARNING"):
                await open_limiter(request, Response())

            closed_limiter = self.mod.RateLimit(
                BrokenStore(),
                self.mod.RateLimitPolicy("login", 1, 60),
                key_secret=SECRET,
                fail_closed=True,
            )
            with self.assertLogs(self.mod.LOGGER, level="WARNING"):
                with self.assertRaises(self.mod.HTTPException) as raised:
                    await closed_limiter(request, Response())
            self.assertEqual(raised.exception.status_code, 503)

        asyncio.run(exercise())

    def test_atomic_redis_counter_and_429_contract(self) -> None:
        import fakeredis.aioredis
        from starlette.requests import Request
        from starlette.responses import Response

        async def exercise() -> None:
            store = self.mod.RedisFixedWindowStore(fakeredis.aioredis.FakeRedis())
            counts = await asyncio.gather(*(store.hit("counter", 30) for _ in range(25)))
            self.assertEqual(sorted(count for count, _ in counts), list(range(1, 26)))

            limiter = self.mod.RateLimit(
                store,
                self.mod.RateLimitPolicy("login", 1, 30),
                key_secret=SECRET,
                fail_closed=True,
            )
            request = Request(
                {
                    "type": "http",
                    "method": "POST",
                    "path": "/login",
                    "headers": [],
                    "client": ("203.0.113.9", 1234),
                }
            )
            response = Response()
            await limiter(request, response)
            self.assertEqual(response.headers["RateLimit-Remaining"], "0")
            with self.assertRaises(self.mod.HTTPException) as raised:
                await limiter(request, Response())
            self.assertEqual(raised.exception.status_code, 429)
            self.assertIn("Retry-After", raised.exception.headers)

        asyncio.run(exercise())


class DjangoRateLimitTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        from django.conf import settings

        if not settings.configured:
            settings.configure(
                SECRET_KEY="test-only",
                ALLOWED_HOSTS=["testserver"],
                CACHES={
                    "default": {
                        "BACKEND": "django.core.cache.backends.locmem.LocMemCache"
                    }
                },
            )
        import django

        django.setup()
        cls.mod = load_module(
            "tested_django_rate_limit",
            ROOT / "assets" / "django-security-kit" / "rate_limit.py",
        )

    def test_method_container_and_explicit_failure_mode(self) -> None:
        def options(methods):
            return {
                "scope": "login",
                "limit": 1,
                "window_seconds": 60,
                "methods": methods,
                "key_secret": SECRET,
                "fail_closed": True,
                "require_shared_cache": False,
            }

        for invalid in ("POST", b"POST"):
            with self.subTest(invalid=invalid), self.assertRaises(TypeError):
                self.mod.rate_limit(**options(invalid))
        decorator = self.mod.rate_limit(**options(value for value in ("post", "PURGE")))
        self.assertTrue(callable(decorator))
        with self.assertRaises(TypeError):
            self.mod.rate_limit(
                scope="login",
                limit=1,
                window_seconds=60,
                key_secret=SECRET,
                require_shared_cache=False,
            )

    def test_limit_and_store_failure_contract(self) -> None:
        from django.core.cache import cache
        from django.http import HttpResponse
        from django.test import RequestFactory

        cache.clear()
        factory = RequestFactory()

        def view(request):
            return HttpResponse("ok")

        limited = self.mod.rate_limit(
            scope="login",
            limit=1,
            window_seconds=30,
            key_secret=SECRET,
            fail_closed=True,
            require_shared_cache=False,
        )(view)
        request = factory.post("/login", REMOTE_ADDR="203.0.113.11")
        self.assertEqual(limited(request).status_code, 200)
        self.assertEqual(limited(request).status_code, 429)

        fail_open = self.mod.rate_limit(
            scope="public",
            limit=1,
            window_seconds=30,
            key_secret=SECRET,
            fail_closed=False,
            require_shared_cache=False,
        )(view)
        with patch.object(cache, "add", side_effect=OSError("down")):
            with self.assertLogs(self.mod.LOGGER, level="WARNING") as logs:
                self.assertEqual(fail_open(request).status_code, 200)
            with self.assertNoLogs(self.mod.LOGGER, level="WARNING"):
                self.assertEqual(fail_open(request).status_code, 200)
        self.assertIn("mode=open", " ".join(logs.output))


if __name__ == "__main__":
    unittest.main()
