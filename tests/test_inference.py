import asyncio
import json

import httpx
import pytest

from agentzero.inference import InferenceError, Nosana
from agentzero.config import Settings


def test_model_discovery_and_structured_retry(system):
    calls = []
    def handler(request):
        calls.append(request)
        assert request.headers["Authorization"] == "Bearer fixture-key"
        if request.url.path.endswith("/models"):
            return httpx.Response(200, json={"data": [{"id": "fixture-worker"}, {"id": "fixture-security"}]})
        content = 'not json' if len(calls) == 2 else json.dumps({"action": "read_file", "path": "README.md"})
        return httpx.Response(200, json={"choices": [{"message": {"content": content}}]})
    async def execute():
        client = Nosana(system[0], transport=httpx.MockTransport(handler))
        assert (await client.preflight())["same_model"] is False
        assert (await client.worker([])).path == "README.md"
    asyncio.run(execute())
    assert len(calls) == 3


def test_http_errors_do_not_leak_remote_body(system):
    def handler(request):
        return httpx.Response(401, json={"error": "secret-credential-value"})
    async def execute():
        with pytest.raises(InferenceError) as err:
            await Nosana(system[0], transport=httpx.MockTransport(handler)).preflight()
        assert "401" in str(err.value)
        assert "secret-credential-value" not in str(err.value)
    asyncio.run(execute())


def test_unavailable_configured_model_has_no_fallback(system):
    async def execute():
        transport = httpx.MockTransport(lambda request: httpx.Response(200, json={"data": [{"id": "other"}]}))
        with pytest.raises(InferenceError, match="not currently served"):
            await Nosana(system[0], transport=transport).preflight()
    asyncio.run(execute())


def test_model_listing_only_requires_nosana_key(tmp_path):
    async def execute():
        settings = Settings(data_dir=tmp_path, nosana_key="fixture-key")
        transport = httpx.MockTransport(lambda request: httpx.Response(200, json={"data": [
            {"id": "served", "available": True}, {"id": "offline", "available": False},
        ]}))
        assert await Nosana(settings, transport).list_models() == [{"id": "served", "available": True}]
    asyncio.run(execute())


def test_invalid_model_list_is_reported_safely(system):
    async def execute():
        transport = httpx.MockTransport(lambda request: httpx.Response(200, json={"data": {"secret": "not a model list"}}))
        with pytest.raises(InferenceError, match="invalid model list"):
            await Nosana(system[0], transport).list_models()
    asyncio.run(execute())
