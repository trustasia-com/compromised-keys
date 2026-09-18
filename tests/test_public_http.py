from types import SimpleNamespace

import pytest
from aiohttp.resolver import ThreadedResolver

from compromised_keys.public_http import PublicResolver, public_url_middleware, validate_public_url


@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.1/crl",
        "http://10.0.0.1/crl",
        "http://169.254.169.254/crl",
        "http://[::1]/crl",
        "http://[::ffff:127.0.0.1]/crl",
        "http://224.0.0.1/crl",
        "file:///etc/passwd",
        "https://user:password@example.com/crl",
    ],
)
def test_reject_non_public_crl_urls(url):
    with pytest.raises(ValueError):
        validate_public_url(url)


def test_accept_public_url():
    validate_public_url("https://example.com/crl")
    validate_public_url("http://8.8.8.8/crl")


@pytest.mark.asyncio
async def test_resolver_rejects_mixed_dns_answers(monkeypatch):
    async def resolve(*_args):
        return [{"host": "8.8.8.8"}, {"host": "127.0.0.1"}]

    monkeypatch.setattr(ThreadedResolver, "resolve", resolve)
    resolver = PublicResolver()
    try:
        with pytest.raises(ValueError):
            await resolver.resolve("example.com")
    finally:
        await resolver.close()


@pytest.mark.asyncio
async def test_redirect_middleware_blocks_literal_private_target():
    async def handler(_request):
        pytest.fail("Private redirect reached the network handler")

    with pytest.raises(ValueError):
        await public_url_middleware(SimpleNamespace(url="http://127.0.0.1/"), handler)
