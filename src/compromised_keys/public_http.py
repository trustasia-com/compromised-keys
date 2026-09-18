"""Network boundaries for untrusted, publicly disclosed CRL URLs."""

import ipaddress
import socket

from aiohttp.resolver import ThreadedResolver
from yarl import URL


def _require_public_address(value):
    address = ipaddress.ip_address(value)
    if not address.is_global or address.is_multicast or address.is_reserved:
        raise ValueError("CRL destination must be a public unicast address")


def validate_public_url(value):
    url = URL(value)
    if url.scheme not in {"http", "https"} or not url.host or url.user is not None:
        raise ValueError("CRL URL must use HTTP(S), a host, and no credentials")
    try:
        ipaddress.ip_address(url.host)
    except ValueError:
        return
    _require_public_address(url.host)


class PublicResolver(ThreadedResolver):
    async def resolve(self, host, port=0, family=socket.AF_INET):
        results = await super().resolve(host, port, family)
        for result in results:
            _require_public_address(result["host"])
        return results


async def public_url_middleware(request, handler):
    # aiohttp applies middleware to each redirect, including literal-IP targets.
    validate_public_url(request.url)
    return await handler(request)
