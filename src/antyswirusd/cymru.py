"""Team Cymru Malware Hash Registry — DNS-based lookup.

Queries ``hash.cymru.com`` for a SHA-256 hash via DNS TXT records.
SHA-256 hashes are split into two 32-character segments per the
DNS API specification.

Reference: https://hash.cymru.com/docs_dns
"""

from __future__ import annotations

import asyncio
import logging
import random
import struct

log = logging.getLogger(__name__)

_CYMRU_DOMAIN_TEMPLATE = "{}.{}.hash.cymru.com"
_DEFAULT_RESOLVER = ("1.1.1.1", 53)
_DNS_TIMEOUT = 5.0


def _encode_dns_name(name: str) -> bytes:
    """Encode a domain name into DNS wire format."""
    parts = name.encode("idna").split(b".")
    return b"".join(bytes([len(p)]) + p for p in parts) + b"\x00"


def _build_txt_query(name: str) -> bytes:
    """Build a DNS TXT query message."""
    tid = random.randint(0, 65535)
    header = struct.pack("!6H", tid, 0x0100, 1, 0, 0, 0)
    question = _encode_dns_name(name)
    question += struct.pack("!HH", 16, 1)
    return header + question


def _parse_txt_response(data: bytes) -> list[str]:
    """Parse TXT records from a DNS response.

    Returns a list of TXT record strings. An empty list means the
    queried name does not exist (NXDOMAIN).
    """
    if len(data) < 12:
        raise ValueError("response too short")

    _tid, flags, qdcount, ancount, _nscount, _arcount = struct.unpack("!6H", data[:12])
    if not (flags & 0x8000):
        raise ValueError("not a DNS response")

    rcode = flags & 0x000F
    if rcode == 3:
        return []
    if rcode != 0:
        raise ValueError(f"DNS response error: rcode={rcode}")

    offset = 12
    for _ in range(qdcount):
        while data[offset] != 0:
            offset += data[offset] + 1
        offset += 5

    results: list[str] = []
    for _ in range(ancount):
        if offset >= len(data):
            break
        if data[offset] & 0xC0:
            offset += 2
        else:
            while offset < len(data) and data[offset] != 0:
                offset += data[offset] + 1
            offset += 1

        if offset + 10 > len(data):
            break
        rtype, _rclass, _ttl, rdlength = struct.unpack(
            "!HHiH", data[offset : offset + 10]
        )
        offset += 10

        if offset + rdlength > len(data):
            break
        if rtype == 16:
            rdata = data[offset : offset + rdlength]
            pos = 0
            txt_parts: list[str] = []
            while pos < len(rdata):
                length = rdata[pos]
                pos += 1
                if pos + length > len(rdata):
                    break
                txt_parts.append(
                    rdata[pos : pos + length].decode("utf-8", errors="replace")
                )
                pos += length
            results.append("".join(txt_parts))
        offset += rdlength

    return results


async def _dns_txt_query(name: str) -> list[str]:
    """Send a DNS TXT query over UDP and return the TXT strings."""
    loop = asyncio.get_running_loop()
    transport: asyncio.DatagramTransport | None = None
    try:
        query = _build_txt_query(name)

        fut: asyncio.Future[tuple[bytes, tuple[str, int]]] = loop.create_future()

        class _Protocol(asyncio.DatagramProtocol):
            def connection_made(self, tr: asyncio.DatagramTransport) -> None:
                nonlocal transport
                transport = tr
                tr.sendto(query)

            def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
                if not fut.done():
                    fut.set_result((data, addr))

            def error_received(self, exc: Exception) -> None:
                if not fut.done():
                    fut.set_exception(exc)

            def connection_lost(self, exc: Exception | None) -> None:
                if exc is not None and not fut.done():
                    fut.set_exception(exc)

        _, _ = await loop.create_datagram_endpoint(
            _Protocol,
            remote_addr=_DEFAULT_RESOLVER,
        )

        try:
            data, _ = await asyncio.wait_for(fut, timeout=_DNS_TIMEOUT)
        except asyncio.TimeoutError:
            log.debug("DNS query timed out for %s", name)
            return []

        return _parse_txt_response(data)
    finally:
        if transport is not None:
            transport.close()


async def lookup(content_hash: str) -> tuple[bool, str | None]:
    """Query the Team Cymru Malware Hash Registry for *content_hash*.

    Parameters
    ----------
    content_hash
        A 64-character hex SHA-256 hash.

    Returns
    -------
    tuple[bool, str | None]
        ``(True, "<detection>")`` if the hash is known,
        ``(False, None)`` if not known or the query failed.
    """
    if len(content_hash) != 64:
        return False, None

    domain = _CYMRU_DOMAIN_TEMPLATE.format(content_hash[:32], content_hash[32:])
    try:
        records = await _dns_txt_query(domain)
    except Exception as exc:
        log.debug("cymru lookup failed for %s: %s", content_hash, exc)
        return False, None

    if not records:
        return False, None

    parts = records[0].split()
    detection = parts[1] if len(parts) >= 2 else "unknown"
    return True, detection
