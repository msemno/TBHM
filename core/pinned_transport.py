"""Explicit-origin/IP-pinned Requests transport. No proxy, retry or DNS-at-connect."""
from __future__ import annotations
from contextlib import contextmanager
import fcntl
import ipaddress
import os
from pathlib import Path
import socket
from urllib.parse import urlsplit
import requests
from requests.adapters import HTTPAdapter
from urllib3.connection import HTTPConnection, HTTPSConnection
from urllib3.connectionpool import HTTPConnectionPool, HTTPSConnectionPool
from urllib3.exceptions import NewConnectionError
from core.http_policy import RequestBlocked


def origin(url):
    parsed = urlsplit(url)
    if parsed.scheme not in {'http', 'https'} or not parsed.hostname or parsed.username or parsed.password or parsed.fragment:
        raise ValueError('invalid pinned origin')
    return parsed.scheme, parsed.hostname.lower(), parsed.port or (443 if parsed.scheme == 'https' else 80)


def _address(value):
    if not isinstance(value, str) or '%' in value:
        raise ValueError('numeric address without zone required')
    ip = ipaddress.ip_address(value)
    if ip.is_unspecified or ip.is_multicast or ip.is_link_local or getattr(ip, 'ipv4_mapped', None):
        raise ValueError('unspecified/multicast/link-local/mapped destination unsupported')
    return ip.compressed


class DestinationPins:
    def __init__(self, mapping):
        if not isinstance(mapping, dict) or not 1 <= len(mapping) <= 20:
            raise ValueError('1–20 explicit destination-pinned origins required')
        self.mapping = {}
        for url, values in mapping.items():
            parsed = urlsplit(url)
            if parsed.path not in {'', '/'} or parsed.query:
                raise ValueError('destination pins must name origins, not paths')
            key = origin(url)
            if key in self.mapping or not isinstance(values, list) or not 1 <= len(values) <= 8:
                raise ValueError('unique origins with 1–8 numeric pins required')
            self.mapping[key] = frozenset(_address(v) for v in values)

    def resolve(self, url):
        key = origin(url)
        allowed = self.mapping.get(key)
        if not allowed:
            raise RequestBlocked('origin has no reviewed destination pins')
        try:
            literal = _address(key[1]); resolved = {literal}
        except ValueError:
            try:
                answers = socket.getaddrinfo(key[1], key[2], type=socket.SOCK_STREAM, proto=socket.IPPROTO_TCP)
                if not answers or len(answers) > 64:
                    raise ValueError('DNS answer budget exceeded or empty')
                resolved = {_address(a[4][0]) for a in answers if a[0] in {socket.AF_INET, socket.AF_INET6}}
            except (OSError, ValueError) as exc:
                raise RequestBlocked('destination resolution failed closed') from exc
        if not resolved or not resolved.issubset(allowed):
            raise RequestBlocked('DNS destination differs from reviewed pins')
        return key, sorted(resolved)


class PinnedAdapter(HTTPAdapter):
    def __init__(self, pins):
        super().__init__(max_retries=0)
        self.pins, self._pools = pins, []

    def get_connection_with_tls_context(self, request, verify, proxies=None, cert=None):
        if any(proxies.values()) if proxies else False:
            raise RequestBlocked('proxy transport is unsupported in destination-pinned mode')
        (scheme, host, port), addresses = self.pins.resolve(request.url)
        base = HTTPSConnection if scheme == 'https' else HTTPConnection
        class Connection(base):
            def _new_conn(connection):
                error = None
                for address in addresses:
                    family = socket.AF_INET6 if ':' in address else socket.AF_INET
                    sock = socket.socket(family, socket.SOCK_STREAM)
                    try:
                        sock.settimeout(connection.timeout)
                        for option in connection.socket_options or []: sock.setsockopt(*option)
                        sock.connect((address, port, 0, 0) if family == socket.AF_INET6 else (address, port))
                        return sock
                    except OSError as exc:
                        error = exc; sock.close()
                raise NewConnectionError(connection, 'reviewed destination connection failed') from error
        _, options = self.build_connection_pool_key_attributes(request, verify, cert)
        if scheme == 'http': options = {}
        pool_class = HTTPSConnectionPool if scheme == 'https' else HTTPConnectionPool
        class Pool(pool_class):
            ConnectionCls = Connection
        pool = Pool(host, port, maxsize=1, block=True, **options)
        self._pools.append(pool)
        return pool

    def close(self):
        for pool in self._pools: pool.close()
        self._pools.clear(); super().close()


def install(session, mapping):
    pins = DestinationPins(mapping)
    session.trust_env = False
    session.mount('http://', PinnedAdapter(pins)); session.mount('https://', PinnedAdapter(pins))
    return pins


@contextmanager
def serial_dispatch(path):
    """Fail closed on a concurrent pinned dispatch across processes. No schema change."""
    lock = Path(str(path)+'.dispatch.lock')
    fd = os.open(lock, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        try: fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc: raise RequestBlocked('pinned transport concurrency limit reached') from exc
        yield
    finally:
        os.close(fd)
