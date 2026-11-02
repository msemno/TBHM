#!/usr/bin/env python3
"""Socket-isolated ID-only pipe adapter; it has no HTTP transport or tool API."""
import json
import socket
import sys


def main():
    try:
        channel = socket.socket()
    except PermissionError:
        print(json.dumps({'type': 'isolation', 'network_socket_denied': True}), flush=True)
    else:
        channel.close(); return 77
    line = sys.stdin.readline(16385)
    if not line or len(line) > 16384: return 65
    data = json.loads(line)
    ids = data.get('ids')
    if not isinstance(ids, list) or len(ids) > 100: return 65
    for identity in ids:
        if not isinstance(identity, str) or len(identity) > 80: return 65
        print(json.dumps({'id': identity}), flush=True)
        line = sys.stdin.readline(8193)
        if not line or len(line) > 8192: return 65
        reply = json.loads(line)
        if reply.get('id') != identity: return 65
    return 0


if __name__ == '__main__': raise SystemExit(main())
