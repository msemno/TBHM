"""Linux x86-64 deny-network syscall filter, inherited across fork/exec.

This is an egress boundary, not a filesystem/container sandbox. The CLI installs
it before starting workers. Runner also wraps approved offline children so the
boundary holds when Runner is used without the CLI. No permissive fallback.
"""
from __future__ import annotations
import ctypes
import errno
import os
import platform
import sys

_INSTALLED = False


def install():
    global _INSTALLED
    if _INSTALLED:
        return {'backend': 'linux-seccomp-deny-network', 'installed': True}
    if sys.platform != 'linux' or platform.machine() not in {'x86_64', 'amd64'}:
        raise RuntimeError('offline syscall isolation requires Linux x86-64')
    # Existing sockets could still transmit via write(2). Reject rather than
    # silently claim an egress boundary over inherited network descriptors.
    for entry in os.scandir('/proc/self/fd'):
        try:
            if os.readlink(entry.path).startswith('socket:'):
                raise RuntimeError('offline isolation refuses inherited socket descriptors')
        except FileNotFoundError:
            pass

    class Filter(ctypes.Structure):
        _fields_ = [('code', ctypes.c_ushort), ('jt', ctypes.c_ubyte),
                    ('jf', ctypes.c_ubyte), ('k', ctypes.c_uint)]
    class Program(ctypes.Structure):
        _fields_ = [('length', ctypes.c_ushort), ('filter', ctypes.POINTER(Filter))]

    # Architecture guard blocks alternate ABIs, including int 0x80 and x32.
    rules = [(0x20, 0, 0, 4), (0x15, 1, 0, 0xc000003e),
             (0x06, 0, 0, 0x80000000), (0x20, 0, 0, 0),
             (0x35, 0, 1, 0x40000000), (0x06, 0, 0, 0x00050000 | errno.ENOSYS)]
    # socket/connect/accept/send/bind/listen/socketpair; async networking;
    # process injection and importing someone else's socket descriptors.
    denied = {41, 42, 43, 44, 46, 49, 50, 53, 101, 288, 299, 307,
              310, 311, 321, 425, 426, 427, 438}
    for number in sorted(denied):
        rules.extend([(0x15, 0, 1, number), (0x06, 0, 0, 0x00050000 | errno.EPERM)])
    rules.append((0x06, 0, 0, 0x7fff0000))
    filters = (Filter * len(rules))(*(Filter(*row) for row in rules))
    program = Program(len(rules), filters)
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(38, 1, 0, 0, 0) != 0:  # PR_SET_NO_NEW_PRIVS
        raise RuntimeError('cannot install offline no_new_privs: '+os.strerror(ctypes.get_errno()))
    # SECCOMP_SET_MODE_FILTER + TSYNC: every existing thread, then descendants.
    result = libc.syscall(317, 1, 1, ctypes.byref(program))
    if result != 0:
        raise RuntimeError('cannot install offline syscall filter (no fallback): '+str(result))
    _INSTALLED = True
    return {'backend': 'linux-seccomp-deny-network', 'installed': True}


def child_argv(argv):
    from pathlib import Path
    return [sys.executable, '-I', '-S', str(Path(__file__).resolve()), '--', *map(str, argv)]


if __name__ == '__main__':
    try:
        if len(sys.argv) < 3 or sys.argv[1] != '--':
            raise ValueError('expected -- and an argv command')
        install()
        os.execvpe(sys.argv[2], sys.argv[2:], os.environ)
    except Exception as exc:
        print('offline-isolation: '+str(exc), file=sys.stderr)
        raise SystemExit(77)
