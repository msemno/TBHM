"""Owned regression environments and diagnostics, separate from scan runtime state."""
from __future__ import annotations
from contextlib import contextmanager
import json
import os
from pathlib import Path
import socket


def regression_environment(root, base=None):
    """Use private state; never inherit operator models, credentials or caches."""
    supplied = os.environ if base is None else base
    keep = {'PATH', 'LANG', 'LC_ALL', 'LC_CTYPE', 'TZ', 'TERM', 'SYSTEMROOT',
            'WINDIR', 'COMSPEC', 'PATHEXT', 'LD_LIBRARY_PATH'}
    env = {key: str(value) for key, value in supplied.items() if key in keep}
    root = Path(root).absolute()
    for name in ('home', 'data', 'config', 'cache', 'ai-home', 'tools'):
        (root/name).mkdir(parents=True, exist_ok=True)
    env.update(HOME=str(root/'home'), XDG_DATA_HOME=str(root/'data'),
               XDG_CONFIG_HOME=str(root/'config'), XDG_CACHE_HOME=str(root/'cache'),
               TBHM_AI_HOME=str(root/'ai-home'), TBHM_TOOL_HOME=str(root/'tools'),
               TBHM_RESPECT_PATH='1', NO_PROXY='localhost,127.0.0.1,::1',
               no_proxy='localhost,127.0.0.1,::1', PYTHONDONTWRITEBYTECODE='1')
    if supplied.get('TBHM_VALIDATION_OUTPUT'):
        env['TBHM_VALIDATION_OUTPUT'] = supplied['TBHM_VALIDATION_OUTPUT']
    return env


@contextmanager
def unavailable_model_endpoint():
    """Reserve a private non-listening port for explicit model-unavailable cases.

    Keeping the socket bound prevents another local process from taking it;
    connections fail promptly without touching a real inference service.
    """
    reservation = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        reservation.bind(('127.0.0.1', 0))
        yield f'http://127.0.0.1:{reservation.getsockname()[1]}'
    finally:
        reservation.close()


def fixture_failure_details(output):
    """Collect bounded fixture diagnostics before its temporary directory closes."""
    root = Path(output)
    result = {'output': str(root)}
    try:
        path = root/'execution_ledger.json'
        if path.stat().st_size <= 8*1024*1024:
            rows = json.loads(path.read_text()).get('events', [])
            result['issues'] = [row for row in rows if row.get('status') in {
                'tool-error', 'parser-error', 'network-error', 'partial', 'blocked', 'incomplete'}][-12:]
        if (root/'phase_timings.json').is_file():
            data = json.loads((root/'phase_timings.json').read_text())
            result['phase_outcomes'] = data.get('per_phase_details', {})
    except (OSError, ValueError, TypeError):
        result['diagnostics'] = 'No readable bounded ledger was produced'
    return '\nTBHM_FIXTURE_DIAGNOSTICS: '+json.dumps(result, default=str)[:10000]
