"""NEW: HTTPS-only repository intake with ephemeral, non-argv credentials.

Git is not a sandbox. This adapter prevents credential URL/process metadata
leaks and external protocol helpers; scanners still need separate confinement.
"""
from __future__ import annotations

import os
import re
import subprocess
import tempfile
from pathlib import Path
from urllib.parse import urlsplit, unquote
from core.evidence_redaction import register_secrets


def repository_name(url: str) -> str:
    parsed=urlsplit(str(url))
    if (parsed.scheme != 'https' or not parsed.hostname or parsed.username is not None
            or parsed.password is not None or parsed.query or parsed.fragment):
        raise ValueError('repository intake requires a credential-free HTTPS URL')
    name=unquote(parsed.path.rstrip('/').rsplit('/',1)[-1])
    if name.endswith('.git'): name=name[:-4]
    if name in {'', '.', '..'} or not re.fullmatch(r'[A-Za-z0-9._-]{1,128}',name):
        raise ValueError('unsafe repository name')
    return name


def clone_repository(url: str, destination: Path, token: str = '') -> None:
    repository_name(url)
    env=os.environ.copy()
    env.update({'GIT_TERMINAL_PROMPT':'0','GIT_CONFIG_NOSYSTEM':'1',
                'GIT_CONFIG_GLOBAL':os.devnull,'GIT_LFS_SKIP_SMUDGE':'1'})
    command=['git','-c','credential.helper=', '-c','core.hooksPath='+os.devnull,
             '-c','core.fsmonitor=false','-c','init.templateDir=',
             '-c','protocol.allow=never','-c','protocol.https.allow=always',
             '-c','http.followRedirects=false','clone','--depth','1','--',url,str(destination)]
    with tempfile.TemporaryDirectory(prefix='tbhm-git-credentials-') as td:
        if token and urlsplit(url).hostname.lower() == 'github.com':
            register_secrets([token])
            helper=Path(td)/'askpass'
            helper.write_text('#!/bin/sh\ncase "$1" in\n'
                '*Username*) printf "%s\\n" "x-access-token" ;;\n'
                '*) printf "%s\\n" "$TBHM_GIT_INTAKE_TOKEN" ;;\n'
                'esac\n', encoding='utf-8')
            helper.chmod(0o700)
            env.update({'GIT_ASKPASS':str(helper),'TBHM_GIT_INTAKE_TOKEN':token})
        else:
            # Do not inherit an operator-global executable askpass helper.
            env['GIT_ASKPASS']=os.devnull
        result=subprocess.run(command, env=env, capture_output=True, text=True, timeout=300)
        if result.returncode != 0:
            raise RuntimeError(f'git clone failed (exit {result.returncode})')
