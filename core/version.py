"""Central TBHM release identity."""
VERSION = "4.2.7"
SEMANTIC_VERSION = "4.2.7"
DISPLAY_VERSION = "v4.2.7"


def source_fingerprint():
    """Fingerprint executable Python source for build reporting and resume."""
    import hashlib
    from pathlib import Path
    root = Path(__file__).resolve().parents[1]
    digest = hashlib.sha256()
    paths = [root/'tbhm.py']
    for directory in ('core', 'phases'):
        paths.extend(sorted((root/directory).rglob('*.py')))
    for path in paths:
        digest.update(path.relative_to(root).as_posix().encode()+b'\0')
        digest.update(path.read_bytes())
    return digest.hexdigest()
