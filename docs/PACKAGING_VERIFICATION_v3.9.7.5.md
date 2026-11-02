# TBHM v3.9.7.5 Packaging Verification

## Source-tree verification

The verifier checks:

- no source-tree symlinks;
- every embedded manifest path is safe and present;
- SHA-256 and file sizes match;
- executable bits match the manifest;
- every packaged file except the manifest is listed;
- no stale manifest entries exist;
- every Python source compiles.

## ZIP verification

The ZIP verifier checks:

- archive CRC integrity;
- absolute paths and `..` traversal;
- duplicate member names;
- symlink members;
- total uncompressed-size policy;
- suspicious compression ratios;
- embedded release-manifest hashes, sizes and executable modes;
- complete manifest-to-archive inventory equality.

## Runtime interface

```bash
python3 tbhm.py --profile authorized_safe -y \
  --verify-package /path/to/TBHM-v3.9.7.5-FULL.zip \
  --no-bootstrap --no-html -o results/package-verification
```

Package verification is local and does not require a network target. A successful
ZIP CRC test alone is not sufficient; the embedded manifest and inventory must
also pass.
