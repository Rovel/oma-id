#!/usr/bin/env python3
"""Build a minimal Docker context from the verified authd discovery archive."""
import hashlib
import json
from pathlib import Path
import tarfile

root = Path(__file__).resolve().parents[1]
record = json.loads((root / 'docs/p0/baseline.json').read_text())['repositories']['authd']
archive = root / f".cache/p0/authd-{record['commit']}.tar.gz"
assert hashlib.sha256(archive.read_bytes()).hexdigest() == record['archive_sha256']
output = root / '.cache/p0/arch-context.tar.gz'
with tarfile.open(output, 'w:gz', format=tarfile.GNU_FORMAT) as context:
    context.add(root / 'tests/arch/Dockerfile', arcname='Dockerfile')
    context.add(root / 'tests/arch/build.sh', arcname='build.sh')
    context.add(archive, arcname='authd.tar.gz')
print(output)
