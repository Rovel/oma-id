#!/usr/bin/env python3
"""Build a minimal Docker context for the PAM module Arch build.

The context is exported from the committed git tree (working tree must be
clean), so the recorded commit + tree hashes are exactly what the container
compiles.
"""
import hashlib
import json
import subprocess
import tarfile
from pathlib import Path

root = Path(__file__).resolve().parents[1]
status = subprocess.run(
    ['git', 'status', '--porcelain'], cwd=root, capture_output=True, text=True
).stdout.strip()
assert not status, f'working tree must be clean, got: {status}'
commit = subprocess.run(
    ['git', 'rev-parse', 'HEAD'], cwd=root, capture_output=True, text=True
).stdout.strip()
tree = subprocess.run(
    ['git', 'rev-parse', 'HEAD^{tree}'], cwd=root, capture_output=True, text=True
).stdout.strip()

# Export the committed tree for exactly the paths the container needs.
archive = root / '.cache/p0/arch-pam-source.tar.gz'
archive.parent.mkdir(parents=True, exist_ok=True)
export = subprocess.run(
    ['git', 'archive', '--format=tar.gz', 'HEAD', 'native'], cwd=root, capture_output=True
)
assert export.returncode == 0, export.stderr.decode()
archive.write_bytes(export.stdout)

output = root / '.cache/p0/arch-pam-context.tar.gz'
with tarfile.open(output, 'w:gz') as context:
    context.add(root / 'tests/arch-pam/Dockerfile', arcname='Dockerfile')
    context.add(root / 'tests/arch-pam/build.sh', arcname='build.sh')
    context.add(archive, arcname='context.tar.gz')
manifest = {
    'commit': commit,
    'tree': tree,
    'source_sha256': hashlib.sha256(archive.read_bytes()).hexdigest(),
}
print(json.dumps({'context': str(output), **manifest}, indent=2))
