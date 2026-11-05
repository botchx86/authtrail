"""Protect input identities and replace completed report files atomically."""
import os
from pathlib import Path
import tempfile


def check_outputs(inputs, outputs):
    checked = list(inputs)
    for output in outputs:
        for other in checked:
            if output == other or (output.exists() and other.exists() and output.samefile(other)):
                raise ValueError('report aliases an input, configuration, or another output')
        checked.append(output)


def atomic_write(path, content):
    path = Path(path)
    name = None
    try:
        with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', dir=path.parent, delete=False) as stream:
            name = stream.name
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(name, path)
    finally:
        if name and os.path.exists(name):
            os.unlink(name)
