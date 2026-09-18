"""Replace generated files only after their complete contents reach disk."""

import os
import tempfile
from contextlib import contextmanager
from pathlib import Path


@contextmanager
def atomic_write(path, mode="w", **kwargs):
    destination = Path(path)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(
            mode=mode,
            dir=destination.parent,
            prefix=f".{destination.name}.",
            delete=False,
            **kwargs,
        ) as stream:
            temporary = Path(stream.name)
            yield stream
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, destination)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
