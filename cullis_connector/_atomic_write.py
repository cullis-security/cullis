"""Atomic + permission-correct secret writes (audit F-B-401).

Several Connector call sites used the ``open(..., "w") + chmod 0600``
idiom. POSIX ``open(2)`` applies the default umask (typically 0644) to
the file at creation time; ``chmod`` runs after the bytes touch the
disk. The window between the two is microseconds but mechanically
observable on any multi-user box — Frontdesk container, sandbox with
multiple developer processes, any host where a daemon shares a
filesystem with non-root users.

This helper closes the window: ``tempfile.mkstemp`` creates the file
with mode 0600 by default, we then ``os.fchmod`` to the requested mode
(idempotent if it was already 0600), write the bytes, and ``os.replace``
atomically into the destination. Crash safety is preserved (replace is
atomic on POSIX) and no readable-by-other window ever opens.

Use:

    from cullis_connector._atomic_write import write_with_mode

    write_with_mode(
        path,
        data=b"...",
        mode=0o600,
    )

Or, when the existing call uses text + encoding:

    write_with_mode(
        path,
        data=text.encode("utf-8"),
        mode=0o600,
    )

All call sites in the Connector that write secret material (Bearer
tokens, PEM private keys, cookie secrets) must use this helper.
"""
from __future__ import annotations

import logging
import os
import tempfile
from pathlib import Path

_log = logging.getLogger("cullis_connector._atomic_write")


def write_with_mode(path: Path, *, data: bytes, mode: int) -> None:
    """Atomically write ``data`` to ``path`` with file mode ``mode``.

    Implementation steps:

      1. ``tempfile.mkstemp`` creates a fresh file *in the same
         directory* with permissions 0600 (the tempfile default).
         Same-dir ensures ``os.replace`` is atomic (POSIX requires the
         tmp file and the destination live on the same filesystem).
      2. ``os.fchmod`` brings the mode to the caller-requested value.
         For 0600 this is a no-op; for other modes (e.g. 0644 for a
         non-secret config sibling) it adjusts before any byte hits.
      3. Write the bytes through the fd.
      4. ``os.replace`` swaps the tmp into the destination atomically.

    On Windows ``mkstemp`` ignores the POSIX mode and ``os.fchmod``
    raises NotImplementedError. We catch + warn rather than fail —
    the trust boundary on Windows is the OS user account, not the
    file ACL.
    """
    parent = path.parent
    parent.mkdir(parents=True, exist_ok=True)

    fd, tmp_name = tempfile.mkstemp(dir=str(parent), prefix=path.name + ".", suffix=".tmp")
    tmp_path = Path(tmp_name)
    try:
        try:
            os.fchmod(fd, mode)
        except (NotImplementedError, OSError) as exc:
            _log.info(
                "could not fchmod %o on %s (filesystem may not support it): %s",
                mode, tmp_path, exc,
            )
        with os.fdopen(fd, "wb") as fh:
            fd = -1  # ownership transferred to the file object
            fh.write(data)
        os.replace(tmp_path, path)
    except Exception:
        # Clean up the temp file on any failure path. If we transferred
        # ownership to the file object, fdopen's context manager already
        # closed the fd; only unlink is left.
        if fd != -1:
            try:
                os.close(fd)
            except OSError:
                pass
        try:
            tmp_path.unlink(missing_ok=True)
        except OSError:
            pass
        raise


def write_text_with_mode(path: Path, *, text: str, mode: int, encoding: str = "utf-8") -> None:
    """Convenience wrapper for text payloads. Encodes then delegates."""
    write_with_mode(path, data=text.encode(encoding), mode=mode)
