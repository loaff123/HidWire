"""Strict, bounded regular-file reading. No URL or device input (MIT)."""
import os
from pathlib import Path
import stat
from .model import DEFAULT_LIMITS, Limits


class SourceError(ValueError):
    """Invocation, file-access, or input-format error."""


def read_descriptor(path: Path, format: str, limits: Limits = DEFAULT_LIMITS) -> bytes:
    if format not in ('binary', 'hex'):
        raise SourceError('format must explicitly be binary or hex')
    if not all(hasattr(os, name) for name in ('O_PATH', 'O_NOFOLLOW', 'O_DIRECTORY')):
        raise SourceError('secure regular-file reader requires Linux O_PATH support')
    if '\x00' in os.fspath(path):
        raise SourceError('descriptor path contains a NUL byte')
    cap = limits.max_descriptor_bytes if format == 'binary' else limits.max_text_bytes
    handles = []
    try:
        absolute = Path(path).absolute()
        parent = os.open('/', os.O_PATH | os.O_DIRECTORY)
        handles.append(parent)
        for part in absolute.parts[1:-1]:
            parent = os.open(part, os.O_PATH | os.O_NOFOLLOW | os.O_DIRECTORY, dir_fd=parent)
            handles.append(parent)
        # O_PATH gets an object handle without opening a device or FIFO for I/O.
        handle = os.open(absolute.name or '.', os.O_PATH | os.O_NOFOLLOW, dir_fd=parent)
        handles.append(handle)
        info = os.fstat(handle)
        if not stat.S_ISREG(info.st_mode):
            raise SourceError('input must be a regular file; symlinks are not followed')
        if info.st_size > cap:
            raise SourceError('source byte limit exceeded')
        # Reopen the verified inode, not its possibly replaced pathname.
        fd = os.open(f'/proc/self/fd/{handle}', os.O_RDONLY)
        handles.append(fd)
        chunks = bytearray()
        while len(chunks) <= cap:
            chunk = os.read(fd, min(8192, cap + 1 - len(chunks)))
            if not chunk:
                break
            chunks.extend(chunk)
        if len(chunks) > cap:
            raise SourceError('source byte limit exceeded while reading')
        data = bytes(chunks)
    except OSError as exc:
        raise SourceError(f'cannot read descriptor: {exc.strerror}') from exc
    finally:
        for handle in reversed(handles):
            os.close(handle)
    if format == 'binary':
        return data
    allowed = b'0123456789abcdefABCDEF \t\n\r\v\f'
    if any(ch not in allowed for ch in data):
        raise SourceError('hex input permits only ASCII hexadecimal digits and whitespace')
    compact = b''.join(data.split())
    if len(compact) % 2:
        raise SourceError('hex input contains an odd number of digits')
    if len(compact) // 2 > limits.max_descriptor_bytes:
        raise SourceError('decoded descriptor byte limit exceeded')
    return bytes.fromhex(compact.decode('ascii'))
