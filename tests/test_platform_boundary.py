"""Fail-closed simulations, not claims of non-Linux platform testing."""
import errno
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from hidwire.bytesource import SourceError, read_descriptor


class PlatformBoundaryTests(unittest.TestCase):
    def test_missing_o_path_refuses_before_open(self):
        original = os.O_PATH
        try:
            del os.O_PATH
            with patch('hidwire.bytesource.os.open') as opened:
                with self.assertRaisesRegex(SourceError,'requires Linux O_PATH'):
                    read_descriptor(Path('unused'), 'binary')
                opened.assert_not_called()
        finally:
            os.O_PATH = original

    def test_unavailable_procfs_refuses_without_data_read(self):
        with tempfile.TemporaryDirectory() as td:
            path=Path(td)/'descriptor'; path.write_bytes(b'\x75\x08')
            original = os.open
            def guarded(name,*args,**kwargs):
                if isinstance(name,str) and name.startswith('/proc/self/fd/'):
                    raise OSError(errno.ENOENT, 'procfs is unavailable')
                return original(name,*args,**kwargs)
            with patch('hidwire.bytesource.os.open',side_effect=guarded), patch('hidwire.bytesource.os.read') as read:
                with self.assertRaisesRegex(SourceError,'procfs is unavailable'):
                    read_descriptor(path,'binary')
                read.assert_not_called()
