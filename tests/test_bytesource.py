"""Input boundary tests; each rejects before any input-dependent execution."""
import importlib
import os
from pathlib import Path
import tempfile
import unittest


class ByteSourceTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(importlib.util.find_spec('hidwire.bytesource'), 'bounded byte source API missing')
        self.api = importlib.import_module('hidwire.bytesource')
        self.model = importlib.import_module('hidwire.model')
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def read(self, data, format='hex', **limits):
        p = self.root / 'descriptor'
        p.write_bytes(data)
        return self.api.read_descriptor(p, format, self.model.Limits(**limits))

    def test_strict_hex_and_binary(self):
        self.assertEqual(self.read(b'05 01\n09\t02\r\x0b\x0cA1 01'), bytes.fromhex('05010902a101'))
        self.assertEqual(self.read(b'\x00\xfe\xff', 'binary'), b'\x00\xfe\xff')

    def test_reject_malformed_text(self):
        for data in (b'0', b'0x01', b'01,02', b'01 # note', b'\xc2\xa001', b'gg', b'01\x0002'):
            with self.subTest(data=data), self.assertRaises(self.api.SourceError):
                self.read(data)

    def test_reject_unknown_format_and_limits(self):
        with self.assertRaises(self.api.SourceError): self.read(b'00', 'auto')
        with self.assertRaises(self.api.SourceError): self.read(b'00 01', max_descriptor_bytes=1)
        with self.assertRaises(self.api.SourceError): self.read(b'\0\0', 'binary', max_descriptor_bytes=1)
        with self.assertRaises(self.api.SourceError): self.read(b'     00', max_text_bytes=4)

    def test_nonregular_and_symlink_rejected_without_blocking(self):
        target = self.root / 'target'; target.write_bytes(b'00')
        link = self.root / 'link'; link.symlink_to(target)
        pipe = self.root / 'pipe'; os.mkfifo(pipe)
        for path in (link, pipe, self.root):
            with self.subTest(path=path), self.assertRaises(self.api.SourceError):
                self.api.read_descriptor(path, 'hex', self.model.Limits())

    def test_missing_file_wrapped(self):
        with self.assertRaises(self.api.SourceError):
            self.api.read_descriptor(self.root / 'absent', 'binary', self.model.Limits())

    def test_exact_input_bounds(self):
        self.assertEqual(self.read(b'00 01', max_descriptor_bytes=2, max_text_bytes=5), b'\0\1')
        self.assertEqual(self.read(b'', 'binary'), b'')


class TokenTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(importlib.util.find_spec('hidwire.parser'), 'short item tokenizer API missing')
        self.api = importlib.import_module('hidwire.parser')
        self.model = importlib.import_module('hidwire.model')

    def test_short_item_lengths_and_source_offsets(self):
        items = self.api.tokenize(bytes.fromhex('c0 0501 260001 2701020304'))
        self.assertEqual([(x.offset,x.prefix,x.item_type,x.tag,x.data) for x in items],
                         [(0,0xc0,0,12,b''),(1,5,1,0,b'\1'),(3,0x26,1,2,b'\0\1'),(6,0x27,1,2,b'\1\2\3\4')])

    def test_truncated_short_items_invalid(self):
        for data in ('05','2600','2700','270001','27000102'):
            with self.subTest(data=data), self.assertRaises(self.api.ParseError) as cm:
                self.api.tokenize(bytes.fromhex(data))
            self.assertEqual(cm.exception.diagnostic.category, 'invalid')
            self.assertEqual(cm.exception.diagnostic.offset, 0)

    def test_complete_long_item_blocked_and_truncated_invalid(self):
        with self.assertRaises(self.api.ParseError) as cm: self.api.tokenize(bytes.fromhex('fe0199aa'))
        self.assertEqual(cm.exception.diagnostic.category, 'blocked')
        for data in ('fe','fe01','fe0199'):
            with self.subTest(data=data), self.assertRaises(self.api.ParseError) as cm:
                self.api.tokenize(bytes.fromhex(data))
            self.assertEqual(cm.exception.diagnostic.category, 'invalid')

    def test_token_limit(self):
        with self.assertRaises(self.api.ParseError) as cm:
            self.api.tokenize(b'\xc0\xc0', self.model.Limits(max_descriptor_bytes=1))
        self.assertEqual(cm.exception.diagnostic.category, 'blocked')
