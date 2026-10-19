"""Pinned source receipts and independent extraction, with no product imports."""
import hashlib
import json
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1] / 'fixtures'


class FixtureProvenance(unittest.TestCase):
    def test_all_four_original_source_blobs_and_sha256(self):
        manifest = json.loads((ROOT / 'manifest.json').read_text())
        self.assertEqual(len(manifest['sources']), 4)
        for entry in manifest['sources']:
            with self.subTest(path=entry['path']):
                content = (ROOT / entry['bundled_path']).read_bytes()
                git_blob = b'blob ' + str(len(content)).encode() + b'\0' + content
                self.assertEqual(hashlib.sha1(git_blob).hexdigest(), entry['blob_sha'])
                self.assertEqual(hashlib.sha256(content).hexdigest(), entry['sha256'])
                self.assertIn(entry['commit'], entry['source_url'])

    def test_all_four_binary_fixtures_match_source_initializers(self):
        manifest = json.loads((ROOT / 'manifest.json').read_text())
        self.assertEqual(len(manifest['fixtures']), 4)
        for entry in manifest['fixtures']:
            with self.subTest(fixture=entry['name']):
                actual = (ROOT / entry['path']).read_bytes()
                self.assertEqual(len(actual), entry['byte_length'])
                self.assertEqual(hashlib.sha256(actual).hexdigest(), entry['sha256'])
                source = (ROOT / entry['source_path']).read_text()
                initializer = re.search(r'\b' + entry['source_symbol'] +
                    r'\s*\[\s*\]\s*=\s*\{(.*?)\};', source, re.S).group(1)
                without_comments = re.sub(r'//[^\n]*', '', initializer)
                expected = bytes(int(s, 16) for s in re.findall(r'0x([0-9a-fA-F]+)', without_comments))
                self.assertEqual(actual, expected)
                self.assertEqual(entry['license'], 'MIT')
                license_text = (ROOT / entry['license_path']).read_text()
                self.assertIn('Permission is hereby granted, free of charge', license_text)

    def test_source_notice_is_retained(self):
        source = (ROOT / 'sources/circuitpython-report-descriptors.c').read_text()
        self.assertIn('SPDX-License-Identifier: MIT', source)
        self.assertIn('Copyright (c) 2018 hathach for Adafruit Industries', source)
        notice = (ROOT / 'NOTICE.md').read_text()
        self.assertIn('Copyright (c) Microsoft Corporation.', notice)


if __name__ == '__main__':
    unittest.main()
