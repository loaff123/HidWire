"""The artifact reader must accept a result emitted within the contract caps."""
from pathlib import Path
import tempfile
import unittest
from hidwire import parse_descriptor, compare_descriptors
from hidwire.bytesource import SourceError
from hidwire.cli import _load_witnesses
from hidwire.render import comparison_data, json_text

class LargeArtifactTests(unittest.TestCase):
    def test_maximum_payload_deep_paths_replayable_artifact(self):
        # 1023 8-bit fields + 8 pad bits = maximum 8192 payload bits.
        # 32 nested collection paths and per-field metadata/raw changes stress
        # deterministic JSON expansion while keeping descriptors under 4 KiB.
        prefix=bytes.fromhex('0501')+b''.join(bytes([9,i,0xa1,1]) for i in range(1,33))
        fields=bytes.fromhex('150025ff750896ff0319012aff038102')
        end=bytes.fromhex('c0')*32
        old=parse_descriptor(prefix+fields+bytes.fromhex('750895018101')+end)
        new=parse_descriptor(prefix+bytes.fromhex('750195018101')+fields[:-1]+b'\x06'+bytes.fromhex('750795018101')+end)
        self.assertEqual((old.status,new.status),('supported','supported'))
        result=compare_descriptors(old,new)
        self.assertEqual(len(result.witnesses),1023)
        artifact=json_text(comparison_data(result))
        self.assertGreater(len(artifact),16*1024*1024)
        with tempfile.TemporaryDirectory() as td:
            path=Path(td)/'result.json'; path.write_text(artifact)
            try:
                restored=_load_witnesses(path)
            except SourceError as exc:
                self.fail(f'own supported comparison output cannot be read: {exc}')
        self.assertEqual(restored,result.witnesses)
