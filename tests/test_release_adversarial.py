"""Fresh whole-tool release review, with test-authored descriptors and expectations.

No network, device, or hardware operations. Temporary input files are owned by
these tests. The procfs race test substitutes only ordinary fixture files.
"""
from copy import deepcopy
from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from hidwire import compare_descriptors, decode_report, parse_descriptor, verify_witness
from hidwire.bytesource import read_descriptor, SourceError
from hidwire.model import Limits, ReportKey
from hidwire.render import comparison_data, comparison_text

ROOT = Path(__file__).resolve().parents[1]
KEY = ReportKey('input', None)
XY = '0501150025ff75089502093009318102'
YX = '0501150025ff75089502093109308102'
ONE = '05011500257f7508950109308102'


def parse(text):
    return parse_descriptor(bytes.fromhex(text))


class WholeToolReviewTests(unittest.TestCase):
    def cli(self, *args, seed='1'):
        return subprocess.run([sys.executable, '-m', 'hidwire', *map(str, args)],
            cwd=ROOT, env=dict(os.environ, PYTHONPATH=str(ROOT/'src'),
                              PYTHONHASHSEED=seed, PYTHONDONTWRITEBYTECODE='1'),
            capture_output=True, text=True, timeout=15)

    def compare_cli(self, left, right, *args, seed='1'):
        return self.cli('compare', left, right, '--old-format', 'binary',
                        '--new-format', 'binary', *args, seed=seed)

    def test_numbered_and_unnumbered_witnesses_have_exact_prefix(self):
        for prefix, rid, expected in [('', None, '0100'), ('8507', 7, '070100')]:
            with self.subTest(rid=rid):
                a, b = parse(prefix+XY), parse(prefix+YX)
                result = compare_descriptors(a, b)
                self.assertEqual(result.status, 'different')
                self.assertEqual(len(result.witnesses), 2)
                self.assertEqual({w.wire_hex for w in result.witnesses}, {expected})
                key = ReportKey('input', rid)
                wire = bytes.fromhex(expected)
                self.assertEqual([v.value for v in decode_report(a,key,wire).values], [1,0])
                self.assertEqual([v.value for v in decode_report(b,key,wire).values], [1,0])
                for w in result.witnesses:
                    self.assertTrue(verify_witness(a,b,w))
                for wrong in (wire[1:], b'\x00'+wire, wire+b'\x00'):
                    with self.assertRaises(ValueError):
                        decode_report(a,key,wrong)
                if rid is not None:
                    with self.assertRaises(ValueError):
                        decode_report(a,key,b'\x00'+wire[1:])

    def test_late_page_and_pop_produce_equal_resolved_contracts(self):
        canonical = '0509150025ff75089502093009318102'
        variants = [
            '0501150025ff750895020930093105098102',
            '0509150025ff75089502a4050109300931b48102',
            '0509150025ff75089502a4050119302931b48102',
        ]
        for text in variants:
            with self.subTest(text=text):
                result = compare_descriptors(parse(canonical),parse(text))
                self.assertEqual(result.status,'equal')
                self.assertEqual(result.witnesses,())
                values = decode_report(result.new,KEY,bytes([0x81,0x42])).values
                self.assertEqual([(v.key.page,v.key.usage,v.value) for v in values],
                                 [(9,48,129),(9,49,66)])
        extended = parse('0509150025ff75089501a405010b3000ff00b48102')
        self.assertEqual(extended.reports[0].fields[0].key.page,255)
        self.assertEqual(compare_descriptors(extended,parse(ONE)).status,'different')

    def test_collections_padding_and_constant_only_shapes_survive_comparison(self):
        base = ('05010902a101750895018101150025ff09308102c0'
                '0904a1017504950281037508950109318102c0')
        regrouped = base.replace('750495028103','750895018101')
        result = compare_descriptors(parse(base),parse(regrouped))
        self.assertEqual(result.status,'equal')
        self.assertEqual(result.old.reports[0].payload_bits,32)
        decoded = decode_report(result.old,KEY,bytes.fromhex('ffaa55bb'))
        self.assertEqual([(v.key.path[0].usage,v.value) for v in decoded.values],[(2,170),(4,187)])
        changed = base.replace('750895018101150025ff09308102',
                               '75089501150025ff093081028101')
        moved = compare_descriptors(parse(base),parse(changed))
        self.assertEqual(moved.status,'different')
        self.assertEqual(len(moved.witnesses),1)
        self.assertEqual(moved.witnesses[0].wire_hex,'01000000')
        self.assertEqual((moved.witnesses[0].old_value,moved.witnesses[0].new_value),(0,1))
        for main, kind in [('81','input'),('91','output'),('b1','feature')]:
            for prefix,rid in [('',None),('8503',3)]:
                a = parse(prefix+'75089501'+main+'01')
                b = parse(prefix+'75109501'+main+'03')
                changed = compare_descriptors(a,b,(ReportKey(kind,rid),))
                self.assertEqual(changed.status,'different')
                self.assertEqual([d.component for d in changed.differences],['report_shape'])
                self.assertEqual(changed.witnesses,())

    def test_every_unknown_category_blocks_selected_comparison_and_decode(self):
        head = '750895019101'
        unknowns = [(0,t) for t in range(16) if t not in (8,9,10,11,12)]
        unknowns += [(1,t) for t in range(12,16)]
        unknowns += [(2,t) for t in range(3,16)]
        unknowns += [(3,t) for t in range(16)]
        tails = [bytes([(tag<<4)|(kind<<2)|1,0]).hex() for kind,tag in unknowns]
        tails += ['fe0199aa']
        key = ReportKey('output',None)
        for tail in tails:
            with self.subTest(tail=tail):
                d = parse(head+tail)
                result = compare_descriptors(d,d,(key,))
                self.assertEqual(result.status,'blocked')
                self.assertEqual(result.witnesses,())
                with self.assertRaises(ValueError):
                    decode_report(d,key,b'\x00')

    def test_invalid_unselected_report_precedes_blocked_and_difference(self):
        # Input is malformed because 1-bit data cannot represent logical max 255.
        raw = '0501150025ff750895010930910275010931810275078101'
        d = parse(raw)
        self.assertEqual(d.status,'invalid')
        old = parse(raw.replace('9102','9106'))
        result = compare_descriptors(old,d,(ReportKey('output',None),))
        self.assertEqual(result.status,'invalid')
        self.assertEqual(result.witnesses,())

    def test_whole_report_ranges_are_side_specific(self):
        a = parse(XY+'1500250a950109328102')
        b = parse(YX+'1501250a950109328102')
        result = compare_descriptors(a,b)
        self.assertEqual(result.status,'different')
        for witness in result.witnesses:
            self.assertTrue(witness.old_range_valid)
            self.assertFalse(witness.new_range_valid)
            self.assertTrue(verify_witness(a,b,witness))
            self.assertFalse(verify_witness(a,b,replace(witness,new_range_valid=True)))
            decoded = decode_report(b,KEY,bytes.fromhex(witness.wire_hex))
            self.assertEqual([(k.page,k.usage) for k in decoded.out_of_range_keys],[(1,50)])
        self.assertIn('range-valid',comparison_text(result))
        self.assertIn('out-of-range',comparison_text(result))

    def test_metadata_changes_never_fabricate_integer_witnesses(self):
        edits = [('1500','1501'),('257f','257e'),('0930','3500457e0930'),
                 ('0930','65110930'),('0930','550f0930'),('8102','8106')]
        for old,new in edits:
            with self.subTest(edit=(old,new)):
                result = compare_descriptors(parse(ONE),parse(ONE.replace(old,new)))
                self.assertEqual(result.status,'different')
                self.assertEqual({d.kind for d in result.differences},{'metadata'})
                self.assertEqual(result.witnesses,())

    def test_source_hash_binding_rejects_semantically_equal_replacement(self):
        a,b = parse(XY),parse(YX)
        equivalent = parse('0501'+XY)
        self.assertEqual(compare_descriptors(a,equivalent).status,'equal')
        result = compare_descriptors(a,b)
        for w in result.witnesses:
            self.assertTrue(verify_witness(a,b,w))
            self.assertFalse(verify_witness(equivalent,b,w))
            self.assertEqual(w.old_hash,hashlib.sha256(bytes.fromhex(XY)).hexdigest())

    def test_selected_missing_one_side_is_schema_and_missing_both_errors(self):
        a = parse('750895018101')
        b = parse('750895019101')
        result = compare_descriptors(a,b,(KEY,))
        self.assertEqual(result.status,'different')
        self.assertEqual([d.component for d in result.differences],['report_presence'])
        self.assertEqual(result.witnesses,())
        with self.assertRaises(ValueError):
            compare_descriptors(a,b,(ReportKey('feature',None),))

    def test_comparison_reports_are_stable_across_hash_seeds(self):
        with tempfile.TemporaryDirectory() as td:
            a,b = Path(td)/'a',Path(td)/'b'
            a.write_bytes(bytes.fromhex(XY)); b.write_bytes(bytes.fromhex(YX))
            before = a.read_bytes(),b.read_bytes()
            first = self.compare_cli(a,b,'--json',seed='1')
            second = self.compare_cli(a,b,'--json',seed='90210')
            self.assertEqual(first.returncode,1,first.stderr)
            self.assertEqual(second.returncode,1,second.stderr)
            self.assertEqual(first.stdout,second.stdout)
            self.assertEqual(before,(a.read_bytes(),b.read_bytes()))
            data = json.loads(first.stdout)
            self.assertEqual(data['scope'],{'mode':'all','reports':[{'kind':'input','report_id':None}]})
            self.assertEqual(data['sources']['old']['sha256'],hashlib.sha256(before[0]).hexdigest())

    def test_cli_unknown_tail_cannot_green_selected_constant_output(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td)/'input.bin'
            path.write_bytes(bytes.fromhex('750895019101d501'))
            result = self.compare_cli(path,path,'--report','output:none','--json')
            self.assertEqual(result.returncode,2,result.stderr)
            data = json.loads(result.stdout)
            self.assertEqual(data['scope']['mode'],'selected')
            self.assertEqual(data['coverage']['old'][0]['status'],'blocked')
            decoded = self.cli('decode',path,'--format','binary','--report','output:none','--wire','00','--json')
            self.assertEqual(decoded.returncode,2,decoded.stderr)
            self.assertNotIn('decoded',json.loads(decoded.stdout))

    def test_cli_unnumbered_decode_never_accepts_phantom_zero(self):
        with tempfile.TemporaryDirectory() as td:
            path=Path(td)/'input.bin'; path.write_bytes(bytes.fromhex(ONE))
            args=('decode',path,'--format','binary','--report','input:none','--json')
            right=self.cli(*args,'--wire','7f')
            self.assertEqual(right.returncode,0,right.stderr)
            self.assertEqual(json.loads(right.stdout)['decoded']['values'][0]['value'],127)
            for wire in ('007f','', '7f00','0x7f','7','gg','７f'):
                wrong=self.cli(*args,'--wire',wire)
                self.assertEqual(wrong.returncode,64,wrong.stderr)
                self.assertNotIn('Traceback',wrong.stderr)

    def test_witness_artifact_mutations_fail_without_tracebacks(self):
        good = comparison_data(compare_descriptors(parse(XY),parse(YX)))
        with tempfile.TemporaryDirectory() as td:
            a,b,artifact = [Path(td)/name for name in ('old','new','artifact')]
            a.write_bytes(bytes.fromhex(XY)); b.write_bytes(bytes.fromhex(YX))
            args=('witness-check',a,b,'--old-format','binary','--new-format','binary','--artifact',artifact,'--json')
            malformed = []
            def mutate(path,value,code):
                data=deepcopy(good); target=data
                for part in path[:-1]: target=target[part]
                target[path[-1]]=value
                malformed.append((json.dumps(data),code,path))
            for path,value,code in [
                (('schema_version',),True,64),
                (('contract_version',),'different-contract',64),
                (('witnesses',),[],64),
                (('witnesses',),{},64),
                (('witnesses',0,'old_value'),True,64),
                (('witnesses',0,'new_value'),2**32,64),
                (('witnesses',0,'old_range_valid'),1,64),
                (('witnesses',0,'report_key','kind'),[],64),
                (('witnesses',0,'report_key','report_id'),True,64),
                (('witnesses',0,'differing_key','path'),[{}],64),
                (('witnesses',0,'differing_key','page'),-1,64),
                (('witnesses',0,'old_hash'),'z'*64,64),
                (('witnesses',0,'old_hash'),'0'*64,1),
                (('witnesses',0,'wire_hex'),'01 00',1),
                (('witnesses',0,'wire_hex'),'010',1),
                (('witnesses',0,'wire_hex'),'zzzz',1),
                (('witnesses',0,'wire_hex'),'0000',1),
                (('witnesses',0,'wire_hex'),'010000',1),
                (('witnesses',0,'new_value'),900,1),
                (('witnesses',0,'new_range_valid'),False,1),
            ]: mutate(path,value,code)
            malformed += [('{"schema_version":1,"schema_version":1}',64,'duplicate'),
                          ('[NaN]',64,'nonfinite'),('['*2000,64,'depth'),
                          ('\ufeff[]',64,'BOM-nonobject')]
            for raw,code,name in malformed:
                with self.subTest(name=name):
                    artifact.write_text(raw)
                    result=self.cli(*args)
                    self.assertEqual(result.returncode,code,result.stderr)
                    self.assertNotIn('Traceback',result.stderr)
            artifact.write_text(json.dumps(good))
            passed=self.cli(*args)
            self.assertEqual(passed.returncode,0,passed.stderr)
            # Replay is expressly a witness check, not artifact certification.
            altered=deepcopy(good); altered['status']='equal'; altered['differences']=[]
            artifact.write_text(json.dumps(altered))
            replay=self.cli(*args)
            self.assertEqual(replay.returncode,0,replay.stderr)
            self.assertIn('does not certify artifact completeness or equality',json.loads(replay.stdout)['meaning'])
            a.write_bytes(bytes.fromhex('0501'+XY))
            self.assertEqual(self.cli(*args).returncode,1)

    def test_maximum_wire_length_and_signed32_extremes(self):
        prefix = '85ff75ff95208101752095010501'
        a = parse(prefix+'150027ffffffff09308102')
        b = parse(prefix+'170000008027ffffff7f09308102')
        result = compare_descriptors(a,b)
        self.assertEqual(result.status,'different')
        witness, = result.witnesses
        expected = bytes([255])+bytes(1023)+bytes([128])
        self.assertEqual(witness.wire_hex,expected.hex())
        self.assertEqual(len(expected),1025)
        self.assertEqual((witness.old_value,witness.new_value),(2**31,-(2**31)))
        self.assertTrue(witness.old_range_valid)
        self.assertTrue(witness.new_range_valid)
        self.assertTrue(verify_witness(a,b,witness))
        all_ones = bytes([255])+bytes(1020)+bytes([255])*4
        extreme = replace(witness,wire_hex=all_ones.hex(),old_value=2**32-1,new_value=-1)
        self.assertTrue(verify_witness(a,b,extreme))
        with tempfile.TemporaryDirectory() as td:
            old,new,artifact = [Path(td)/name for name in ('old','new','artifact')]
            old.write_bytes(bytes.fromhex(prefix+'150027ffffffff09308102'))
            new.write_bytes(bytes.fromhex(prefix+'170000008027ffffff7f09308102'))
            data = comparison_data(result)
            data['witnesses'][0]['wire_hex'] = extreme.wire_hex
            data['witnesses'][0]['old_value'] = extreme.old_value
            data['witnesses'][0]['new_value'] = extreme.new_value
            artifact.write_text(json.dumps(data))
            checked = self.cli('witness-check',old,new,'--old-format','binary',
                               '--new-format','binary','--artifact',artifact,'--json')
            self.assertEqual(checked.returncode,0,checked.stderr)

    def test_unused_usage_state_cannot_amplify_unknown_item_diagnostics(self):
        # Formerly 1,864,590 pending Usage copies from only 4,096 input bytes.
        raw = bytes.fromhex('0930')*1365+bytes([0x38])*1366
        descriptor = parse_descriptor(raw)
        self.assertEqual(descriptor.status,'blocked')
        self.assertEqual(len(descriptor.diagnostics),1366)
        self.assertEqual(sum(len(d.sources.usages) for d in descriptor.diagnostics),0)
        small = parse_descriptor(bytes.fromhex('0930')*300+bytes([0x38])*300)
        from hidwire.render import json_text
        rendered = json_text(comparison_data(compare_descriptors(small,small)))
        self.assertLess(len(rendered),500_000)

    def test_artifact_size_bound_precedes_json_parsing(self):
        with tempfile.TemporaryDirectory() as td:
            a,artifact=Path(td)/'input',Path(td)/'artifact'
            a.write_bytes(bytes.fromhex(ONE))
            with artifact.open('wb') as stream: stream.truncate(32*1024*1024+1)
            result=self.cli('witness-check',a,a,'--old-format','binary','--new-format','binary','--artifact',artifact)
            self.assertEqual(result.returncode,64,result.stderr)
            self.assertIn('source byte limit exceeded',result.stderr)
            self.assertNotIn('Traceback',result.stderr)

    def test_inode_reader_survives_filename_replacement(self):
        with tempfile.TemporaryDirectory() as td:
            path=Path(td)/'descriptor'; saved=Path(td)/'original'
            path.write_bytes(b'original bytes')
            original_open=os.open
            raced=False
            def controlled_open(name,*args,**kwargs):
                nonlocal raced
                if isinstance(name,str) and name.startswith('/proc/self/fd/') and not raced:
                    raced=True
                    path.rename(saved)
                    path.write_bytes(b'replacement bytes')
                return original_open(name,*args,**kwargs)
            with patch('hidwire.bytesource.os.open',side_effect=controlled_open):
                actual=read_descriptor(path,'binary')
            self.assertTrue(raced)
            self.assertEqual(actual,b'original bytes')
            self.assertEqual(path.read_bytes(),b'replacement bytes')

    def test_inode_reader_caps_growth_after_fstat(self):
        with tempfile.TemporaryDirectory() as td:
            path=Path(td)/'descriptor'; path.write_bytes(b'12')
            original_open=os.open
            def controlled_open(name,*args,**kwargs):
                if isinstance(name,str) and name.startswith('/proc/self/fd/'):
                    path.write_bytes(b'12345678')
                return original_open(name,*args,**kwargs)
            with patch('hidwire.bytesource.os.open',side_effect=controlled_open):
                with self.assertRaisesRegex(SourceError,'limit exceeded while reading'):
                    read_descriptor(path,'binary',Limits(max_descriptor_bytes=4))


if __name__ == '__main__':
    unittest.main()
