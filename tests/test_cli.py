import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
FIX = ROOT/'fixtures/real'

class CliTests(unittest.TestCase):
    def run_cli(self,*args):
        env = dict(os.environ, PYTHONPATH=str(ROOT/'src'),PYTHONDONTWRITEBYTECODE='1')
        return subprocess.run([sys.executable,'-m','hidwire',*map(str,args)],cwd=ROOT,
                              env=env,capture_output=True,text=True,timeout=10)

    def compare(self,old,new,*args):
        return self.run_cli('compare',old,new,'--old-format','binary','--new-format','binary',*args)

    def test_help_and_required_formats(self):
        help = self.run_cli('--help')
        self.assertEqual(help.returncode,0,help.stderr)
        self.assertIn('witness-check',help.stdout)
        self.assertEqual(self.run_cli('compare',FIX/'circuitpython-mouse.bin',FIX/'circuitpython-mouse.bin').returncode,64)

    def test_compare_status_scope_determinism_and_sources(self):
        path = FIX/'circuitpython-keyboard.bin'
        before = path.read_bytes()
        all_reports = self.compare(path,path,'--json')
        self.assertEqual(all_reports.returncode,2,all_reports.stderr)
        all_data = json.loads(all_reports.stdout)
        self.assertEqual(all_data['status'],'blocked')
        first = self.compare(path,path,'--report','output:1','--json')
        second = self.compare(path,path,'--report','output:1','--json')
        self.assertEqual(first.returncode,0,first.stderr)
        self.assertEqual(first.stdout,second.stdout)
        data = json.loads(first.stdout)
        self.assertEqual(data['schema_version'],1)
        self.assertEqual(data['scope']['mode'],'selected')
        self.assertEqual(data['scope']['reports'],[{'kind':'output','report_id':1}])
        self.assertEqual(data['sources']['old']['byte_length'],67)
        self.assertTrue(any(not r['selected'] and r['status']=='blocked' for r in data['coverage']['old']))
        self.assertEqual(before,path.read_bytes())
        self.assertEqual(self.compare(path,path,'--report','output:2').returncode,64)

    def test_negative_and_invalid_inputs(self):
        path = FIX/'circuitpython-consumer-control.bin'
        self.assertEqual(self.compare(path,path).returncode,2)
        with tempfile.TemporaryDirectory() as td:
            invalid=Path(td)/'bad.bin'; invalid.write_bytes(b'\x75')
            result=self.compare(path,invalid,'--json')
            self.assertEqual(result.returncode,3,result.stderr)
        self.assertEqual(self.compare('/missing','/missing').returncode,64)

    def test_decode_numbered_and_unnumbered(self):
        result=self.run_cli('decode',FIX/'circuitpython-mouse.bin','--format','binary',
                            '--report','input:2','--wire','02 05 50 a0 ff','--json')
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual([v['value'] for v in json.loads(result.stdout)['decoded']['values']],
                         [1,0,1,0,0,80,-96,-1])
        wrong=self.run_cli('decode',FIX/'circuitpython-mouse.bin','--format','binary',
                          '--report','input:2','--wire','0200')
        self.assertEqual(wrong.returncode,64)

    def test_saved_witness_check_and_tampering(self):
        with tempfile.TemporaryDirectory() as td:
            changed=Path(td)/'new.bin'; artifact=Path(td)/'report.json'
            old=FIX/'circuitpython-mouse.bin'
            raw=old.read_bytes(); changed.write_bytes(raw[:36]+bytes.fromhex('09310930')+raw[40:])
            result=self.compare(old,changed,'--json')
            self.assertEqual(result.returncode,1,result.stderr)
            data=json.loads(result.stdout)
            self.assertEqual(len(data['witnesses']),2)
            self.assertEqual(data['witnesses'][0]['wire_hex'],'0200010000')
            artifact.write_text(result.stdout)
            args=('witness-check',old,changed,'--old-format','binary','--new-format','binary','--artifact',artifact,'--json')
            checked=self.run_cli(*args)
            self.assertEqual(checked.returncode,0,checked.stderr)
            self.assertEqual(json.loads(checked.stdout)['checked_witnesses'],2)
            data['witnesses'][0]['old_value']=900
            artifact.write_text(json.dumps(data))
            self.assertEqual(self.run_cli(*args).returncode,1)
            for malformed in ['{}','[]','{"schema_version":1,"schema_version":1}', '[NaN]', '['*2000]:
                artifact.write_text(malformed)
                result=self.run_cli(*args)
                self.assertEqual(result.returncode,64,result.stderr)
                self.assertNotIn('Traceback',result.stderr)

    def test_text_keeps_scope_and_raw_range_qualification(self):
        with tempfile.TemporaryDirectory() as td:
            a,b=Path(td)/'a.hex',Path(td)/'b.hex'
            a.write_text('0501150025ff750895020930093181021501250a950109328102')
            b.write_text('0501150025ff750895020931093081021501250a950109328102')
            result=self.run_cli('compare',a,b,'--old-format','hex','--new-format','hex')
            self.assertEqual(result.returncode,1,result.stderr)
            self.assertIn('Scope: all reports',result.stdout)
            self.assertIn('raw-extraction',result.stdout)
            self.assertIn('out-of-range',result.stdout)
