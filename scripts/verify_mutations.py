"""Isolated parser mutations with a required clean, fixture-complete baseline.

A mutant counts as caught only when its named regression test reports assertion
failures, with no errors/skips. Import errors, missing fixture failures, timeouts,
zero discovered tests, and a broken baseline cannot produce a passing report.
"""
from pathlib import Path
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
MUTATIONS = {
    'phantom_id_byte': ('(r.key.report_id is not None)', 'True',
        'tests.test_parser_fields.FieldsTests.test_constant_padding_does_not_require_usage_or_logical_bounds'),
    'forget_signedness': ('signed = lo < 0', 'signed = False',
        'tests.test_parser_fields.FieldsTests.test_signed_widths_and_unsigned_maximum'),
    'freeze_ordinary_usage_page': ('else (page, self.value)', 'else (1, self.value)',
        'tests.test_parser_fields.FieldsTests.test_ordinary_and_extended_usage_binding'),
    'omit_local_reset': ('        usages = []\n        minimum = maximum = None', '        pass  # omitted local reset',
        'tests.test_parser_state.StateTests.test_local_reset_after_each_main_item'),
    'accept_null_state_flag': ('elif value not in (2, 6):', 'elif value not in (2, 6, 66):',
        'tests.test_parser_rejects.RejectTests.test_all_excluded_flags'),
    'offset_shift': ('offset + index * width, width, signed,', 'offset + index * width + 1, width, signed,',
        'tests.test_parser_fields.FieldsTests.test_cross_byte_offsets'),
}


def run_tests(root, tests):
    env = dict(os.environ, PYTHONPATH=str(root/'src'), PYTHONDONTWRITEBYTECODE='1')
    args = [sys.executable,'-m','unittest',*tests,'-v']
    try:
        run = subprocess.run(args,cwd=root,env=env,capture_output=True,text=True,timeout=120)
    except subprocess.TimeoutExpired:
        return {'returncode':None,'tests_run':0,'failures':[],'errors':['timeout'],
                'skipped':None,'summary':'timeout','output':''}
    output = run.stdout + run.stderr
    match = re.search(r'^Ran (\d+) tests? in ',output,re.M)
    failures = [line for line in output.splitlines() if line.startswith('FAIL:')]
    errors = [line for line in output.splitlines() if line.startswith('ERROR:')]
    skipped = len(re.findall(r'\.\.\. skipped ',output))
    summary = '\n'.join(line for line in output.splitlines()
                        if line.startswith(('Ran ','OK','FAILED (')))
    return {'returncode':run.returncode,'tests_run':int(match.group(1)) if match else 0,
            'failures':failures,'errors':errors,'skipped':skipped,'summary':summary,'output':output}


def run_mutations(mutations):
    """Each tuple is (name, relative source path, old text, new text, test)."""
    with tempfile.TemporaryDirectory(prefix='hidwire-mutations-') as tmp:
        root = Path(tmp)
        baseline_root = root/'baseline'
        for name in ('src','tests','fixtures'):
            shutil.copytree(ROOT/name,baseline_root/name,ignore=shutil.ignore_patterns('__pycache__'))
        # All subsequent mutants branch from this one immutable source snapshot.
        baseline = run_tests(baseline_root,['discover','-s','tests'])
        baseline_passed = (baseline['returncode'] == 0 and baseline['tests_run'] > 0
                           and not baseline['failures'] and not baseline['errors']
                           and baseline['skipped'] == 0)
        if not baseline_passed:
            return {'baseline':baseline,'baseline_passed':False,'mutants':[],
                    'all_caught':False,'reason':'Isolated baseline must pass before mutation testing.'}
        results = []
        for name,relative_path,before,after,test in mutations:
            mutant_root = root/name
            shutil.copytree(baseline_root,mutant_root,ignore=shutil.ignore_patterns('__pycache__'))
            path = mutant_root/relative_path
            original = path.read_text()
            if original.count(before) != 1:
                results.append({'mutation':name,'caught':False,
                                'reason':'Expected exactly one mutation target','test':test})
                continue
            path.write_text(original.replace(before,after))
            measured = run_tests(mutant_root,[test])
            caught = (measured['returncode'] == 1 and measured['tests_run'] == 1
                      and bool(measured['failures']) and not measured['errors']
                      and measured['skipped'] == 0)
            results.append({'mutation':name,'test':test,'caught':caught,**measured})
        return {'baseline':baseline,'baseline_passed':True,'mutants':results,
                'all_caught':all(result['caught'] for result in results)}


def main():
    report = run_mutations([(name,'src/hidwire/parser.py',*mutation)
                            for name,mutation in MUTATIONS.items()])
    print(json.dumps(report,indent=2))
    return 0 if report['all_caught'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
