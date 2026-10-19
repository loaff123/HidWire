import importlib

def parse(test, hexbytes, **limits):
    api = importlib.import_module('hidwire.parser')
    test.assertTrue(hasattr(api, 'parse_descriptor'), 'stateful parser API missing')
    model = importlib.import_module('hidwire.model')
    return api.parse_descriptor(bytes.fromhex(hexbytes), model.Limits(**limits))

def simple(body='', prefix='', suffix='', flags='02', usages='0930', size='08', count='01', bounds='1500257f'):
    return '05010902a101' + prefix + bounds + '75' + size + '95' + count + usages + body + '81' + flags + suffix + 'c0'

def codes(descriptor):
    return {x.code for x in descriptor.diagnostics} | {x.code for r in descriptor.reports for x in r.diagnostics}
