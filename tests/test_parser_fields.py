from pathlib import Path
import unittest
from tests.helpers import parse, simple, codes
ROOT = Path(__file__).resolve().parents[1]


class FieldsTests(unittest.TestCase):
    def test_mouse_golden(self):
        d = parse(self, '05010902a1010901a1008502050919012905150025019505750181029501750381010501093009311581257f75089502810609381581257f750895018106c0c0')
        self.assertEqual(d.status, 'supported')
        r, = d.reports
        self.assertEqual((r.key.kind,r.key.report_id,r.payload_bits,r.wire_bytes), ('input',2,32,5))
        self.assertEqual([(f.key.page,f.key.usage,f.bit_offset,f.width,f.signed) for f in r.fields],
                         [(9,u,u-1,1,False) for u in range(1,6)]+[(1,0x30,8,8,True),(1,0x31,16,8,True),(1,0x38,24,8,True)])
        self.assertEqual([(c.kind,c.page,c.usage) for c in r.fields[0].key.path],[(1,1,2),(0,1,1)])
        self.assertEqual(r.fields[5].sources.main.offset,48)
        self.assertEqual(r.fields[5].sources.global_origin('report_size').offset,44)
        self.assertEqual(r.fields[5].sources.usages[0].offset,36)

    def test_signed_widths_and_unsigned_maximum(self):
        for width in (1,8,12,16,32):
            lo=-(1<<(width-1)); hi=(1<<(width-1))-1
            bounds='17'+lo.to_bytes(4,'little',signed=True).hex()+'27'+hi.to_bytes(4,'little',signed=True).hex()
            padding='' if width%8==0 else '75'+f'{8-width%8:02x}'+'95018101'
            d=parse(self,simple(size=f'{width:02x}',bounds=bounds,suffix=padding))
            self.assertEqual(d.status,'supported',d.diagnostics)
            f=d.reports[0].fields[0]
            self.assertEqual((f.width,f.signed,f.logical_min,f.logical_max),(width,True,lo,hi))
        f=parse(self,simple(bounds='150025ff')).reports[0].fields[0]
        self.assertEqual((f.signed,f.logical_max),(False,255))

    def test_metadata_defaults_and_explicit_values(self):
        for extra in ('','35004500','3501'):
            f=parse(self,simple(prefix=extra)).reports[0].fields[0]
            self.assertEqual((f.physical_min,f.physical_max,f.unit,f.unit_exponent),(0,127,0,0))
        f=parse(self,simple(prefix='350145646511550f',flags='06')).reports[0].fields[0]
        self.assertEqual((f.physical_min,f.physical_max,f.unit,f.unit_exponent,f.flags),(1,100,17,-1,6))

    def test_ordinary_and_extended_usage_binding(self):
        d=parse(self,simple(body='0509'))
        self.assertEqual((d.reports[0].fields[0].key.page,d.reports[0].fields[0].key.usage),(9,0x30))
        d=parse(self,simple(usages='0b30000100',body='0509'))
        self.assertEqual((d.reports[0].fields[0].key.page,d.reports[0].fields[0].key.usage),(1,0x30))

    def test_ranges_and_equivalent_widths(self):
        for usages in ('09300931','19302931','1b300001002b31000100'):
            d=parse(self,simple(usages=usages,count='02'))
            self.assertEqual(d.status,'supported')
            self.assertEqual([f.key.usage for f in d.reports[0].fields],[48,49])
        d=parse(self,'0601000a0200a2010016000026ff007608009601000a3000820200c0')
        self.assertEqual(d.status,'supported')
        self.assertEqual(d.reports[0].fields[0].logical_max,255)

    def test_constant_padding_does_not_require_usage_or_logical_bounds(self):
        for flags in ('01','03'):
            d=parse(self,'7508950281'+flags)
            self.assertEqual(d.status,'supported')
            self.assertEqual((d.reports[0].payload_bits,d.reports[0].wire_bytes,d.reports[0].fields),(16,2,()))

    def test_cross_byte_offsets(self):
        d=parse(self,'05010902a10115002501750195030901090209038102750d9501150026ff1f09308102c0')
        self.assertEqual(d.status,'supported')
        self.assertEqual([(f.bit_offset,f.width) for f in d.reports[0].fields],[(0,1),(1,1),(2,1),(3,13)])

    def test_collection_tree_sources_independently_expected(self):
        d=parse(self,'05010902a1010901a1001500257f7508950109308102c0c0')
        root,=d.collection_tree
        self.assertEqual((root.identity.kind,root.identity.page,root.identity.usage,root.source.offset),(1,1,2,4))
        child,=root.children
        self.assertEqual((child.identity.kind,child.identity.page,child.identity.usage,child.source.offset),(0,1,1,8))
        self.assertEqual(child.children,())
