"""Independent test-authored descriptors; no product parser/builders involved."""
from dataclasses import dataclass


@dataclass(frozen=True)
class GrammarCase:
    name: str
    hex: str
    expected_usages: tuple[int, ...]


CASES = (
    GrammarCase('same_usage_different_paths', '05010902a101150025ff7508950109308102c00904a10109308102c0', (0x10030,0x10030)),
    GrammarCase('zero_data_collection', '05010902a01500257f7508950109308102c0', (0x10030,)),
    GrammarCase('extended_page_zero', '05010902a101150025ff750895010b300000008102c0', (0x30,)),
    GrammarCase('vendor_unit', '05010902a101150025ff650f7508950109308102c0', (0x10030,)),
    GrammarCase('full_unit_encoding', '05010902a101150025ff67ffffff0f7508950109308102c0', (0x10030,)),
    GrammarCase('same_id_inside_push', '05010902a10185011500257f75089501a4850109308102b4c0', (0x10030,)),
    GrammarCase('late_collection_page', '050109020509a1011500257f7508950109018102c0', (0x90001,)),
    GrammarCase('relative_output_feature', '05010902a1011580257f75089501093091060931b106c0', (0x10030,0x10031)),
    GrammarCase('unsigned_8', '05010902a101150025ff7508950109308102c0', (0x10030,)),
    GrammarCase('late_page', '05010902a1011500257f75089501093005098102c0', (0x90030,)),
    GrammarCase('late_range', '05010902a10115002501750195081901290805098102c0', tuple(range(0x90001, 0x90009))),
    GrammarCase('extended_usage', '05010902a1011500257f750895010b30000900050c8102c0', (0x90030,)),
    GrammarCase('extended_range', '05010902a10115002501750195081b010009002b080009008102c0', tuple(range(0x90001, 0x90009))),
    GrammarCase('ordinary_2byte_usage', '05010902a1011500257f750895010a30008102c0', (0x10030,)),
    GrammarCase('ordinary_2byte_range', '05010902a10115002501750195082a08001a01008102c0', tuple(range(0x10001, 0x10009))),
    GrammarCase('vendor_page', '0600ff0901a101150026ff007508950109028102c0', (0xff000002,)),
    GrammarCase('pop_pending_page', '05010902a1011500257f75089501a405090930b48102c0', (0x10030,)),
    GrammarCase('push_does_not_restore_locals', '05010902a1011500257f75089501a40930b48102c0', (0x10030,)),
    GrammarCase('pop_all_globals', '05010902a1011581257f359c45646511550f7508950109308102a4050915002501350045006500550075019503190129038102750595018101b409318102c0', (0x10030, 0x90001, 0x90002, 0x90003, 0x10031)),
    GrammarCase('nested_push', '05010902a1011500257f75089501a40509a4050cb4b409308102c0', (0x10030,)),
    GrammarCase('constant_array', '05010902a1011500257f75089501810109308102c0', (0x10030,)),
    GrammarCase('constant_variable', '05010902a1011500257f75089501810309308102c0', (0x10030,)),
    GrammarCase('logical_max_decoded_at_declaration', '05010902a1011500257f15ff7508950109308102c0', (0x10030,)),
    GrammarCase('three_directions', '05010902a1011500257f7508950109308102093191020938b102c0', (0x10030, 0x10031, 0x10038)),
    GrammarCase('multiple_ids', '05010902a10185011500257f7508950109308102850209318102850109388102c0', (0x10030, 0x10038, 0x10031)),
    GrammarCase('collection_does_not_reset_offset', '05010902a1011500257f7508950109308102c005010904a10109318102c0', (0x10030, 0x10031)),
    GrammarCase('physical_and_units', '05010902a1011581257f359c45646511550f7508950109308106c0', (0x10030,)),
    GrammarCase('unsigned_max_16', '05010902a101150026ffff7510950109308102c0', (0x10030,)),
    GrammarCase('unsigned_max_32', '05010902a101150027ffffffff7520950109308102c0', (0x10030,)),
)


def scalar_descriptor(width: int, signed: bool, prefix_bits: int = 0) -> bytes:
    """Compose a test case directly from the HID short-item wire encoding."""
    low = -(1 << (width - 1)) if signed else 0
    high = (1 << (width - int(signed))) - 1
    data = bytearray.fromhex('05010902a101')
    data += b'\x17' + low.to_bytes(4, 'little', signed=True)
    data += b'\x27' + high.to_bytes(4, 'little', signed=False)
    data += b'\x95\x01'
    if prefix_bits:
        data += bytes([0x75, prefix_bits, 0x81, 0x01])
    data += bytes([0x75, width, 0x09, 0x30, 0x81, 0x02])
    trailing = -(prefix_bits + width) % 8
    if trailing:
        data += bytes([0x75, trailing, 0x81, 0x03])
    data += b'\xc0'
    return bytes(data)


def slow_bit_value(payload: bytes, offset: int, width: int, signed: bool) -> int:
    """Independent bit-by-bit decoder, avoiding product helpers and vectors."""
    value = 0
    for bit in range(width):
        position = offset + bit
        if payload[position // 8] & (1 << (position % 8)):
            value += (-(1 << bit) if signed and bit == width - 1 else (1 << bit))
    return value
