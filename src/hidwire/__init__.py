"""HidWire: exact scalar wire contracts within a bounded HID subset."""
__version__ = '0.1.0a1'
CONTRACT_VERSION = '1'

from .compare import compare_descriptors
from .decode import decode_report, verify_witness
from .parser import parse_descriptor

__all__ = ['compare_descriptors', 'decode_report', 'verify_witness', 'parse_descriptor']
