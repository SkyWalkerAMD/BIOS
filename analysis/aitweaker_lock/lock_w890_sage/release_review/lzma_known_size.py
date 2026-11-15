"""Known-size LZMA1 container helper for bounded, in-memory packing experiments.

The ABI declaration follows xz v5.8.3's public 0BSD lzma12.h. LZMA1EXT
explicitly omits the EOS marker. Merely overwriting Python FORMAT_ALONE's
unknown-size header is not used: that leaves an EOS marker in the payload.
This file neither reads nor writes firmware. Caller must validate round-trip.
https://raw.githubusercontent.com/tukaani-project/xz/v5.8.3/src/liblzma/api/lzma/lzma12.h
"""
import ctypes as c
import hashlib
import lzma
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
DLL = ROOT/'tools/qemu-11.1.0/liblzma-5.dll'
FILTER_EXT = 0x4000000000000002

class Options(c.Structure):
    _fields_ = [('dict_size', c.c_uint32), ('preset_dict', c.c_void_p)] + [
        (name, c.c_uint32) for name in
        ('preset_dict_size', 'lc', 'lp', 'pb', 'mode', 'nice_len', 'mf', 'depth',
         'ext_flags', 'ext_size_low', 'ext_size_high', 'reserved_int4',
         'reserved_int5', 'reserved_int6', 'reserved_int7', 'reserved_int8',
         'reserved_enum1', 'reserved_enum2', 'reserved_enum3', 'reserved_enum4')
    ] + [('reserved_ptr1', c.c_void_p), ('reserved_ptr2', c.c_void_p)]

class Filter(c.Structure):
    _fields_ = [('id', c.c_uint64), ('options', c.c_void_p)]

def library():
    if c.sizeof(c.c_void_p) != 8 or c.sizeof(Options) != 112:
        raise ValueError('Only the documented 64-bit ABI is supported')
    if Options.ext_flags.offset != 48 or Options.reserved_ptr1.offset != 96:
        raise ValueError('Unexpected structure alignment')
    lib = c.CDLL(str(DLL))
    lib.lzma_version_string.argtypes = []
    lib.lzma_version_string.restype = c.c_char_p
    if lib.lzma_version_string() != b'5.8.3':
        raise ValueError('Unexpected liblzma version; recheck ABI before use')
    lib.lzma_lzma_preset.argtypes = [c.POINTER(Options), c.c_uint32]
    lib.lzma_lzma_preset.restype = c.c_ubyte
    lib.lzma_filter_encoder_is_supported.argtypes = [c.c_uint64]
    lib.lzma_filter_encoder_is_supported.restype = c.c_ubyte
    lib.lzma_properties_encode.argtypes = [c.POINTER(Filter), c.c_void_p]
    lib.lzma_properties_encode.restype = c.c_int
    lib.lzma_raw_encoder_memusage.argtypes = [c.POINTER(Filter)]
    lib.lzma_raw_encoder_memusage.restype = c.c_uint64
    lib.lzma_raw_buffer_encode.argtypes = [c.POINTER(Filter), c.c_void_p,
        c.c_void_p, c.c_size_t, c.c_void_p, c.POINTER(c.c_size_t), c.c_size_t]
    lib.lzma_raw_buffer_encode.restype = c.c_int
    if not lib.lzma_filter_encoder_is_supported(FILTER_EXT):
        raise ValueError('LZMA1EXT encoder unavailable')
    return lib

def encode(data, dictionary=0x1000000):
    if len(data) > 0x2200000:
        raise ValueError('Experiment input exceeds 34 MiB bound')
    lib = library()
    opts = Options()
    if lib.lzma_lzma_preset(c.byref(opts), 9):
        raise ValueError('Preset unavailable')
    opts.dict_size = dictionary
    opts.lc, opts.lp, opts.pb = 3, 0, 2
    opts.mode, opts.nice_len, opts.mf, opts.depth = 2, 273, 0x14, 0
    opts.ext_flags = 0  # no end-of-payload marker: size lives in ALONE header
    opts.ext_size_low, opts.ext_size_high = len(data) & 0xffffffff, len(data) >> 32
    filters = (Filter * 2)(Filter(FILTER_EXT, c.addressof(opts)),
                          Filter(0xffffffffffffffff, None))
    memory = lib.lzma_raw_encoder_memusage(filters)
    if memory == 0xffffffffffffffff or memory > 512*1024*1024:
        raise ValueError('Unsupported options or excessive memory requirement')
    props = c.create_string_buffer(5)
    if lib.lzma_properties_encode(c.byref(filters[0]), props):
        raise ValueError('Property encoding failed')
    inp = c.create_string_buffer(data)
    out_size = len(data)*2 + 65536
    out = c.create_string_buffer(out_size)
    position = c.c_size_t(0)
    ret = lib.lzma_raw_buffer_encode(filters, None, inp, len(data), out,
                                   c.byref(position), out_size)
    if ret:
        raise ValueError(f'liblzma raw encoding returned {ret}')
    packed = props.raw + struct.pack('<Q', len(data)) + out.raw[:position.value]
    if lzma.decompress(packed, format=lzma.FORMAT_ALONE) != data:
        raise ValueError('Known-size ALONE round-trip mismatch')
    return packed

def controls():
    cases = [b'', b'hello', bytes(8192), bytes(range(256))*128]
    outcomes = []
    for data in cases:
        packed = encode(data, 4096)
        outcomes.append(dict(input_bytes=len(data), packed_bytes=len(packed),
                             known_size_roundtrip=True))
    original = lzma.compress(b'hello', format=lzma.FORMAT_ALONE)
    altered = bytearray(original)
    struct.pack_into('<Q', altered, 5, 5)
    try:
        lzma.decompress(altered, format=lzma.FORMAT_ALONE)
        naive_patch = 'accepted_by_current_python_decoder'
    except lzma.LZMAError:
        naive_patch = 'rejected_by_current_python_decoder'
    return dict(dll=str(DLL), dll_sha256=hashlib.sha256(DLL.read_bytes()).hexdigest(),
                version='5.8.3', abi_size=c.sizeof(Options), filter='LZMA1EXT',
                eos_marker=False, cases=outcomes,
                python_unknown_size_control=lzma.decompress(original, format=lzma.FORMAT_ALONE)==b'hello',
                naive_header_patch_control=naive_patch,
                api_header='https://raw.githubusercontent.com/tukaani-project/xz/v5.8.3/src/liblzma/api/lzma/lzma12.h')

if __name__ == '__main__':
    import json
    print(json.dumps(controls(), indent=2))
