"""Pinned public-input parsing and mathematical verification. No key generation."""
from pathlib import Path
import ast
import base64
import hashlib
import json
import struct
import sys
import uuid

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
ROOT = next(p for p in HERE.parents if (p/'tools/pydeps').is_dir())
HELPER = ROOT/'analysis/aitweaker_lock/lock_sage_1904/review/flash_readiness/verify_capsule_static.py'
HELPER_SHA = 'fc7348a36ba77cf100095db89de12e6f45963ed456b962c876839160fbe693c2'
SOURCE = HERE.parent/'lock_1904_candidate05/lab/asus_review/W790-ACE-1904-lock.review.bin'
SOURCE_SHA = '9b038c4eae111a985c5c5fef460f0874338d16764b0ead6f89a3e55c775f5455'
ORIGINAL = ROOT/'analysis/aitweaker_lock/official_W790_ACE_1904/W790_ACE_1904/Pro-WS-W790-ACE-ASUS-1904.CAP'
ORIGINAL_SHA = '03e4330430b2510d5e9e5c9868ca64c730844992b82c6a272b815aef3d20bf29'
OPENSSL = Path('D:/OpenSSL-Win64/bin/openssl.exe')
LIBCRYPTO = OPENSSL.parent/'libcrypto-4-x64.dll'
ARTIFACT = HERE/'W790-ACE-1904-CANDIDATE05-ENGINEERING-NONOEM-NOT-FLASH-READY.CAP'
BLOCKS = {'firmware': 0x38, 'certificate': 0x248}
ALLOWED_HEADER_RANGES = [(0x48, 0x148), (0x148, 0x248), (0x258, 0x358), (0x358, 0x458)]

def sha(data): return hashlib.sha256(data).hexdigest()
def record(path):
    return {'path': path.relative_to(ROOT).as_posix() if path.is_relative_to(ROOT) else str(path), 'bytes': path.stat().st_size, 'sha256': sha(path.read_bytes())}
def save(path, data): path.write_text(json.dumps(data, indent=2, ensure_ascii=False)+'\n', encoding='utf8')

def parser():
    code = HELPER.read_bytes(); assert sha(code) == HELPER_SHA
    names = {'sha', 'require', 'guid', 'mgf1', 'rsa_pss_sha256', 'parse_capsule', 'firmware_digest', 'signatures'}
    tree = ast.parse(code)
    functions = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name in names]
    assert {node.name for node in functions} == names
    scope = {'hashlib': hashlib, 'struct': struct, 'uuid': uuid,
             'CAPSULE_GUID': '4a3ca68b-7723-48fb-803d-578cc1fec44d', 'RSA_CERT_GUID': 'a7717414-c616-4977-9420-844712a735bf',
             'SHA256_GUID': '51aa59de-fdf2-4ea3-bc63-875fb7842ee9'}
    exec(compile(ast.Module(body=functions, type_ignores=[]), str(HELPER), 'exec'), scope)
    return scope

def inputs(scope):
    original = ORIGINAL.read_bytes(); source = SOURCE.read_bytes()
    assert sha(original) == ORIGINAL_SHA and sha(source) == SOURCE_SHA
    assert len(original) == len(source) == 0x4001000
    oh = scope['parse_capsule'](original); sh = scope['parse_capsule'](source)
    assert oh == sh and original[:4096] == source[:4096]
    original_signatures = scope['signatures'](original, oh); source_signatures = scope['signatures'](source, sh)
    assert all(v['valid'] for v in original_signatures.values())
    assert not source_signatures['firmware_signature']['valid'] and source_signatures['certificate_signature']['valid']
    return original, source, sh

def preservation(scope, source, candidate):
    header = scope['parse_capsule'](candidate)
    assert header == scope['parse_capsule'](source)
    assert len(source) == len(candidate) and source[4096:] == candidate[4096:]
    changes = [i for i in range(4096) if source[i] != candidate[i]]
    assert changes and all(any(a <= i < b for a, b in ALLOWED_HEADER_RANGES) for i in changes)
    for a, b in ALLOWED_HEADER_RANGES: assert source[a:b] != candidate[a:b]
    assert candidate[0x458:4096] == source[0x458:4096]
    return {'payload_bytes': len(source)-4096, 'payload_source_sha256': sha(source[4096:]), 'payload_candidate_sha256': sha(candidate[4096:]),
            'payload_byte_identical': True, 'map_flags_hash_identifiers_sizes_and_header_other_fields_unchanged': True,
            'allowed_ranges': [{'start': hex(a), 'end_exclusive': hex(b)} for a, b in ALLOWED_HEADER_RANGES],
            'actual_changed_header_bytes': len(changes), 'changed_header_offsets': [hex(i) for i in changes],
            'resident_verifier_and_trust_anchor_bytes_modified': False}

def tlv(tag, value):
    n = len(value); count = (n.bit_length()+7)//8
    length = bytes([n]) if n < 128 else bytes([128+count])+n.to_bytes(count, 'big')
    return bytes([tag])+length+value

def public_pem(modulus):
    assert len(modulus) == 256 and modulus[0]&128
    der = tlv(0x30, tlv(2, b'\0'+modulus)+tlv(2, b'\x01\0\x01'))
    encoded = base64.b64encode(der)
    return b'-----BEGIN RSA PUBLIC KEY-----\n'+b'\n'.join(encoded[i:i+64] for i in range(0, len(encoded), 64))+b'\n-----END RSA PUBLIC KEY-----\n'
