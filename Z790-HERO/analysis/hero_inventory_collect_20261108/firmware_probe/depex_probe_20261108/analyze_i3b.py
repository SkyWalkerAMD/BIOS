"""Validate I3B QR payloads and analyze dependency observations without changing them."""
from pathlib import Path
import argparse
import hashlib
import importlib.util
import json
import re
import sys
import zlib

sys.dont_write_bytecode = True
OUT = Path(__file__).resolve().parent
ROOT = OUT.parents[3]
CAPTURE = ROOT / 'analysis/hero_ipmi_continued_live_20261108/hero71-i3b-preflight.TXT'
FRAMES = CAPTURE.parent / 'captures/hero71-i3b-preflight'
DECODER = ROOT / 'analysis/hero_inventory_publish_i3b_20261108/decode_captures.py'


def load_capture(require_full):
    spec = importlib.util.spec_from_file_location('i3b_decoder_readonly', DECODER)
    decoder = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(decoder)
    raw_frames = [p.read_bytes() for p in sorted(FRAMES.glob('*.qr.bin'))]
    frames = [decoder.parse_frame(raw) for raw in raw_frames]
    assert frames, 'No individually validated frames'
    first = frames[0]
    key = first['total'], first['crc'], first['pages']
    assert all((f['total'], f['crc'], f['pages']) == key for f in frames), 'Mixed snapshots'
    parts = {}
    for f in frames:
        assert f['page'] not in parts or parts[f['page']] == f['data'], 'Conflicting page'
        parts[f['page']] = f['data']
    if CAPTURE.exists():
        assembled, meta = decoder.assemble(raw_frames)
        data = CAPTURE.read_bytes()
        assert data == assembled, 'Published TXT differs from validated QR assembly'
        return data, dict(complete=True, **meta, path=CAPTURE.relative_to(ROOT).as_posix())
    if require_full:
        raise RuntimeError('Full capture TXT has not landed; no full-CRC claim is made')
    count = 0
    while count+1 in parts:
        count += 1
    data = b''.join(parts[i] for i in range(1, count+1))
    # Exclude an incomplete last line from semantic interpretation.
    safe = data[:data.rfind(b'\n')+1]
    return safe, dict(complete=False, individually_validated_pages=len(parts),
        contiguous_prefix_pages=count, expected_pages=first['pages'],
        prefix_bytes=len(data), interpreted_complete_line_bytes=len(safe),
        expected_total_bytes=first['total'], expected_crc32=f"{first['crc']:08X}",
        crc_note='Expected whole CRC is unverified; only individual received pages were verified.')


def parse_block(block):
    protocols = []
    fields = {}
    record = None
    for line in block.splitlines():
        if '=' not in line:
            continue
        key, value = line.split('=', 1)
        if key == 'DP_PROTOCOL':
            record = dict(name=value)
            protocols.append(record)
        elif key in ('DP_GUID', 'DP_LOCATE_STATUS', 'DP_INTERFACE', 'DP_PRESENT'):
            assert record is not None
            record[key] = value
        else:
            fields[key] = value
    assert len(protocols) == 5 and all('DP_PRESENT' in p for p in protocols)
    for protocol in protocols:
        status = int(protocol['DP_LOCATE_STATUS'], 16)
        present = int(protocol['DP_PRESENT'], 16)
        assert present == (1 if status == 0 else 0 if status == (1 << 63) | 14 else 2)
        protocol['present'] = present
        protocol['null_interface'] = int(protocol['DP_INTERFACE'], 16) == 0
    by_name = {p['name']: p['present'] for p in protocols}
    def both(values):
        return 0 if 0 in values else 2 if 2 in values else 1
    r2 = both([by_name['PciEnumerationComplete'], by_name['VariableWriteArch']])
    p6 = both([by_name['HiiDatabase'], by_name['HiiString'], by_name['VariableWriteArch']])
    assert r2 == int(fields['DP_R2_DEPEX_AT_CAPTURE'], 16)
    assert p6 == int(fields['DP_P6_DEPEX_AT_CAPTURE'], 16)
    network = {k: v for k, v in fields.items() if k.startswith('DP_NETWORK_')}
    if 'DP_NETWORK_RAW' in network:
        raw = bytes.fromhex(network['DP_NETWORK_RAW'])
        assert len(raw) == int(network['DP_NETWORK_BYTES'], 16) <= 64
        assert int(network['DP_NETWORK_STATUS'], 16) == 0
        assert int(network['DP_NETWORK_BUFFER_GUARD'], 16) == 1
        network['byte0_decimal'] = raw[0] if raw else None
    return dict(protocols=protocols, r2_expression_at_capture=r2,
        p6_expression_at_capture=p6, network_variable=network)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--require-full', action='store_true')
    args = parser.parse_args()
    raw, meta = load_capture(args.require_full)
    text = raw.decode('ascii')
    blocks = re.findall(r'HERO_DEPEX_READONLY_D1_BEGIN\r?\n(.*?)HERO_DEPEX_READONLY_D1_END', text, re.S)
    observations = [parse_block(b) for b in blocks]
    result = dict(scope='Read-only offline analysis; no browser/KVM, BMC or firmware operations.',
        capture=meta, depex_observations=observations,
        related_status_lines=[line for line in text.splitlines() if line.startswith((
            'I3B_DEPEX_DIAGNOSTIC=', 'I3B_INVENTORY_SOURCE_EXACT=', 'I3_IDENTITY_STATUS=',
            'I3_TARGET_71_VERIFIED=', 'I3B_PREFLIGHT_', 'I3_PREFLIGHT_'))],
        correlation_with_i2b=dict(
            reference='i2b-analysis.json',
            earlier_evidence='I2B found R2 and early-RC4 P6 in visible FV index 6 by size/CRC/DEPEX correspondence; their LoadedImage path matches and exposed APIs were absent at I2B capture.',
            limitation='I3B dependency status is a later application-stage observation; it neither remeasures those module fingerprints nor proves earlier DXE dispatch history.'),
        findings=[])
    for obs in observations:
        if obs['r2_expression_at_capture'] == 1 and obs['p6_expression_at_capture'] == 1:
            result['findings'].append('All operands of both captured R2/P6 DEPEX expressions are present at the I3B query; missing VariableWriteArch at this query is ruled out.')
            result['findings'].append('This observation does not explain earlier absent APIs by a currently unsatisfied DEPEX. Entry failure, dispatch/loader policy, discovery timing, or later unload remain unproven alternatives; do not remove the dependency based on these logs.')
        else:
            missing = [p['name'] for p in obs['protocols'] if p['present'] == 0]
            result['findings'].append('At this query the missing protocols are: '+', '.join(missing)+'. This is not a reconstruction of DXE-time protocol state.')
    if not meta['complete']:
        result['findings'].insert(0, 'PARTIAL snapshot: semantic observations derive only from validated contiguous received pages; whole-log completeness/CRC has NOT been established.')
    output = OUT / ('i3b-live-analysis.json' if meta['complete'] else 'i3b-partial-analysis.json')
    output.write_text(json.dumps(result, indent=2)+'\n', encoding='utf-8')
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
