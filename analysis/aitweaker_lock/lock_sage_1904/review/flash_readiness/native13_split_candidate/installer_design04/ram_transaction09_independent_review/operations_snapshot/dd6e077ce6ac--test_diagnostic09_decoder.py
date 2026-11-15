"""Synthetic format corruption tests, awaiting actual provider output binding."""
from pathlib import Path
import hashlib,json,struct,zlib
from decode_diagnostic09 import decode
HERE=Path(__file__).resolve().parent
# Known arbitrary scalars include signed sentinels and unavailable bits.
values=[1,2,1,5,11,2,4,5,11,2,0xffffffff,0,1,0,0xffffffff,4,14,0x6d6f0,2,0xffffffff,3,4]
assert len(values)==22
payload=struct.pack('<3Q19I',*values)
crc=zlib.crc32(payload)&0xffffffff
sample=('D09 R=0000000000000001 P=0000000000000002 A=0000000000000001\n'
        'F H=00000005 E=0000000B D=00000002 K=00000004\n'
        'R H=00000005 E=0000000B D=00000002 C=FFFFFFFF\n'
        'P I=00000000 F=00000001 O=00000000 V=FFFFFFFF\n'
        'C K=00000004 T=0000000E V=0006D6F0 H=00000002 O=FFFFFFFF\n'
        f'S V=00000003 F=00000004 CRC={crc:08X}\n')
r=decode(sample)
assert r['scalar_sha256']==hashlib.sha256(payload).hexdigest()
checks=['Complete100B scalar order and independent struct checksum match']
for label,text in [
    ('bit substitution',sample.replace('H=00000005','H=00000004',1)),
    ('missing line','\n'.join(sample.splitlines()[1:])),
    ('repeated line',sample+sample.splitlines()[0]),
    ('OCR character',sample.replace('0006D6F0','OOO6D6FO')),
    ('unknown field',sample.replace('K=00000004','Z=00000004',1)),
    ('truncated scalar',sample.replace('D=00000002','D=0000002',1)),
    ('extra text',sample+'CRC verified'),
    ('unicode',sample.replace('D09','Ｄ09')),
    ('too large',sample+' '*2048),
]:
    try:decode(text)
    except ValueError:checks.append(label+' rejected')
    else:raise AssertionError(label)
(HERE/'diagnostic09_synthetic_display.txt').write_text(sample,encoding='ascii')
report={'status':'PASS_SYNTHETIC_DIAGNOSTIC_DISPLAY_DECODER','checks':checks,
        'decoder_sha256':hashlib.sha256((HERE/'decode_diagnostic09.py').read_bytes()).hexdigest(),
        'sample_sha256':hashlib.sha256(sample.encode('ascii')).hexdigest(),
        'actual_provider_output_tested':False,'device_calls':0,'full_record_crc_claim':False}
(HERE/'diagnostic09_decoder_tests.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
print(json.dumps(report))
