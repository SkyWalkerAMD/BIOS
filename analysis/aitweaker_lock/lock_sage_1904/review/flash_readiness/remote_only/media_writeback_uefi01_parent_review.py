"""Independent bounded review of frozen child file-test artifacts and QR parser."""
from pathlib import Path
import hashlib,importlib.util,json,sys
HERE=Path(__file__).resolve().parent
WB=HERE/'media_writeback_uefi01';HW=HERE.parents[2]/'remote_172_20_2_162'
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
manifest=json.loads((WB/'candidate_manifest.json').read_text())
for item in manifest['artifacts']:
    p=Path(item['path']);assert p.stat().st_size==item['bytes'] and sha(p)==item['sha256']
spec=importlib.util.spec_from_file_location('wbqr',HW/'read_media_writeback01_qr.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
vm=json.loads((WB/'build/ovmf_verification.json').read_text())
rows=[]
for item in vm['cases']:
    p=WB/item['folder']/'RESTORED-LOG.TXT';raw=p.read_bytes()
    parsed=m.parse_log(raw)
    assert (parsed['efi_status']=='0x0')==(item['case']=='positive')
    rows.append({'case':item['case'],'passed':True,'log_sha256':sha(p)})
positive=(WB/vm['cases'][0]['folder']/'RESTORED-LOG.TXT').read_bytes()
mutations=[positive.replace(b'FILE_WRITE_BYTES=0x0000000000000078',b'FILE_WRITE_BYTES=0x0000000000000077'),
           positive.replace(b'UEFI_FILE_READBACK_STATUS=0x0000000000000000',b'UEFI_FILE_READBACK_STATUS=0x8000000000000007'),
           positive.replace(b'EXACT_MATCHES=0x0000000000000001',b'EXACT_MATCHES=0x0000000000000002'),
           positive.replace(b'EXPECTED_FILE_CRC32=0x000000002DC67546',b'EXPECTED_FILE_CRC32=0x000000002DC67547'),
           positive.replace(b'PROBE_COMPLETE\r\n',b''),
           positive.replace(b'TEST_STATUS=',b'TEST_STATUS_DUPLICATE='),
           positive.replace(b'PROBE_COMPLETE\r\n',b'TEST_STATUS=0x0000000000000000\r\nPROBE_COMPLETE\r\n')]
for i,raw in enumerate(mutations):
    assert raw!=positive
    try:m.parse_log(raw)
    except ValueError:rows.append({'case':f'mutation_{i+1}_rejected','passed':True})
    else:raise AssertionError('Invalid success log accepted')
report={'status':'PASS_PARENT_ARTIFACT_AND_QR_REVIEW','artifact_count':len(manifest['artifacts']),
        'cases':rows,'case_count':len(rows),'manifest_sha256':sha(WB/'candidate_manifest.json'),
        'efi_sha256':sha(WB/'build/BOOTX64.EFI'),'iso_sha256':sha(WB/'build/SAGE1904-MEDIA-WRITEBACK01.iso'),
        'parser_sha256':sha(HW/'read_media_writeback01_qr.py'),'source_sha256':sha(Path(__file__)),
        'scope':'Pins frozen artifact hashes and independently parses seven actual OVMF logs; no hardware claim.'}
(HERE/'media_writeback_uefi01_parent_review.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps({'status':report['status'],'artifacts':report['artifact_count'],'cases':len(rows)}))
