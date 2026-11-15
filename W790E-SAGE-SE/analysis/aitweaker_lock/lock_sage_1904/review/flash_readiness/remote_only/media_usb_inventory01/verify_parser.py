from pathlib import Path
import hashlib,json
from decode_inventory_log import parse
HERE=Path(__file__).resolve().parent
good=[]
for p in sorted((HERE/'review/native_logs').glob('*.txt')):
    b=p.read_bytes()
    if b:
        r=parse(b);good.append({'case':p.stem,'complete':r['complete'],'overflow':r['overflow'],'bytes':len(b)})
b=(HERE/'review/native_logs/mixed_devices.txt').read_bytes()
bad=[b[:-1],b.replace(b'PROBE_COMPLETE',b'OTHER_COMPLETE'),b'wrong\r\n'+b,b+b'extra',b.replace(b'LOG_OVERFLOW=0',b'LOG_OVERFLOW=0\r\nLOG_OVERFLOW=0'),b.replace(b'HANDLES_REPORTED=0005',b'HANDLES_REPORTED=0004'),b.replace(b'HANDLE_END=0000',b'HANDLE_END=0001'),b.replace(b'USB_VID=046B',b'USB_VID=0000',1),b.replace(b'VENDOR_HD_ID_MATCH=1',b'VENDOR_HD_ID_MATCH=0',1),b.replace(b'DP_BYTES=000A',b'DP_BYTES=0009',1),b.replace(b'INVENTORY_COMPLETE=1',b'INVENTORY_COMPLETE=2'),b.replace(b'ENUMERATION_UNCERTAIN=0',b'ENUMERATION_UNCERTAIN=1'),b.replace(b'TEST_STATUS=0000000000000000',b'TEST_STATUS=8000000000000007'),b.replace(b'USB_PID=FF31',b'USB_PID=FF31\r\nUSB_PID=FF31',1)]
for i,x in enumerate(bad):
    try:parse(x)
    except (ValueError,KeyError):pass
    else:raise AssertionError('Badlog accepted '+str(i))
out={'status':'PASS','accepted_fixture_logs':len(good),'rejected_mutations':len(bad),'accepted':good,'parser_sha256':hashlib.sha256((HERE/'decode_inventory_log.py').read_bytes()).hexdigest()}
(HERE/'build/parser_verification.json').write_text(json.dumps(out,indent=2));print(json.dumps({'status':'PASS','accepted':len(good),'rejected':len(bad)}))
