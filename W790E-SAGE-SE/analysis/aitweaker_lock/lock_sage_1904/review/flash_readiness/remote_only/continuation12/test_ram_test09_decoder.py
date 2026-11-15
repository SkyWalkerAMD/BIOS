"""Exercise new capture identity/completeness gates with real transport parsing."""
from pathlib import Path
import hashlib,importlib.util,json,sys,zlib
HERE=Path(__file__).resolve().parent
SOURCE=HERE.parents[3]/'remote_172_20_2_162/read_native13_ram_test09_qr.py'
spec=importlib.util.spec_from_file_location('test09_decoder',SOURCE)
m=importlib.util.module_from_spec(spec);sys.modules[spec.name]=m;spec.loader.exec_module(m)
raw=m.PREFIX+b'SNAPSHOT_ID=0000000000000007\r\n'+b'LOCAL_TEST_DATA=YES\r\n'*80+b'LOG_COMPLETE=YES\r\nLOG_OVERFLOW=NO\r\n'+m.END
def frames(data):
    out=[];total=len(data);pages=(total+767)//768;crc=zlib.crc32(data)
    for i in range(pages):
        part=data[i*768:(i+1)*768]
        out.append(f'AITWK-P3-KVM\nT={total};C={crc:08X};P={i+1}/{pages};O={i*768};N={len(part)};D={zlib.crc32(part):08X}\n\n'.encode()+part)
    return out
checks=[]
assert m.validate(raw)=='0000000000000007';parts=frames(raw)
joined,meta=m.decoder.assemble(parts[::-1],require_inventory=False);assert joined==raw and meta['sha256']==hashlib.sha256(raw).hexdigest();checks.append('out-of-order valid snapshot assembled with exact CRC/length and unique ID')
for label,bad in [
 ('wrong family',raw.replace(b'RAM_TEST09',b'PREREQUISITE04')),
 ('missing end',raw[:-len(m.END)]),
 ('duplicate end',raw+m.END),
 ('duplicate ID',raw.replace(b'LOCAL_TEST_DATA=YES',b'SNAPSHOT_ID=0000000000000008',1)),
 ('overflow',raw.replace(b'LOG_OVERFLOW=NO',b'LOG_OVERFLOW=YES')),
 ('incomplete',raw.replace(b'LOG_COMPLETE=YES',b'LOG_COMPLETE=NO')),
 ('duplicate complete',raw.replace(b'LOG_COMPLETE=YES',b'LOG_COMPLETE=YES\r\nLOG_COMPLETE=YES')),
 ('ID outside first chunk',raw.replace(b'SNAPSHOT_ID=0000000000000007\r\n',b'').replace(b'LOG_COMPLETE',b'SNAPSHOT_ID=0000000000000007\r\nLOG_COMPLETE')),
 ('oversize',raw[:-len(m.END)]+b'X'*24576+m.END),
]:
    try:m.validate(bad)
    except ValueError:checks.append(label+' rejected')
    else:raise AssertionError(label)
for label,selected in [('missing page',parts[1:]),('mixed snapshot',[parts[0],frames(raw.replace(b'0000000000000007',b'0000000000000008'))[1],*parts[2:]]),('page corruption',[parts[0][:-1]+b'X',*parts[1:]])]:
    try:m.decoder.assemble(selected,require_inventory=False)
    except ValueError:checks.append(label+' rejected')
    else:raise AssertionError(label)
tmp=HERE/'decoder09-immutability-fixture.bin'
m.put_exact(tmp,b'fixture');m.put_exact(tmp,b'fixture')
try:m.put_exact(tmp,b'changed')
except FileExistsError:checks.append('different existing evidence refused')
else:raise AssertionError('overwrite')
report={'status':'PASS_CAPTURE_TRANSPORT_AND_IDENTITY_GATES','checks':checks,'source_sha256':hashlib.sha256(SOURCE.read_bytes()).hexdigest(),'scope':'Synthetic frames through actual pinned decoder; no hardware and no claim of installer success'}
(HERE/'decoder09_tests.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report))
