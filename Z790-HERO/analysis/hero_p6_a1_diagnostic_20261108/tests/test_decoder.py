"""Independent frame encoder exercises A1 completeness and mixing rejection."""
from pathlib import Path
import importlib.util,json,zlib
BASE=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('a1decoder',BASE/'decode_captures.py');d=importlib.util.module_from_spec(spec);spec.loader.exec_module(d)
def frames(data):
 out=[];total=len(data)
 for off in range(0,total,512):
  part=data[off:off+512];header=f'HERO-P6-A1-DIAGNOSTIC-QR1\nT={total};C={zlib.crc32(data):08X};P={off//512+1}/{(total+511)//512};O={off};N={len(part)};D={zlib.crc32(part):08X}\n\n'.encode()
  out.append(header+part)
 return out
full=(BASE/'tests/OFFLINE-A1-FULL.txt').read_bytes().split(b'\n',1)[1].replace(b'\r\r\n',b'\r\n')+b'SNAPSHOT_END\r\n'
compact=(BASE/'tests/OFFLINE-A1-COMPACT.txt').read_bytes();rows=[]
def accept(name,data):
 f=frames(data);got,_=d.assemble(list(reversed(f))+f[:1]);assert got==data;rows.append(name)
def reject(name,f):
 try:d.assemble(f)
 except ValueError:rows.append(name);return
 raise AssertionError(name)
accept('full trace exact roundtrip shuffled pages and duplicate',full)
accept('compact summary exact roundtrip shuffled pages and duplicate',compact)
reject('cannot mix full and compact snapshots',frames(full)[:1]+frames(compact))
reject('missing page rejected',frames(compact)[1:])
f=frames(compact);f[0]=f[0][:-1]+bytes([f[0][-1]^1]);reject('page corruption rejected',f)
reject('incomplete log marker rejected',frames(compact.replace(b'SNAPSHOT_END',b'SNAPSHOT_INCOMPLETE')))
reject('foreign old RAMCHECK header rejected',frames(b'HERO-P6-RAMCHECK-3\r\nRUN=0\r\nSNAPSHOT_END\r\n'))
data=b'HERO-P6-A1-DIAGNOSTIC\r\nRUN=TEST\r\n'+b'X'*1100000+b'\r\nSNAPSHOT_END\r\n';accept('seven digit total and offset exact roundtrip',data)
report={'passed':True,'cases':len(rows),'results':rows,'method':'Independent Python frame encoder; actual QR renderer roundtrip separately verified under OVMF.'}
(BASE/'tests/decoder.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report))
