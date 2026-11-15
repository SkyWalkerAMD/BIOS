"""Actual PE whitelist/authorization checks. No firmware or network calls."""
from pathlib import Path
import hashlib,json,struct
import verify as core
OUT=Path(__file__).resolve().parent
m=core.Machine();k=m.alloc(bytes(272));buf=m.alloc(bytes(272));used=m.alloc(bytes(8))
rows=[]
for nf,cmd,data in [(48,148,b'\x20\0'),(48,148,b'\x20\1'),(48,154,b'\0\1\1'),
    (48,154,b'\1\1'+bytes(15)),(48,154,b'\2\1'+bytes(15)),(48,154,b'\3\1'+bytes(15)),
    (48,154,b'\4\0'),(4,40,b'\x20\xc0'),(6,2,b''),(10,39,b'CLR\xaa')]:
    p=m.alloc(data or b'\0');n=len(m.calls)
    assert m.call('kcs_query',k,nf,cmd,p,len(data),buf,272,used)==7
    assert not m.dev.packets and len(m.calls)==n and m.r64(used)==0
    rows.append(dict(netfn=nf,command=cmd,data=data.hex(),denied=True))
assert m.call('rpm_query',k,buf,272,used)==7 and not m.dev.packets
rows.append(dict(case='unarmed_rpm_query',denied=True))
m=core.Machine();m.w64(m.functions['audit_len'],131072-49000)
assert m.call('engine_run',1)!=0 and not m.dev.packets and not m.pci_writes and not m.nv_writes
rows.append(dict(case='audit_headroom_gate_before_hardware',denied=True))
result=dict(all_passed=True,count=len(rows),cases=rows,driver_sha256=hashlib.sha256((OUT/'USB/EFI/HERO/HeroIpmiR4.efi').read_bytes()).hexdigest(),hardware=False)
(OUT/'write-boundary-verification.json').write_text(json.dumps(result,indent=2)+'\n')
print('WRITE BOUNDARY PASS',len(rows))
