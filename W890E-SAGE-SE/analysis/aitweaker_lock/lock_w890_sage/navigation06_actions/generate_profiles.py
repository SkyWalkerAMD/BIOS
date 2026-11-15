"""Reproduce static local profiles from immutable original bytes/snapshot."""
from pathlib import Path
import sys,json,zipfile,struct,hashlib
H=Path(__file__).resolve().parent;B=H.parent;R=H.parents[3]
sys.path.insert(0,str(R/'tools/pydeps'));import pefile
P=B/'navigation/modules/Setup.efi';p=pefile.PE(str(P));im=p.get_memory_mapped_image();rows=[]
for i in range(2048):
 a=0x2c600+16*i;kind,qid,fn=struct.unpack_from('<IH2xQ',im,a)
 if not fn:break
 rows.append({'index':i,'rva':a,'type':kind,'qid':qid,'handler':hex(fn)})
assert len(rows)==883 and len({x['handler']for x in rows})==35
(H/'setup_handler_table.json').write_text(json.dumps({'entries':rows,'terminator_rva':a,'terminator_hex':im[a:a+16].hex()},indent=2)+'\n')
Z=B/'integration05/parser-snapshot.zip'
with zipfile.ZipFile(Z)as z:s=json.loads(z.read('state.json'));pool=z.read('pool.bin');m=z.read('tse-mapped.bin')
def read(a,n):
 if s['pool_base']<=a and a+n<=s['pool_base']+len(pool):return pool[a-s['pool_base']:a-s['pool_base']+n]
 raise ValueError(hex(a))
def q(a):return int.from_bytes(read(a,8),'little')
def u(a):return int.from_bytes(read(a,4),'little')
pt=int.from_bytes(m[0xbaaf0:0xbaaf8],'little');blob=int.from_bytes(m[0xbabc0:0xbabc8],'little');cb=int.from_bytes(m[0xbab08:0xbab10],'little')
x=next(x for x in s['pages']if x['hii']and x['form']==0x2712);raw=blob+u(pt+4+x['index']*4);count=u(raw+0x1c);rows=[]
for i in range(count):
 c=cb+u(raw+0x20+i*4);d=read(c,64);op=q(c+0x28);length=read(op+1,1)[0]&127 if op else 0
 rows.append({'index':i,'qid':int.from_bytes(d[12:14],'little'),'kind':int.from_bytes(d[20:22],'little'),'flags':int.from_bytes(d[28:32],'little'),'ifr_hex':read(op,length).hex()if op else None})
assert count==55 and not any(x['flags']&32 for x in rows)
out={'snapshot_sha256':hashlib.sha256(Z.read_bytes()).hexdigest(),'form':0x2712,'control_count':count,'rows':rows,'scope':'Main descriptors from immutable bounded original parser snapshot; not complete parser boot evidence'}
(H/'main_profile.json').write_text(json.dumps(out,indent=2)+'\n')
t='/* Generated exact Main zero-callback descriptor profile; see main_profile.json. */\n'
t+='typedef struct {uint16_t qid,kind;uint32_t flags;unsigned length;uint8_t ifr[127];} N06_MAIN_CONTROL;\nstatic const N06_MAIN_CONTROL n06_main_controls[]={\n'
for row in rows:
 b=bytes.fromhex(row['ifr_hex']or'');t+='{'+f'{row["qid"]},{row["kind"]},{row["flags"]},{len(b)}'+',{'+','.join(hex(x)for x in b)+'}},\n'
t+='};\n';(H/'main_profile.inc').write_text(t)
