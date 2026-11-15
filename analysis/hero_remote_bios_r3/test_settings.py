"""Exercise exact-change, stale-snapshot, malformed-journal and recovery bounds."""
from pathlib import Path
import ctypes as C,hashlib,json,random,zlib
OUT=Path(__file__).resolve().parent
dll=C.CDLL(str(OUT/'settings_test.dll'))
class Tx(C.Structure):
 _fields_=[(n,C.c_uint32) for n in ('magic','version','size','setting','before_crc','after_crc','attrs','setup_size')]+[('old_value',C.c_uint8),('new_value',C.c_uint8),('reserved',C.c_uint8*26),('checksum',C.c_uint32)]
B=C.c_uint8*3398
dll.prepare_update.argtypes=[C.c_void_p,C.c_size_t,C.c_uint32,C.c_uint32,C.c_uint32,C.c_void_p,C.c_void_p];dll.prepare_update.restype=C.c_int
dll.prepare_restore.argtypes=[C.c_void_p,C.c_size_t,C.c_void_p,C.c_void_p];dll.prepare_restore.restype=C.c_int
dll.transaction_valid.argtypes=[C.c_void_p];dll.transaction_valid.restype=C.c_int
count=0
def check(v):
 global count
 assert v;count+=1
check(C.sizeof(Tx)==64)
rng=random.Random(3107);offsets=(0,3293,3291);maxima=(1,1,10)
for setting in range(3):
 for old in range(maxima[setting]+1):
  before=bytearray(rng.randbytes(3398));before[offsets[setting]]=old;src=B.from_buffer_copy(before);crc=zlib.crc32(before)
  for new in range(maxima[setting]+1):
   dst=B();t=Tx();rc=dll.prepare_update(src,3398,setting,new,crc,dst,C.byref(t))
   check(bool(rc)==(new!=old))
   if not rc:continue
   expected=before.copy();expected[offsets[setting]]=new
   check(bytes(dst)==bytes(expected));check(dll.transaction_valid(C.byref(t))==1)
   check(t.before_crc==crc and t.after_crc==zlib.crc32(expected))
   restored=B();check(dll.prepare_restore(dst,3398,C.byref(t),restored)==1);check(bytes(restored)==before)
   check(dll.prepare_restore(src,3398,C.byref(t),restored)==2)
   unrelated=bytearray(expected);unrelated[200]^=1
   check(dll.prepare_restore(B.from_buffer_copy(unrelated),3398,C.byref(t),restored)==0)
   check(dll.prepare_update(src,3398,setting,new,crc^1,dst,C.byref(Tx()))==0)
   for i in range(64):
    bad=bytearray(bytes(t));bad[i]^=1
    check(dll.transaction_valid(C.byref(Tx.from_buffer_copy(bad)))==0)
   bad=Tx.from_buffer_copy(t);bad.attrs=3;bad.checksum=zlib.crc32(bytes(bad)[:60]);check(dll.transaction_valid(C.byref(bad))==0)
   bad=Tx.from_buffer_copy(t);bad.setting=99;bad.checksum=zlib.crc32(bytes(bad)[:60]);check(dll.transaction_valid(C.byref(bad))==0)
   for length in (0,3397,3399):
    check(dll.prepare_update(src,length,setting,new,crc,dst,C.byref(Tx()))==0)
    check(dll.prepare_restore(src,length,C.byref(t),restored)==0)
for sid,value in ((3,0),(0,2),(1,2),(2,11),(0,0xffffffff),(0xffffffff,0)):
 src=B();check(dll.prepare_update(src,3398,sid,value,zlib.crc32(bytes(src)),B(),C.byref(Tx()))==0)
ifr=json.loads((OUT/'hero-3107-ifr.json').read_text());wanted={'Bootup NumLock State':(0,1),"Wait For 'F1' If Error":(3293,1),'  POST Delay Time':(3291,10)}
for label,(offset,maximum) in wanted.items():
 q=next(q for q in ifr['questions'] if q['prompt']==label and q['form']=='Boot Configuration')
 check(q['store']['name']=='Setup' and q['store']['size']==3398 and q['store']['guid']=='ec87d643-eba4-4bb5-a1e5-3f3e36b20da9')
 check(q['var_offset']==offset and q['width']==1 and q['flags']==16 and q['maximum']==maximum)
 check({x['value'] for x in q['options']}==set(range(maximum+1)))
check((OUT/'reference/HERO-3107-Setup.efi').read_bytes()[0xc8b93:0xc8b9b]==bytes.fromhex('0a821206c72c0000'))
report={'passed':True,'assertions':count,'dll_sha256':hashlib.sha256((OUT/'settings_test.dll').read_bytes()).hexdigest(),'coverage':['Every supported original/new value pair','Exact one-byte change and original restoration','Refuse stale/changed full-variable state','Every transaction byte corruption','Recomputed CRC cannot bypass setting/attribute policy','Wrong sizes and out-of-range values','Mappings cross-checked against HERO 3107 IFR']}
(OUT/'unit-tests.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
