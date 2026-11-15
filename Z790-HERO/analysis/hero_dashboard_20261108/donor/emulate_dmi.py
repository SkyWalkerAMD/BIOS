"""Offline execution of exact Creator DMI packet constructor and IPMI wrapper.
All firmware services are inert bounded mocks. No hardware or network calls.
"""
from pathlib import Path
import sys,json,struct,hashlib
OUT=Path(__file__).resolve().parent;ROOT=OUT.parents[2]
sys.path.insert(0,str(ROOT/'tools/pydeps'))
sys.path.insert(0,str(ROOT/'analysis/hero_inventory_20261108'))
import pefile
from unicorn import Uc,UC_ARCH_X86,UC_MODE_64,UC_HOOK_CODE
from unicorn.x86_const import *
from smbios_inventory import parse_capture,block

PE=OUT/'B1DA0ADF-4F77-4070-A88E-BFFE1C60529A.efi'
raw=PE.read_bytes(); sha=hashlib.sha256(raw).hexdigest()
assert sha=='3ac7e59349b706b82c29ff1fa8a9adea4746380c22e77aaed955f3c2a11e6b17'
image=pefile.PE(data=raw).get_memory_mapped_image()
capture=ROOT/'analysis/hero_ipmi_continued_live_20261108/hero71-smbios-i1.TXT'
text=capture.read_text();records,meta=parse_capture(text)
actual={r['type']:r for r in records if r['type'] in (0,1,2)}

BASE=0x100000; SMB=0x300000; TABLE=0x310000; BS=0x400000
STACK=0x500000; POOL=0x600000; STUB=0x700000; IPMI=0x800000; DESC=0x810000
NOT_FOUND=0x800000000000000e

def replay(recs):
    uc=Uc(UC_ARCH_X86,UC_MODE_64)
    for at,size in [(BASE,0x100000),(SMB,0x20000),(BS,0x1000),(STACK,0x20000),
                    (POOL,0x100000),(STUB,0x1000),(IPMI,0x20000)]:uc.mem_map(at,size)
    uc.mem_write(BASE,image)
    def q(at,val):uc.mem_write(at,struct.pack('<Q',val))
    def rdq(at):return struct.unpack('<Q',uc.mem_read(at,8))[0]
    def reg(r):return uc.reg_read(r)
    q(BASE+0x786c8,BS);q(BASE+0x862d8,SMB);q(BASE+0x78b30,IPMI)
    q(SMB+0x18,STUB+0x100);q(BS+0x40,STUB+0x200);q(BS+0x48,STUB+0x300)
    q(BS+0x168,STUB+0x400);q(IPMI+8,STUB+0x500)
    ptrs={};off=0
    for typ,r in recs.items():
        data=r['data']+b'\0'.join(s.encode() for s in r['strings'])+b'\0\0'
        ptrs[typ]=TABLE+off;uc.mem_write(TABLE+off,data);off+=0x1000
    uc.mem_write(STACK,b'\xa5'*0x20000)
    sp=STACK+0x18000-8;q(sp,STUB+0x800)
    uc.reg_write(UC_X86_REG_RSP,sp);uc.reg_write(UC_X86_REG_RCX,DESC)
    calls=[];packets=[];pool={};free=[];nextpool=POOL;finished=[]
    def finish(status=0):
        rsp=reg(UC_X86_REG_RSP);ret=rdq(rsp)
        uc.reg_write(UC_X86_REG_RAX,status);uc.reg_write(UC_X86_REG_RSP,rsp+8);uc.reg_write(UC_X86_REG_RIP,ret)
    def hook(uc,addr,size,_):
        nonlocal nextpool
        if not STUB<=addr<STUB+0x1000:return
        a,b,c,d=map(reg,(UC_X86_REG_RCX,UC_X86_REG_RDX,UC_X86_REG_R8,UC_X86_REG_R9))
        sp=reg(UC_X86_REG_RSP)
        if addr==STUB+0x100:
            typ=uc.mem_read(c,1)[0];calls.append({'service':'Smbios.GetNext','type':typ})
            if typ not in recs:finish(NOT_FOUND);return
            q(d,ptrs[typ]);uc.mem_write(b,recs[typ]['data'][2:4]);finish()
        elif addr==STUB+0x200:
            assert b in (1,255)
            dest=nextpool;nextpool+=0x1000;pool[dest]=b;q(c,dest);finish()
        elif addr==STUB+0x300:
            assert a in pool and a not in free;free.append(a);finish()
        elif addr==STUB+0x400:
            assert STACK<=a<a+b<=STACK+0x20000 and b<=400
            uc.mem_write(a,bytes([c&255])*b);finish()
        elif addr==STUB+0x500:
            ptr=rdq(sp+0x28);length=uc.mem_read(sp+0x30,1)[0]
            body=bytes(uc.mem_read(ptr,length));resp=rdq(sp+0x38);rp=rdq(sp+0x40)
            packets.append({'netfn':b&255,'lun':c&255,'command':d&255,'request_hex':body.hex(),
                'request_bytes':len(body),'selector':body[0],'strings':body[1:].split(b'\0')[:-1]})
            uc.mem_write(resp,b'\0');uc.mem_write(rp,b'\x01');finish()
        elif addr==STUB+0x800:finished.append(reg(UC_X86_REG_RAX));uc.emu_stop()
        else:raise AssertionError('unexpected stub '+hex(addr))
    uc.hook_add(UC_HOOK_CODE,hook)
    uc.emu_start(BASE+0x3a0f4,STUB+0x900,count=1000000)
    assert finished,'bounded execution failed to return'
    assert set(pool)==set(free),'pool leak in tested path'
    for p in packets:p['strings']=[s.decode('ascii') for s in p['strings']]
    return dict(return_status=hex(finished[0]),calls=calls,packets=packets,pools_allocated=len(pool),pools_freed=len(free))

def expected(record,offsets,sel):
    def s(o):return record['strings'][record['data'][o]-1].encode()+b'\0'
    return bytes([sel])+b''.join(s(o) for o in offsets)

live=replay(actual)
for item,typ,offsets in zip(live['packets'],(0,1,2),((5,8),(4,5,6,7),(4,5,6,7))):
    assert item['netfn']==0x30 and item['lun']==0 and item['command']==4
    assert bytes.fromhex(item['request_hex'])==expected(actual[typ],offsets,typ)
    (OUT/f'hero71-selector{typ}.request.bin').write_bytes(bytes.fromhex(item['request_hex']))

# Reorder Type2 physical strings to prove indexed selection rather than raw set.
reordered={t:{**r,'strings':list(r['strings'])} for t,r in actual.items()}
r=reordered[2];r['strings']=list(reversed(r['strings']));d=bytearray(r['data'])
for o in (4,5,6,7):d[o]=len(r['strings'])+1-d[o]
r['data']=bytes(d)
reordered_result=replay(reordered)
assert reordered_result['packets']==live['packets']

# Missing Type0 exits before any command; missing Type2 proves prior operations
# are not rolled back, so the native reference must not be copied as an atomic API.
missing0=replay({k:v for k,v in actual.items() if k!=0});assert not missing0['packets']
missing2=replay({k:v for k,v in actual.items() if k!=2});assert len(missing2['packets'])==2

result={'passed':True,'scope':'Offline actual Creator PE machine code; mocked SMBIOS, pool, SetMem, IPMI send only',
    'pe_sha256':sha,'constructor_rva':'0x3a0f4','string_helper_rva':'0x3a038',
    'packet_helper_rva':'0x3a098','transport_wrapper_rva':'0x39d1c',
    'source_capture':str(capture.relative_to(ROOT)), 'smbios_source':meta,
    'actual_case':live,'reordered_strings_same_packets':True,
    'missing_type0':missing0,'missing_type2':missing2,
    'warning':'Reference ignores individual OEM return statuses and is not an atomic transaction. Do not replicate unchecked source/string behavior.'}
(OUT/'donor-dmi-machine-code.json').write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps(result,indent=2))
