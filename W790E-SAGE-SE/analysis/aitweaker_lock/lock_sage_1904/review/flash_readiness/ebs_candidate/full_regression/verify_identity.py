"""Execute compiled target discovery against synthetic SMBIOS tables in Unicorn.

Page mapping and LocateHandleBuffer are explicit firmware stubs. No device I/O,
real SMBIOS access or firmware write takes place. Positive identity stops before
loaded-image discovery; this does not prove successful ASUS automatic dispatch.
"""
from pathlib import Path
import hashlib, json, re, struct, sys, uuid

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[3]/'tools/pydeps'))
import pefile
import unicorn as U
from unicorn import x86_const as R

BASE=0x140000000;HEAP=0x60000000;STACK=0x70000000;STOP=0x50000000
q=lambda v:struct.pack('<Q',v)
symbols={n:int(v,16) for n,v in re.findall(r'^\s+[0-9A-Fa-f]{4}:[0-9A-Fa-f]{8}\s+(\S+)\s+([0-9A-Fa-f]{16})\s',(CANDIDATE/'build/driver.map').read_text(),re.M)}

def record(kind,length,strings,version_index=1,product_index=2):
    b=bytearray(length);b[0]=kind;b[1]=length
    if kind==0:b[5]=version_index
    if kind==2:b[4]=1;b[5]=product_index
    return bytes(b)+b'\0'.join(s.encode('ascii') for s in strings)+b'\0\0'

def execute(board='Pro WS W790E-SAGE SE',version='1904',smbios=3,damage=None,want=False):
    driver=CANDIDATE/'build/AiTweakerLock1904.efi'
    u=U.Uc(U.UC_ARCH_X86,U.UC_MODE_64)
    pe=pefile.PE(str(driver));pe.relocate_image(BASE);image=pe.get_memory_mapped_image()
    image_n=(len(image)+4095)&~4095
    ranges=[(BASE,BASE+image_n),(HEAP,HEAP+0x10000),(STACK,STACK+0x10000),(STOP,STOP+0x1000)]
    for lo,hi in ranges:u.mem_map(lo,hi-lo)
    u.mem_write(BASE,image)
    st=HEAP;bs=HEAP+0x1000;ct=HEAP+0x2000;entry=HEAP+0x3000;table=HEAP+0x4000
    raw=record(0,24,[version])+record(2,15,['ASUSTeK COMPUTER INC.',board])+record(127,4,[])
    if damage=='bad_record_length':raw=raw[:1]+b'\xff'+raw[2:]
    if damage=='unterminated':raw=raw[:24]+b'A'*24
    if smbios==3:
        ep=bytearray(24);ep[:5]=b'_SM3_';ep[6]=24;ep[7:11]=bytes([3,6,0,1])
        struct.pack_into('<IQ',ep,12,len(raw),table);ep[5]=(-sum(ep))&255
        guid='f2fd1544-9794-4a2c-992e-e5bbcf20e394'
    else:
        ep=bytearray(31);ep[:4]=b'_SM_';ep[5]=31;ep[6:8]=bytes([2,8]);ep[16:21]=b'_DMI_'
        struct.pack_into('<HIH',ep,22,len(raw),table,3);ep[21]=(-sum(ep[16:]))&255;ep[4]=(-sum(ep))&255
        guid='eb9d2d31-2d88-11d3-9a16-0090273fc14d'
    if damage=='checksum':ep[4 if smbios==2 else 5]^=1
    u.mem_write(table,raw);u.mem_write(entry,bytes(ep))
    u.mem_write(ct,uuid.UUID(guid).bytes_le+q(entry))
    u.mem_write(st+0x60,q(bs)+q(1)+q(ct))
    u.mem_write(bs+0x138,q(STOP+0x100))
    u.mem_write(symbols['system_table'],q(st))
    def getq(a):return struct.unpack('<Q',u.mem_read(a,8))[0]
    calls=[]
    def ret(value):
        sp=u.reg_read(R.UC_X86_REG_RSP);u.reg_write(R.UC_X86_REG_RAX,value);u.reg_write(R.UC_X86_REG_RIP,getq(sp));u.reg_write(R.UC_X86_REG_RSP,sp+8)
    def hook(uc,address,size,data):
        if address==STOP:uc.emu_stop()
        elif address==STOP+0x100:
            calls.append('locate_loaded_images');ret(0x800000000000000e)
        elif address==symbols['memory_present']:
            a=uc.reg_read(R.UC_X86_REG_RCX);n=uc.reg_read(R.UC_X86_REG_RDX)
            ret(int(n>0 and any(lo<=a and a+n<=hi for lo,hi in ranges)))
    for address in [STOP,STOP+0x100,symbols['memory_present']]:u.hook_add(U.UC_HOOK_CODE,hook,begin=address,end=address)
    sp=STACK+0xff08;u.mem_write(sp,q(STOP));u.reg_write(R.UC_X86_REG_RSP,sp);u.reg_write(R.UC_X86_REG_CR4,0x600)
    u.reg_write(R.UC_X86_REG_RCX,0);u.reg_write(R.UC_X86_REG_RDX,0)
    u.emu_start(symbols['discover'],STOP+0x200,count=1000000)
    assert u.reg_read(R.UC_X86_REG_RIP)==STOP
    observed=struct.unpack('<I',u.mem_read(symbols['matching_board'],4))[0]
    assert observed==int(want),(board,version,smbios,damage,observed)
    assert calls==(['locate_loaded_images'] if want else [])
    assert bytes(u.mem_read(symbols['platform_ready'],4))==b'\0'*4
    return {'board':board,'version':version,'smbios':smbios,'damage':damage,'matched':bool(observed),'passed':True}

cases=[execute(want=True),execute(smbios=2,want=True),
       execute(board='Pro WS W790-ACE'),execute(board='Pro WS W890E-SAGE SE'),
       execute(version='2003'),execute(version='1904x'),execute(board='Pro WS W790E-SAGE SE X'),
       execute(board='pro ws w790e-sage se'),execute(damage='checksum'),
       execute(smbios=2,damage='checksum'),execute(damage='bad_record_length'),execute(damage='unterminated')]
report={'status':'PASS','driver_sha256':hashlib.sha256((CANDIDATE/'build/AiTweakerLock1904.efi').read_bytes()).hexdigest(),'scope':__doc__,'cases':cases}
(CANDIDATE/'build/identity_test.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf8')
print(json.dumps({'status':'PASS','cases':len(cases),'driver_sha256':report['driver_sha256']}))
