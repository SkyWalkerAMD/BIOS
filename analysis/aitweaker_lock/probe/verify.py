"""Test the shipped EFI bytes against synthetic UEFI services in Unicorn.
No physical device, NVRAM, firmware, or removable drive is accessed.
"""
from pathlib import Path
import ctypes
import hashlib
import json
import struct
import sys
import uuid
import zlib

OUT=Path(__file__).resolve().parent
sys.path.insert(0,str(OUT.parent))
from inspect_setup import ROOT,TAGS,get_module
import pefile
from unicorn import Uc,UC_ARCH_X86,UC_MODE_64,UC_HOOK_CODE,UC_PROT_READ
from unicorn.x86_const import *
P64=lambda x:struct.pack('<Q',x)
ERR=lambda x:(1<<63)|x
LOADED='5b1b31a1-9562-11d2-8e3f-00a0c969723b'
FS='964e5b22-6459-11d2-8e39-00a0c969723b'
HII='ef9fc172-a1b2-4693-b327-6d32fc416042'
BROWSER='b9d4c360-bcfb-4f9b-9298-53c136982258'
CONFIG='330d4706-f2a0-4e4f-a369-b66fa8d54385'
POST='8a91b1e1-56c7-4adc-abeb-1c2ca1729eff'


def stock_package(tag):
    p=json.loads((OUT.parent/tag/'Setup_IFR.json').read_text(encoding='utf8'))[0]
    _,_,data=get_module(tag,'Setup')
    form=data[p['offset']:p['offset']+p['length']]
    return uuid.UUID('7b59104a-c00d-4158-87ff-f04d6396a915').bytes_le+struct.pack('<I',24+len(form))+form+b'\4\0\0\xdf'


class ImageInfo(ctypes.Structure):
    _fields_=[(k,ctypes.c_uint32) for k in ('rva','size','entry','image_size','crc')]


class HiiInfo(ctypes.Structure):
    _fields_=[(k,ctypes.c_uint32) for k in ('packages','formsets','forms','passwords','f2714','f2713')]


def parser_tests():
    dll=ctypes.CDLL(str(OUT/'core_test.dll'))
    dll.probe_image.argtypes=[ctypes.c_void_p,ctypes.c_size_t,ctypes.POINTER(ImageInfo)]
    dll.probe_hii.argtypes=[ctypes.c_void_p,ctypes.c_size_t,ctypes.POINTER(HiiInfo)]
    dll.probe_crc32.argtypes=[ctypes.c_void_p,ctypes.c_size_t]
    dll.probe_crc32.restype=ctypes.c_uint32
    assert dll.probe_crc32(b'123456789',9)==0xcbf43926
    assertions=1
    for tag in TAGS:
        for name in ('AMITSE','Setup'):
            _,_,data=get_module(tag,name);pe=pefile.PE(data=data)
            b=pe.get_memory_mapped_image().ljust(pe.OPTIONAL_HEADER.SizeOfImage,b'\0')
            out=ImageInfo();buf=ctypes.create_string_buffer(b)
            assert dll.probe_image(buf,len(b),ctypes.byref(out))
            s=next(s for s in pe.sections if s.Name.rstrip(b'\0')==b'.text')
            assert out.crc==zlib.crc32(s.get_data()[:s.Misc_VirtualSize])
            assert out.rva==s.VirtualAddress and out.size==s.Misc_VirtualSize
            assertions+=3
            for pos,patch in ((0,b'ZZ'),(0x3c,b'\xff'*4),(pe.DOS_HEADER.e_lfanew+20,b'\xff\xff'),
                              (s.get_file_offset()+8,b'\xff'*4),(s.get_file_offset()+12,b'\xff'*4)):
                bad=bytearray(b);bad[pos:pos+len(patch)]=patch;buf=ctypes.create_string_buffer(bytes(bad))
                assert not dll.probe_image(buf,len(bad),ctypes.byref(out));assertions+=1
            for size in (0,2,32,63,64,128,256):
                buf=ctypes.create_string_buffer(b[:size])
                assert not dll.probe_image(buf,size,ctypes.byref(out));assertions+=1
        b=stock_package(tag);out=HiiInfo();buf=ctypes.create_string_buffer(b)
        assert dll.probe_hii(buf,len(b),ctypes.byref(out))
        assert out.passwords==4 and out.f2713==1 and out.f2714==1
        assertions+=2
        bads=[b[:19],b[:-1],b+b'\0',b[:16]+b'\xff'*4+b[20:],b[:24]+b'\x29\x02'+b[26:],
              b[:25]+b'\x01'+b[26:],b[:-4]+b'\4\0\0\4']
        for bad in bads:
            buf=ctypes.create_string_buffer(bad)
            assert not dll.probe_hii(buf,len(bad),ctypes.byref(out));assertions+=1
    return assertions


class Machine:
    def __init__(self,tag,case='normal'):
        self.tag=tag;self.case=case;self.u=Uc(UC_ARCH_X86,UC_MODE_64)
        self.u.mem_map(0x100000,0x100000)
        self.u.mem_map(0x600000,0x300000)
        self.u.mem_map(0xd00000,0x200000)
        self.u.mem_map(0x10000000,0x2000000)
        self.heap=0x10000000;self.allocations={};self.freed=[]
        p=pefile.PE(str(OUT/'USB/EFI/BOOT/BOOTX64.EFI'));p.relocate_image(0x100000)
        self.u.mem_write(0x100000,p.get_memory_mapped_image());self.entry=0x100000+p.OPTIONAL_HEADER.AddressOfEntryPoint
        self.st=0x700000;self.bs=0x701000;self.rt=0x702000;self.console=0x703000
        self.fs=0x707000;self.root=0x708000;self.marker=0x709000;self.file=0x70a000;self.existing=0x70b000
        self.hii=0x70c000;self.browser=0x70d000;self.config=0x70e000
        self.next_stub=0x800000;self.stubs={};self.calls=[];self.output='';self.log=b'';self.created=[]
        self.w64(self.st+0x60,self.bs);self.w64(self.st+0x58,self.rt);self.w64(self.st+0x40,self.console)
        for offset in range(0x18,0x178,8):self.stub(self.bs+offset,'FORBIDDEN_BS_'+hex(offset))
        for offset in range(0x18,0x90,8):self.stub(self.rt+offset,'FORBIDDEN_RT_'+hex(offset))
        for off,name in ((0x40,'AllocatePool'),(0x48,'FreePool'),(0x98,'HandleProtocol'),(0xf8,'Stall'),
                         (0x138,'LocateHandles'),(0x140,'LocateProtocol')):self.stub(self.bs+off,name)
        self.stub(self.console+8,'Output');self.stub(self.fs+8,'OpenVolume')
        for ptr in (self.root,self.marker,self.file,self.existing):self.stub(ptr+16,'CloseFile')
        self.stub(self.root+8,'OpenFile');self.stub(self.marker+32,'ReadMarker')
        self.stub(self.file+40,'WriteLog');self.stub(self.file+80,'FlushLog')
        for off in range(0,88,8):self.stub(self.hii+off,'FORBIDDEN_HII_'+hex(off))
        for off,name in ((24,'ListPackages'),(32,'ExportPackages'),(80,'GetHiiDriver')):self.stub(self.hii+off,name)
        self.stub(self.browser,'FORBIDDEN_SendForm');self.stub(self.browser+8,'FORBIDDEN_BrowserCallback')
        self.loaded={};self.module_images={}
        for i,name in enumerate(('AMITSE','Setup')):
            m,_,data=get_module(tag,name);image=pefile.PE(data=data);base=0x2000000+i*0x400000
            image.relocate_image(base)
            mapped=image.get_memory_mapped_image().ljust(image.OPTIONAL_HEADER.SizeOfImage,b'\0')
            if case=='unknown_build' and name=='AMITSE':
                mapped=bytearray(mapped);mapped[image.sections[0].VirtualAddress]^=1;mapped=bytes(mapped)
            self.u.mem_map(base,(len(mapped)+4095)&~4095);self.u.mem_write(base,mapped)
            self.u.mem_protect(base,(len(mapped)+4095)&~4095,UC_PROT_READ)
            path=bytes([4,6,20,0])+uuid.UUID(m['guid']).bytes_le+bytes([127,255,4,0])
            pathptr=self.alloc(path);li=bytearray(96)
            struct.pack_into('<Q',li,0x20,pathptr);struct.pack_into('<QQ',li,0x40,base,len(mapped))
            self.loaded[0x1111+i*0x1111]=self.alloc(li)
            self.module_images[name]=(base,mapped)
        li=bytearray(96);struct.pack_into('<Q',li,24,0x4444)
        self.loaded[0x3333]=self.alloc(li)
        # Test ownership reporting without invoking any of these pointers.
        self.w64(self.browser,0x2000000+0x1234);self.w64(self.browser+8,0x2000000+0x4321)
        for i in range(3):self.w64(self.config+i*8,0x2400000+0x1100+i*16)
        self.package=stock_package(tag)
        if case=='malformed_hii':self.package=self.package[:-1]
        self.u.hook_add(UC_HOOK_CODE,self.hook,begin=0x800000,end=0x810000)

    def alloc(self,data):
        addr=self.heap+16;self.heap+=(len(data)+47)&~15
        self.u.mem_write(addr-16,b'\xa5'*16+bytes(data)+b'\xa5'*16)
        self.allocations[addr]=len(data);return addr

    def w64(self,a,v):self.u.mem_write(a,P64(v))
    def r64(self,a):return struct.unpack('<Q',self.u.mem_read(a,8))[0]
    def guid(self,a):return str(uuid.UUID(bytes_le=bytes(self.u.mem_read(a,16))))

    def wide(self,a):
        chars=[]
        for i in range(1024):
            c=struct.unpack('<H',self.u.mem_read(a+2*i,2))[0]
            if not c:return ''.join(chars)
            chars.append(chr(c))
        raise AssertionError('unterminated string')

    def stub(self,slot,name):
        a=self.next_stub;self.next_stub+=16;self.w64(slot,a);self.stubs[a]=name;self.u.mem_write(a,b'\xc3')

    def hook(self,u,addr,size,user):
        name=self.stubs.get(addr)
        assert name is not None
        assert not name.startswith('FORBIDDEN'),name
        sp=u.reg_read(UC_X86_REG_RSP);assert sp%16==8
        a,b,c,d=[u.reg_read(r) for r in (UC_X86_REG_RCX,UC_X86_REG_RDX,UC_X86_REG_R8,UC_X86_REG_R9)]
        e=self.r64(sp+40);ret=0;self.calls.append(name)
        if name=='Output':self.output+=self.wide(b)
        elif name=='AllocatePool':
            assert a==4 and b<=16*1024*1024
            if self.case=='allocation_failure':ret=ERR(9)
            else:self.w64(c,self.alloc(bytes(b)))
        elif name=='FreePool':
            assert a in self.allocations and a not in self.freed
            self.freed.append(a)
        elif name=='LocateHandles':
            assert a==2 and self.guid(b)==LOADED
            if self.case=='no_modules':ret=ERR(14)
            else:self.w64(d,3);self.w64(e,self.alloc(b''.join(P64(h) for h in self.loaded)))
        elif name=='HandleProtocol':
            g=self.guid(b);ptr=0
            if g==LOADED:ptr=self.loaded.get(a,0)
            elif g==FS and a==0x4444:ptr=self.fs
            elif g==CONFIG and a==0x2222:ptr=self.config
            if ptr:self.w64(c,ptr)
            else:ret=ERR(14)
        elif name=='LocateProtocol':
            g=self.guid(a);ptr={HII:self.hii,BROWSER:self.browser,POST:0x70f000}.get(g,0)
            if self.case=='no_protocols':ptr=0
            if ptr:self.w64(c,ptr)
            else:ret=ERR(14)
        elif name=='ListPackages':
            assert a==self.hii and (b&255)==2 and c==0,(hex(a),hex(b),hex(c))
            if self.r64(d)<8:self.w64(d,8);ret=ERR(5)
            else:self.w64(e,0x5555);self.w64(d,8)
        elif name=='ExportPackages':
            assert a==self.hii and b==0x5555
            if self.r64(c)<len(self.package):self.w64(c,len(self.package));ret=ERR(9)
            else:self.u.mem_write(d,self.package);self.w64(c,len(self.package))
        elif name=='GetHiiDriver':self.w64(c,0x2222)
        elif name=='OpenVolume':assert a==self.fs;self.w64(b,self.root)
        elif name=='OpenFile':
            assert a==self.root;path=self.wide(c)
            if path=='\\AITWEAKER-PROBE.TAG':
                assert d==1
                if self.case=='missing_marker':ret=ERR(14)
                else:self.w64(b,self.marker)
            elif d==1:
                if self.case=='existing_log' and path=='\\AITWK-000.TXT':self.w64(b,self.existing)
                elif self.case=='unreadable_log':ret=ERR(7)
                else:ret=ERR(14)
            else:
                assert d==0x8000000000000003 and e==0 and path.startswith('\\AITWK-')
                self.created.append(path);self.w64(b,self.file)
        elif name=='ReadMarker':
            assert a==self.marker
            data=b'AITWEAKER-PROBE-P1\r\n' if self.case!='bad_marker' else b'WRONG\r\n'
            self.u.mem_write(c,data);self.w64(b,len(data))
        elif name=='WriteLog':
            assert a==self.file
            size=self.r64(b)
            if self.case=='short_write':size-=1;self.w64(b,size)
            self.log+=bytes(self.u.mem_read(c,size))
        elif name=='FlushLog':
            assert a==self.file
            if self.case=='flush_error':ret=ERR(7)
        elif name=='CloseFile':assert a in (self.root,self.file,self.marker,self.existing)
        elif name=='Stall':assert a==3000000
        else:raise AssertionError(name)
        u.reg_write(UC_X86_REG_RAX,ret)

    def run(self):
        self.u.reg_write(UC_X86_REG_RSP,0xefff08);self.w64(0xefff08,0x8ff000)
        self.u.reg_write(UC_X86_REG_RCX,0x3333);self.u.reg_write(UC_X86_REG_RDX,self.st)
        self.u.emu_start(self.entry,0x8ff000,count=250000000)
        assert self.u.reg_read(UC_X86_REG_RIP)==0x8ff000,'execution limit'
        for base,data in self.module_images.values():assert bytes(self.u.mem_read(base,len(data)))==data
        for addr,n in self.allocations.items():
            assert bytes(self.u.mem_read(addr-16,16))==b'\xa5'*16
            assert bytes(self.u.mem_read(addr+n,16))==b'\xa5'*16
        result=self.u.reg_read(UC_X86_REG_RAX)
        failure=self.case in ('missing_marker','bad_marker','unreadable_log','short_write','flush_error')
        assert result==(ERR(7) if failure else 0),(self.case,hex(result))
        if self.case in ('missing_marker','bad_marker','unreadable_log'):assert not self.created and not self.log
        if self.case=='existing_log':assert self.created==['\\AITWK-001.TXT']
        if not failure:
            assert self.log.endswith(b'PROBE_COMPLETE\r\n')
            if self.case=='normal':
                for name in ('AMITSE','Setup'):assert (self.tag+'/'+name).encode() in self.log
                assert b'ConfigAccess.Callback' in self.log
        if self.case=='unknown_build':assert b'UNKNOWN_BUILD' in self.log
        if self.case=='malformed_hii':assert b'HII package parse failed' in self.log
        return {'tag':self.tag,'case':self.case,'passed':True,'bytes_logged':len(self.log),
                'firmware_memory_unchanged':True,'allowed_calls_only':True}


def main():
    count=parser_tests();print('Native parser checks passed:',count,flush=True)
    results=[]
    cases=['normal','missing_marker','bad_marker','existing_log','unreadable_log','short_write','flush_error',
           'no_protocols','no_modules','malformed_hii','allocation_failure','unknown_build']
    for tag in TAGS:
        for case in cases if tag==TAGS[0] else ['normal']:
            m=Machine(tag,case);results.append(m.run());print(tag,case,'PASS',flush=True)
            if case=='normal' and tag==TAGS[0]:
                (OUT/'example-MOCK-log.txt').write_bytes(b'SYNTHETIC TEST DATA - NOT A REAL BOARD LOG\r\n'+m.log)
    result={'status':'OFFLINE_TESTS_PASS_NOT_HARDWARE_VALIDATION','native_parser_assertions':count,
            'efi_emulation_cases':results,'shipped_efi_sha256':hashlib.sha256((OUT/'USB/EFI/BOOT/BOOTX64.EFI').read_bytes()).hexdigest(),
            'limitations':['No physical board was accessed.','Does not validate any password lock or flashing path.']}
    (OUT/'verification.json').write_text(json.dumps(result,indent=2),encoding='utf8')
    print('Verification saved.',flush=True)


if __name__=='__main__':main()
