"""Execute composed PE entry, exact static branch, and copied original window.

The extension is intentionally a packaging fixture. This is not a test of the
password driver or a claim that a complete ASUS firmware boots in QEMU.
"""
from pathlib import Path
import os, subprocess, json, struct, sys
from merge_pe import *
import unicorn
from unicorn.x86_const import *

OUT=HERE/'build'; OUT.mkdir(exist_ok=True)
Z=ROOT/'tools/zig-x86_64-windows-0.14.1/zig.exe'
env=os.environ.copy();env.update(ZIG_LOCAL_CACHE_DIR=str(OUT/'zig-local'),ZIG_GLOBAL_CACHE_DIR=str(OUT/'zig-global'))
cmds=[
 [str(Z),'clang','-target','x86_64-unknown-windows-msvc','-nostdinc','-isystem',str(Z.parent/'lib/include'),
  '-O2','-std=c11','-ffreestanding','-fno-builtin','-fno-stack-protector','-fno-unwind-tables',
  '-fno-asynchronous-unwind-tables','-mno-red-zone','-mno-stack-arg-probe','-Wall','-Wextra','-Werror',
  '-c',str(HERE/'fixture.c'),'-o',str(OUT/'fixture.obj')],
 [str(Z),'lld-link','/dll','/noentry','/nodefaultlib','/machine:x64','/timestamp:0','/base:0x180000000',
  '/out:'+str(OUT/'PACKAGING-FIXTURE.dll'),str(OUT/'fixture.obj')]]
for cmd in cmds:
    r=subprocess.run(cmd,env=env,capture_output=True,text=True,creationflags=subprocess.CREATE_NO_WINDOW)
    if r.returncode: print(r.stdout+r.stderr);r.check_returncode()
ext=(OUT/'PACKAGING-FIXTURE.dll').read_bytes(); orig=baseline(); op=pefile.PE(data=orig)
windows=json.loads((BASE/'native_observer04/hook_windows.json').read_text())['windows']
w=next(w for w in windows if w['rva']==0x190f4)
patch={'rva':w['rva'],'original_hex':w['hex'],'mode':'jmp','export':'i05_fixture_hook','trampoline':'original_loop'}
merged, report=compose(ext,sha(ext),'i05_fixture_entry',[patch]); mp=pefile.PE(data=merged)
STOP=0x09000000;STACK=0x0a000000;STOP_VALUE=0x11234567; rows=[]

def load(raw,base):
    """Independent mapper: allocate headers/sections; parse base-reloc blocks directly."""
    p=pefile.PE(data=raw); image=bytearray(p.OPTIONAL_HEADER.SizeOfImage)
    image[:p.OPTIONAL_HEADER.SizeOfHeaders]=raw[:p.OPTIONAL_HEADER.SizeOfHeaders]
    for s in p.sections:
        image[s.VirtualAddress:s.VirtualAddress+s.SizeOfRawData]=raw[s.PointerToRawData:s.PointerToRawData+s.SizeOfRawData]
    d=p.OPTIONAL_HEADER.DATA_DIRECTORY[5]; at=d.VirtualAddress; end=at+d.Size; count=0
    while at<end:
        page,n=struct.unpack_from('<II',image,at); assert n>=8 and n%4==0 and at+n<=end
        for cursor in range(at+8,at+n,2):
            word=struct.unpack_from('<H',image,cursor)[0]; typ=word>>12
            if typ==0:continue
            assert typ==10; dest=page+(word&4095)
            struct.pack_into('<Q',image,dest,(u64(image,dest)+base-p.OPTIONAL_HEADER.ImageBase)&((1<<64)-1));count+=1
        at+=n
    assert at==end
    return bytes(image),count

def machine(raw,base):
    p=pefile.PE(data=raw); data,count=load(raw,base)
    mu=unicorn.Uc(unicorn.UC_ARCH_X86,unicorn.UC_MODE_64)
    mu.mem_map(base,align(len(data),4096));mu.mem_write(base,data)
    mu.mem_protect(base,align(len(data),4096),unicorn.UC_PROT_READ)
    for s in p.sections:
        flags=0
        if s.Characteristics&0x40000000:flags|=unicorn.UC_PROT_READ
        if s.Characteristics&0x80000000:flags|=unicorn.UC_PROT_WRITE
        if s.Characteristics&0x20000000:flags|=unicorn.UC_PROT_EXEC
        mu.mem_protect(base+s.VirtualAddress,align(max(s.Misc_VirtualSize,s.SizeOfRawData),4096),flags)
    mu.mem_map(STACK,0x10000,unicorn.UC_PROT_READ|unicorn.UC_PROT_WRITE)
    mu.mem_map(STOP,4096,unicorn.UC_PROT_READ|unicorn.UC_PROT_EXEC)
    mu.reg_write(UC_X86_REG_RSP,STACK+0xeff8);mu.mem_write(STACK+0xeff8,struct.pack('<Q',STOP))
    mu.reg_write(UC_X86_REG_RCX,0x11223344);mu.reg_write(UC_X86_REG_RDX,0x55667788)
    for reg in [UC_X86_REG_RBX,UC_X86_REG_RBP,UC_X86_REG_RSI,UC_X86_REG_RDI,UC_X86_REG_R12,UC_X86_REG_R13,UC_X86_REG_R14,UC_X86_REG_R15]:mu.reg_write(reg,0x5555000012340000+reg)
    return mu

for base in [0x20000000,0x120000000]:
    mi,c=load(merged,base); oi,oc=load(orig,base)
    assert c==report['original_relocation_count']+report['extension_relocation_count']
    for s in op.sections:
        expected=bytearray(oi[s.VirtualAddress:s.VirtualAddress+s.SizeOfRawData])
        for p in report['patches']:
            if s.VirtualAddress<=p['rva']<s.VirtualAddress+s.SizeOfRawData:
                q=p['rva']-s.VirtualAddress;expected[q:q+p['bytes']]=bytes.fromhex(p['installed_hex'])
        assert mi[s.VirtualAddress:s.VirtualAddress+s.SizeOfRawData]==expected
    rows.append({'case':'all_original_loaded_sections_preserved','base':hex(base),'passed':True,'original_DIR64':oc})
    mu=machine(merged,base);mu.emu_start(base+report['entry_rva'],STOP,count=10000)
    assert mu.reg_read(UC_X86_REG_RIP)==STOP and mu.reg_read(UC_X86_REG_RAX)==(0x4c4b5041434b3035^0x1234567812345678)
    rows.append({'case':'new_entry_own_data_function_pointers_and_bss','base':hex(base),'passed':True})
    mu=machine(merged,base);mu.emu_start(base+w['rva'],STOP,count=10000)
    assert mu.reg_read(UC_X86_REG_RIP)==STOP and mu.reg_read(UC_X86_REG_RAX)==0x5052455041525345
    rows.append({'case':'original_function_entry_static_jump','base':hex(base),'passed':True})
    a=machine(orig,base);b=machine(merged,base);end=base+w['rva']+w['bytes']
    a.emu_start(base+w['rva'],end,count=10000);b.emu_start(base+report['trampolines']['original_loop'],end,count=10000)
    regs=[UC_X86_REG_RAX,UC_X86_REG_RBX,UC_X86_REG_RCX,UC_X86_REG_RDX,UC_X86_REG_RSP,UC_X86_REG_RBP,
          UC_X86_REG_RSI,UC_X86_REG_RDI,UC_X86_REG_R8,UC_X86_REG_R9,UC_X86_REG_R10,UC_X86_REG_R11,
          UC_X86_REG_R12,UC_X86_REG_R13,UC_X86_REG_R14,UC_X86_REG_R15,UC_X86_REG_RIP,UC_X86_REG_EFLAGS]
    assert all(a.reg_read(x)==b.reg_read(x) for x in regs)
    assert a.mem_read(STACK,0x10000)==b.mem_read(STACK,0x10000)
    rows.append({'case':'copied_original_prologue_same_registers_flags_stack_resume','base':hex(base),'passed':True})

negative=[('wrong_extension_hash',ext,'0'*64,'i05_fixture_entry',[patch]),
          ('missing_entry',ext,sha(ext),'missing',[patch]),
          ('window_changed',ext,sha(ext),'i05_fixture_entry',[{**patch,'original_hex':'90'*w['bytes']}]),
          ('partial_instruction',ext,sha(ext),'i05_fixture_entry',[{**patch,'original_hex':w['hex'][:-2]}]),
          ('overlapping_windows',ext,sha(ext),'i05_fixture_entry',[patch,patch])]
ep=pefile.PE(data=ext); bad=bytearray(ext); rr=relocations(ep)[0]
struct.pack_into('<Q',bad,raw_offset(ep,rr,8),0x12345678)
negative.append(('external_relocated_pointer',bytes(bad),sha(bad),'i05_fixture_entry',[patch]))
for name,x,h,e,p in negative:
    try:compose(x,h,e,p)
    except ValueError as error:rows.append({'case':name,'passed':True,'rejection':str(error)})
    else:raise AssertionError('negative case accepted: '+name)
report.update(status='PASS_PE_COMPOSITION_FIXTURE_ONLY',cases=rows,commands=cmds,
    limitations=['Extension is a relocation fixture, not the functional password aggregate.',
                 'Original prologue was executed through its first window only; no firmware services or whole boot.',
                 'No merged PE, CAP, ROM, credentials or firmware update was persisted or transmitted.'],
    bindings=[{'path':str(p),'sha256':sha(p.read_bytes())} for p in [HERE/'merge_pe.py',HERE/'test_merge.py',HERE/'fixture.c',OUT/'PACKAGING-FIXTURE.dll']])
(HERE/'pe_composition_test.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
print(json.dumps({'status':report['status'],'cases':len(rows),'image_size':report['image_size'],'extension_sha':sha(ext)}))
