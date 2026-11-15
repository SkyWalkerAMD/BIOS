"""Compile and execute the real immutable layout validator at two load bases."""
from bind_layout import *
import os, subprocess
import unicorn
from unicorn.x86_const import *

OUT=HERE/'build';OUT.mkdir(exist_ok=True);Z=ROOT/'tools/zig-x86_64-windows-0.14.1/zig.exe'
env=os.environ.copy();env.update(ZIG_LOCAL_CACHE_DIR=str(OUT/'zig-local'),ZIG_GLOBAL_CACHE_DIR=str(OUT/'zig-global'))
sources=[HERE/'fixture.c',HERE/'layout.c',HERE/'layout_slot.c',BASE/'password/core/password_crypto.c']
objects=[];commands=[]
for src in sources:
    obj=OUT/('layout_'+src.stem+'.obj')
    cmd=[str(Z),'clang','-target','x86_64-unknown-windows-msvc','-nostdinc','-isystem',str(Z.parent/'lib/include'),
      '-O2','-std=c11','-ffreestanding','-fno-builtin','-fno-stack-protector','-fno-unwind-tables',
      '-fno-asynchronous-unwind-tables','-mno-red-zone','-mno-stack-arg-probe','-Wall','-Wextra','-Werror','-c',str(src),'-o',str(obj)]
    r=subprocess.run(cmd,env=env,capture_output=True,text=True,creationflags=subprocess.CREATE_NO_WINDOW)
    if r.returncode:print(r.stdout+r.stderr);r.check_returncode()
    commands.append(cmd);objects.append(obj)
extpath=OUT/'LAYOUT-FIXTURE.dll'
cmd=[str(Z),'lld-link','/dll','/noentry','/nodefaultlib','/machine:x64','/timestamp:0','/base:0x180000000',
     '/out:'+str(extpath),*[str(x)for x in objects],'/export:i05_layout_get','/export:i05_layout_live','/export:i05_layout_symbol']
r=subprocess.run(cmd,env=env,capture_output=True,text=True,creationflags=subprocess.CREATE_NO_WINDOW)
if r.returncode:print(r.stdout+r.stderr);r.check_returncode()
commands.append(cmd);extension=extpath.read_bytes()
w=next(w for w in json.loads((BASE/'native_observer04/hook_windows.json').read_text())['windows']if w['rva']==0x190f4)
patch={'rva':w['rva'],'original_hex':w['hex'],'mode':'jmp','export':'i05_fixture_hook','trampoline':'original_loop'}
pointer={'rva':0xa9d08,'original_value':0x1d814,'export':'i05_fixture_hook'}
unbound,composition=compose(extension,sha(extension),'i05_fixture_entry',[patch],[pointer])
bound,report=bind_layout(unbound,composition);pe=pefile.PE(data=bound);image=mapped(pe)
STOP=0x09000000;STACK=0x0a000000;cases=[]

def run(base,change=None,wrong_size=False,raw=None,loader_base=None):
    p=pefile.PE(data=bound if raw is None else raw);mi=bytearray(mapped(p))
    for rva in relocations(p):struct.pack_into('<Q',mi,rva,u64(mi,rva)+base)
    if loader_base is not None:struct.pack_into('<Q',mi,p.DOS_HEADER.e_lfanew+24+24,loader_base)
    if change:mi[change]^=1
    mu=unicorn.Uc(unicorn.UC_ARCH_X86,unicorn.UC_MODE_64)
    mu.mem_map(base,align(len(mi),4096));mu.mem_write(base,bytes(mi));mu.mem_protect(base,align(len(mi),4096),unicorn.UC_PROT_READ)
    for s in p.sections:
        flags=0
        if s.Characteristics&0x40000000:flags|=unicorn.UC_PROT_READ
        if s.Characteristics&0x80000000:flags|=unicorn.UC_PROT_WRITE
        if s.Characteristics&0x20000000:flags|=unicorn.UC_PROT_EXEC
        mu.mem_protect(base+s.VirtualAddress,align(max(s.Misc_VirtualSize,s.SizeOfRawData),4096),flags)
    mu.mem_map(STOP,4096,unicorn.UC_PROT_READ|unicorn.UC_PROT_EXEC)
    mu.mem_map(STACK,0x10000,unicorn.UC_PROT_READ|unicorn.UC_PROT_WRITE)
    mu.reg_write(UC_X86_REG_RSP,STACK+0xeff8);mu.mem_write(STACK+0xeff8,struct.pack('<Q',STOP))
    mu.reg_write(UC_X86_REG_RCX,base);mu.reg_write(UC_X86_REG_RDX,len(mi)+(4096 if wrong_size else 0))
    mu.emu_start(base+report['exports']['i05_layout_live'],STOP,count=250000000)
    need(mu.reg_read(UC_X86_REG_RIP)==STOP,'validator did not return')
    return mu.reg_read(UC_X86_REG_RAX)

layout=Layout.from_buffer_copy(bound[raw_offset(pe,report['static_layout']['slot_rva'],C.sizeof(Layout)):][:C.sizeof(Layout)])
need(layout.fixup_count>0,'test must contain a readonly relocated pointer')
for base in [0x20000000,0x120000000]:
    vectors=[('exact_static_layout',None,False,bound,1),('unfilled_slot',None,False,unbound,0),
       ('wrong_loaded_size',None,True,bound,0),('changed_original_code',0x1500,False,bound,0),
       ('changed_installed_jump',w['rva']+1,False,bound,0),
       ('changed_extension_function',report['exports']['i05_fixture_hook'],False,bound,0),
       ('changed_header_entry',pe.DOS_HEADER.e_lfanew+24+16,False,bound,0),
       ('changed_readonly_pointer',layout.fixups[0].rva,False,bound,0),
       ('changed_original_static_callback_pointer',pointer['rva'],False,bound,0)]
    for name,changed,size,raw,expected in vectors:
        got=run(base,changed,size,raw);need(got==expected,name+' unexpected validator result')
        cases.append({'case':name,'base':hex(base),'result':got,'passed':True})
    for name,value,expected in [('real_loader_header_base',base,1),('wrong_loader_header_base',base+4096,0)]:
        got=run(base,loader_base=value);need(got==expected,name)
        cases.append({'case':name,'base':hex(base),'result':got,'passed':True})
report.update(status='PASS_REAL_LAYOUT_VALIDATOR_WITH_PACKAGING_FIXTURE',cases=cases,commands=commands,
    saved_firmware_candidate=False,limitations=['Functional driver and actual ASUS load/dispatch are not tested by this packaging fixture.',
      'Genuine caller must prove readable LoadedImage range before calling the validator.',
      'Immutable static identity is separate from native UI session and password authorization.'],
    bindings=[{'path':str(p),'sha256':sha(p.read_bytes())}for p in sources+[HERE/'layout.h',HERE/'bind_layout.py',HERE/'test_layout.py',HERE/'merge_pe.py',extpath]])
(HERE/'layout_validator_test.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
print(json.dumps({'status':report['status'],'cases':len(cases),'slot_bytes':C.sizeof(Layout),'fixups':layout.fixup_count}),flush=True)
