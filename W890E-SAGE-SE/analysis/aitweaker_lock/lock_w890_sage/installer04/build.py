"""Build exact W890 lifecycle transaction and isolated real-service lab.

No ROM/CAP is written. Lab input images are owned mapped copies and never run
their original entry; only reviewed detours execute a small lab return stub.
"""
from pathlib import Path
import hashlib
import json
import os
import subprocess
import sys
sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
BASE = HERE.parent
ROOT = BASE.parents[2]
sys.path[:0] = [str(ROOT/'tools/pydeps'), str(ROOT/'tools/kvm-pydeps')]
import pefile
import capstone

def sha(p): return hashlib.sha256(p.read_bytes()).hexdigest()
def save(p, obj): p.write_text(json.dumps(obj, indent=2, ensure_ascii=False)+'\n', encoding='utf-8')
def data(b): return '{'+','.join(f'0x{x:02x}' for x in b)+'}'
def main():
    out = HERE/'build'; out.mkdir(parents=True, exist_ok=True)
    profile = json.loads((BASE/'password/profile_0603.json').read_text())
    windows = json.loads((BASE/'native_observer04/hook_windows.json').read_text())['windows']
    assert [(w['rva'],w['bytes']) for w in windows] == [(0x6480,16),(0x190f4,18),(0x36da4,15)]
    sources = []
    module_rows = []
    segments = []
    fixtures = []
    mapped = []
    dis = capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64); dis.detail=True
    for module, name in enumerate(['AMITSE','Setup']):
        item = profile['sources'][name]; p=ROOT/item['path']; sources.append(p)
        assert sha(p)==item['sha256']
        pe=pefile.PE(str(p)); image=pe.get_memory_mapped_image()
        image=image.ljust(pe.OPTIONAL_HEADER.SizeOfImage,b'\0'); mapped.append(image)
        text=next(s for s in pe.sections if s.Name==b'.text\0\0\0')
        lo=text.VirtualAddress; hi=lo+text.Misc_VirtualSize
        module_rows.append('{'+','.join(map(str,[pe.OPTIONAL_HEADER.SizeOfImage,pe.OPTIONAL_HEADER.AddressOfEntryPoint,lo,text.Misc_VirtualSize]))+'}')
        at=lo
        for w in windows if module==0 else []:
            raw=bytes.fromhex(w['hex']); assert len(raw)==w['bytes'] and image[w['rva']:w['rva']+len(raw)]==raw
            ins=list(dis.disasm(raw,w['rva'])); assert sum(i.size for i in ins)==len(raw)
            for i in ins:
                assert not i.group(capstone.CS_GRP_JUMP) and not i.group(capstone.CS_GRP_CALL)
                assert not any(o.type==capstone.x86.X86_OP_MEM and o.mem.base==capstone.x86.X86_REG_RIP for o in i.operands)
            segments.append((module,at,w['rva']-at,hashlib.sha256(image[at:w['rva']]).digest()))
            at=w['rva']+len(raw)
        segments.append((module,at,hi-at,hashlib.sha256(image[at:hi]).digest()))
        # Per-image mapped fixture, no OS or vendor init is executed by the lab.
        fixtures.append('static const uint8_t fixture_'+name.lower()+'[] = '+data(image)+';\n')
    h='/* Generated from exact original 0603 .text and independently decoded windows. */\n'
    h+='typedef struct {uint32_t size,entry,text_rva,text_size;} I04_MODULE;\n'
    h+='typedef struct {uint32_t rva,length;uint8_t bytes[24];} I04_SITE;\n'
    h+='typedef struct {uint32_t module,rva,length;uint8_t hash[32];} I04_SEGMENT;\n'
    h+='static const I04_MODULE i04_modules[]={'+','.join(module_rows)+'};\n'
    h+='static const I04_SITE i04_sites[]={'+','.join('{'+str(w['rva'])+','+str(w['bytes'])+','+data(bytes.fromhex(w['hex']))+'}' for w in windows)+'};\n'
    h+='static const I04_SEGMENT i04_segments[]={'+','.join('{'+f'{m},{a},{n},'+data(d)+'}' for m,a,n,d in segments)+'};\n'
    h+=f'#define I04_SEGMENT_COUNT {len(segments)}U\n'
    (out/'profile.h').write_text(h,encoding='ascii')
    (out/'fixtures.h').write_text(''.join(fixtures),encoding='ascii')
    zig=ROOT/'tools/zig-x86_64-windows-0.14.1/zig.exe'
    env=os.environ.copy();env.update(ZIG_LOCAL_CACHE_DIR=str(out/'zig-local'),ZIG_GLOBAL_CACHE_DIR=str(out/'zig-global'))
    cs=[HERE/'source/memory.c',HERE/'source/transaction.c',HERE/'lab.c',BASE/'password/core/password_crypto.c']
    commands=[];objects=[]
    for p in cs:
        obj=out/(p.stem+'.obj')
        cmd=[str(zig),'clang','-target','x86_64-unknown-windows-msvc','-nostdinc','-isystem',str(zig.parent/'lib/include'),'-I',str(out),'-std=c11','-O2','-Wall','-Wextra','-Werror','-ffreestanding','-fno-builtin','-fno-stack-protector','-mno-red-zone','-mno-stack-arg-probe','-fshort-wchar','-c',str(p),'-o',str(obj)]
        result=subprocess.run(cmd,env=env,capture_output=True,text=True,creationflags=subprocess.CREATE_NO_WINDOW)
        (out/(p.stem+'.build.log')).write_text(result.stdout+result.stderr,encoding='utf-8')
        if result.returncode: print(result.stdout+result.stderr,flush=True);result.check_returncode()
        commands.append(cmd);objects.append(obj)
    app=out/'W890-Installer04.TCG-ONLY.efi'
    cmd=[str(zig),'lld-link','/subsystem:efi_application','/entry:efi_main','/nodefaultlib','/machine:x64','/dynamicbase','/fixed:no','/nxcompat','/timestamp:0','/out:'+str(app),*[str(p) for p in objects]]
    commands.append(cmd);subprocess.run(cmd,check=True,env=env,creationflags=subprocess.CREATE_NO_WINDOW)
    pe=pefile.PE(str(app));pe.OPTIONAL_HEADER.CheckSum=pe.generate_checksum();app.write_bytes(pe.write())
    inputs=cs+sources+[HERE/'build.py',HERE/'source/memory.h',HERE/'source/transaction.h',out/'profile.h',out/'fixtures.h',BASE/'native_observer04/hook_windows.json',BASE/'password_runtime02/source/efi.h',BASE/'password/core/password_core.h']
    save(out/'build_commands.json',commands)
    save(out/'build_manifest.json',{'status':'TCG_ONLY_TRANSACTION_LAB_NOT_AN_INSTALLABLE_DRIVER','inputs':{str(p):{'bytes':p.stat().st_size,'sha256':sha(p)} for p in inputs},'output':{'path':str(app),'sha256':sha(app),'bytes':app.stat().st_size},'windows':windows,'coverage':'3 lifecycle prologues and Setup ConfigAccess callback; full navigation/save enforcement and before-StartImage loader authority not bound'})
    print(json.dumps({'efi':str(app),'sha256':sha(app),'bytes':app.stat().st_size}))
if __name__=='__main__':main()
