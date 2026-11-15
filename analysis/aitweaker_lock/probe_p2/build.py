"""Build an offline diagnostic application, not a modified BIOS image."""
from pathlib import Path
import hashlib
import json
import os
import subprocess
import sys
import uuid
import zlib

OUT=Path(__file__).resolve().parent
SRC=OUT/'source'
sys.path.insert(0,str(OUT.parent))
from inspect_setup import ROOT,TAGS,get_module
import pefile
ZIG=ROOT/'tools/zig-x86_64-windows-0.14.1/zig.exe'


def main():
    profiles=[]
    rows=[]
    for tag in TAGS:
        for module in ('AMITSE','Setup'):
            m,s,b=get_module(tag,module)
            pe=pefile.PE(data=b)
            sec=next(s for s in pe.sections if s.Name.rstrip(b'\0')==b'.text')
            size,rva=sec.Misc_VirtualSize,sec.VirtualAddress
            assert not any(rva<=e.rva<rva+size for block in pe.DIRECTORY_ENTRY_BASERELOC for e in block.entries if e.type)
            p={'tag':tag,'module':module,'guid':m['guid'],'sha256':s['sha256'],
               'text_rva':rva,'text_size':size,'text_crc32':zlib.crc32(sec.get_data()[:size]),
               'entry':pe.OPTIONAL_HEADER.AddressOfEntryPoint,'image_size':pe.OPTIONAL_HEADER.SizeOfImage}
            profiles.append(p)
            g=uuid.UUID(m['guid']);a,b1,c,d1,d2,node=g.fields
            gb=f'{{0x{a:08x},0x{b1:04x},0x{c:04x},{{'+','.join(f'0x{v:02x}' for v in g.bytes[8:])+'}}'
            rows.append('{'+gb+','+f'{p["text_crc32"]}U,{rva}U,{size}U,{p["entry"]}U,{p["image_size"]}U,"{tag}/{module}"'+'}')
    (SRC/'profiles.h').write_text('/* Generated from SHA-256-checked original modules. CRC is identification, not authentication. */\n'
        'typedef struct { GUID guid; uint32_t crc,rva,size,entry,image_size; const char *name; } PROFILE;\n'
        'static const PROFILE profiles[]={\n'+',\n'.join(rows)+'\n};\n',encoding='utf8')
    (OUT/'profiles.json').write_text(json.dumps(profiles,indent=2),encoding='utf8')
    boot=OUT/'USB/EFI/BOOT';boot.mkdir(parents=True,exist_ok=True)
    env=os.environ.copy()
    env['ZIG_GLOBAL_CACHE_DIR']=str(ROOT/'tools/zig-cache-global')
    env['ZIG_LOCAL_CACHE_DIR']=str(ROOT/'tools/zig-cache-local')
    commands=[]
    for name in ('probe','probe_core'):
        args=[str(ZIG),'clang','-target','x86_64-unknown-windows-msvc','-nostdinc','-isystem',str(ZIG.parent/'lib/include'),
              '-std=c11','-O2','-Wall','-Wextra','-Werror','-ffreestanding','-fno-builtin','-fno-stack-protector',
              '-mno-red-zone','-fshort-wchar','-c',str(SRC/(name+'.c')),'-o',str(OUT/(name+'.obj'))]
        subprocess.run(args,check=True,env=env,cwd=ROOT);commands.append(args)
    args=[str(ZIG),'lld-link','/subsystem:efi_application','/entry:efi_main','/nodefaultlib','/machine:x64',
          '/dynamicbase','/fixed:no','/nxcompat','/timestamp:0','/map:'+str(OUT/'probe.map'),
          '/out:'+str(boot/'BOOTX64.EFI'),str(OUT/'probe.obj'),str(OUT/'probe_core.obj')]
    subprocess.run(args,check=True,env=env,cwd=ROOT);commands.append(args)
    args=[str(ZIG),'lld-link','/dll','/noentry','/nodefaultlib','/machine:x64','/timestamp:0',
          '/export:probe_crc32','/export:probe_image','/export:probe_hii','/out:'+str(OUT/'core_test.dll'),str(OUT/'probe_core.obj')]
    subprocess.run(args,check=True,env=env,cwd=ROOT);commands.append(args)
    exe=boot/'BOOTX64.EFI';pe=pefile.PE(str(exe));pe.OPTIONAL_HEADER.CheckSum=pe.generate_checksum();exe.write_bytes(pe.write())
    pe=pefile.PE(str(exe))
    assert pe.FILE_HEADER.Machine==0x8664 and pe.OPTIONAL_HEADER.Subsystem==10
    assert not hasattr(pe,'DIRECTORY_ENTRY_IMPORT')
    assert pe.OPTIONAL_HEADER.DATA_DIRECTORY[5].Size>0
    assert pe.OPTIONAL_HEADER.DATA_DIRECTORY[4].Size==0 and pe.verify_checksum()
    (OUT/'USB/AITWEAKER-PROBE.TAG').write_bytes(b'AITWEAKER-PROBE-P2\r\n')
    result={'status':'BUILT_NOT_RUN_ON_TARGET','image':'USB/EFI/BOOT/BOOTX64.EFI',
            'purpose':'Read-only firmware interface inventory; not a password lock or flashable BIOS.',
            'bytes':exe.stat().st_size,'sha256':hashlib.sha256(exe.read_bytes()).hexdigest(),
            'x64':True,'efi_application':True,'no_imports':True,'relocations_present':True,
            'pe_checksum_valid':True,'unsigned':True,
            'compiler':'Zig 0.14.1 / bundled Clang and LLD',
            'sources':{p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in SRC.iterdir() if p.is_file()},
            'commands':commands}
    (OUT/'build.json').write_text(json.dumps(result,indent=2),encoding='utf8')
    print(json.dumps({k:result[k] for k in ('status','bytes','sha256')},indent=2))


if __name__=='__main__':main()
