"""Compile reusable source, native test DLL and a non-collecting PE test carrier."""
from pathlib import Path
import hashlib,json,os,subprocess,sys
P=Path(__file__).resolve().parent;ROOT=P.parents[1];sys.path.insert(0,str(ROOT/'tools/pydeps'))
import pefile
ZIG=ROOT/'tools/zig-x86_64-windows-0.14.1/zig.exe'
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 env=os.environ.copy();env['ZIG_GLOBAL_CACHE_DIR']=str(P/'zig-global');env['ZIG_LOCAL_CACHE_DIR']=str(P/'zig-local')
 flags=['-target','x86_64-unknown-windows-msvc','-nostdinc','-isystem',str(ZIG.parent/'lib/include'),'-std=c11','-O2','-Wall','-Wextra','-Werror','-Wframe-larger-than=2048','-ffreestanding','-fno-builtin','-fno-stack-protector','-mno-red-zone','-ffunction-sections','-fdata-sections']
 commands=[];sources=['hero_hardware_source','hero_hardware_pcie_adapter','hhs_read_helpers','common','test_entry']
 for name in sources:
  cmd=[str(ZIG),'clang',*flags,'-c',str(P/'source'/f'{name}.c'),'-o',str(P/f'{name}.obj')];subprocess.run(cmd,check=True,env=env);commands.append(cmd)
 exports=['HeroHardwareSourceWorkspaceSize','HeroHardwareSourceInit','HeroHardwareSourceCollect','HeroHardwarePciSinkInit','HeroHardwarePciVisit','HeroHardwarePciCapture','hhs_range_readable','hhs_path_copy','hhs_media_bytes','hhs_media_fields_equal']
 cmd=[str(ZIG),'lld-link','/dll','/noentry','/nodefaultlib','/machine:x64','/opt:ref','/timestamp:0','/out:'+str(P/'hardware_source.dll')]+['/export:'+s for s in exports]+[str(P/(s+'.obj')) for s in sources[:-1]]
 subprocess.run(cmd,check=True,env=env);commands.append(cmd)
 pe_path=P/'HHS-TEST-CARRIER.EFI'
 cmd=[str(ZIG),'lld-link','/subsystem:efi_application','/entry:efi_main','/nodefaultlib','/machine:x64','/dynamicbase','/fixed:no','/nxcompat','/opt:ref','/opt:noicf','/timestamp:0','/map:'+str(P/'source.map'),'/out:'+str(pe_path)]+['/include:'+s for s in exports]+[str(P/(s+'.obj')) for s in sources]
 subprocess.run(cmd,check=True,env=env);commands.append(cmd)
 pe=pefile.PE(str(pe_path));pe.OPTIONAL_HEADER.CheckSum=pe.generate_checksum();pe_path.write_bytes(pe.write());pe=pefile.PE(str(pe_path));assert pe.verify_checksum() and pe.OPTIONAL_HEADER.Subsystem==10 and not hasattr(pe,'DIRECTORY_ENTRY_IMPORT')
 dll=pefile.PE(str(P/'hardware_source.dll'));assert not hasattr(dll,'DIRECTORY_ENTRY_IMPORT')
 import ctypes as C
 lib=C.CDLL(str(P/'hardware_source.dll'));lib.HeroHardwareSourceWorkspaceSize.restype=C.c_size_t
 report=dict(passed=True,pe_file=pe_path.name,pe_sha256=sha(pe_path),pe_bytes=pe_path.stat().st_size,dll_sha256=sha(P/'hardware_source.dll'),workspace_bytes=lib.HeroHardwareSourceWorkspaceSize(),max_stack_frame_compile_limit=2048,no_imports=True,test_carrier_entry_collects=False,
  source_hashes={p.relative_to(P/'source').as_posix():sha(p) for p in (P/'source').glob('*') if p.is_file()},commands=commands)
 (P/'build.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({k:v for k,v in report.items() if k not in ['commands','source_hashes']},indent=2))
if __name__=='__main__':main()
