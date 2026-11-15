from pathlib import Path
import sys,json,hashlib,os,subprocess
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent
ROOT=next(p for p in HERE.parents if (p/'tools/pydeps').is_dir())
sys.path.insert(0,str(ROOT/'tools/pydeps'))
import pefile,capstone
md=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64);md.detail=True
out=[]
for name in ['20261104_001343','20261104_001457']:
 p=HERE/'runs'/name/'fixture-snapshot/P15-DIAGNOSTIC-OVMF-FIXTURE-NOT-FOR-HARDWARE.EFI'
 pe=pefile.PE(str(p));base=pe.OPTIONAL_HEADER.ImageBase;im=pe.get_memory_mapped_image()
 build=HERE/'counter_investigation'/name;build.mkdir(parents=True,exist_ok=True)
 meta=json.loads((p.parent/'build.json').read_text());env=os.environ.copy();env.update(ZIG_GLOBAL_CACHE_DIR=str(HERE/'build/zig-global'),ZIG_LOCAL_CACHE_DIR=str(build/'zig-local'))
 commands=[]
 for cmd in meta['commands'][:2]:
  cmd=list(cmd);cmd[cmd.index('-I')+1]=str(p.parent)
  source_index=cmd.index('-c')+1
  if cmd[source_index].endswith('diagnostic_ui.c'):cmd[source_index]=str(p.parent/'diagnostic_ui.c')
  cmd[cmd.index('-o')+1]=str(build/Path(cmd[cmd.index('-o')+1]).name)
  subprocess.run(cmd,check=True,env=env,cwd=ROOT);commands.append(cmd)
 cmd=list(meta['commands'][2]);cmd=[str(build/Path(x).name) if x.endswith('.obj') else '/out:'+str(build/'fixture.efi') if x.startswith('/out:') else x for x in cmd];cmd.append('/map:'+str(build/'fixture.map'));subprocess.run(cmd,check=True,cwd=ROOT,env=env);commands.append(cmd)
 compiled=pefile.PE(str(build/'fixture.efi'));compiled.OPTIONAL_HEADER.CheckSum=compiled.generate_checksum();(build/'fixture.efi').write_bytes(compiled.write())
 assert (build/'fixture.efi').read_bytes()==p.read_bytes(),name
 (build/'commands.json').write_text(json.dumps(commands,indent=2)+'\n')
 text=next(s for s in pe.sections if s.Name.startswith(b'.text'))
 ins=list(md.disasm(text.get_data(),base+text.VirtualAddress))
 out.append(f'RUN {name} SHA {hashlib.sha256(p.read_bytes()).hexdigest()} EXACT REBUILD')
 out.extend(f'{x.address-base:08x} {x.bytes.hex():24} {x.mnemonic} {x.op_str}' for x in ins)
dest=HERE/'counter_machine_review.txt';dest.write_text('\n'.join(out)+'\n');print(dest.read_text())
