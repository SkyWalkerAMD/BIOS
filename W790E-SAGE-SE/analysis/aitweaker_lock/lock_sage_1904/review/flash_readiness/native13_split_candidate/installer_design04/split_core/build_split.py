"""Compile PIC split guard and synthetic runtime fixtures; no installer/CAP."""
from pathlib import Path
import hashlib,json,os,re,struct,subprocess,sys,zlib
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent;N13=HERE.parents[1];CASE=N13.parents[2];ROOT=CASE.parents[2]
sys.path.insert(0,str(ROOT/'tools/pydeps'));import pefile,capstone
SRC=HERE/'source';BUILD=HERE/'build';BUILD.mkdir(exist_ok=True)
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
zig=ROOT/'tools/zig-x86_64-windows-0.14.1/zig.exe'
env=os.environ.copy();env.update(ZIG_LOCAL_CACHE_DIR=str(BUILD/'zig-local'),ZIG_GLOBAL_CACHE_DIR=str(BUILD/'zig-global'))
obj=BUILD/'gate.obj';pefile_out=BUILD/'SplitGuard.template.pe';mapfile=BUILD/'guard.map'
commands=[
 [str(zig),'clang','-target','x86_64-unknown-windows-msvc','-nostdinc','-isystem',str(zig.parent/'lib/include'),'-I',str(SRC),'-std=c11','-Oz','-Wall','-Wextra','-Werror','-ffreestanding','-fno-builtin','-fno-stack-protector','-mno-red-zone','-mno-stack-arg-probe','-fshort-wchar','-fno-asynchronous-unwind-tables','-fno-unwind-tables','-c',str(SRC/'gate.c'),'-o',str(obj)],
 [str(zig),'lld-link','/subsystem:efi_boot_service_driver','/entry:gate_render','/nodefaultlib','/machine:x64','/dynamicbase','/fixed:no','/nxcompat','/timestamp:0','/merge:.rdata=.text','/section:.text,ER','/map:'+str(mapfile),'/out:'+str(pefile_out),str(obj)]
]
for cmd in commands:subprocess.run(cmd,check=True,cwd=ROOT,env=env)
pe=pefile.PE(str(pefile_out));sections=[s for s in pe.sections if s.SizeOfRawData]
assert len(sections)==1 and sections[0].Name.rstrip(b'\0')==b'.text'
assert not pe.OPTIONAL_HEADER.DATA_DIRECTORY[1].Size and not pe.OPTIONAL_HEADER.DATA_DIRECTORY[5].Size
section=sections[0];template=pe.get_data(section.VirtualAddress,section.Misc_VirtualSize)
symbols={name:int(value,16)-pe.OPTIONAL_HEADER.ImageBase-section.VirtualAddress for name,value in re.findall(r'^\s+[0-9a-fA-F]{4}:[0-9a-fA-F]+\s+(\S+)\s+([0-9a-fA-F]{16})',mapfile.read_text(),re.M)}
assert 0<=symbols['gate_binding']<=len(template)-160
(BUILD/'guard_template.bin').write_bytes(template)
old_manifest=json.loads((N13.parent/'native12_safety_review/implementation/build/build.json').read_text())
originals={name:N13/'boot_context'/f'{name}.original.efi' for name in ['AMITSE','Setup']}
base={'AMITSE':0x10000000,'Setup':0x20000000};guard={'AMITSE':0x30000000,'Setup':0x30010000};state=0x30020000
op={name:pefile.PE(str(path))for name,path in originals.items()}
payloads={};tramps={};trampoline_evidence=[]
md=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64);md.detail=True
for name in ['Setup','AMITSE']:
 assert sha(originals[name])==old_manifest['modules'][name]['original_sha256']
 data=bytearray(template);tramps[name]={k:0 for k in ['loop','frame','commit','defaults','save']}
 if name=='AMITSE':
  while len(data)%16:data.append(0x90)
  for kind,rva,n in [('loop',0xe1b8,18),('frame',0x15320,15),('commit',0x11164,10),('defaults',0x5abc,11),('save',0x1425c,13)]:
   code=op[name].get_data(rva,n);ins=list(md.disasm(code,base[name]+rva));assert sum(i.size for i in ins)==n
   assert all(not i.group(capstone.CS_GRP_CALL)and not i.group(capstone.CS_GRP_JUMP)and not i.group(capstone.CS_GRP_RET)for i in ins)
   assert all(not(o.type==capstone.x86.X86_OP_MEM and o.mem.base==capstone.x86.X86_REG_RIP)for i in ins for o in i.operands)
   entry=guard[name]+len(data);back=base[name]+rva+n;tramps[name][kind]=entry
   # RIP-indirect jump uses no temporary register; copied prologue has no
   # PC-relative operand. The inline target is inside this owned RX payload.
   code+=b'\xff\x25\0\0\0\0'+struct.pack('<Q',back);data.extend(code)
   trampoline_evidence.append({'kind':kind,'original_rva':hex(rva),'original_bytes':n,'entry':hex(entry),'back':hex(back),'bytes':code.hex(),'no_pc_relative_or_control_flow_in_copied_window':True})
 payloads[name]=data

def bind(name,setup_crc):
 kind=1 if name=='AMITSE'else 2;orig_size=op[name].OPTIONAL_HEADER.SizeOfImage;t=tramps[name]
 values=[base[name],orig_size,guard[name],state,4096,t['loop'],t['frame'],t['commit'],t['defaults'],t['save'],base['Setup'],op['Setup'].OPTIONAL_HEADER.SizeOfImage,guard['Setup']+symbols['gate_callback'],guard['Setup']+symbols['gate_route'],guard['Setup'],len(payloads['Setup'])]
 data=struct.pack('<Q4I16Q2I',0x3430393153504c47,1,kind,symbols['gate_binding'],len(payloads[name]),*values,setup_crc,0);assert len(data)==160
 at=symbols['gate_binding'];payloads[name][at:at+160]=data
bind('Setup',0);bind('AMITSE',zlib.crc32(payloads['Setup']))
patches=[];memory_images={}
for name in ['AMITSE','Setup']:
 p=op[name];p.relocate_image(base[name]);memory=bytearray(p.get_memory_mapped_image());assert len(memory)==p.OPTIONAL_HEADER.SizeOfImage
 for row in old_manifest['modules'][name]['patches']:
  rva=int(row['rva'],16);entry=guard[name]+symbols[row['entry']]
  if row['kind']=='DIR64 slot':
   n=8;old=struct.pack('<Q',base[name]+int(row['old_rva'],16));new=struct.pack('<Q',entry)
  elif row['kind']=='rel32 prologue jump':
   n=row['bytes'];old=bytes.fromhex(row['old_bytes']);delta=entry-(base[name]+rva+5);assert-(1<<31)<=delta<(1<<31);new=b'\xe9'+struct.pack('<i',delta)+b'\x90'*(n-5)
  else:
   assert row['kind']=='rel32 poll call';n=5;old=op[name].get_data(rva,n);delta=entry-(base[name]+rva+5);assert-(1<<31)<=delta<(1<<31);new=b'\xe8'+struct.pack('<i',delta)
  assert bytes(memory[rva:rva+n])==old,(name,row)
  memory[rva:rva+n]=new
  patches.append({'module':name,'entry':row['entry'],'kind':row['kind'],'rva':hex(rva),'address':hex(base[name]+rva),'length':n,'old':old.hex(),'new':new.hex(),'target':hex(entry)})
 path=BUILD/(name+'.memory-fixture.bin');path.write_bytes(memory);memory_images[name]=path
 (BUILD/(name+'.split-guard.bin')).write_bytes(payloads[name])
 # Old header/section sizes remain original; these are simulated memory bytes,
 # never packaged as a flash image or as a standalone loader target.
 assert bytes(memory[:0x2c0])==p.get_memory_mapped_image()[:0x2c0]
assert len(patches)==12
state_bytes=struct.pack('<3Q2I',0,0,0x3331535441544547,1,0)+bytes(4096-32);(BUILD/'owned-state-fixture.bin').write_bytes(state_bytes)
report={'status':'COMPILED_SPLIT_GUARD_RUNTIME_FIXTURES_NO_INSTALLER_PROVIDER_OR_CAP','profile':'RAM_SPLIT_PROFILE_1_SIMULATION_ONLY','template_sha256':sha(BUILD/'guard_template.bin'),'template_bytes':len(template),'symbol_offsets':{k:hex(v)for k,v in symbols.items()},'original_bases':{k:hex(v)for k,v in base.items()},'guard_bases':{k:hex(v)for k,v in guard.items()},'state_base':hex(state),'state_bytes':4096,'immutable_binding_bytes':160,'sources':{p.name:sha(p)for p in SRC.iterdir()if p.is_file()},'commands':commands,'trampolines':trampoline_evidence,'patches':patches,'module_fixtures':{k:{'original_sha256':sha(originals[k]),'original_image_size':op[k].OPTIONAL_HEADER.SizeOfImage,'memory_fixture_sha256':sha(memory_images[k]),'guard_sha256':sha(BUILD/(k+'.split-guard.bin')),'guard_bytes':len(payloads[k])}for k in base},'same_policy_input_sha256':sha(SRC/'policy_data.h'),'old_n12_build_sha256':sha(N13.parent/'native12_safety_review/implementation/build/build.json'),'no_original_file_modified':True,'unimplemented':['Physical allocation/permissions transaction','N13 credential provider ownership binding and separate management HII','Resident installer/harness lifecycle','Permanent firmware bootstrap/default-deny integration','Native ASUS UI or hardware acceptance'],'builder_sha256':sha(Path(__file__))}
(BUILD/'split_build.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({'status':report['status'],'template_bytes':len(template),'patches':len(patches),'template_sha256':report['template_sha256']}))
