"""Build position-independent guard payload and isolated modified module copies.

Never writes a CAP/FFS or modifies original/production files. Standard UEFI image
load and whole-firmware/container acceptance are separate required checks.
"""
from pathlib import Path
import hashlib,json,os,re,struct,subprocess,sys,zlib
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent;CASE=HERE.parents[3];ROOT=CASE.parents[2]
SRC=HERE/'source';OUT=HERE/'build';OUT.mkdir(exist_ok=True)
sys.path.insert(0,str(ROOT/'tools/pydeps'));import pefile
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
ZIG=ROOT/'tools/zig-x86_64-windows-0.14.1/zig.exe'
env=os.environ.copy();env.update(ZIG_GLOBAL_CACHE_DIR=str(ROOT/'tools/zig-cache-global'),ZIG_LOCAL_CACHE_DIR=str(ROOT/'tools/zig-cache-local'))
commands=[]
cc=[str(ZIG),'clang','-target','x86_64-unknown-windows-msvc','-nostdinc','-isystem',str(ZIG.parent/'lib/include'),'-I',str(SRC),'-std=c11','-Oz','-Wall','-Wextra','-Werror','-ffreestanding','-fno-builtin','-fno-stack-protector','-mno-red-zone','-mno-stack-arg-probe','-fshort-wchar','-fno-asynchronous-unwind-tables','-fno-unwind-tables','-c',str(SRC/'gate.c'),'-o',str(OUT/'gate.obj')]
subprocess.run(cc,check=True,env=env,cwd=ROOT);commands.append(cc)
efi=OUT/'GuardPayload.efi'
link=[str(ZIG),'lld-link','/subsystem:efi_boot_service_driver','/entry:gate_render','/nodefaultlib','/machine:x64','/dynamicbase','/fixed:no','/nxcompat','/timestamp:0','/merge:.rdata=.text','/section:.text,ER','/map:'+str(OUT/'gate.map'),'/out:'+str(efi),str(OUT/'gate.obj')]
subprocess.run(link,check=True,env=env,cwd=ROOT);commands.append(link)
p=pefile.PE(str(efi));symbols={n:int(v,16)-p.OPTIONAL_HEADER.ImageBase for n,v in re.findall(r'^\s+[0-9A-Fa-f]{4}:[0-9A-Fa-f]{8}\s+(\S+)\s+([0-9A-Fa-f]{16})\s',(OUT/'gate.map').read_text(),re.M)}
sections=[s for s in p.sections if s.SizeOfRawData]
assert len(sections)==1 and sections[0].Name.rstrip(b'\0')==b'.text',[(s.Name,s.SizeOfRawData)for s in p.sections]
assert not p.OPTIONAL_HEADER.DATA_DIRECTORY[5].Size,'Payload must contain no base relocations'
assert not p.OPTIONAL_HEADER.DATA_DIRECTORY[1].Size,'No import table'
s=sections[0];payload=bytes(p.get_data(s.VirtualAddress,s.Misc_VirtualSize));relative={k:v-s.VirtualAddress for k,v in symbols.items()}
for k in ['gate_binding','gate_render','gate_page_input','gate_app_input','gate_frame_input','gate_navigation','gate_poll','gate_loop','gate_callback','gate_route','gate_memory','gate_owner','gate_redirect','gate_variable_commit','gate_defaults']:
 assert 0<=relative[k]<len(payload),k
assert relative['gate_binding']+64<=len(payload)

originals={n:CASE/'analysis/modules'/f'{n}.efi' for n in ['AMITSE','Setup']}
expected={'AMITSE':'531ed4993b27252df7bc9c2104e0b752857868e3e40691707e4e490b362de3b1','Setup':'719bad779e9ae60340187c7aae6c12ab9dff3ee398c58a9fca2a4e027a33f21d'}
for n,path in originals.items():assert sha(path)==expected[n]
orig_pe={n:pefile.PE(str(path)) for n,path in originals.items()}
append={n:(orig_pe[n].OPTIONAL_HEADER.SizeOfImage+31)&~31 for n in originals}
setup_cb=append['Setup']+relative['gate_callback'];setup_route=append['Setup']+relative['gate_route']
out_records={};payloads={}
for n in ['Setup','AMITSE']:
 op=orig_pe[n];data=bytearray(originals[n].read_bytes());last=op.sections[-1]
 assert last.Name.rstrip(b'\0')==b'.reloc' and last.PointerToRawData+last.SizeOfRawData==len(data)
 assert last.VirtualAddress==last.PointerToRawData and append[n]==len(data)
 block=bytearray(payload);tramps={}
 if n=='AMITSE':
  while len(block)%16:block.append(0x90)
  for name,rva,length in [('loop',0xe1b8,18),('frame',0x15320,15),('commit',0x11164,10),('defaults',0x5abc,11)]:
   start=append[n]+len(block);tramps[name]=start
   block.extend(op.get_data(rva,length));block.extend(b'\xe9'+struct.pack('<i',rva+length-(append[n]+len(block)+5)))
 else:tramps={'loop':0,'frame':0,'commit':0,'defaults':0}
 rx_end=(len(data)+len(block)+31)&~31
 context_rva=(rx_end+4095)&~4095 if n=='AMITSE' else 0
 total=context_rva+32 if context_rva else rx_end
 setup_guard_crc=0 if n=='Setup' else out_records['Setup']['payload_text_crc32']
 # Fingerprint only the source text portion before the immutable binding. All
 # functions and generated policy follow in the same readonly payload; full
 # artifact hashes independently bind constants and patched binding values.
 setup_gate_size=relative['gate_binding']
 bind=struct.pack('<Q14I',0x3430393145544147,1,1 if n=='AMITSE' else 2,append[n]+relative['gate_binding'],total,tramps['loop'],tramps['frame'],setup_cb,setup_route,append['Setup'],setup_gate_size,setup_guard_crc,context_rva,tramps['commit'],tramps['defaults'])
 block[relative['gate_binding']:relative['gate_binding']+64]=bind
 data.extend(block);data.extend(bytes(total-len(data)))
 changes=[]
 def slot(rva,name,old):
  off=op.get_offset_from_rva(rva);assert int.from_bytes(data[off:off+8],'little')==old
  new=append[n]+relative[name];data[off:off+8]=struct.pack('<Q',new)
  relocs={e.rva:e.type for b in op.DIRECTORY_ENTRY_BASERELOC for e in b.entries};assert relocs[rva]==10
  changes.append({'kind':'DIR64 slot','rva':hex(rva),'old_rva':hex(old),'new_rva':hex(new),'entry':name})
 if n=='AMITSE':
  for rva,name,old in [(0x6b928,'gate_render',0x16a90),(0x6b930,'gate_page_input',0x16c20),(0x6b840,'gate_app_input',0x12168),(0x7d4f8,'gate_navigation',0x11fbc)]:slot(rva,name,old)
  for rva,name,length in [(0xe1b8,'gate_loop',18),(0x15320,'gate_frame_input',15),(0x11164,'gate_variable_commit',10),(0x5abc,'gate_defaults',11)]:
   new=append[n]+relative[name];old=data[rva:rva+length].hex();data[rva:rva+length]=b'\xe9'+struct.pack('<i',new-(rva+5))+b'\x90'*(length-5)
   changes.append({'kind':'rel32 prologue jump','rva':hex(rva),'old_bytes':old,'bytes':length,'new_rva':hex(new),'entry':name})
  rva=0xe6bd;assert data[rva:rva+5]==bytes.fromhex('e86a640200');new=append[n]+relative['gate_poll']
  data[rva:rva+5]=b'\xe8'+struct.pack('<i',new-(rva+5));changes.append({'kind':'rel32 poll call','rva':hex(rva),'old_rva':'0x34b2c','new_rva':hex(new),'entry':'gate_poll'})
 else:
  slot(0x2bdd8,'gate_route',0x152c);slot(0x2bde0,'gate_callback',0x1534)
 # Extend only last section; retain all original RVAs/raw offsets and original
 # relocation directory address+size. It becomes RX and non-discardable.
 last.Misc_VirtualSize=rx_end-last.PointerToRawData;last.SizeOfRawData=rx_end-last.PointerToRawData
 last.Characteristics=0x60000060
 op.OPTIONAL_HEADER.SizeOfImage=len(data);op.OPTIONAL_HEADER.SizeOfCode+=rx_end-len(originals[n].read_bytes())
 if context_rva:op.OPTIONAL_HEADER.SizeOfInitializedData+=32
 header=op.write()[:op.OPTIONAL_HEADER.SizeOfHeaders];data[:len(header)]=header
 if context_rva:
  # Create an explicit RW, non-X state section rather than occupying original
  # globals/padding. Shift only the NT headers 40B into proven zero DOS stub;
  # all original sections and their raw/RVA addresses remain exactly in place.
  assert op.DOS_HEADER.e_lfanew==0xc8 and bytes(data[0xa0:0xc8])==bytes(40)
  assert op.FILE_HEADER.NumberOfSections==6 and op.OPTIONAL_HEADER.SizeOfHeaders==0x2c0
  data[0xa0:0x298]=data[0xc8:0x2c0]
  struct.pack_into('<I',data,0x3c,0xa0);struct.pack_into('<H',data,0xa0+6,7)
  data[0x298:0x2c0]=struct.pack('<8sIIIIIIHHI',b'.gstate\0',8,context_rva,32,context_rva,0,0,0,0,0xc0000040)
 changed=pefile.PE(data=bytes(data));changed.OPTIONAL_HEADER.CheckSum=changed.generate_checksum();data=changed.write()
 path=OUT/(n+'.native-gate.UNSIGNED.review.efi');path.write_bytes(data)
 check=pefile.PE(str(path));assert check.OPTIONAL_HEADER.DATA_DIRECTORY[5].VirtualAddress==op.OPTIONAL_HEADER.DATA_DIRECTORY[5].VirtualAddress
 assert check.OPTIONAL_HEADER.DATA_DIRECTORY[5].Size==op.OPTIONAL_HEADER.DATA_DIRECTORY[5].Size
 for sec in check.sections:assert not(sec.Characteristics&0x20000000 and sec.Characteristics&0x80000000),'No RWX section'
 out_records[n]={'path':str(path.relative_to(HERE)),'sha256':sha(path),'original_sha256':expected[n],'bytes':len(data),
  'appended_rva':hex(append[n]),'payload_bytes':len(payload),'payload_text_crc32':zlib.crc32(block[:relative['gate_binding']]),
  'payload_symbols':{k:hex(append[n]+v)for k,v in relative.items()},'trampoline_rvas':{k:hex(v)for k,v in tramps.items()},'patches':changes,
  'original_section_count':op.FILE_HEADER.NumberOfSections,'section_count':check.FILE_HEADER.NumberOfSections,
  'context_head_rva':hex(context_rva),'NT_header_rva':hex(check.DOS_HEADER.e_lfanew),
  'original_rvas_preserved':True,'relocation_directory_preserved':True,'no_RWX_section':True}
 payloads[n]=bytes(block)
report={'status':'ISOLATED_NATIVE_MODULE_PROTOTYPES_NOT_FIRMWARE_ACCEPTANCE','source_sha256':{p.name:sha(p)for p in SRC.glob('*')if p.is_file()},
 'builder_sha256':sha(Path(__file__)),'guard_payload_sha256':sha(efi),'commands':commands,'modules':out_records,
 'known_unfinished':['No-safe-page fallback intentionally does not force native cleanup/ResetSystem; its safe exit proof remains pending.',
 'Optional credential/session provider is an isolated separate candidate and must be rebound to these exact module bytes. Existing e41 is incompatible with these static module hooks.',
 'The non-UI vendor defaults call is retained only at the dispatcher. Its later protected save compatibility and the direct protocol defaults method6286c remain separately unaccepted.',
 'Whole-firmware container fit, standard UEFI load/permissions, dynamic original browser and physical cold boot are not yet accepted.'],
 'device_access':False,'CAP_or_FFS_written':False}
(OUT/'build.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf8');print(json.dumps({'status':report['status'],'payload_bytes':len(payload),'modules':{k:{x:v[x]for x in ['bytes','sha256']}for k,v in out_records.items()}},indent=2))
