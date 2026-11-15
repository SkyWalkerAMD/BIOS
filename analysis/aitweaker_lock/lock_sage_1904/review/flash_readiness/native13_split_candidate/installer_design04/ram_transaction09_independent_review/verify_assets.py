"""Independent constants/PE/12-site audit and real bind_guard byte execution."""
from pathlib import Path
import hashlib,json,re,struct,subprocess,sys
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent;D04=HERE.parent;TX=D04/'ram_transaction09'
CORE=D04/'diagnostic_guard09';P15=D04/'provider15_diagnostic09'
ROOT=next(p for p in HERE.parents if(p/'tools/pydeps').is_dir())
sys.path.insert(0,str(ROOT/'tools/pydeps'))
import pefile,unicorn as U
from unicorn import x86_const as R
EXPECTED='3a1def1697c50d1a61b20fc205539fca24107d12891d62b2e971dd6ccde7d1b9'
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
q=lambda n:struct.pack('<Q',n)
checks=[]
def check(label,ok):assert ok,label;checks.append(label)
def main():
 app=TX/'app_build/SageNative13RamTest09.efi';buildfile=TX/'app_build/app_build.json';build=json.loads(buildfile.read_text())
 check('exact final app hash',sha(app)==build['efi_sha256']==EXPECTED)
 for row in build['sources']:check('source '+row['path'],sha(TX/row['path'])==row['sha256'])
 for n,digest in build['objects'].items():check('object '+n,sha(TX/'app_build'/n)==digest)
 pe=pefile.PE(str(app));BASE=pe.OPTIONAL_HEADER.ImageBase;raw=bytes(pe.get_memory_mapped_image())
 entries=re.findall(r'^\s+[0-9A-Fa-f]{4}:[0-9A-Fa-f]+\s+(\S+)\s+([0-9A-Fa-f]{16})\s+(.+)$',(TX/'app_build/app.map').read_text(),re.M)
 symbols={n:int(a,16)for n,a,obj in entries}
 def at(name,n):a=symbols[name]-BASE;return raw[a:a+n]
 meta=json.loads((CORE/'build/split_build.json').read_text());template=(CORE/'build/guard_template.bin').read_bytes()
 check('actual app embeds full frozen guard template',at('split_template',len(template))==template)
 table_objects=[(int(a,16),obj)for n,a,obj in entries if n=='tx_sites']
 check('two compiled site tables found',len(table_objects)==2)
 expected=[]
 for p in meta['patches']:
  m=0 if p['module']=='AMITSE'else 1;old=bytes.fromhex(p['old']);kind={'DIR64 slot':0,'rel32 prologue jump':1,'rel32 CALL':2}.get(p['kind'])
  if kind is None:kind=2 if 'call' in p['kind'].lower()else None
  check('recognized exact detour kind '+p['entry'],kind is not None)
  original_rva=int.from_bytes(old,'little')-int(meta['original_bases'][p['module']],16) if not kind else 0
  expected.append(struct.pack('<6I',m,int(p['rva'],16),kind,p['length'],int(meta['symbol_offsets'][p['entry']],16),original_rva)+old.ljust(24,b'\0'))
 table=b''.join(expected)
 for a,obj in table_objects:check('compiled12 table exact '+obj,raw[a-BASE:a-BASE+len(table)]==table)
 # Read provider bytes from the compiled app, not just a generated C array.
 provider=P15/'build/AiTweakerSplitProvider15.UNSIGNED.local.efi';pdata=provider.read_bytes();pp=pefile.PE(data=pdata)
 check('embedded actual P15 file exact',at('provider_file',len(pdata))==pdata and sha(provider)=='d15438fde33bf0fada0a33f9f62a9ca8ff72cf21bb924ceaeca0bc75a0b0a5cf')
 declared=[(0,pp.OPTIONAL_HEADER.SizeOfHeaders)]+[(s.VirtualAddress,s.Misc_VirtualSize or s.SizeOfRawData)for s in pp.sections]
 canonical=bytearray(pp.OPTIONAL_HEADER.SizeOfImage);canonical[:pp.OPTIONAL_HEADER.SizeOfHeaders]=pdata[:pp.OPTIONAL_HEADER.SizeOfHeaders]
 for s in pp.sections:
  copied=s.Misc_VirtualSize
  if not copied or copied>s.SizeOfRawData:copied=s.SizeOfRawData
  canonical[s.VirtualAddress:s.VirtualAddress+copied]=pdata[s.PointerToRawData:s.PointerToRawData+copied]
 segments=b''.join(struct.pack('<II',a,n)+hashlib.sha256(canonical[a:a+n]).digest()for a,n in declared)
 check('compiled declared ranges include complete header/virtual bytes/BSS only',at('provider_segments',len(segments))==segments)
 check('declared ranges bounded and nonoverlapping',all(a+n<=len(canonical)and n>=8 for a,n in declared)and all(declared[i][0]+declared[i][1]<=declared[i+1][0]for i in range(len(declared)-1)))
 relocs=[r.rva for b in pp.DIRECTORY_ENTRY_BASERELOC for r in b.entries if r.type]
 check('37 unique actual DIR64 relocations',len(relocs)==len(set(relocs))==37 and all(r.type in[0,10]for b in pp.DIRECTORY_ENTRY_BASERELOC for r in b.entries))
 check('compiled relocation list exact',at('provider_relocs',len(relocs)*4)==struct.pack('<'+'I'*len(relocs),*relocs))
 check('all relocations completely inside declared bytes',all(any(a<=r and r+8<=a+n for a,n in declared)for r in relocs))
 # Execute the actual app bind_guard against independent owned copies. No
 # allocator, protocol or validation service is replaced inside bind_guard.
 vm=U.Uc(U.UC_ARCH_X86,U.UC_MODE_64);vm.mem_map(BASE,(pe.OPTIONAL_HEADER.SizeOfImage+4095)&~4095);vm.mem_write(BASE,raw)
 DATA=0x50000000;STACK=0x70000000;STOP=0x51000000;guard=[0x30000000,0x31000000];state=0x32000000;modules=[0x10000000,0x20000000]
 for a,n in[(DATA,0x10000),(STACK,0x10000),(STOP,4096),(state,4096),(guard[0],0x6000),(guard[1],0x6000)]:vm.mem_map(a,n)
 sizes=[meta['module_fixtures'][n]['original_image_size']for n in['AMITSE','Setup']]
 gsizes=[meta['module_fixtures'][n]['guard_bytes']for n in['AMITSE','Setup']]
 plan=struct.pack('<10Q',*modules,*sizes,*guard,*gsizes,state,4096);vm.mem_write(DATA+40,plan)
 writes=[]
 vm.hook_add(U.UC_HOOK_MEM_WRITE,lambda u,access,a,n,v,d:writes.append((a,n)))
 vm.hook_add(U.UC_HOOK_CODE,lambda u,a,n,d:u.emu_stop(),begin=STOP,end=STOP)
 for m in[1,0]:
  sp=STACK+0xfe08;vm.mem_write(sp,q(STOP)+bytes(0x100));vm.reg_write(R.UC_X86_REG_RSP,sp);vm.reg_write(R.UC_X86_REG_RCX,DATA);vm.reg_write(R.UC_X86_REG_RDX,m)
  vm.emu_start(symbols['bind_guard'],0,count=5000000);check('actual bind_guard returns for module'+str(m),vm.reg_read(R.UC_X86_REG_RIP)==STOP)
 expected_payloads={};offset=int(meta['symbol_offsets']['gate_binding'],16)
 import zlib
 tramp_offsets=[];cursor=(len(template)+15)&~15
 for rva,n in[(0xe1b8,18),(0x15320,15),(0x11164,10),(0x5abc,11),(0x1425c,13)]:tramp_offsets.append((cursor,rva,n));cursor+=n+14
 for m in[1,0]:
  blob=bytearray(template)+bytearray([0x90])*(gsizes[m]-len(template));targets=[0]*5
  if not m:
   original=pefile.PE(str(D04.parent/'boot_context/AMITSE.original.efi')).get_memory_mapped_image()
   for i,(a,rva,n)in enumerate(tramp_offsets):
    blob[a:a+n+14]=original[rva:rva+n]+b'\xff\x25\0\0\0\0'+q(modules[0]+rva+n);targets[i]=guard[0]+a
  values=[modules[m],sizes[m],guard[m],state,4096,*targets,modules[1],sizes[1],guard[1]+int(meta['symbol_offsets']['gate_callback'],16),guard[1]+int(meta['symbol_offsets']['gate_route'],16),guard[1],gsizes[1]]
  binding=struct.pack('<Q4I16Q2I',0x3430393153504c47,1,m+1,offset,gsizes[m],*values,zlib.crc32(expected_payloads[1])if not m else 0,0)
  blob[offset:offset+160]=binding;expected_payloads[m]=bytes(blob)
  check('runtime guard/trampolines/binding independently reconstructed module'+str(m),bytes(vm.mem_read(guard[m],gsizes[m]))==blob)
  check('rounded guard tail zero module'+str(m),not any(vm.mem_read(guard[m]+gsizes[m],((gsizes[m]+4095)&~4095)-gsizes[m])))
 check('actual bind_guard only writes owned guards and stack',all(any(a<=p and p+n<=a+size for a,size in[(guard[0],0x6000),(guard[1],0x6000),(STACK,0x10000)])for p,n in writes))
 # No source inference transfers a runtime pass: this proves the new adapter
 # delta really is the reviewed init block, labels and regenerated assets.
 old=D04/'ram_transaction08';platform=(TX/'source/platform.c').read_text();before=(old/'source/platform.c').read_text()
 added=''' /* Private diagnostics use only the existing exclusively owned RW/NX page.
  * The full page was zeroed above; initialize once before any native detour.
  * Neither trace availability nor its contents enter authorization/rollback. */
 DIAG09_REGION *diagnostic=(void *)(uintptr_t)(p.state_base+DIAG09_STATE_OFFSET);
 diagnostic->magic=DIAG09_MAGIC;diagnostic->revision=DIAG09_REVISION;diagnostic->bytes=DIAG09_REGION_BYTES;
'''
 check('platform delta only exact header/init block',platform.replace('#include "diagnostic09.h"\n','').replace(added,'')==before)
 for name in['transaction.c','transaction.h','app.h','entry.S','platform_readonly.inc','ui_bindings.h']:
  check('unchanged lifecycle/source '+name,(TX/'source'/name).read_bytes()==(old/'source'/name).read_bytes())
 check('diag header exact frozen private ABI',(TX/'source/diagnostic09.h').read_bytes()==(CORE/'source/diagnostic09.h').read_bytes())
 check('UI only P15 label delta',(TX/'source/session_ui.c').read_text().replace('P15','P14')==(old/'source/session_ui.c').read_text())
 check('app only09 labels',(TX/'source/app.c').read_text().replace('TEST09','TEST08')==(old/'source/app.c').read_text())
 check('transport only09 labels',(TX/'source/transport/kvm.c').read_text().replace('TEST09','TEST08')==(old/'source/transport/kvm.c').read_text())
 # Relink the exact objects into this review directory; no source rebuild.
 out=HERE/'object_relink';out.mkdir(exist_ok=True);file=out/'RELINK_ONLY_NEVER_BOOT.efi';command=build['commands'][-1][:]
 check('known local linker',command[1]=='lld-link'and Path(command[0]).resolve()==(ROOT/'tools/zig-x86_64-windows-0.14.1/zig.exe').resolve())
 check('object list pinned',command[-len(build['objects']):]==[str(TX/'app_build'/n)for n in build['objects']])
 command=[('/out:'+str(file))if a.startswith('/out:')else('/map:'+str(out/'app.map'))if a.startswith('/map:')else a for a in command]
 subprocess.run(command,cwd=ROOT,capture_output=True,check=True)
 linked=pefile.PE(str(file));linked.OPTIONAL_HEADER.CheckSum=linked.generate_checksum();file.write_bytes(linked.write())
 check('independent exact object relink matches final app',sha(file)==EXPECTED)
 report={'status':'PASS_INDEPENDENT_TX09_COMPILED_ASSETS_RUNTIME_BINDING_AND_RELINK','checks':len(checks),'check_names':checks,'efi_sha256':EXPECTED,'test_source_sha256':sha(Path(__file__)),'build_sha256':sha(buildfile),'provider_sha256':sha(provider),'template_sha256':sha(CORE/'build/guard_template.bin'),'declared_provider_ranges':declared,'declared_provider_bytes':sum(n for a,n in declared),'dir64_count':len(relocs),'runtime_guard_sha256':{str(m):hashlib.sha256(b).hexdigest()for m,b in expected_payloads.items()},'source_init_extent':[64,640],'limitations':['Only actual bind_guard executes in this test. Allocator, permission/TPL transition and platform_prepare are reviewed and tested separately; this fixture does not establish physical ownership.','The source delta check proves the exact reviewed initialization block was compiled with the bound source; it is not a full initialization execution trace.','Relink uses the author compiler objects; it is an object/link reproducibility check, not a second compiler proof.','Provider validation compares declared loaded bytes and all37 relocations, excluding unspecified PE alignment gaps.','No hardware, credential, NVRAM, foreign page modification or flash operation.']}
 (HERE/'assets_review.json').write_text(json.dumps(report,indent=2)+'\n')
 print(json.dumps({'status':report['status'],'checks':len(checks),'sha256':sha(HERE/'assets_review.json')}))
if __name__=='__main__':main()
