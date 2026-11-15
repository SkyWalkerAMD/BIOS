"""Build bounded transaction core for machine-code tests; not a hardware app."""
from pathlib import Path
import hashlib,json,os,re,struct,subprocess,sys
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent;D04=HERE.parent;N13=D04.parent;ROOT=N13.parents[5]
exec(compile((HERE/'verify_frozen_inputs.py').read_text(),str(HERE/'verify_frozen_inputs.py'),'exec'),{'__file__':str(HERE/'verify_frozen_inputs.py')})
SRC=HERE/'source';BUILD=HERE/'build';BUILD.mkdir(exist_ok=True)
CORE=D04/'diagnostic_guard09';b=json.loads((CORE/'build/split_build.json').read_text());sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
frozen=json.loads((D04/'provider15_diagnostic09/local_candidate_manifest.json').read_text())
for a in frozen['artifacts']:assert sha(D04/a['path'])==a['sha256']
decl=['/* Generated from frozen split profile1; exact12 sites, no generic patch API. */','typedef struct {uint32_t module,rva,kind,length,target,original_rva;uint8_t original[24];} TX_SITE;']
for name in ['AMITSE','Setup']:
 row=b['module_fixtures'][name];decl.extend([f'#define TX_{name.upper()}_SIZE {row["original_image_size"]}u',f'#define TX_{name.upper()}_GUARD_SIZE {row["guard_bytes"]}u'])
rows=[]
for r in b['patches']:
 i=0 if r['module']=='AMITSE'else 1;kind=0 if r['kind']=='DIR64 slot'else 1 if r['kind']=='rel32 prologue jump'else 2
 original=bytes.fromhex(r['old']);old_rva=struct.unpack('<Q',original)[0]-int(b['original_bases'][r['module']],16)if kind==0 else 0
 rows.append('{'+f'{i},{int(r["rva"],16)},{kind},{r["length"]},{int(b["symbol_offsets"][r["entry"]],16)},{old_rva},'+'{'+','.join(str(x)for x in original)+'}}')
decl.append('static const TX_SITE tx_sites[12]={'+','.join(rows)+'};')
(SRC/'transaction_plan.h').write_text('\n'.join(decl)+'\n')
zig=ROOT/'tools/zig-x86_64-windows-0.14.1/zig.exe';env=os.environ.copy();env.update(ZIG_LOCAL_CACHE_DIR=str(BUILD/'zig-local'),ZIG_GLOBAL_CACHE_DIR=str(BUILD/'zig-global'))
obj=BUILD/'transaction.obj';efi=BUILD/'TransactionCore09.TESTONLY.efi'
commands=[[str(zig),'clang','-target','x86_64-unknown-windows-msvc','-nostdinc','-isystem',str(zig.parent/'lib/include'),'-I',str(SRC),'-std=c11','-O2','-Wall','-Wextra','-Werror','-ffreestanding','-fno-builtin','-fno-stack-protector','-mno-red-zone','-mno-stack-arg-probe','-fshort-wchar','-c',str(SRC/'transaction.c'),'-o',str(obj)],
 [str(zig),'lld-link','/subsystem:efi_boot_service_driver','/entry:tx_install','/nodefaultlib','/machine:x64','/dynamicbase','/fixed:no','/nxcompat','/timestamp:0','/map:'+str(BUILD/'transaction.map'),'/out:'+str(efi),str(obj)]]
for cmd in commands:subprocess.run(cmd,check=True,env=env,cwd=ROOT)
sys.path.insert(0,str(ROOT/'tools/pydeps'));import pefile
p=pefile.PE(str(efi));assert not p.OPTIONAL_HEADER.DATA_DIRECTORY[1].Size
assert all(not(s.Characteristics&0x20000000 and s.Characteristics&0x80000000)for s in p.sections)
r={'status':'COMPILED_BOUNDED_TRANSACTION_CORE_TEST_CARRIER_NOT_UEFI_ENTRY_APP','efi_sha256':sha(efi),'efi_bytes':efi.stat().st_size,'source_sha256':{x.name:sha(x)for x in SRC.iterdir()if x.is_file()},'split_build_sha256':sha(CORE/'build/split_build.json'),'frozen_p15_manifest_sha256':sha(D04/'provider15_diagnostic09/local_candidate_manifest.json'),'commands':commands,'sites':12,'limits':['Host validator and UEFI app/allocator/provider/UI lifecycle adapter are not yet implemented by this core.','No permission services or allocation/variable/HII/filesystem/RT-table/flash operations exist in this core.','BSP TPL transaction cannot exclude arbitrary AP/SMM writes or recover an unhandled hardware page fault. Unknown target bytes or failed restoration require resident hold with raised TPL.','This PE has a test-only entry signature and must not be launched by firmware.']}
(BUILD/'build.json').write_text(json.dumps(r,indent=2)+'\n');print(json.dumps({'status':r['status'],'efi_sha256':r['efi_sha256'],'bytes':r['efi_bytes']}))
