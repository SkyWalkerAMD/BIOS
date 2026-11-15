"""Independent A1 boundary cases using the exact built PE and UEFI doubles.

The author fixture's class definitions supply memory/UEFI mocks only. Tests
below are separate, do not modify that fixture, and do not invoke hardware.
"""
from pathlib import Path
import gc,hashlib,io,json,struct,sys
sys.dont_write_bytecode=True
OUT=Path(__file__).resolve().parent;ROOT=OUT.parents[1]
BASE=ROOT/'analysis/hero_p6_a1_diagnostic_20261108'
for part in ('tools/pydeps','tools/kvm-pydeps','tools/vm-pydeps','analysis/aitweaker_lock/uefi_vm_20261015'):
 sys.path.insert(0,str(ROOT/part))
PIN='232d6f2111a1089a24df8a621539a71ffdeaa91f91fa39439bc44477ec6a35c0'
ISO='fdc72f68d63fc337673292a217c9262a87cc9e43c206c0b089c0a96963c40233'
assert hashlib.sha256((BASE/'USB/EFI/BOOT/BOOTX64.EFI').read_bytes()).hexdigest()==PIN
assert hashlib.sha256((BASE/'HERO-P6-A1-DIAGNOSTIC.iso').read_bytes()).hexdigest()==ISO
path=BASE/'tests/test_actual_pe.py';ns={'__file__':str(path),'__name__':'definitions_only'}
exec(compile(path.read_text(encoding='utf8').split('\nrows=[]\n',1)[0],str(path),'exec'),ns)
Machine,DEFAULT,ERR=(ns[k] for k in ('Machine','DEFAULT','ERR'))
rows=[]
def verify(name,make,expected,check=lambda m:None):
 m=make();m.run();assert list(m.boundary.values())==expected,(name,m.boundary)
 check(m);rows.append({'name':name,'passed':True,'stages':m.boundary.copy(),'hii_sets':len(m.hii_sets),'ipmi_requests':len(m.dev.packets)})
 del m;gc.collect();print(name,'PASS',flush=True)
def changed_after_read():
 m=Machine('B\rR\rP\rPQQ')
 def change(m,k):
  if k=='P':m.vars['HeroIpmiSettings']=(3,DEFAULT)
 m.key_mutate=change;return m
verify('safe variable width changes after R: P refuses before HII write',changed_after_read,[1,1,0,0],lambda m: (not m.hii_sets) or (_ for _ in ()).throw(AssertionError()))
def resident_late():
 m=Machine('B\rR\rRPQQ')
 def change(m,k):
  if k=='R':m.p6_present=True
 m.key_mutate=change;return m
verify('P6 resident appears after B: R refuses before KCS access',resident_late,[1,0,0,0],lambda m: (not m.dev.packets) or (_ for _ in ()).throw(AssertionError()))
def duplicate():
 m=Machine('B\rRPQQ')
 def fault(m,name,args,n):
  if name=='HiiList':
   a,b,c,d,e=args;m.w64(d,16)
   if not e:return ERR(5)
   m.w64(e,100);m.w64(e+8,100);return 0
 m.call_fault=fault;return m
verify('two exact matching Forms handles refuse ambiguous binding',duplicate,[1,0,0,0])
def growing():
 m=Machine('B\rRPQQ')
 def fault(m,name,args,n):
  if name=='HiiExport' and args[3]:m.w64(args[2],m.r64(args[2])+1);return 0
 m.call_fault=fault;return m
verify('export success with size beyond allocated capacity rejected and freed',growing,[1,0,0,0])
def unterminated():
 m=Machine('B\rRPQQ')
 def fault(m,name,args,n):
  if name=='HiiGet':
   sp=m.u.reg_read(ns['UC_X86_REG_RSP']);size_ptr=m.r64(sp+0x30)
   m.u.mem_write(args[4],b'A\0'*160);m.w64(size_ptr,320);return 0
 m.call_fault=fault;return m
verify('unterminated HII GetString refuses B before hardware use',unterminated,[1,0,0,0])
def partial_publish():
 m=Machine('B\rR\rP\rP\rPQQ')
 def fault(m,name,args,n):
  if name=='HiiSet' and n==17:return ERR(7)
 m.call_fault=fault;return m
def partial_check(m):
 assert len(m.hii_sets)==16 and m.config[4]&2==0
verify('full publish service failure is terminal with no automatic retry',partial_publish,[1,1,1,1],partial_check)
import pycdlib,disk_images
iso=pycdlib.PyCdlib();iso.open(str(BASE/'HERO-P6-A1-DIAGNOSTIC.iso'))
assert iso.eltorito_boot_catalog.validation_entry.platform_id==0xef
for name,local in (('/EFI/BOOT/BOOTX64.EFI;1','USB/EFI/BOOT/BOOTX64.EFI'),('/EFIBOOT.IMG;1','efi-boot.img')):
 out=io.BytesIO();iso.get_file_from_iso_fp(out,iso_path=name);assert out.getvalue()==(BASE/local).read_bytes()
iso.close()
with disk_images.PyFatFS(str(BASE/'efi-boot.img'),read_only=True) as fat:
 assert fat.readbytes('/EFI/BOOT/BOOTX64.EFI')==(BASE/'USB/EFI/BOOT/BOOTX64.EFI').read_bytes()
build=json.loads((BASE/'build.json').read_text(encoding='utf8'))
for name,digest in build['sources'].items():assert hashlib.sha256((BASE/'source'/name).read_bytes()).hexdigest()==digest,name
report={'passed':True,'pe_sha256':PIN,'iso_sha256':ISO,'cases':len(rows),'results':rows,'iso_root_and_el_torito_fat_pe_exact':True,'build_sources_match':True,
 'limits':['Simulated UEFI/HII services; does not prove real AMITSE reentry or native automatic behavior.','Expected full-publish service failure can leave some display strings updated; configuration and firmware remain untouched.']}
(OUT/'a1-stage-independent.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf8')
print(json.dumps({k:v for k,v in report.items() if k!='results'}))
