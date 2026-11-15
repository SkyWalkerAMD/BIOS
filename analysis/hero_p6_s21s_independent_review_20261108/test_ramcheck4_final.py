"""Independent frozen RAMCHECK4 loader and ISO review; offline only."""
from pathlib import Path
import gc,hashlib,io,json,sys
if not __debug__:raise RuntimeError('Run without -O')
sys.dont_write_bytecode=True
OUT=Path(__file__).resolve().parent;ROOT=OUT.parents[1]
BASE=ROOT/'analysis/hero_p6_ramcheck4_20261108'
CORE=ROOT/'analysis/hero_p6_settings21s_20261108'
PE='ad88d5ec533b65b3b2b983490e62afcdc1f05ea067cb23cbda85eaa2a8e3899c'
ISO='e982ff36f2eedd7bd5be710c2562546d23da61ed9e7c524d60d90d5fae2355b8'
DRIVER='401a61dbf60f128a1f0aba86462aa90ce6e69a95f4266c64876072a841672b66'
for path,pin in ((BASE/'USB/EFI/BOOT/BOOTX64.EFI',PE),(BASE/'HERO-P6-RAMCHECK-4.iso',ISO),(BASE/'USB/EFI/BOOT/HEROP6.EFI',DRIVER)):
 assert hashlib.sha256(path.read_bytes()).hexdigest()==pin
manifest=json.loads((BASE/'FROZEN-ARTIFACTS.json').read_text(encoding='utf8'))
core=json.loads((CORE/'FROZEN-CORE-UTF8.json').read_text(encoding='utf8'))
for folder,document in ((BASE,manifest),(CORE,core)):
 for name,row in document['files'].items():
  b=(folder/name).read_bytes();assert len(b)==row['bytes'] and hashlib.sha256(b).hexdigest()==row['sha256'],name
 for name,digest in document.get('sources',{}).items():assert hashlib.sha256((folder/name).read_bytes()).hexdigest()==digest,name
for name,digest in json.loads((BASE/'build.json').read_text(encoding='utf8'))['sources'].items():
 assert hashlib.sha256((BASE/'source'/name).read_bytes()).hexdigest()==digest,name
path=BASE/'tests/test_launcher_pe.py'
ns={'__file__':str(path),'__name__':'fixture_only'}
exec(compile(path.read_text(encoding='utf8').split('\nrows=[]\n',1)[0],str(path),'exec'),ns)
Machine,DEFAULT,journal=(ns[x] for x in ('Machine','DEFAULT','journal'))
rows=[]
def run(name,m,loads=0,token=None):
 text=m.run()
 assert m.calls.count('Load')==loads and m.calls.count('Start')==loads,(name,text[-2000:])
 assert not token or token in text,(name,text[-2000:])
 assert not any(n.startswith('Forbidden') for n in m.calls)
 rows.append({'name':name,'passed':True,'loads':loads,'starts':loads})
 gc.collect()
for n in (21,32):
 for state in (None,journal()):
  m=Machine(DEFAULT[:n],state)
  run(f'exact{n} defaults state_present={state is not None}',m,1,'POST_START_ONLY_EXPECTED_NV_CHANGE=0x0000000000000000')
  assert m.settings==DEFAULT[:n] and m.state==state
for n in (20,22,31,33):run(f'reject width{n}',Machine((DEFAULT+bytes(4))[:n]))
run('missing seeded exactly32 accepted',Machine(),1,'POST_START_ONLY_EXPECTED_NV_CHANGE=0x0000000000000000')
m=Machine();m.seed_width=21
run('missing unexpectedly seeded21 reported not expected',m,1,'POST_START_ONLY_EXPECTED_NV_CHANGE=0x8000000000000021')
m=Machine(DEFAULT[:21])
def race(m,name,count):
 if name=='HeroIpmiSettings' and count==2:m.settings=DEFAULT
m.mutate=race
run('21to32 width race rejects before load',m,0,'LOAD_REFUSED_CHANGED_SINCE_ENTRY')
bad=bytearray(DEFAULT[:21]);bad[0]=1
run('nondefault21 LAN configuration rejects load',Machine(bytes(bad)))

for part in ('tools/pydeps','tools/kvm-pydeps','tools/vm-pydeps','analysis/aitweaker_lock/uefi_vm_20261015'):sys.path.insert(0,str(ROOT/part))
import pycdlib,disk_images
iso=pycdlib.PyCdlib();iso.open(str(BASE/'HERO-P6-RAMCHECK-4.iso'))
assert iso.eltorito_boot_catalog.validation_entry.platform_id==0xef
for name,local in (('/EFI/BOOT/BOOTX64.EFI;1','USB/EFI/BOOT/BOOTX64.EFI'),('/EFI/BOOT/HEROP6.EFI;1','USB/EFI/BOOT/HEROP6.EFI'),('/EFIBOOT.IMG;1','efi-boot.img')):
 dest=io.BytesIO();iso.get_file_from_iso_fp(dest,iso_path=name);assert dest.getvalue()==(BASE/local).read_bytes()
iso.close()
with disk_images.PyFatFS(str(BASE/'efi-boot.img'),read_only=True) as fat:
 for name in ('BOOTX64.EFI','HEROP6.EFI'):assert fat.readbytes('/EFI/BOOT/'+name)==(BASE/'USB/EFI/BOOT'/name).read_bytes()
assert (BASE/'USB/EFI/BOOT/HEROP6.EFI').read_bytes()==(CORE/'HeroIpmiP6.efi').read_bytes()
result={'passed':True,'cases':len(rows),'launcher_sha256':PE,'iso_sha256':ISO,'core_sha256':DRIVER,'frozen_launcher_manifest_files_verified':len(manifest['files']),'frozen_core_manifest_files_verified':len(core['files']),'build_sources_match':True,'iso_root_and_el_torito_fat_match':True,'results':rows,'limits':['Actual loader PE with synthetic services; StartImage is modeled, not real machine execution.','No BMC operations, native Setup refresh, flash or recovery result is established by these offline cases.','Source is only retained in driver allocation, no launcher-owned callback is installed; unload behavior remains as reviewed.']}
(OUT/'ramcheck4-final-independent.json').write_text(json.dumps(result,indent=2)+'\n',encoding='utf8')
print(json.dumps({'passed':True,'cases':len(rows),'iso_sha256':ISO}))
