"""Replay captured .71 SMBIOS against frozen production and A1 PE parsers.
No source/core changes, firmware services, hardware or network are performed.
"""
from pathlib import Path
import hashlib,importlib.util,json,re,struct,sys,uuid,zlib
BASE=Path(__file__).resolve().parent;ROOT=BASE.parents[1]
source=ROOT/'analysis/hero_ipmi_complete_live_20261108/hero71-i1-current.TXT';log=source.read_text();manifest=json.loads((source.parent/'captures/hero71-i1-current/manifest.json').read_text())
assert hashlib.sha256(source.read_bytes()).hexdigest()==manifest['sha256']
def block(name):return bytes.fromhex(log.split(name+'_HEX_BEGIN\n')[1].split(name+'_HEX_END')[0])
raw=block('TABLE');ep3=block('ENTRY3');ep2=block('ENTRY2');address=struct.unpack_from('<Q',ep3,16)[0]
assert len(raw)==0x1753 and zlib.crc32(raw)==0x8b120398 and struct.unpack_from('<I',ep2,24)[0]==address
live=(source.parent/'hero71-p6a1-read.TXT').read_text();assert 'SMBIOS_BYTES=00001753 CRC32=8B120398' in live
spec=importlib.util.spec_from_file_location('prod',ROOT/'analysis/hero_p6_settings21r_20261108/verify_runtime.py');prod=importlib.util.module_from_spec(spec);spec.loader.exec_module(prod)
fixture=ROOT/'analysis/hero_p6_a1_diagnostic_20261108/tests/test_actual_pe.py';ns={'__file__':str(fixture),'__name__':'a1_fixture_only'}
exec(compile(fixture.read_text().split('\nrows=[]')[0],str(fixture),'exec'),ns)
App=ns['Machine'];uc=ns['unicorn'];from unicorn.x86_const import *
rows=[]
for mode in ('both','SMBIOS3_only','SMBIOS2_only'):
 for label in ('production_S21R','A1_bounded'):
  m=prod.Machine(prod.cfg()[:21]) if label.startswith('production') else App('QQ')
  mapped=(len(raw)+4095)&~4095;m.u.mem_map(address,mapped);m.u.mem_write(address,raw)
  tables=[]
  if mode!='SMBIOS2_only':tables.append(uuid.UUID('f2fd1544-9794-4a2c-992e-e5bbcf20e394').bytes_le+struct.pack('<Q',m.alloc(ep3)))
  if mode!='SMBIOS3_only':tables.append(uuid.UUID('eb9d2d31-2d88-11d3-9a16-0090273fc14d').bytes_le+struct.pack('<Q',m.alloc(ep2)))
  m.w64(m.st+0x68,len(tables));m.w64(m.st+0x70,m.alloc(b''.join(tables)))
  reads=[]
  def read_guard(u,access,at,n,value,ctx):
   assert address<=at and at+n<=address+len(raw),(label,hex(at),n,'outside captured SMBIOS bytes')
   reads.append((at,n))
  m.u.hook_add(uc.UC_HOOK_MEM_READ,read_guard,begin=address,end=address+mapped-1)
  if label=='A1_bounded':
   def getmap(machine,name,args,n):
    if name!='GetMap':return None
    a,b,c,d,e=args;regions=((0x100000,0x100000),(0x600000,0x300000),(0xd00000,0x200000),(0x2000000,0x200000),(ns['IMAGE'],0x2000000),(address,mapped))
    data=b''.join(struct.pack('<IIQQQQ',4,0,p,0,size//4096,0) for p,size in regions)
    assert machine.r64(a)>=len(data);machine.u.mem_write(b,data);machine.w64(a,len(data));machine.w64(c,1);machine.w64(d,40);machine.u.mem_write(e,struct.pack('<I',1));return 0
   m.call_fault=getmap
  m.call('detect_board');p=m.functions['report'];board=bytes(m.u.mem_read(p,96)).split(b'\0',1)[0].decode();bios=bytes(m.u.mem_read(p+96,96)).split(b'\0',1)[0].decode()
  assert board=='ROG MAXIMUS Z790 HERO' and bios=='3107' and reads
  assert not m.dev.packets and not m.pci_writes and not m.nv_writes
  pe=ROOT/('analysis/hero_p6_settings21r_20261108/HeroIpmiP6.efi' if label.startswith('production') else 'analysis/hero_p6_a1_diagnostic_20261108/USB/EFI/BOOT/BOOTX64.EFI')
  rows.append(dict(case=mode,implementation=label,pe_sha256=hashlib.sha256(pe.read_bytes()).hexdigest(),board=board,bios=bios,reads=len(reads),minimum_offset=min(a-address for a,n in reads),maximum_read_end=max(a+n-address for a,n in reads),all_reads_inside_captured_table=True,uefi_calls=m.calls))
result={'passed':True,'source':str(source.relative_to(ROOT)),'capture_sha256':manifest['sha256'],'table_bytes':len(raw),'table_crc32':f'{zlib.crc32(raw):08X}','table_sha256':hashlib.sha256(raw).hexdigest(),'latest_A1_read_log_has_same_table_bytes_and_crc':True,'cases':rows,'limits':['Tests replay immutable captured table bytes, real entrypoint bytes, and mapped memory. They do not assert unchanged runtime pointers or contents during the failed S21R callback.','A1 also validates raw Type1 UUID, uniqueness, stable table bytes and readable memory; production detect_board does not. Equivalence is demonstrated for this valid captured table, not malformed/adversarial tables.','No new core, loader, ISO or CAP was built.']}
(BASE/'actual-identity-comparison.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result,indent=2))
