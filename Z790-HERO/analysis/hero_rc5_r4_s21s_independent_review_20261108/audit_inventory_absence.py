"""Independent official-to-baseline provenance; no project inventory publisher.

Uses this agent's strict container parser, not the author builder/parser.
Stock ASUS inventory/network support is outside the exclusion claim.
"""
from pathlib import Path
import hashlib,importlib.util,json,lzma,struct,sys,uuid
if not __debug__:raise RuntimeError('Assertions required')
sys.dont_write_bytecode=True
OUT=Path(__file__).resolve().parent;ROOT=OUT.parents[1]
spec=importlib.util.spec_from_file_location('independent',ROOT/'analysis/hero_rc5_independent_review_20261108/audit_rc5.py')
a=importlib.util.module_from_spec(spec);spec.loader.exec_module(a)
import pefile
SETUP='899407d7-99fe-43d8-9a21-79ec328cac21';SPF='fe612b72-203c-47b1-8560-a66d946eb371'
CANDIDATE=ROOT/'analysis/hero_ipmi_rc5_s21s_20261108/RC5-IPMI-ONLY-R4-S21S-CANDIDATE03/HERO-3107-IPMI-RC5-IPMI-ONLY-R4-S21S-CANDIDATE03-UNSIGNED.CAP'
PINS={'official':a.PINNED['official'],'baseline':a.PINNED['baseline'],'candidate':'7a21f28c5a805ea29d651524b2ec2e05925252ff0799b71251583d99e1d53624'}
APIS=('dfb7ec4e-5499-4812-a2b7-ab6601f4e505','7e06fa9a-532e-44c6-928a-cf19d2718e4b')
MARKERS=(b'HERO-INVENTORY-I3',b'HERO-INVENTORY-I5',b'I3D_INVENTORY_STEP',b'I3B_INVENTORY_STEP',b'I5_AUTOMATIC_NETWORK_PREPARATION',b'I5_DRIVER_RESIDENT_UNTIL_RESET')
def sha(b):return hashlib.sha256(b).hexdigest()
def leaves(stream,depth=0):
 assert depth<8 and len(stream)<=32*1024*1024
 for s in a.sections(stream):
  if s['type']==2:
   b=s['body'];assert a.guid(b[:16])==a.LZMA_GUID
   off,flags=struct.unpack_from('<HH',b,16);assert off==s['head']+20 and flags==1
   z=s['data'][off:];plain=lzma.decompress(z,format=lzma.FORMAT_ALONE)
   assert len(plain)==struct.unpack_from('<Q',z,5)[0]
   yield from leaves(plain,depth+1)
  else:yield s
def project_pes():
 known={}
 for name in ('hero_inventory_publish_20261108','hero_inventory_publish_i3a_20261108','hero_inventory_publish_i3b_20261108','hero_inventory_publish_i3d_20261108','hero_inventory_i5_20261108'):
  family=ROOT/'analysis'/name;assert family.is_dir()
  for p in family.glob('**/USB/EFI/BOOT/*.EFI'):
   if p.name.upper()!='BOOTX64.EFI' and not p.name.upper().startswith('I5'):continue
   raw=p.read_bytes();pe=pefile.PE(data=raw);assert pe.OPTIONAL_HEADER.Subsystem in (10,11)
   row=known.setdefault(sha(raw),dict(raw=raw,bytes=len(raw),subsystem=pe.OPTIONAL_HEADER.Subsystem,paths=[]))
   row['paths'].append(p.relative_to(ROOT).as_posix())
 assert len(known)==15
 return known
def main():
 imgs={k:a.image(p) for k,p in [('official',a.OFFICIAL),('baseline',a.BASELINE),('candidate',CANDIDATE)]}
 for key,image in imgs.items():assert sha(image['cap'])==PINS[key]
 known=project_pes();official=imgs['official'];records={}
 oldsetup=list(leaves(official['inner']['files'][SETUP]['data'][24:]));assert [x['type'] for x in oldsetup]==[19,16,20]
 oldpe=pefile.PE(data=oldsetup[1]['body'])
 for key in ('baseline','candidate'):
  image=imgs[key];changes={};unchanged=[]
  assert image['cap'][:a.BASE]==official['cap'][:a.BASE] and image['cap'][a.BASE+a.LENGTH:]==official['cap'][a.BASE+a.LENGTH:]
  for layer,allowed in [('outer',{a.WRAPPER}),('inner',{SETUP,SPF})]:
   old=official[layer]['files'];new=image[layer]['files'];added=set(new)-set(old);removed=set(old)-set(new)
   assert not removed and added==({a.R2,a.P6} if layer=='inner' else set())
   assert [x for x in image[layer]['order'] if x in old]==official[layer]['order']
   changed={g for g in old if old[g]['data']!=new[g]['data']};assert changed==allowed
   unchanged.extend((layer,g,sha(new[g]['data'])) for g in old if g not in changed)
   changes[layer]=dict(added=sorted(added),removed=[],changed=sorted(changed))
  assert len(unchanged)==541
  setup=list(leaves(image['inner']['files'][SETUP]['data'][24:]));assert [x['type'] for x in setup]==[19,16,20]
  assert setup[0]['data']==oldsetup[0]['data'] and setup[2]['data']==oldsetup[2]['data']
  assert setup[1]['body']==(ROOT/'analysis/hero_ipmi_p6_20261104/native/Setup-P6-RESOURCE-REVIEW.efi').read_bytes()
  newpe=pefile.PE(data=setup[1]['body']);assert newpe.verify_checksum()
  assert newpe.OPTIONAL_HEADER.AddressOfEntryPoint==oldpe.OPTIONAL_HEADER.AddressOfEntryPoint==0x500
  assert len(newpe.sections)==len(oldpe.sections)==6
  sections=[]
  for old,new in zip(oldpe.sections,newpe.sections):
   assert old.Name==new.Name and old.Characteristics==new.Characteristics
   resource=old.Name==b'.rsrc\0\0\0'
   if not resource:assert old.get_data()==new.get_data()
   else:assert not new.Characteristics&0x20000000
   if old.Name!=b'.reloc\0\0':assert old.VirtualAddress==new.VirtualAddress
   sections.append(dict(name=old.Name.rstrip(b'\0').decode(),old_sha256=sha(old.get_data()),new_sha256=sha(new.get_data()),executable=bool(new.Characteristics&0x20000000),identical=old.get_data()==new.get_data()))
  assert [(e.type,e.rva) for x in oldpe.DIRECTORY_ENTRY_BASERELOC for e in x.entries]==[(e.type,e.rva) for x in newpe.DIRECTORY_ENTRY_BASERELOC for e in x.entries]
  for i,(old,new) in enumerate(zip(oldpe.OPTIONAL_HEADER.DATA_DIRECTORY,newpe.OPTIONAL_HEADER.DATA_DIRECTORY)):
   if i==2:assert old.VirtualAddress==new.VirtualAddress
   elif i==5:assert old.Size==new.Size
   else:assert (old.VirtualAddress,old.Size)==(new.VirtualAddress,new.Size)
  spf=list(leaves(image['inner']['files'][SPF]['data'][24:]));assert [x['type'] for x in spf]==[24,21]
  assert spf[0]['body'][:16]==uuid.UUID(SPF).bytes_le
  assert spf[0]['body'][16:]==(ROOT/'analysis/hero_ipmi_p6_20261104/native/AMITSESetupData-P6.bin').read_bytes()
  scanned=[]
  for guid in (SETUP,SPF,a.R2,a.P6):
   for index,s in enumerate(leaves(image['inner']['files'][guid]['data'][24:])):
    b=s['body']
    for digest,row in known.items():assert row['raw'] not in b,(key,guid,digest)
    for marker in MARKERS:assert marker not in b and marker.decode().encode('utf-16-le') not in b
    for api in APIS:
     assert uuid.UUID(api).bytes_le not in b
     for spelling in (api,api.upper()):assert spelling.encode() not in b and spelling.encode('utf-16-le') not in b
    scanned.append(dict(guid=guid,section=index,type=s['type'],bytes=len(b),sha256=sha(b)))
  records[key]=dict(changes_from_official=changes,original_ffs_byte_identical_count=541,unchanged_ffs=unchanged,setup_entry_rva=0x500,setup_sections=sections,setup_relocations_identical=True,spf_raw_hii_ui_only=True,exact_previously_reviewed_native_resources=True,decoded_leaves_scanned=scanned,inventory_pe_or_api_or_markers_found=False)
 for g in (SETUP,SPF):assert imgs['baseline']['inner']['files'][g]['data']==imgs['candidate']['inner']['files'][g]['data']
 artifacts=[dict(sha256=h,**{k:v for k,v in row.items() if k!='raw'}) for h,row in known.items()]
 result=dict(passed=True,no_project_i3_i5_publisher_in_baseline_or_candidate=True,input_sha256=PINS,independent_parser='hero_rc5_independent_review_20261108/audit_rc5.py strict parser',images=records,known_compiled_project_executables=artifacts,known_project_api_guids=APIS,api_guids_are_not_ffs_guids=True,scope='Complete official provenance plus only four modified/new FFS leaf inspections; no claim that stock ASUS network/inventory functionality is absent.',hardware_access=False)
 (OUT/'independent-inventory-exclusion.json').write_text(json.dumps(result,indent=2)+'\n',encoding='utf8')
 print(json.dumps(dict(passed=True,sha256=sha((OUT/'independent-inventory-exclusion.json').read_bytes()),original_unchanged=541,known_compiled_pes=len(known))))
if __name__=='__main__':main()
