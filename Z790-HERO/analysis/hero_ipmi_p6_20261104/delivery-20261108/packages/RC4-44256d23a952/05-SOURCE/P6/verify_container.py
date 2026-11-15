"""Independent FV parser and complete UEFIExtract inventory of P6 RC4."""
from pathlib import Path
from collections import Counter
import hashlib,json,sys
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[1];sys.dont_write_bytecode=True
sys.path.insert(0,str(ROOT/'analysis/hero_ipmi_p5_rea_review_20261103'))
from container_review import read_image,sections,depex_tokens,BASE,SIZE,WRAPPER,DRIVER,SETUP,SPF
from container_review_rc2 import extracted_files
RC3=ROOT/'analysis/hero_ipmi_rc3_20261104/firmware/HERO-3107-IPMI-P5-R2-RC3-UNSIGNED.CAP'
CAP=HERE/'firmware/HERO-3107-IPMI-P6-R2-RC4-UNSIGNED.CAP'
OFFICIAL=ROOT/'analysis/hero_3107_official/ROG-MAXIMUS-Z790-HERO-ASUS-3107.CAP'
R2='89924765-f984-4ad3-839b-51fdce378d88'
def sha(b):return hashlib.sha256(b).hexdigest()
def main():
 old,new=read_image(RC3),read_image(CAP);official=OFFICIAL.read_bytes()
 assert sha(old['cap'])=='8ffc4b33f6d0e2bb7180c724de01a805f556ad126d08830e7f052b37ce771951'
 assert len(old['cap'])==len(new['cap'])==len(official)==33558528
 for b in (old['cap'],official):assert new['cap'][:BASE]==b[:BASE] and new['cap'][BASE+SIZE:]==b[BASE+SIZE:]
 for layer,allowed in [('outer',{WRAPPER}),('inner',{SETUP,SPF,DRIVER})]:
  assert set(old[layer+'_files'])==set(new[layer+'_files'])
  assert old[layer+'_info']['header_sha256']==new[layer+'_info']['header_sha256']
  for guid,entry in old[layer+'_files'].items():
   if guid not in allowed:assert entry['data']==new[layer+'_files'][guid]['data'],guid
 assert R2 not in new['outer_files'] and DRIVER not in new['outer_files']
 assert new['inner_files'][R2]['data']==(ROOT/'analysis/hero_ipmi_r2/HeroIpmiCoreR2.ffs').read_bytes()
 before,after=extracted_files(RC3),extracted_files(CAP);assert set(before)==set(after)
 changes=[];same=0
 for guid,entries in before.items():
  assert len(entries)==len(after[guid])
  if Counter(sha(x['data']) for x in entries)!=Counter(sha(x['data']) for x in after[guid]):changes.append(guid)
  else:same+=len(entries)
 assert set(changes)=={WRAPPER,SETUP,SPF,DRIVER} and sum(map(len,after.values()))==719 and same==715
 payloads=[]
 for guid,ref in [(DRIVER,HERE/'HeroIpmiP6.efi'),(SETUP,HERE/'native/Setup-P6-RESOURCE-REVIEW.efi'),(R2,ROOT/'analysis/hero_ipmi_r2/USB/EFI/HERO/HeroIpmiR2.efi')]:
  assert len(after[guid])==1
  images=[p for p in after[guid][0]['path'].rglob('body.bin') if p.parent.name.endswith('PE32 image section')]
  assert len(images)==1 and images[0].read_bytes()==ref.read_bytes()
  payloads.append(dict(guid=guid,extracted=str(images[0].relative_to(ROOT)),reference=str(ref.relative_to(ROOT)),sha256=sha(ref.read_bytes())))
 dp=depex_tokens(sections(new['inner_files'][DRIVER]['data'][24:])[0]['body'])
 assert [t[1] for t in dp if t[0]=='PUSH']==json.loads((HERE/'runtime-build.json').read_text())['depex']
 report=dict(passed=True,candidate_sha256=sha(new['cap']),base_sha256=sha(old['cap']),total_ffs=719,unchanged_ffs=715,changed_ffs=changes,r2_byte_identical=True,outside_dxe_and_capsule_header_byte_identical=True,inner_offsets_may_change=True,checksums_alignment_lzma_lengths_valid=True,extracted_payloads=payloads,depex=dp,inner=new['inner_info'],outer=new['outer_info'],scope='Offline structural checks; no firmware update or hardware execution.')
 (HERE/'container-verification.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({k:v for k,v in report.items() if k not in ('inner','outer','extracted_payloads')},indent=2))
if __name__=='__main__':main()
