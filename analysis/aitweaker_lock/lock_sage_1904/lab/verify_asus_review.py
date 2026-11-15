"""Independent UEFIExtract validation of an offline review image.
This never opens a device and never invokes a firmware updater."""
from pathlib import Path
from collections import Counter
import argparse,datetime,hashlib,json,re,shutil,subprocess
from build_asus_review import SOURCE,SOURCE_SHA,OUT,ROOT,GUID
import uuid
def sha(data):return hashlib.sha256(data).hexdigest()
def collect(root):
 result=[]
 for p in root.rglob('info.txt'):
  text=p.read_text(encoding='utf8',errors='replace')
  if not re.search(r'^Type: File\s*$',text,re.M):continue
  match=re.search(r'^File GUID: (\S+)',text,re.M)
  if not match:continue
  folder=p.parent;header=(folder/'header.bin').read_bytes();body_path=folder/'body.bin'
  if body_path.exists():body=body_path.read_bytes()
  else:
   full=re.search(r'^Full size: ([0-9A-Fa-f]+)h',text,re.M)
   assert full and int(full[1],16)==len(header),str(folder)
   body=b''
  result.append({'guid':match[1].upper(),'sha256':sha(header+body),'folder':folder,'info':text})
 return result
def main(candidate=None):
 candidate=Path(candidate or OUT/'asus_review/W790E-SAGE-SE-1904-lock.review.bin').resolve()
 assert candidate.is_relative_to(OUT.resolve()) and candidate.name.endswith('.review.bin')
 manifest=candidate.with_suffix('.json')
 report=json.loads(manifest.read_text(encoding='utf8'));data=candidate.read_bytes()
 assert sha(data)==report['candidate_sha256'] and sha(SOURCE.read_bytes())==SOURCE_SHA
 driver=Path(report['driver']);assert sha(driver.read_bytes())==report['driver_sha256']
 folder=candidate.parent/'verification'/report['candidate_sha256'][:16]/datetime.datetime.now().strftime('%Y%m%d_%H%M%S');folder.mkdir(parents=True)
 isolated=folder/'W790E-SAGE-SE-1904.review.bin';shutil.copyfile(candidate,isolated)
 cmd=[str(ROOT/'tools/UEFIExtract_A75/UEFIExtract.exe'),str(isolated),'all']
 completed=subprocess.run(cmd,capture_output=True);(folder/'extract.stdout.txt').write_bytes(completed.stdout);(folder/'extract.stderr.txt').write_bytes(completed.stderr)
 assert completed.returncode==0,completed.stderr[-2000:]
 original=collect(Path(str(SOURCE)+'.dump'));modified=collect(Path(str(isolated)+'.dump'))
 container='9E21FD93-9C72-4C15-8C4B-E77F1DB2D792'
 assert len(original)==623 and sum(x['guid']==container for x in original)==1,'Incomplete original extraction baseline'
 assert len(modified)==625 and sum(x['guid']==container for x in modified)==1,'Unexpected modified FFS inventory'
 old=Counter((x['guid'],x['sha256']) for x in original if x['guid']!=container)
 new=Counter((x['guid'],x['sha256']) for x in modified if x['guid']!=container)
 assert not old-new,old-new
 extra=new-old
 assert sum(extra.values())==2 and Counter(g for (g,h),n in extra.items() for _ in range(n))==Counter({str(GUID).upper():1,'FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF':1}),extra
 inserted=[x for x in modified if x['guid']==str(GUID).upper()];assert len(inserted)==1
 added=inserted[0];assert 'Header checksum:' in added['info'] and 'invalid' not in added['info'].lower()
 payload=next(added['folder'].glob('*PE32*/body.bin')).read_bytes();assert payload==driver.read_bytes()
 depex=next(added['folder'].glob('*dependency*/body.bin')).read_bytes()
 expected_depex=b'\x02'+uuid.UUID('1e5668e2-8481-11d4-bcf1-0080c73c8881').bytes_le+b'\x02'+uuid.UUID('6441f818-6362-4e44-b570-7dba31dd2453').bytes_le+b'\x03\x08'
 assert depex==expected_depex
 # Unchanged parser warnings must not be misreported as newly introduced.
 report_new=Path(str(isolated)+'.report.txt').read_text(encoding='utf8')
 report_old=Path(str(SOURCE)+'.report.txt').read_text(encoding='utf8')
 unknown=lambda text:Counter(tuple(s.strip() for s in line.split('|')[0:2]+line.split('|')[4:5]) for line in text.splitlines() if '| Unknown' in line)
 assert unknown(report_new)==unknown(report_old)
 verification={'status':'PASS','candidate_sha256':report['candidate_sha256'],'driver_sha256':report['driver_sha256'],'uefiextract_exit_code':completed.returncode,'original_ffs_count':len(original),'candidate_ffs_count':len(modified),'original_ffs_except_recompressed_container_preserved_byte_for_byte':sum(old.values()),'inserted_driver_pe32_exact_match':True,'inserted_driver_ffs_checksums_valid':True,'depex_bytes':depex.hex(),'unknown_section_inventory_unchanged':True,'source_capsule_unchanged':True,'contains_original_signature_without_resigning':True,'hardware_boot_and_capsule_acceptance_verified':False,'evidence_folder':str(folder),'command':cmd}
 (folder/'verification.json').write_text(json.dumps(verification,indent=2),encoding='utf8')
 (candidate.parent/'verification.json').write_text(json.dumps(verification,indent=2),encoding='utf8')
 report['independent_uefiextract_validation']='PASS';report['independent_validation_report']=str(folder/'verification.json');manifest.write_text(json.dumps(report,indent=2),encoding='utf8')
 print(json.dumps(verification,indent=2))
if __name__=='__main__':
 parser=argparse.ArgumentParser();parser.add_argument('--candidate',type=Path)
 main(parser.parse_args().candidate)
