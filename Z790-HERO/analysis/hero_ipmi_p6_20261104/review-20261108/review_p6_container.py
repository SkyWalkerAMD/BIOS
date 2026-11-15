"""Independent release-container follow-up; never imports P6 builder/verifier.

Reuse the older independently implemented FV parser, then add strict single
LZMA stream checks, extraction crosschecks, source PE region checks, and fresh
UEFIExtract warning comparison on immutable copies inside this review tree.
"""
from pathlib import Path
from collections import Counter
import argparse,hashlib,json,lzma,shutil,struct,subprocess,sys,uuid
P=Path(__file__).resolve().parent;BASE=P.parent;ROOT=P.parents[2]
# Independent adaptation: .reloc RVA relocates after enlarged .rsrc by design.
sys.dont_write_bytecode=True
sys.path.insert(0,str(ROOT/'analysis/hero_ipmi_p5_rea_review_20261103'))
sys.path.insert(0,str(ROOT/'tools/pydeps'))
from container_review import read_image,sections,decode,depex_tokens,sha,BASE as FVBASE,SIZE as FVSIZE,WRAPPER,DRIVER,SETUP,SPF
from container_review_rc2 import extracted_files
import pefile
R2='89924765-f984-4ad3-839b-51fdce378d88'
RC3=ROOT/'analysis/hero_ipmi_rc3_20261104/firmware/HERO-3107-IPMI-P5-R2-RC3-UNSIGNED.CAP'
OFFICIAL=ROOT/'analysis/hero_3107_official/ROG-MAXIMUS-Z790-HERO-ASUS-3107.CAP'
def strict_guided(s):
 raw,meta=decode(s);b=s['data'];o=struct.unpack_from('<H',b,s['head']+16)[0]
 d=lzma.LZMADecompressor(format=lzma.FORMAT_ALONE);actual=d.decompress(b[o:])
 assert d.eof and not d.unused_data and actual==raw
 meta['single_complete_stream']=True;return raw,meta
def pe_body(entry):
 sec=sections(entry['data'][24:]);out=[]
 for s in sec:
  if s['type']==0x10:out.append(s['body'])
  if s['type']==2:
   raw,_=strict_guided(s);out.extend(x['body'] for x in sections(raw) if x['type']==0x10)
 assert len(out)==1;return out[0]
def describe_pe(raw):
 pe=pefile.PE(data=raw)
 return {'bytes':len(raw),'sha256':sha(raw),'machine':hex(pe.FILE_HEADER.Machine),'subsystem':pe.OPTIONAL_HEADER.Subsystem,
 'entry_rva':hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),'imagebase':hex(pe.OPTIONAL_HEADER.ImageBase),
 'checksum_valid':pe.verify_checksum(),'sections':[{'name':s.Name.rstrip(b'\0').decode(),'rva':hex(s.VirtualAddress),'raw_size':s.SizeOfRawData,
 'virtual_size':s.Misc_VirtualSize,'flags':hex(s.Characteristics),'sha256':sha(s.get_data())} for s in pe.sections]}
def extract_warning_report(capcopy):
 tool=ROOT/'tools/UEFIExtract_A75/UEFIExtract.exe'
 r=subprocess.run([str(tool),str(capcopy),'report'],cwd=P,capture_output=True,text=True,encoding='utf-8',errors='replace')
 (capcopy.parent/(capcopy.stem+'-stdout.txt')).write_text(r.stdout,encoding='utf-8')
 (capcopy.parent/(capcopy.stem+'-stderr.txt')).write_text(r.stderr,encoding='utf-8')
 assert r.returncode==0,r.stderr
 return {'returncode':r.returncode,'stdout_lines':r.stdout.splitlines(),'stderr_lines':r.stderr.splitlines()}
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--sha',default='441b61136974278a0c6fc0d46edc159c1f1557c981ae9e4a4b42b67eb65fba0f');args=ap.parse_args()
 path=BASE/'firmware/HERO-3107-IPMI-P6-R2-RC4-UNSIGNED.CAP';data=path.read_bytes();assert sha(data)==args.sha
 out=P/('container-'+args.sha[:12]);out.mkdir(exist_ok=True)
 copy=out/'P6-RC4.CAP';copy.write_bytes(data)
 prior=out/'P5-R2-RC3.CAP';prior.write_bytes(RC3.read_bytes())
 off=out/'HERO-OFFICIAL-3107.CAP';off.write_bytes(OFFICIAL.read_bytes())
 new,old,stock=read_image(copy),read_image(prior),read_image(off)
 assert sha(old['cap'])=='8ffc4b33f6d0e2bb7180c724de01a805f556ad126d08830e7f052b37ce771951'
 assert len(data)==len(old['cap'])==len(stock['cap'])==33558528
 for reference in (old,stock):
  assert data[:FVBASE]==reference['cap'][:FVBASE]
  assert data[FVBASE+FVSIZE:]==reference['cap'][FVBASE+FVSIZE:]
 direct={}
 for layer,allowed in [('outer',{WRAPPER}),('inner',{SETUP,SPF,DRIVER})]:
  a,b=old[layer+'_files'],new[layer+'_files'];assert set(a)==set(b)
  changed=[g for g in a if a[g]['data']!=b[g]['data']];assert set(changed)==allowed
  assert old[layer+'_info']['header_sha256']==new[layer+'_info']['header_sha256']
  direct[layer]={'changed':changed,'same':len(a)-len(changed),'files':len(a),'info':new[layer+'_info']}
 assert DRIVER not in new['outer_files'] and R2 not in new['outer_files']
 assert new['inner_files'][R2]['data']==old['inner_files'][R2]['data']==(ROOT/'analysis/hero_ipmi_r2/HeroIpmiCoreR2.ffs').read_bytes()
 compressed={}
 wrapper=sections(new['outer_files'][WRAPPER]['data'][24:]);assert len(wrapper)==1
 expanded,compressed['wrapper']=strict_guided(wrapper[0]);xs=sections(expanded);assert [x['type'] for x in xs]==[0x19,0x17]
 for g,n in [(SETUP,'setup'),(SPF,'spf')]:
  ss=sections(new['inner_files'][g]['data'][24:]);gs=[x for x in ss if x['type']==2];assert len(gs)==1
  plain,compressed[n]=strict_guided(gs[0])
  if g==SPF:
   pp=sections(plain);assert [x['type'] for x in pp]==[0x18,0x15]
   assert pp[0]['body'][:16]==uuid.UUID(SPF).bytes_le
   assert pp[0]['body'][16:]==(BASE/'native/AMITSESetupData-P6.bin').read_bytes()
   extracted_spf=pp[0]['body'][16:]
  else:
   pp=sections(plain);assert len(pp)==1 and pp[0]['type']==0x10
   a=sections(old['inner_files'][g]['data'][24:]);assert [x['type'] for x in a]==[0x13,2,0x14]
   assert ss[0]['data']==a[0]['data'] and ss[2]['data']==a[2]['data']
 payloads={}
 expected={DRIVER:BASE/'HeroIpmiP6.efi',SETUP:BASE/'native/Setup-P6-RESOURCE-REVIEW.efi',R2:ROOT/'analysis/hero_ipmi_r2/USB/EFI/HERO/HeroIpmiR2.efi'}
 for g,p in expected.items():
  raw=pe_body(new['inner_files'][g]);assert raw==p.read_bytes()
  payloads[g]=describe_pe(raw)
  pe=pefile.PE(data=raw)
  assert pe.FILE_HEADER.Machine==0x8664
  assert any(s.VirtualAddress<=pe.OPTIONAL_HEADER.AddressOfEntryPoint<s.VirtualAddress+s.Misc_VirtualSize and s.Characteristics&0x20000000 for s in pe.sections)
  if g in (DRIVER,R2):
   assert pe.OPTIONAL_HEADER.Subsystem==11 and not pe.FILE_HEADER.Characteristics&1
   assert pe.OPTIONAL_HEADER.DATA_DIRECTORY[5].VirtualAddress and pe.OPTIONAL_HEADER.DATA_DIRECTORY[5].Size
 a=pefile.PE(data=pe_body(stock['inner_files'][SETUP]));b=pefile.PE(data=pe_body(new['inner_files'][SETUP]))
 assert a.OPTIONAL_HEADER.AddressOfEntryPoint==b.OPTIONAL_HEADER.AddressOfEntryPoint
 assert len(a.sections)==len(b.sections)==6 and b.verify_checksum()
 setup_regions=[]
 for x,y in zip(a.sections,b.sections):
  assert x.Name==y.Name
  if x.Name.rstrip(b'\0')!=b'.reloc':assert x.VirtualAddress==y.VirtualAddress
  else:
   assert a.OPTIONAL_HEADER.DATA_DIRECTORY[5].VirtualAddress==x.VirtualAddress
   assert b.OPTIONAL_HEADER.DATA_DIRECTORY[5].VirtualAddress==y.VirtualAddress
   assert a.OPTIONAL_HEADER.DATA_DIRECTORY[5].Size==b.OPTIONAL_HEADER.DATA_DIRECTORY[5].Size
   assert all(not x.VirtualAddress<=e.rva<x.VirtualAddress+x.Misc_VirtualSize for block in a.DIRECTORY_ENTRY_BASERELOC for e in block.entries)
  same=x.get_data()==y.get_data();setup_regions.append({'name':x.Name.rstrip(b'\0').decode(),'identical_to_stock':same,'official_rva':hex(x.VirtualAddress),'candidate_rva':hex(y.VirtualAddress)})
  if x.Name.rstrip(b'\0')!=b'.rsrc':assert same
 reloc_a=[(e.type,e.rva) for block in a.DIRECTORY_ENTRY_BASERELOC for e in block.entries]
 reloc_b=[(e.type,e.rva) for block in b.DIRECTORY_ENTRY_BASERELOC for e in block.entries]
 assert reloc_a==reloc_b
 ds=sections(new['inner_files'][DRIVER]['data'][24:]);assert [s['type'] for s in ds]==[0x13,0x10,0x15]
 dp=depex_tokens(ds[0]['body']);assert [t[1] for t in dp if t[0]=='PUSH']==['ef9fc172-a1b2-4693-b327-6d32fc416042','0fd96974-23aa-4cdc-b9cb-98d17750322a','6441f818-6362-4e44-b570-7dba31dd2453']
 dep_old=depex_tokens(sections(stock['inner_files'][SETUP]['data'][24:])[0]['body'])
 assert {t[1] for t in dp if t[0]=='PUSH'}<={t[1] for t in dep_old if t[0]=='PUSH'}
 # Never trust an existing dump adjacent to a mutable main build path. Extract
 # all three pinned immutable review copies and compare their exact bytes.
 inventories={}
 for n,p in [('stock',off),('rc3',prior),('p6',copy)]:
  r=subprocess.run([str(ROOT/'tools/UEFIExtract_A75/UEFIExtract.exe'),str(p),'all'],cwd=out,capture_output=True,text=True,encoding='utf-8',errors='replace')
  (out/(n+'-fresh-extract-stdout.txt')).write_text(r.stdout,encoding='utf-8')
  (out/(n+'-fresh-extract-stderr.txt')).write_text(r.stderr,encoding='utf-8')
  assert r.returncode==0,(n,r.returncode,r.stderr)
  inventories[n]=extracted_files(p)
 counts={n:sum(map(len,inv.values())) for n,inv in inventories.items()};assert counts=={'stock':717,'rc3':719,'p6':719}
 changes={}
 for label in ['stock','rc3']:
  inv=inventories[label];actual=inventories['p6'];assert not set(inv)-set(actual)
  added=set(actual)-set(inv);same=0;diff=[]
  for g,entries in inv.items():
   assert len(entries)==len(actual[g])
   if Counter(sha(x['data']) for x in entries)==Counter(sha(x['data']) for x in actual[g]):same+=len(entries)
   else:diff.append(g)
  changes[label]={'same':same,'changed':diff,'added':sorted(added)}
  assert set(diff)==({SETUP,SPF,WRAPPER} if label=='stock' else {SETUP,SPF,WRAPPER,DRIVER})
  assert added==({DRIVER,R2} if label=='stock' else set())
 assert changes['stock']['same']==714 and changes['rc3']['same']==715
 for g,p in expected.items():
  entries=inventories['p6'][g];assert len(entries)==1
  assert entries[0]['data']==new['inner_files'][g]['data']
  images=[f for f in entries[0]['path'].rglob('body.bin') if f.parent.name.endswith('PE32 image section')]
  assert len(images)==1 and images[0].read_bytes()==p.read_bytes()
 spffiles=[f for f in inventories['p6'][SPF][0]['path'].rglob('body.bin') if f.read_bytes()==extracted_spf];assert len(spffiles)==1
 neighbors=[];keys=list(new['inner_files']);idx=keys.index(DRIVER)
 for g in keys[max(0,idx-1):idx+3]:
  e=new['inner_files'][g];neighbors.append({'guid':g,'offset':hex(e['offset']),'size':e['size'],'attributes':hex(e['attributes'])})
 warning={n:extract_warning_report(p) for n,p in [('stock',off),('rc3',prior),('p6',copy)]}
 # Preserve exact diagnostics; path/status headings may differ. Only compare
 # parse/checksum/warning lines, never rely on extractor's exit status alone.
 keys=('parse','warning','checksum','invalid','unknown','overlap','unreferenced')
 wc={n:Counter(l for l in r['stdout_lines']+r['stderr_lines'] if any(k in l.lower() for k in keys)) for n,r in warning.items()}
 newwarn={label:dict(wc['p6']-wc[label]) for label in ['stock','rc3']}
 report={'scope':'Independent CAP parsing and final-byte component identity; no flashing or BMC access','passed':True,
 'candidate':str(path),'candidate_copy':str(copy.relative_to(P)),'sha256':args.sha,'bytes':len(data),
 'base_sha256':sha(old['cap']),'official_sha256':sha(stock['cap']),'outside_dxe_including_capsule_header_identical_to_rc3_and_stock':True,
 'direct_fv':direct,'complete_inventory_counts':counts,'complete_inventory_delta':changes,'strict_lzma':compressed,
 'setup_non_resource_sections_and_relocations_identical_to_stock':True,'setup_regions':setup_regions,
 'payloads':payloads,'spf_exact':True,'setup_dependency_and_version_preserved':True,'p6_depex':dp,
 'dependencies_subset_of_stock_setup':True,'r2_exact_bytes_retained':True,'p6_driver_inner_fv_only':True,'inner_driver_neighbors':neighbors,
 'warnings':warning,'new_warning_lines':newwarn,
 'limits':['Fresh UEFIExtract reports are additional parser evidence, not a hardware decoder test.','ASUS signed capsule wrapper remains copied from official; modified payload is not ASUS re-signed.','FlashBack acceptance, cold/warm startup, native F10 edits and resulting BMC writes still require separate target validation.','Only this SHA256 is reviewed; rebuilding any component requires a new CAP identity review.']}
 (out/'independent-container-review.json').write_text(json.dumps(report,indent=2)+'\n')
 print(json.dumps({k:report[k] for k in ['passed','sha256','complete_inventory_counts','complete_inventory_delta','new_warning_lines','inner_driver_neighbors']},indent=2))
if __name__=='__main__':main()
