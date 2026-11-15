"""Read independently produced UEFIExtract dumps for the sizing-only FV."""
from pathlib import Path
from collections import Counter
import hashlib,json,lzma,sys
HERE=Path(__file__).resolve().parent;CASE=HERE.parents[3];ROOT=CASE.parents[2];OUT=HERE/'build/sizing_only'
sys.path.insert(0,str(CASE/'lab'))
from verify_asus_review import collect
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
s=json.loads((OUT/'sizing_report.json').read_text());old=OUT/'original-inner.BASELINE.fv';new=OUT/'native-gates-only.SIZING-ONLY.fv'
cap=ROOT/'analysis/aitweaker_lock/official_W790E_SAGE_SE_1904/W790E_SAGE_SE_1904/Pro-WS-W790E-SAGE-SE-ASUS-1904.CAP'
assert sha(cap)==s['source_CAP_sha256'];b=cap.read_bytes();at=0x3181078+24;n=int.from_bytes(b[at:at+3],'little')
assert old.read_bytes()==lzma.decompress(b[at+24:at+n],format=lzma.FORMAT_ALONE)[16:]
assert sha(new)==s['alternative_provider_in_existing_outer_erased_space']['guard_only_FV_sha256']
a=collect(Path(str(old)+'.dump'));b=collect(Path(str(new)+'.dump'));assert len(a)==len(b)
guids={'Setup':'899407D7-99FE-43D8-9A21-79EC328CAC21','AMITSE':'B1DA0ADF-4F77-4070-A88E-BFFE1C60529A'}
aa=Counter((x['guid'],x['sha256'])for x in a if x['guid']not in guids.values());bb=Counter((x['guid'],x['sha256'])for x in b if x['guid']not in guids.values());assert aa==bb
modules={}
for name,guid in guids.items():
 previous=[x for x in a if x['guid']==guid];changed=[x for x in b if x['guid']==guid];assert len(previous)==len(changed)==1
 pes=list(changed[0]['folder'].rglob('*PE32 image section/body.bin'));assert len(pes)==1 and sha(pes[0])==s['guard_module_sha256'][name]
 assert pes[0].read_bytes()==(OUT/(name+'.snapshot.efi')).read_bytes()
 assert 'invalid'not in changed[0]['info'].lower()
 # Every non-PE original section in each modified module retains exact body.
 non_pe=lambda root:Counter((p.parent.name.split(' ',1)[-1],sha(p))for p in root.rglob('body.bin')if p.parent!=root and 'PE32 image section'not in p.parent.name and 'EE4E5898'not in p.parent.name)
 assert non_pe(previous[0]['folder'])==non_pe(changed[0]['folder'])
 modules[name]={'FFS_sha256':changed[0]['sha256'],'PE32_sha256':sha(pes[0]),'PE32_path':str(pes[0]),'unchanged_non_PE_section_bodies':sum(non_pe(changed[0]['folder']).values())}
unknown=lambda text:Counter(tuple(x.strip()for x in line.split('|')[:2]+line.split('|')[4:5])for line in text.splitlines()if '| Unknown'in line)
ra=Path(str(old)+'.report.txt');rb=Path(str(new)+'.report.txt');assert unknown(ra.read_text())==unknown(rb.read_text())
r={'status':'PASS_INDEPENDENT_UEFIEXTRACT_SIZING_ONLY_INNER_FV','source_CAP_sha256':s['source_CAP_sha256'],'original_inner_FV_sha256':sha(old),'changed_inner_FV_sha256':sha(new),'original_FFS_count':len(a),'changed_FFS_count':len(b),'all_other_FFS_bytes_preserved_count':sum(aa.values()),'modified_modules':modules,'all_other_module_section_bodies_unchanged':True,'unknown_section_inventory_unchanged':True,'reports_sha256':{'original':sha(ra),'changed':sha(rb)},'extractor_sha256':sha(ROOT/'tools/UEFIExtract_A75/UEFIExtract.exe'),'sizing_report_sha256':sha(OUT/'sizing_report.json'),'verifier_sha256':sha(Path(__file__)),
 'limitations':['UEFIExtract parsed each standalone FV with exit0. Both emitted the same no-Volume-Top-File warning because only the inner FV is supplied; no whole-firmware validity claim.','This validates the sizing-only guard FV. The old provider size snapshot is not present in this FV and is not accepted as a final driver.','Inner FFS offsets move; firmware behavior must not be inferred solely from successful extraction.','No CAP, full flash image, hardware access or production artifact mutation.']}
(OUT/'extract_verification.json').write_text(json.dumps(r,indent=2)+'\n',encoding='utf8');print(json.dumps({k:r[k]for k in ['status','original_FFS_count','changed_FFS_count','all_other_FFS_bytes_preserved_count']},indent=2))
