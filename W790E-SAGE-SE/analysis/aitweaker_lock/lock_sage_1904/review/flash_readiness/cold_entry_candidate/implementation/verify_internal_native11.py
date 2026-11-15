"""Independent whole-image byte/FFS/extraction validation, offline only."""
from pathlib import Path
from collections import Counter
import hashlib,json,lzma,struct,subprocess,sys,uuid
HERE=Path(__file__).resolve().parent;CASE=HERE.parents[3];ROOT=CASE.parents[2]
sys.path[:0]=[str(CASE/'lab'),str(CASE/'review/flash_readiness')]
from inject_ovmf import valid_fv,find_free
from verify_asus_review import collect
from verify_capsule_static import parse_capsule,signatures
OUT=HERE/'build/integration_native11_review';sha=lambda b:hashlib.sha256(b).hexdigest();digest=lambda p:sha(p.read_bytes())
m=json.loads((OUT/'integration_manifest.json').read_text());original=Path(m['source_CAP']);candidate=Path(m['candidate_path']);a=original.read_bytes();b=candidate.read_bytes()
assert sha(a)==m['source_CAP_sha256']=='aba26bf927de341f1859dd6b5f35645564d5aea104fb26bcc7b5a98bcd96b0b3'
assert sha(b)==m['candidate_sha256'] and len(a)==len(b)==67112960
assert candidate.resolve().parent==OUT.resolve() and m['status']=='INTERNAL_UNSIGNED_NOT_RELEASE_READY'
allowed=m['allowed_changed_ranges'];assert [(x['offset'],x['size'])for x in allowed]==[(0x3181078,0x35f9e8),(0x35bf950,m['provider_FFS_allocation'])]
cursor=0;cover=[];range_changes=[]
for r in allowed:
 at=r['offset'];end=at+r['size'];assert cursor<=at<end<=len(a)
 assert a[cursor:at]==b[cursor:at];cover.append({'offset':cursor,'size':at-cursor,'equal':True,'sha256':sha(a[cursor:at])})
 range_changes.append({**r,'changed_bytes':sum(x!=y for x,y in zip(a[at:end],b[at:end])),'old_sha256':sha(a[at:end]),'new_sha256':sha(b[at:end])});cursor=end
assert a[cursor:]==b[cursor:];cover.append({'offset':cursor,'size':len(a)-cursor,'equal':True,'sha256':sha(a[cursor:])})
assert sum(x['size']for x in cover)+sum(x['size']for x in allowed)==len(a)
assert a[:4096]==b[:4096] and a[0x35bf950:0x35bf950+m['provider_FFS_allocation']]==b'\xff'*m['provider_FFS_allocation']
def check_files(data,fv):
 size,header=valid_fv(data,fv);free,available,files=find_free(data,fv)
 for r in files:
  at=int(r['offset'],16);h=data[at:at+24];body=data[at+24:at+r['size']]
  assert (sum(h)-h[17]-h[23])&255==0
  assert (sum(body)+h[17])&255==0 if h[19]&0x40 else h[17]==0xaa
  assert at%8==0 and at+r['size']<=fv+size
 return files
old_outer=check_files(a,0x3181000);new_outer=check_files(b,0x3181000)
assert len(new_outer)==len(old_outer)+2
for row in old_outer:
 at=int(row['offset'],16)
 if at!=0x3181078:assert sha(b[at:at+row['size']])==row['sha256']
def unpack(image):
 at=0x3181078+24;n=int.from_bytes(image[at:at+3],'little');s=image[at:at+n];props=s[24]
 filters={'id':lzma.FILTER_LZMA1,'lc':props%9,'lp':props//9%5,'pb':props//45,'dict_size':int.from_bytes(s[25:29],'little')}
 dec=lzma.LZMADecompressor(format=lzma.FORMAT_RAW,filters=[filters]);raw=dec.decompress(s[37:]);assert not dec.unused_data and len(raw)==int.from_bytes(s[29:37],'little')
 assert raw[:12]==bytes.fromhex('0800001900000000ffffff17') and int.from_bytes(raw[12:16],'little')==len(raw)-8
 return raw
old_raw=unpack(a);new_raw=unpack(b);old_inner=check_files(old_raw,16);new_inner=check_files(new_raw,16)
assert len(old_inner)==len(new_inner)==413
modified_guids={'899407d7-99fe-43d8-9a21-79ec328cac21','b1da0adf-4f77-4070-a88e-bffe1c60529a'}
for old,new in zip(old_inner,new_inner):
 assert old['guid']==new['guid']
 if old['guid']not in modified_guids:assert old['sha256']==new['sha256']
header=parse_capsule(a);assert parse_capsule(b)==header
old_sig=signatures(a,header);new_sig=signatures(b,header)
assert old_sig['firmware_signature']['valid']and old_sig['certificate_signature']['valid']and not new_sig['firmware_signature']['valid']and new_sig['certificate_signature']['valid']
regions=[]
for area in sorted(header['regions'],key=lambda r:r['body_offset']):
 start=area['cap_offset'];end=start+area['size'];regions.append({**area,'old_sha256':sha(a[start:end]),'new_sha256':sha(b[start:end]),'equal':a[start:end]==b[start:end]})
assert sum(r['size']for r in regions)==len(a)-4096
# Execute the independent parser only on the new review image; original dump
# already exists from the pinned original source and is rechecked below.
cmd=[str(ROOT/'tools/UEFIExtract_A75/UEFIExtract.exe'),str(candidate),'all']
run=subprocess.run(cmd,capture_output=True);(OUT/'uefiextract.stdout.txt').write_bytes(run.stdout);(OUT/'uefiextract.stderr.txt').write_bytes(run.stderr)
assert run.returncode==0,run.stderr[-2000:]
old=collect(Path(str(original)+'.dump'));new=collect(Path(str(candidate)+'.dump'))
assert len(old)==623 and len(new)==625,(len(old),len(new))
changed_guids={g.upper()for g in modified_guids}|{'9E21FD93-9C72-4C15-8C4B-E77F1DB2D792'}
old_rest=Counter((x['guid'],x['sha256'])for x in old if x['guid']not in changed_guids)
new_rest=Counter((x['guid'],x['sha256'])for x in new if x['guid']not in changed_guids)
assert not(old_rest-new_rest);extra=new_rest-old_rest
assert sum(extra.values())==2 and Counter(g for (g,h),n in extra.items()for _ in range(n))==Counter({m['provider_FFS_guid'].upper():1,'FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF':1})
modules={}
for name,guid,expected in [('Setup','899407D7-99FE-43D8-9A21-79EC328CAC21',m['guard_module_sha256']['Setup']),('AMITSE','B1DA0ADF-4F77-4070-A88E-BFFE1C60529A',m['guard_module_sha256']['AMITSE']),('Provider',m['provider_FFS_guid'].upper(),m['provider_sha256'])]:
 rows=[x for x in new if x['guid']==guid];assert len(rows)==1;row=rows[0]
 pes=list(row['folder'].rglob('*PE32 image section/body.bin'));assert len(pes)==1 and digest(pes[0])==expected
 snapshot=OUT/'inputs'/('AiTweakerNativeProvider1904.UNSIGNED.review.efi'if name=='Provider'else name+'.UNSIGNED.review.efi')
 assert pes[0].read_bytes()==snapshot.read_bytes();assert 'invalid'not in row['info'].lower()
 copied=OUT/('reextracted-'+name+'.UNSIGNED.review.efi');copied.write_bytes(pes[0].read_bytes())
 modules[name]={'FFS_guid':guid,'FFS_sha256':row['sha256'],'PE32_sha256':digest(copied),'bytes':copied.stat().st_size,'reextracted_path':str(copied)}
 if name=='Provider':
  deps=list(row['folder'].glob('*dependency*/body.bin'));assert len(deps)==1
  expected_depex=b'\x02'+uuid.UUID('1e5668e2-8481-11d4-bcf1-0080c73c8881').bytes_le+b'\x02'+uuid.UUID('6441f818-6362-4e44-b570-7dba31dd2453').bytes_le+b'\x03\x08'
  assert deps[0].read_bytes()==expected_depex
unknown=lambda text:Counter(tuple(s.strip()for s in line.split('|')[:2]+line.split('|')[4:5])for line in text.splitlines()if '| Unknown'in line)
assert unknown(Path(str(candidate)+'.report.txt').read_text())==unknown(Path(str(original)+'.report.txt').read_text())
r={'status':'PASS_INTERNAL_UNSIGNED_STRUCTURE_ONLY_NOT_RELEASE_READY','candidate_sha256':sha(b),'source_CAP_sha256':sha(a),'input_manifest_sha256':digest(OUT/'integration_manifest.json'),'full_image_bytes':len(b),'all_image_bytes_accounted_for':True,'unchanged_segments':cover,'allowed_changed_ranges':range_changes,'all_22_ROM_regions':regions,'original_header_equal':True,'original_signatures':old_sig,'candidate_signatures':new_sig,'all_bytes_outside_two_ranges_equal':True,'outer_original_FFS_count':len(old_outer),'outer_new_FFS_count':len(new_outer),'other_outer_files_same_offsets_and_bytes':len(old_outer)-1,'inner_original_FFS_count':len(old_inner),'inner_new_FFS_count':len(new_inner),'inner_unmodified_FFS_bytes_exact':len(old_inner)-2,'inner_original_order_preserved':True,'all_checked_FFS_headers_and_data_checksums_valid':True,'all_checked_FV_headers_valid':True,'original_uefiextract_FFS_count':len(old),'new_uefiextract_FFS_count':len(new),'all_other_extracted_FFS_exact':sum(old_rest.values()),'reextracted_modules':modules,'provider_DEPEX_hex':expected_depex.hex(),'uefiextract_exit_code':run.returncode,'uefiextract_command':cmd,'uefiextract_sha256':digest(ROOT/'tools/UEFIExtract_A75/UEFIExtract.exe'),'unknown_section_inventory_unchanged':True,'verifier_sha256':digest(Path(__file__)),'unchanged_limitations':m['not_accepted'],'hardware_boot_verified':False,'updater_acceptance_verified':False,'uploaded_or_flashed':False,'production_EXP02_EXP03_root_ZIPs_modified':False}
(OUT/'verification.json').write_text(json.dumps(r,indent=2)+'\n',encoding='utf8')
print(json.dumps({k:r[k]for k in ['status','candidate_sha256','all_image_bytes_accounted_for','all_other_extracted_FFS_exact','original_uefiextract_FFS_count','new_uefiextract_FFS_count','hardware_boot_verified']},indent=2))
