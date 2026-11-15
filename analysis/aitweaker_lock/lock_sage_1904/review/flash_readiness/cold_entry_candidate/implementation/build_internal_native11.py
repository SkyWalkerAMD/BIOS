"""Build one isolated INTERNAL/UNSIGNED/NOT_RELEASE_READY image offline.

Requires the final provider's manifest, exact guard binding and completed local
joint/OVMF review. Never changes an original or previously published artifact.
"""
from pathlib import Path
import argparse,hashlib,json,lzma,struct,sys,uuid
HERE=Path(__file__).resolve().parent;CASE=HERE.parents[3];ROOT=CASE.parents[2]
sys.path[:0]=[str(CASE/'lab'),str(CASE/'review/flash_readiness')]
from build_asus_review import SOURCE,SOURCE_SHA,CONTAINER,SECTION,OUTER,INNER,FILTER,align,ffs_header,padding_file,validate_ffs
from inject_ovmf import valid_fv,find_free,ffs_for_driver
from verify_capsule_static import parse_capsule,signatures
sha=lambda b:hashlib.sha256(b).hexdigest()
digest=lambda p:sha(p.read_bytes())
OUT=HERE/'build/integration_native11_review';SIZING=HERE/'build/sizing_only';PROV=CASE/'review/flash_readiness/native_provider_candidate'
GUID=uuid.UUID('8b4e0d52-28b5-4d1f-b4bc-750e9d9d1904')
PIN_MODULES={'AMITSE':'03f8b6011ad624106f03e95b5e568906d2f7d64b73a1ff6ddf76899b56631593','Setup':'f70ec6f75f46bddb20aa57513c611d5957cb29414bb1918a1bdedd0c215a5739'}
def json_read(p):return json.loads(p.read_text())
def validate_inputs(expected):
 m=json_read(HERE/'build/build.json');review=json_read(HERE/'build/native11_review.json')
 assert {n:r['sha256']for n,r in m['modules'].items()}==PIN_MODULES==review['frozen_module_sha256']
 assert review['build_manifest_sha256']==digest(HERE/'build/build.json') and review['guard_points']==11
 for n,r in m['modules'].items():assert digest(HERE/r['path'])==r['sha256']
 for n,h in m['source_sha256'].items():assert digest(HERE/'source'/n)==h
 for r in review['evidence']:assert digest(HERE/'build'/r['report'])==r['sha256'] and digest(HERE/r['source'])==r['source_sha256']
 sizing=json_read(SIZING/'sizing_report.json');extract=json_read(SIZING/'extract_verification.json')
 assert sizing['guard_module_sha256']==PIN_MODULES and extract['sizing_report_sha256']==digest(SIZING/'sizing_report.json')
 fv=SIZING/'native-gates-only.SIZING-ONLY.fv';assert digest(fv)==extract['changed_inner_FV_sha256']==sizing['alternative_provider_in_existing_outer_erased_space']['guard_only_FV_sha256']
 pb=json_read(PROV/'build/build.json');pr=json_read(PROV/'provider_review.json');pm=json_read(PROV/'candidate_manifest.json');binding=json_read(PROV/'guard_binding.json')
 provider=PROV/'build/AiTweakerNativeProvider1904.UNSIGNED.review.efi'
 assert expected==pb['efi_sha256']==pr['efi']['sha256']==pm['efi_sha256']==digest(provider),'Provider is not consistently frozen'
 assert pr['status']=='INTERNAL_PROVIDER_COMPLETE_WITH_LOCAL_VALIDATION_NOT_FLASH_RELEASE'
 assert binding['guard_build_sha256']==digest(HERE/'build/build.json') and pb['guard_binding_sha256']==digest(PROV/'guard_binding.json')
 assert {n:r['module_sha256']for n,r in binding['modules'].items()}==PIN_MODULES
 assert {n:r['module_sha256']for n,r in pr['bound_static_modules'].items()}==PIN_MODULES
 for n,h in pb['sources'].items():assert digest(PROV/'source'/n)==h
 for n,h in pb['objects'].items():assert digest(PROV/'build'/n)==h
 for r in pm['artifacts']:
  p=Path(r['path']).resolve();assert p.is_relative_to(PROV.resolve()),p
  assert p.stat().st_size==r['bytes'] and digest(p)==r['sha256'],p
 reports={}
 for row in pr['tests']:
  p=Path(row['path']);assert digest(p)==row['sha256'];r=json_read(p);assert r['status'].startswith('PASS_')
  if 'efi_sha256'in r:assert r['efi_sha256']==expected
  if 'guard_binding_sha256'in r:assert r['guard_binding_sha256']==digest(PROV/'guard_binding.json')
  reports[p.name]={'sha256':digest(p),'status':r['status'],'checks':r.get('check_count',r.get('case_count'))}
 for name in ['native_joint_verification.json','ovmf_load_result.json']:assert name in reports
 ovmf=json_read(PROV/'ovmf_load_result.json');assert ovmf['provider_entrypoint_started']and not ovmf['OEM_entrypoints_started']and ovmf['input_disk_unchanged']
 assert digest(Path(ovmf['debug_log']))==ovmf['debug_sha256']
 return m,provider,fv,review,pr,reports
def build(expected,check_only=False):
 m,provider,fv,review,pr,reports=validate_inputs(expected)
 original=SOURCE.read_bytes();assert sha(original)==SOURCE_SHA and len(original)==0x4001000
 outer_size,_=valid_fv(original,OUTER);assert outer_size==0x59f000
 outer_free,outer_available,outer_files=find_free(original,OUTER);assert outer_free==0x35bf950
 old_slot=align(int.from_bytes(original[CONTAINER+20:CONTAINER+23],'little'),8);assert old_slot==0x35f9e8
 assert CONTAINER+old_slot<=outer_free and outer_free+outer_available==OUTER+outer_size
 n=int.from_bytes(original[SECTION:SECTION+3],'little');old_raw=lzma.decompress(original[SECTION+24:SECTION+n],format=lzma.FORMAT_ALONE)
 new_fv=fv.read_bytes();valid_fv(new_fv,0);raw=bytearray(old_raw[:16]+new_fv);struct.pack_into('<I',raw,12,len(raw)-8)
 valid_fv(raw,16);_,_,inner_files=find_free(bytes(raw),16)
 packed=lzma.compress(bytes(raw),format=lzma.FORMAT_ALONE,filters=[FILTER]);packed=packed[:5]+len(raw).to_bytes(8,'little')+packed[13:]
 assert lzma.decompress(packed[13:],format=lzma.FORMAT_RAW,filters=[FILTER])==raw
 sh=bytearray(original[SECTION:SECTION+24]);sh[:3]=(24+len(packed)).to_bytes(3,'little');body=bytes(sh)+packed
 container=ffs_header(original[CONTAINER:CONTAINER+24],body)+body;required=align(len(container),8);pad=old_slot-required
 assert pad>=24 and pad%8==0
 replacement=container+b'\xff'*(required-len(container))+padding_file(pad);assert len(replacement)==old_slot
 data=provider.read_bytes();pffs=ffs_for_driver(data,GUID,'Ai Tweaker native provider INTERNAL');provider_allocation=align(len(pffs),8)
 assert provider_allocation<=outer_available and original[outer_free:outer_free+provider_allocation]==b'\xff'*provider_allocation
 result=bytearray(original);result[CONTAINER:CONTAINER+old_slot]=replacement;result[outer_free:outer_free+len(pffs)]=pffs;result=bytes(result)
 assert len(result)==len(original)and result[:4096]==original[:4096]
 segments=[(0,CONTAINER),(CONTAINER+old_slot,outer_free),(outer_free+provider_allocation,len(original))]
 for start,end in segments:assert result[start:end]==original[start:end]
 valid_fv(result,OUTER);validate_ffs(result,CONTAINER,len(container));validate_ffs(result,CONTAINER+required,pad);validate_ffs(result,outer_free,len(pffs))
 _,remaining,new_outer=find_free(result,OUTER);assert len(new_outer)==len(outer_files)+2 and remaining==outer_available-provider_allocation
 for row in outer_files:
  at=int(row['offset'],16)
  if at!=CONTAINER:assert sha(result[at:at+row['size']])==row['sha256']
 old_header=parse_capsule(original);new_header=parse_capsule(result);assert old_header==new_header
 original_signatures=signatures(original,old_header);new_signatures=signatures(result,new_header)
 assert original_signatures['firmware_signature']['valid']and original_signatures['certificate_signature']['valid']
 assert not new_signatures['firmware_signature']['valid']and new_signatures['certificate_signature']['valid']
 regions=[]
 for area in old_header['regions']:
  at=area['cap_offset'];end=at+area['size'];regions.append({**area,'old_sha256':sha(original[at:end]),'new_sha256':sha(result[at:end]),'equal':original[at:end]==result[at:end]})
 report={'status':'INTERNAL_UNSIGNED_NOT_RELEASE_READY','purpose':'OFFLINE INTEGRATION REVIEW ONLY; DO NOT FLASH','source_CAP':str(SOURCE),'source_CAP_sha256':SOURCE_SHA,'candidate_sha256':sha(result),'candidate_bytes':len(result),'guard_module_sha256':PIN_MODULES,'provider_sha256':expected,'provider_bytes':len(data),'provider_FFS_guid':str(GUID),'provider_FFS_offset':hex(outer_free),'provider_FFS_bytes':len(pffs),'provider_FFS_allocation':provider_allocation,'outer_container_offset':hex(CONTAINER),'outer_container_original_allocation':old_slot,'new_compressed_container_bytes':len(container),'outer_padding_FFS_bytes':pad,'outer_remaining_erased_bytes':remaining,'original_other_outer_FFS_offsets_and_bytes_preserved':len(outer_files)-1,'inner_FFS_count':len(inner_files),'original_inner_FFS_order_preserved':True,'inner_FFS_offsets_after_growing_modules_moved':True,
 'allowed_changed_ranges':[{'offset':CONTAINER,'size':old_slot,'description':'Recompressed existing nested FV container plus padding FFS within its original allocation'},{'offset':outer_free,'size':provider_allocation,'description':'Final native provider FFS in previously erased outer-FV tail'}],
 'all_bytes_outside_two_allowed_ranges_equal':True,'unchanged_segments':[{'offset':a,'size':b-a,'sha256':sha(original[a:b])}for a,b in segments],'full_ROM_layout_regions':regions,'all_22_ROM_regions_partition_complete_body':True,'original_4096_capsule_header_identical':True,'original_signatures':original_signatures,'candidate_signatures':new_signatures,'signature_note':'Original OEM certificate/signature bytes are retained. RSA-PSS verifies the original payload; the changed firmware payload fails that same original signature. No signing or verification bypass. No assumption about BMC trust-anchor enforcement.',
 'DEPEX':['EFI_VARIABLE_ARCH_PROTOCOL','EFI_VARIABLE_WRITE_ARCH_PROTOCOL','AND','END'],'insertion_order':'Existing inner FFS order is retained; static Setup and AMITSE module copies replace their respective original entries. Provider is a new last outer-FV FFS. Dependency truth and placement do not prove dispatch order or physical boot.',
 'native11_review_sha256':digest(HERE/'build/native11_review.json'),'provider_review_sha256':digest(PROV/'provider_review.json'),'provider_manifest_sha256':digest(PROV/'candidate_manifest.json'),'provider_binding_sha256':digest(PROV/'guard_binding.json'),'provider_local_tests':reports,'sizing_extract_report_sha256':digest(SIZING/'extract_verification.json'),'builder_sha256':digest(Path(__file__)),'independent_UEFIExtract':'PENDING','check_only':check_only,
 'not_accepted':['Normal cold boot / direct Del full graphical BIOS and automatic DXE scheduling.','CMOS/missing-variable initialization and subsequent protected save compatibility.','Direct protocol6286C defaults path has no established normal UI caller and remains separately unaccepted.','OEM save/default action feedback can ignore denial; no complete graphical save/exit acceptance.','Missing safe Main or malformed history has no accepted safe-exit recovery.','Actual ASUS NVRAM enrollment/persistence, runtime page permissions and hardware compatibility.','ASUS updater acceptance, cryptographic authorization and recoverable physical flashing.'],
 'hardware_access':False,'uploaded_or_flashed':False,'production_EXP02_EXP03_root_ZIPs_modified':False}
 if check_only:return report
 OUT.mkdir(exist_ok=True);target=OUT/'W790E-SAGE-SE-1904-NATIVE11-INTERNAL-UNSIGNED-NOT-RELEASE-READY.review.bin'
 assert not target.exists(),'Immutable review output already exists; do not overwrite'
 inputs=OUT/'inputs';inputs.mkdir(exist_ok=True)
 for path in [HERE/'build/build.json',HERE/'build/native11_review.json',PROV/'build/build.json',PROV/'provider_review.json',PROV/'candidate_manifest.json',PROV/'guard_binding.json',PROV/'ovmf_load_result.json']:
  tag='guard-'if path.is_relative_to(HERE)else'provider-';(inputs/(tag+path.name)).write_bytes(path.read_bytes())
 for name,row in m['modules'].items():(inputs/(name+'.UNSIGNED.review.efi')).write_bytes((HERE/row['path']).read_bytes())
 (inputs/'AiTweakerNativeProvider1904.UNSIGNED.review.efi').write_bytes(data)
 target.write_bytes(result);report['candidate_path']=str(target);(OUT/'integration_manifest.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf8')
 return report
if __name__=='__main__':
 parser=argparse.ArgumentParser();parser.add_argument('--provider-sha',required=True);parser.add_argument('--check-only',action='store_true');a=parser.parse_args();r=build(a.provider_sha,a.check_only)
 print(json.dumps({k:r[k]for k in ['status','candidate_sha256','candidate_bytes','provider_sha256','outer_padding_FFS_bytes','outer_remaining_erased_bytes','check_only']},indent=2))
