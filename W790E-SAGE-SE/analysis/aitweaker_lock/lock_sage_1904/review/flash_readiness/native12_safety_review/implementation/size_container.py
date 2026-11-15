"""Sizing-only inner FV reconstruction; NEVER produces a CAP or full image.

Use one explicitly archived provider snapshot only to estimate size. It is NOT
accepted or ABI/current-guard matched by this script. Do not deliver its FV.
"""
from pathlib import Path
import hashlib,json,lzma,struct,sys,uuid
HERE=Path(__file__).resolve().parent;CASE=HERE.parents[3];ROOT=CASE.parents[2]
sys.path.insert(0,str(CASE/'lab'))
from inject_ovmf import valid_fv,find_free,ffs_for_driver
from build_asus_review import ffs_header,validate_ffs,align,FILTER
OUT=HERE/'build/sizing_only';OUT.mkdir(exist_ok=True)
sha=lambda b:hashlib.sha256(b).hexdigest()
CAP=ROOT/'analysis/aitweaker_lock/official_W790E_SAGE_SE_1904/W790E_SAGE_SE_1904/Pro-WS-W790E-SAGE-SE-ASUS-1904.CAP'
EXPECTED='aba26bf927de341f1859dd6b5f35645564d5aea104fb26bcc7b5a98bcd96b0b3'
MODULE_GUID={'Setup':'899407d7-99fe-43d8-9a21-79ec328cac21','AMITSE':'b1da0adf-4f77-4070-a88e-bffe1c60529a'}
def sections(b):
 p=0;out=[]
 while p<len(b):
  assert len(b)-p>=4
  n=int.from_bytes(b[p:p+3],'little');assert 4<=n<0xffffff and p+n<=len(b)
  end=min(align(p+n,4),len(b));pad=b[p+n:end];assert all(x in [0,255]for x in pad)
  out.append((b[p+3],b[p:p+n],pad));p=end
 return out
def compress(b):
 out=lzma.compress(b,format=lzma.FORMAT_ALONE,filters=[FILTER]);out=out[:5]+len(b).to_bytes(8,'little')+out[13:]
 assert lzma.decompress(out[13:],format=lzma.FORMAT_RAW,filters=[FILTER])==b
 return out
def replace_pe(b,new):
 result=[];found=0;unchanged=[]
 for kind,s,pad in sections(b):
  if kind==0x10:
   result.append((len(new)+4).to_bytes(3,'little')+bytes([kind])+new+pad);found+=1
  else:result.append(s+pad);unchanged.append({'type':kind,'sha256':sha(s+pad),'bytes':len(s+pad)})
 assert found==1
 return b''.join(result),unchanged
def read_pe(b,compressed=False):
 if compressed:
  ss=sections(b);assert len(ss)==1 and ss[0][0]==2
  s=ss[0][1];assert s[4:20]==uuid.UUID('ee4e5898-3914-4259-9d6e-dc7bd79403cf').bytes_le and s[20:24]==b'\x18\0\x01\0'
  props=s[24];filters={'id':lzma.FILTER_LZMA1,'lc':props%9,'lp':props//9%5,'pb':props//45,'dict_size':int.from_bytes(s[25:29],'little')}
  decoder=lzma.LZMADecompressor(format=lzma.FORMAT_RAW,filters=[filters]);b=decoder.decompress(s[37:])
  # The OEM uses a known output size without an EOS marker. Its 8-byte size
  # controls completion; the reconstructed stream also validates exact output.
  assert len(b)==int.from_bytes(s[29:37],'little') and not decoder.unused_data
 pes=[s[4:]for k,s,pad in sections(b)if k==0x10];assert len(pes)==1;return pes[0]

cap=CAP.read_bytes();assert sha(cap)==EXPECTED
guard=json.loads((HERE/'build/build.json').read_text());modules={n:(HERE/r['path']).read_bytes()for n,r in guard['modules'].items()}
for n,b in modules.items():assert sha(b)==guard['modules'][n]['sha256'];(OUT/(n+'.snapshot.efi')).write_bytes(b)
provider_root=CASE/'review/flash_readiness/native_provider_candidate/build'
provider_manifest=(provider_root/'build.json').read_bytes();pm=json.loads(provider_manifest);provider=(provider_root/'AiTweakerNativeProvider1904.UNSIGNED.review.efi').read_bytes()
assert sha(provider)==pm['efi_sha256'];(OUT/'provider.SIZE_ONLY.snapshot.efi').write_bytes(provider);(OUT/'provider.SIZE_ONLY.build.json').write_bytes(provider_manifest)
container=0x3181078;section=container+24;n=int.from_bytes(cap[section:section+3],'little');outer_header=cap[section:section+24]
raw=lzma.decompress(cap[section+24:section+n],format=lzma.FORMAT_ALONE);fvlen,headerlen=valid_fv(raw,16)
free,available,files=find_free(raw,16);assert files and files[0]['offset']=='0x58'
out=bytearray(raw[:16+headerlen]);rows=[];changed=[]
for row in files:
 old_at=int(row['offset'],16);file=raw[old_at:old_at+row['size']];assert sha(file)==row['sha256'];validate_ffs(file,0,len(file))
 assert file[19]==0,'Unknown fixed/alignment/checksum attribute: no speculative relocation'
 name=next((n for n,g in MODULE_GUID.items()if row['guid']==g),None);new_file=file;meta={}
 if name:
  body=file[24:];assert sha(read_pe(body,name=='AMITSE'))==guard['modules'][name]['original_sha256']
  if name=='AMITSE':
   ss=sections(body);assert len(ss)==1 and ss[0][0]==2;s=ss[0][1];inner=lzma.decompress(s[24:],format=lzma.FORMAT_ALONE)
   inner,unchanged=replace_pe(inner,modules[name]);packed=compress(inner);header=bytearray(s[:24]);header[:3]=(24+len(packed)).to_bytes(3,'little');body=bytes(header)+packed
  else:body,unchanged=replace_pe(body,modules[name])
  new_file=ffs_header(file[:24],body)+body;validate_ffs(new_file,0,len(new_file))
  assert read_pe(body,name=='AMITSE')==modules[name]
  meta={'module':name,'new_PE_sha256':sha(modules[name]),'unchanged_non_PE_sections':unchanged};changed.append(name)
 assert len(out)%8==0;new_at=len(out);out.extend(new_file);out.extend(b'\xff'*((-len(out))%8))
 rows.append({**row,'new_offset':hex(new_at),'new_size':len(new_file),'new_sha256':sha(new_file),'bytes_identical':new_file==file,**meta})
assert set(changed)==set(MODULE_GUID)
provider_guid=uuid.UUID('8b4e0d52-28b5-4d1f-b4bc-750e9d9d1904')
assert str(provider_guid)not in {x['guid']for x in files}
pffs=ffs_for_driver(provider,provider_guid,'SIZING ONLY - NOT AN ACCEPTED PROVIDER');poff=len(out);out.extend(pffs);out.extend(b'\xff'*((-len(out))%8))
new_fvlen=align(len(out)-16,4096);out.extend(b'\xff'*(new_fvlen+16-len(out)))
struct.pack_into('<I',out,12,len(out)-8);struct.pack_into('<Q',out,16+32,new_fvlen)
blocks,size=struct.unpack_from('<II',out,16+56);assert blocks*size==fvlen and size==4096;struct.pack_into('<I',out,16+56,new_fvlen//4096)
out[16+50:16+52]=b'\0\0';struct.pack_into('<H',out,16+50,(-sum(struct.unpack('<'+'H'*(headerlen//2),out[16:16+headerlen])))&65535)
valid_fv(out,16);new_free,new_available,new_files=find_free(bytes(out),16);assert len(new_files)==len(files)+1
for old,new in zip(rows,new_files):
 assert old['guid']==new['guid'] and old['new_offset']==new['offset'] and old['new_size']==new['size'] and old['new_sha256']==new['sha256']
 validate_ffs(out,int(new['offset'],16),new['size'])
validate_ffs(out,poff,len(pffs));assert new_files[-1]['guid']==str(provider_guid)
assert out[16+0x60:16+0x70]==raw[16+0x60:16+0x70],'FV extension header identity retained'
packed=compress(bytes(out));sh=bytearray(outer_header);sh[:3]=(24+len(packed)).to_bytes(3,'little');body=bytes(sh)+packed
replacement=ffs_header(cap[container:container+24],body)+body;validate_ffs(replacement,0,len(replacement))
slot=align(int.from_bytes(cap[container+20:container+23],'little'),8);required=align(len(replacement),8);padding=slot-required
guard_only=bytearray(out[:poff]);guard_fvlen=align(len(guard_only)-16,4096);guard_only.extend(b'\xff'*(guard_fvlen+16-len(guard_only)))
struct.pack_into('<I',guard_only,12,len(guard_only)-8);struct.pack_into('<Q',guard_only,16+32,guard_fvlen);struct.pack_into('<I',guard_only,16+56,guard_fvlen//4096)
guard_only[16+50:16+52]=b'\0\0';struct.pack_into('<H',guard_only,16+50,(-sum(struct.unpack('<'+'H'*(headerlen//2),guard_only[16:16+headerlen])))&65535)
valid_fv(guard_only,16);gf,ga,guard_files=find_free(bytes(guard_only),16);assert len(guard_files)==len(files)
guard_packed=compress(bytes(guard_only));gh=bytearray(outer_header);gh[:3]=(24+len(guard_packed)).to_bytes(3,'little');gb=bytes(gh)+guard_packed
guard_container=ffs_header(cap[container:container+24],gb)+gb;validate_ffs(guard_container,0,len(guard_container))
guard_required=align(len(guard_container),8);outer_free,outer_available,outer_files=find_free(cap,0x3181000)
assert cap[outer_free:outer_free+align(len(pffs),8)]==b'\xff'*align(len(pffs),8)
(OUT/'native-gates-only.SIZING-ONLY.fv').write_bytes(guard_only[16:]);(OUT/'provider.SIZE-ONLY.ffs').write_bytes(pffs)
(OUT/'native-gates.SIZING-ONLY.fv').write_bytes(out[16:]);(OUT/'inner-ffs-inventory.json').write_text(json.dumps(rows,indent=2)+'\n',encoding='utf8')
r={'purpose':'SIZING ONLY; NOT A FIRMWARE RELEASE OR BOOT-ACCEPTED IMAGE','status':'FITS_ORIGINAL_OUTER_SLOT'if padding>=24 else 'DOES_NOT_FIT_ORIGINAL_OUTER_SLOT',
 'source_CAP_sha256':EXPECTED,'source_CAP_bytes':len(cap),'guard_build_manifest_sha256':sha((HERE/'build/build.json').read_bytes()),'guard_module_sha256':{n:sha(b)for n,b in modules.items()},
 'provider_snapshot_sha256':sha(provider),'provider_snapshot_bytes':len(provider),'provider_binding_accepted':False,'provider_snapshot_manifest_sha256':sha(provider_manifest),
 'original_inner_FV_bytes':fvlen,'new_inner_FV_bytes':new_fvlen,'old_inner_FFS_count':len(files),'new_inner_FFS_count':len(new_files),'unchanged_original_inner_FFS_count':sum(x['bytes_identical']for x in rows),
 'relocated_FFS_count':sum(x['offset']!=x['new_offset']for x in rows),'fixed_or_higher_alignment_FFS_count':0,'original_order_retained':True,'original_non_PE_sections_retained':True,
 'provider_FFS_offset':hex(poff),'provider_FFS_GUID':str(provider_guid),'provider_DEPEX':['VariableArch','VariableWriteArch','AND','END'],'provider_DEPEX_is_boot_order_proof':False,
 'outer_original_allocation':slot,'outer_new_ffs_bytes':len(replacement),'outer_required_aligned':required,'outer_remaining_bytes':padding,'outer_padding_FFS_minimum':24,
 'all_inner_FFS_header_checksums_valid':True,'all_modified_PE_reextracted_bytes_equal':True,'inner_FV_header_checksum_valid':True,'nested_LZMA_roundtrips_equal':True,
 'standalone_inner_FV_path':str(OUT/'native-gates.SIZING-ONLY.fv'),'standalone_inner_FV_sha256':sha(bytes(out[16:])),'script_sha256':sha(Path(__file__).read_bytes()),'compressor_parameters':FILTER,
 'alternative_provider_in_existing_outer_erased_space':{'status':'FITS_BOTH_ALLOCATIONS'if slot-guard_required>=24 and outer_available>=align(len(pffs),8)else 'DOES_NOT_FIT','guard_only_container_aligned_bytes':guard_required,'guard_only_container_remaining_bytes':slot-guard_required,'provider_outer_offset':hex(outer_free),'provider_FFS_bytes':len(pffs),'existing_outer_erased_bytes':outer_available,'remaining_outer_erased_bytes':outer_available-align(len(pffs),8),'all_original_other_outer_FFS_offsets_would_remain':True,'guard_only_FV_sha256':sha(bytes(guard_only[16:])),'provider_FFS_sha256':sha(pffs),'dispatch_order_acceptance':False},
 'CAP_or_full_image_written':False,'device_access':False,'limits':['Provider snapshot is only a size input and is not accepted or matched to the latest guard. Final EBS-reviewed provider must be rebound and all measurements repeated.','All existing inner FFS keep their order and unmodified files keep exact bytes, but their offsets after growing modules move. Offset-dependent native or firmware references still require independent audit.','This is a standalone inner FV only. It is not a signed capsule, flash package, whole-image verification or standard loader/boot acceptance.','No change to source CAP, EXP02/EXP03, production driver or root delivery ZIP.']}
(OUT/'sizing_report.json').write_text(json.dumps(r,indent=2)+'\n',encoding='utf8');print(json.dumps({k:r[k]for k in ['status','provider_snapshot_sha256','unchanged_original_inner_FFS_count','outer_original_allocation','outer_required_aligned','outer_remaining_bytes','alternative_provider_in_existing_outer_erased_space','CAP_or_full_image_written']},indent=2))
