"""Actual compiled C/SHA with exact original PE/SPF and explicit read model."""
from pathlib import Path
import ctypes as C
import hashlib,json,struct,sys
HERE=Path(__file__).resolve().parent;BASE=HERE.parent;ROOT=HERE.parents[3];OUT=HERE/'build'
sys.path.insert(0,str(ROOT/'tools/pydeps'))
import pefile
COPY=C.CFUNCTYPE(C.c_int,C.c_void_p,C.c_uint64,C.c_void_p,C.c_size_t)
ALLOC=C.CFUNCTYPE(C.c_void_p,C.c_void_p,C.c_size_t)
FREE=C.CFUNCTYPE(C.c_int,C.c_void_p,C.c_void_p)
class Host(C.Structure):_fields_=[('ctx',C.c_void_p),('copy',COPY),('alloc',ALLOC),('free',FREE)]
class Snapshot(C.Structure):
 _pack_=1
 _fields_=[(x,C.c_uint64) for x in ('source','source_pages','source_guids','current_blob','current_pages')]+[(x,C.c_uint32) for x in ('declared_size','source_page_count','first_page_offset')]+[('source_page0_hii',C.c_uint64)]+[(x,C.c_uint16) for x in ('header_parent_field','header_guid_index','header_form_id')]+[('status_mask',C.c_uint32)]
class Pair(C.Structure):_pack_=1;_fields_=[('a',Snapshot),('b',Snapshot)]
assert C.sizeof(Snapshot)==70 and C.sizeof(Pair)==140
dll=C.CDLL(str(OUT/'spf_sampler_test.dll'));dll.s7_capture_pair.argtypes=[C.POINTER(Host),C.c_uint64,C.c_uint64,C.POINTER(Pair)];dll.s7_capture_pair.restype=C.c_int
profiles=json.loads((BASE/'diagnostic_hii06/build/profiles.json').read_text());profile=next(x for x in profiles if x['name']=='AMITSE')
spf_record=json.loads((BASE/'parser_review06/original_inventory.json').read_text());original_spf=Path(spf_record['original_source']).read_bytes()
assert hashlib.sha256(original_spf).hexdigest()==spf_record['original_sha256']
text_rva=profile['text_rva'];text_n=profile['text_size'];reloc_rva=profile['reloc_rva'];reloc_n=profile['reloc_size']
GLOBALS=(0xbab20,0xbab10,0xbab18,0xbabc0,0xbaaf0)
SPF_READS={(0x44,4),(0,4),(0x2c,4),(0x30,4),(0x40,4),(0x60,4),(0x64,4),(0x64+378*4,4),(0xf2364,4),(0xf2368,4),(0x650,8),(0x12,2),(0x08,2),(0x0a,2)}
VALID=0xfff;CODE=1<<12;HEADER=1<<13;POINTERS=1<<14;COUNTS=1<<15;COMPLETE=1<<16;ZERO=1<<17;NONZERO=1<<18;UNSTABLE=1<<19;PROFILE=1<<20;UNREADABLE=1<<21;INVALID=1<<22;PROBE=1<<23
checks=[]
def one(mode='normal',base=0x28000000):
 pe=pefile.PE(profile['path']);pe.relocate_image(base);image=bytearray(pe.get_memory_mapped_image().ljust(pe.OPTIONAL_HEADER.SizeOfImage,b'\0'))
 source=0x70000000;spf=bytearray(original_spf)
 for off,value in zip(GLOBALS,(source,source+0x60,source+0xf2394,0x80000000,0x80000000)):
  struct.pack_into('<Q',image,off,value)
 header_end=pe.DOS_HEADER.e_lfanew+24+240+40*pe.FILE_HEADER.NumberOfSections
 if mode=='bad_text':image[text_rva+3]^=1
 if mode=='bad_header':struct.pack_into('<I',spf,0,0)
 if mode=='bad_size':struct.pack_into('<I',spf,0x44,0xf245d)
 if mode=='bad_offset':struct.pack_into('<I',spf,0x2c,0xfffffff0)
 if mode=='bad_count':struct.pack_into('<I',spf,0x60,1)
 if mode=='bad_first_offset':struct.pack_into('<I',spf,0x64,0xfffffff0)
 if mode=='bad_last_offset':struct.pack_into('<I',spf,0x64+378*4,0)
 if mode=='bad_guid_count':struct.pack_into('<I',spf,0xf2364,11)
 if mode=='bad_guid_first':struct.pack_into('<I',spf,0xf2368,0xffffffff)
 if mode=='bad_source_pages':struct.pack_into('<Q',image,0xbab10,0x12345000)
 if mode=='bad_source_guids':struct.pack_into('<Q',image,0xbab18,0x12345000)
 if mode=='source_zero':struct.pack_into('<Q',image,0xbab20,0)
 if mode=='source_overflow':struct.pack_into('<Q',image,0xbab20,0xfffffffffffffff0)
 if mode=='candidate_nonzero':struct.pack_into('<Q',spf,0x650,0x123456789abcdef0)
 if mode=='candidate_low_zero':struct.pack_into('<Q',spf,0x650,0x8000000000000000)
 if mode=='header_parent_nonzero':struct.pack_into('<H',spf,0x12,1)
 if mode=='header_guid_changed':struct.pack_into('<H',spf,8,0xffff)
 before_image=bytes(image);before_spf=bytes(spf);reads=[];errors=[];allocations={};snapshot=0
 @COPY
 def copy(ctx,address,dest,n):
  nonlocal snapshot
  if address==base:snapshot+=1
  at=address-base;part=None;kind=None
  if 0<=at and at+n<=len(image):
   allowed=(at+n<=header_end) or (text_rva<=at and at+n<=text_rva+text_n) or (reloc_rva<=at and at+n<=reloc_rva+reloc_n) or (at in GLOBALS and n==8)
   if not allowed:errors.append(('unapproved_image_read',hex(at),n));return 0
   kind='image';part=bytes(image[at:at+n])
   if mode=='code_unreadable' and at==text_rva:return 0
   if mode=='code_changes_between' and snapshot==2 and at==text_rva:part=bytes([part[0]^1])+part[1:]
   if mode=='unstable_current' and snapshot==2 and at==0xbabc0:part=struct.pack('<Q',0x80001000)
   if mode.startswith('fail_global_') and at==GLOBALS[int(mode.rsplit('_',1)[1])]:
    C.memset(dest,0x55,n);reads.append((snapshot,kind,at,n,'FALSE_WITH_PARTIAL_OUTPUT'));return 0
  else:
   at=address-source
   if (at,n) not in SPF_READS or at<0 or at+n>len(spf):errors.append(('unapproved_spf_or_foreign_read',hex(address),n));return 0
   kind='spf';part=bytes(spf[at:at+n])
   if mode=='unreadable_source_header' and at==0x44:return 0
   if mode=='partial_source_field' and at==0x650:
    C.memset(dest,0x66,n);reads.append((snapshot,kind,at,n,'FALSE_WITH_PARTIAL_OUTPUT'));return 0
   if mode=='unreadable_guid_field' and at==8:return 0
   if mode=='unstable_validity' and snapshot==2 and at==0x12:return 0
   if mode=='unstable_candidate' and snapshot==2 and at==0x650:part=struct.pack('<Q',0x12345678)
  reads.append((snapshot,kind,at,n,'OK'));C.memmove(dest,part,n);return 1
 @ALLOC
 def alloc(ctx,n):
  if mode=='allocation_failure':return None
  b=C.create_string_buffer(n+32);C.memset(C.addressof(b),0xa5,n+32);ptr=C.addressof(b)+16;allocations[ptr]=(b,n);return ptr
 @FREE
 def free(ctx,ptr):
  if ptr not in allocations:errors.append('foreign_free');return 0
  b,n=allocations.pop(ptr)
  if C.string_at(C.addressof(b),16)!=b'\xa5'*16 or C.string_at(ptr+n,16)!=b'\xa5'*16:errors.append('allocation_guard')
  return mode!='free_failure'
 host=Host(None,copy,alloc,free);pair=Pair();C.memset(C.addressof(pair),0xcc,C.sizeof(pair))
 ret=dll.s7_capture_pair(C.byref(host),base,len(image)-int(mode=='wrong_image_size'),C.byref(pair))
 assert not errors and not allocations,(mode,errors,allocations)
 assert bytes(image)==before_image and bytes(spf)==before_spf
 good=mode in ('normal','candidate_nonzero','candidate_low_zero','header_parent_nonzero','header_guid_changed')
 assert ret==int(good),(mode,ret,hex(pair.a.status_mask),hex(pair.b.status_mask))
 if good:
  assert pair.a.status_mask&0x1ffff==0x1ffff
  assert pair.a.source==source and pair.a.source_page_count==379 and pair.a.first_page_offset==0x650
  assert pair.a.declared_size==len(original_spf) and pair.a.current_blob!=pair.a.source
  assert pair.a.status_mask&(NONZERO if mode=='candidate_nonzero' else ZERO)
  assert bytes(pair.a)==bytes(pair.b)
 if mode in ('bad_text','wrong_image_size','code_unreadable','allocation_failure','free_failure'):
  assert not any(k=='spf' or (k=='image' and at in GLOBALS) for _,k,at,n,r in reads)
  assert not pair.a.status_mask&VALID
 if mode=='code_unreadable':assert pair.a.status_mask==UNREADABLE
 if mode in ('allocation_failure','free_failure'):assert pair.a.status_mask==PROBE
 if mode.startswith('bad_'):assert pair.a.status_mask&PROFILE
 if mode.startswith('source_'):
  assert pair.a.status_mask&INVALID
  assert not any(k=='spf' for _,k,at,n,r in reads)
 if mode in ('bad_header','bad_size','bad_offset'):
  assert not any(k=='spf' and at>=0x48 for _,k,at,n,r in reads)
 if mode in ('bad_source_pages','bad_source_guids'):
  assert not any(k=='spf' and at>=0x48 for _,k,at,n,r in reads)
 if mode.startswith('fail_global_'):
  ordinal=int(mode.rsplit('_',1)[1]);assert not pair.a.status_mask&(1<<ordinal)
  assert getattr(pair.a,Snapshot._fields_[ordinal][0])==0
 if mode=='partial_source_field':assert pair.a.source_page0_hii==0 and not pair.a.status_mask&(1<<8)
 if mode=='unreadable_guid_field':assert pair.a.header_guid_index==0 and not pair.a.status_mask&(1<<10)
 if mode in ('unstable_current','unstable_candidate','code_changes_between','unstable_validity'):
  assert pair.a.status_mask&UNSTABLE and pair.b.status_mask&UNSTABLE
  assert bytes(pair.a)!=bytes(pair.b)
 checks.append({'case':mode,'base':hex(base),'passed':True,'return_complete_stable':bool(ret),'snapshot_count':snapshot,'a':{k:int(getattr(pair.a,k)) for k,_ in Snapshot._fields_},'b':{k:int(getattr(pair.b,k)) for k,_ in Snapshot._fields_},'reads':reads,'unapproved_reads':0,'source_mutations':0})
def main():
 for base in (0x28000000,0x180000000):one(base=base)
 for mode in ['bad_text','wrong_image_size','code_unreadable','allocation_failure','free_failure','bad_header','bad_size','bad_offset','bad_count','bad_first_offset','bad_last_offset','bad_guid_count','bad_guid_first','bad_source_pages','bad_source_guids','source_zero','source_overflow','candidate_nonzero','candidate_low_zero','header_parent_nonzero','header_guid_changed','unreadable_source_header','partial_source_field','unreadable_guid_field','unstable_current','unstable_candidate','code_changes_between','unstable_validity']+[f'fail_global_{i}' for i in range(5)]:one(mode)
 report={'passed':True,'count':len(checks),'dll_sha256':hashlib.sha256((OUT/'spf_sampler_test.dll').read_bytes()).hexdigest(),'original_pe_sha256':profile['sha256'],'original_spf_sha256':spf_record['original_sha256'],'checks':checks,'scope':['Actual compiled sampler, h6_probe and SHA256 on original PE/SPF bytes in explicit read models.','Only exact PE header/text/reloc and fixed five globals plus fourteen SPF field extents are readable. Other reads would fail the check.','Source memory and original files unchanged. No EFI carrier or physical device test in this report.','Two equal snapshots do not establish original first-parser timing or allocator-owned extents.']}
 (OUT/'tests.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({'passed':True,'count':len(checks),'dll_sha256':report['dll_sha256']},indent=2))
if __name__=='__main__':main()
