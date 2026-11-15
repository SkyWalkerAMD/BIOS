"""Run actual compiled core/SHA on exact original PE images; no firmware services."""
from pathlib import Path
import ctypes as C,hashlib,json,struct,sys
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[3];OUT=HERE/'build';sys.path.insert(0,str(ROOT/'tools/pydeps'))
import pefile
COPY=C.CFUNCTYPE(C.c_int,C.c_void_p,C.c_uint64,C.c_void_p,C.c_size_t)
ALLOC=C.CFUNCTYPE(C.c_void_p,C.c_void_p,C.c_size_t)
FREE=C.CFUNCTYPE(C.c_int,C.c_void_p,C.c_void_p)
class Host(C.Structure):_fields_=[('ctx',C.c_void_p),('copy',COPY),('alloc',ALLOC),('free',FREE)]
class Result(C.Structure):_fields_=[(x,C.c_uint32) for x in ('status','raw_valid','normalized_valid','entry','image_size','text_rva','text_size','reloc_rva','reloc_size')]+[('raw',C.c_ubyte*32),('normalized',C.c_ubyte*32)]
dll=C.CDLL(str(OUT/'core_test.dll'));dll.h6_probe.argtypes=[C.POINTER(Host),C.c_uint64,C.c_uint64,C.c_void_p,C.POINTER(Result)]
dll.h6_profile_at.argtypes=[C.c_size_t];dll.h6_profile_at.restype=C.c_void_p
profiles=json.loads((OUT/'profiles.json').read_text());checks=[]
def one(index,base=0x28000000,mode='normal'):
 p=profiles[index];pe=pefile.PE(p['path']);pe.relocate_image(base);buf=bytearray(pe.get_memory_mapped_image().ljust(pe.OPTIONAL_HEADER.SizeOfImage,b'\0'));snap=bytes(buf)
 tr=p['text_rva'];tn=p['text_size'];rr=p['reloc_rva'];rn=p['reloc_size'];off=pe.DOS_HEADER.e_lfanew
 if mode=='bad_mz':buf[0:2]=b'ZZ'
 if mode=='bad_pe':struct.pack_into('<I',buf,60,0xffffffff)
 if mode=='bad_sections':struct.pack_into('<H',buf,off+6,97)
 if mode=='bad_text_size':struct.pack_into('<I',buf,pe.sections[0].get_file_offset()+8,0xffffffff)
 if mode=='bad_entry':struct.pack_into('<I',buf,off+24+16,pe.OPTIONAL_HEADER.AddressOfEntryPoint+1)
 if mode=='bad_text':buf[tr+3]^=1
 if mode=='bad_reloc':buf[rr+9]^=1
 if mode=='bad_fixup':buf[p['text_fixups'][0][0]]^=1
 allocations={};reads=[];fail=[]
 @COPY
 def copy(ctx,address,dest,n):
  at=address-base;reads.append((at,n))
  if at<0 or at+n>len(buf) or (mode=='unreadable_text' and at==tr) or (mode=='unreadable_reloc' and at==rr):return 0
  C.memmove(dest,bytes(buf[at:at+n]),n);return 1
 @ALLOC
 def alloc(ctx,n):
  if mode=='allocation_failure':return None
  b=C.create_string_buffer(n+32);C.memset(C.addressof(b),0xa5,n+32);ptr=C.addressof(b)+16;allocations[ptr]=(b,n);return ptr
 @FREE
 def free(ctx,ptr):
  if ptr not in allocations:fail.append('foreign_free');return 0
  b,n=allocations.pop(ptr)
  if C.string_at(C.addressof(b),16)!=b'\xa5'*16 or C.string_at(ptr+n,16)!=b'\xa5'*16:fail.append('guard')
  return mode!='free_failure'
 host=Host(None,copy,alloc,free);r=Result();profile=None if mode=='unknown' else dll.h6_profile_at(index)
 before=bytes(buf);ret=dll.h6_probe(C.byref(host),base,len(buf),profile,C.byref(r));assert bytes(buf)==before and not fail and not allocations
 want={'normal':0,'bad_mz':1,'bad_pe':1,'bad_sections':1,'bad_text_size':1,'bad_entry':4,'bad_text':8,'bad_reloc':6,'bad_fixup':7,'unknown':9,'unreadable_text':2,'unreadable_reloc':5,'allocation_failure':3,'free_failure':10}[mode]
 assert r.status==want,(p['name'],mode,r.status,want)
 if mode=='normal':
  assert ret==1 and r.raw_valid and r.normalized_valid
  assert bytes(r.raw)==hashlib.sha256(snap[tr:tr+tn]).digest()
  assert bytes(r.normalized).hex()==p['text_sha256']
 if r.raw_valid:assert bytes(r.raw)==hashlib.sha256(before[tr:tr+tn]).digest()
 if mode=='unknown':assert not r.normalized_valid
 # Every source read is confined to DOS/PE/section headers, .text or .reloc.
 hdr_end=off+24+240+40*pe.FILE_HEADER.NumberOfSections
 for a,n in reads:
  assert (0<=a and a+n<=hdr_end) or (tr<=a and a+n<=tr+tn) or (rr<=a and a+n<=rr+rn),(p['name'],mode,a,n)
 checks.append({'name':p['name'],'base':hex(base),'case':mode,'status':int(r.status),'passed':True,'foreign_memory_unchanged':True,'no_data_section_reads':True})
def main():
 for i,p in enumerate(profiles):
  for base in (0x28000000,0x180000000):one(i,base)
  for mode in ('bad_mz','bad_pe','bad_sections','bad_text_size','bad_entry','bad_text','unknown','unreadable_text','allocation_failure','free_failure'):one(i,mode=mode)
  if p['reloc_size']:
   one(i,mode='bad_reloc');one(i,mode='unreadable_reloc')
  if p['text_fixups']:one(i,mode='bad_fixup')
 report={'passed':True,'count':len(checks),'checks':checks,'dll_sha256':hashlib.sha256((OUT/'core_test.dll').read_bytes()).hexdigest(),'efi_sha256':hashlib.sha256((OUT/'BOOTX64.EFI').read_bytes()).hexdigest(),'scope':'Actual compiled core and SHA-256; exact original PE bytes rebased in an isolated buffer; memory/service failures are explicit callback models.'}
 (OUT/'core_tests.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({'passed':True,'count':len(checks)},indent=2))
if __name__=='__main__':main()
