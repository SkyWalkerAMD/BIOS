"""Independent byte/section/relocation audit; no original EFI execution."""
from pathlib import Path
import hashlib,json,struct,sys
HERE=Path(__file__).resolve().parent;CASE=HERE.parents[3];ROOT=CASE.parents[2]
sys.path.insert(0,str(ROOT/'tools/pydeps'));import pefile,capstone
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
m=json.loads((HERE/'build/build.json').read_text());checks=[];details={}
def check(s,b):assert b,s;checks.append(s)
for name,row in m['modules'].items():
 original=CASE/'analysis/modules'/f'{name}.efi';modified=HERE/row['path']
 a=original.read_bytes();b=modified.read_bytes();p=pefile.PE(data=a);q=pefile.PE(data=b)
 check(name+' original hash binding',sha(original)==row['original_sha256'])
 check(name+' modified hash binding',sha(modified)==row['sha256'])
 check(name+' checksum valid',q.verify_checksum())
 check(name+' entry retained',p.OPTIONAL_HEADER.AddressOfEntryPoint==q.OPTIONAL_HEADER.AddressOfEntryPoint)
 check(name+' original size/alignment metadata retained',p.OPTIONAL_HEADER.FileAlignment==q.OPTIONAL_HEADER.FileAlignment==32 and p.OPTIONAL_HEADER.SectionAlignment==q.OPTIONAL_HEADER.SectionAlignment==32 and p.OPTIONAL_HEADER.SizeOfHeaders==q.OPTIONAL_HEADER.SizeOfHeaders==0x2c0)
 for i,(s,t) in enumerate(zip(p.sections,q.sections)):
  check(name+f' original section {i} identity and addresses',s.Name==t.Name and s.VirtualAddress==t.VirtualAddress and s.PointerToRawData==t.PointerToRawData)
  if i!=5:check(name+f' original section {i} sizes/flags retained',s.Misc_VirtualSize==t.Misc_VirtualSize and s.SizeOfRawData==t.SizeOfRawData and s.Characteristics==t.Characteristics)
 for i,(d,e) in enumerate(zip(p.OPTIONAL_HEADER.DATA_DIRECTORY,q.OPTIONAL_HEADER.DATA_DIRECTORY)):
  check(name+f' data directory {i} retained',d.VirtualAddress==e.VirtualAddress and d.Size==e.Size)
 allowed=bytearray(len(a));allowed[:0x2c0]=bytes([1])*0x2c0
 for x in row['patches']:
  at=int(x['rva'],16);n=8 if x['kind']=='DIR64 slot' else x.get('bytes',5);allowed[at:at+n]=bytes([1])*n
 unexpected=[i for i,(x,y) in enumerate(zip(a,b))if x!=y and not allowed[i]]
 check(name+' no unlisted original-body byte changes',not unexpected)
 check(name+' old relocation directory bytes retained',p.get_data(p.OPTIONAL_HEADER.DATA_DIRECTORY[5].VirtualAddress,p.OPTIONAL_HEADER.DATA_DIRECTORY[5].Size)==q.get_data(q.OPTIONAL_HEADER.DATA_DIRECTORY[5].VirtualAddress,q.OPTIONAL_HEADER.DATA_DIRECTORY[5].Size))
 check(name+' no executable writable section',all(not(s.Characteristics&0x20000000 and s.Characteristics&0x80000000)for s in q.sections))
 check(name+' last relocation/code section non-discardable',q.sections[5].Characteristics==0x60000060)
 if name=='AMITSE':
  t=q.sections[6];head=int(row['context_head_rva'],16)
  check(name+' NT shift uses original zero DOS bytes',a[0xa0:0xc8]==bytes(40) and q.DOS_HEADER.e_lfanew==0xa0 and p.DOS_HEADER.e_lfanew==0xc8)
  check(name+' explicit isolated writable state section',t.Name.rstrip(b'\0')==b'.gstate' and t.Misc_VirtualSize==8 and t.SizeOfRawData==32 and t.VirtualAddress==t.PointerToRawData==head and t.Characteristics==0xc0000040)
  check(name+' new state starts at separate page from RX payload',head%4096==0 and q.sections[5].VirtualAddress+q.sections[5].Misc_VirtualSize<=head)
  check(name+' state starts zero',q.get_data(head,32)==bytes(32))
 else:check(name+' no unused context section',q.FILE_HEADER.NumberOfSections==6 and int(row['context_head_rva'],16)==0)
 for base in [0x10000000,0x140000000,0x7fff00000000]:
  r=pefile.PE(data=b);r.relocate_image(base);mapped=r.get_memory_mapped_image()
  check(name+f' mapped size at {base:x}',len(mapped)==q.OPTIONAL_HEADER.SizeOfImage)
  for x in row['patches']:
   at=int(x['rva'],16);new=int(x['new_rva'],16)
   if x['kind']=='DIR64 slot':check(name+f' relocated slot {at:x} at {base:x}',struct.unpack_from('<Q',mapped,at)[0]==base+new)
   else:check(name+f' relative target {at:x} at {base:x}',at+5+struct.unpack_from('<i',mapped,at+1)[0]==new)
  start=int(row['appended_rva'],16);end=start+row['payload_bytes']
  check(name+f' appended payload PIC unchanged at {base:x}',mapped[start:end]==b[start:end])
 for label,rv in row['trampoline_rvas'].items():
  at=int(rv,16)
  if not at:continue
  old,length={'loop':(0xe1b8,18),'frame':(0x15320,15),'commit':(0x11164,10),'defaults':(0x5abc,11)}[label]
  check(name+' trampoline '+label+' exact original instructions',b[at:at+length]==a[old:old+length])
  check(name+' trampoline '+label+' exact continuation',at+length+5+struct.unpack_from('<i',b,at+length+1)[0]==old+length)
 details[name]={'sha256':sha(modified),'bytes':len(b),'NT_header':hex(q.DOS_HEADER.e_lfanew),'sections':[{ 'name':s.Name.rstrip(b'\0').decode('ascii'),'rva':hex(s.VirtualAddress),'virtual_size':s.Misc_VirtualSize,'raw_size':s.SizeOfRawData,'flags':hex(s.Characteristics)}for s in q.sections]}
r={'status':'PASS_STATIC_STRUCTURE_AND_SOFTWARE_RELOCATION','checks':len(checks),'check_names':checks,'modules':details,'builder_manifest_sha256':sha(HERE/'build/build.json'),'verifier_sha256':sha(Path(__file__)),'limits':['pefile relocation is independent metadata/byte verification, not a standard UEFI loader run.','No StartImage, native module entry, flash image build, or hardware access occurred.','Section flags do not prove actual page-level W^X enforcement on a loader using the original 32-byte section alignment. New state and appended guard are on separate pages.']}
(HERE/'build/structure_verification.json').write_text(json.dumps(r,indent=2)+'\n',encoding='utf8');print(json.dumps({'status':r['status'],'checks':len(checks),'sha256':sha(HERE/'build/structure_verification.json')}))
