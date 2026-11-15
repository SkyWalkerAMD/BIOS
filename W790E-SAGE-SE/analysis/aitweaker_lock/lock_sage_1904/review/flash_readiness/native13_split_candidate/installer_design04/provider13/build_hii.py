"""Independent formset: no mutation of an original ASUS HII package."""
from pathlib import Path
import hashlib,json,struct,uuid
HERE=Path(__file__).resolve().parent;REF=HERE.parents[2].parent/'remote_only/continuation08/edk2_hii_reference'
REF=HERE.parent.parent.parent/'remote_only/continuation08/edk2_hii_reference'
texts=['English','Ai Tweaker Password','Independent password for Ai Tweaker. This page belongs to the current RAM test.','Set or change password','Set a new password, or authenticate the current password to replace it.','Clear password','Authenticate the current password to disable Ai Tweaker protection.','Verify password','Authenticate for the current BIOS session.','Password verification does not change any overclocking value.']
formset=uuid.UUID('b16b94e6-99f4-4f60-8f7b-b6d234e4a513').bytes_le
package=uuid.UUID('cc575054-4f92-4f04-a348-59efa14c9013').bytes_le
def package_header(n,kind):return struct.pack('<I',n|(kind<<24))
def action(prompt,help_,qid):return bytes([12,15])+struct.pack('<5HBH',prompt,help_,qid,0,0xffff,4,0)
ifr=bytes([14,0x80|23])+formset+struct.pack('<2HB',2,3,0)
ifr+=bytes([1,0x80|6])+struct.pack('<HH',1,2)
ifr+=bytes([3,8])+struct.pack('<3H',10,3,0)
ifr+=action(4,5,0xffe0)+action(6,7,0xffe1)+action(8,9,0xffe2)+bytes([0x29,2,0x29,2])
forms=package_header(len(ifr)+4,2)+ifr
language=b'en-US\0';header_size=4+4+4+32+2+len(language)
blocks=b''.join(b'\x14'+s.encode('utf-16le')+b'\0\0'for s in texts)+b'\0'
strings=package_header(header_size+len(blocks),4)+struct.pack('<II',header_size,header_size)+bytes(32)+struct.pack('<H',1)+language+blocks
body=forms+strings+package_header(4,0xdf);data=package+struct.pack('<I',20+len(body))+body
build=HERE/'build';build.mkdir(exist_ok=True);(build/'management.pack').write_bytes(data)
header=HERE/'source/management_package.h';header.write_text('/* Official IFR/HII layouts; independent prototype package only. */\nstatic const uint8_t management_package[]={'+','.join(f'0x{x:02x}'for x in data)+'};\n')
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
r={'status':'GENERATED_INDEPENDENT_HII_PACKAGE_NOT_NATIVE_GUI_ACCEPTANCE','package_guid':str(uuid.UUID(bytes_le=package)),'formset_guid':str(uuid.UUID(bytes_le=formset)),'form':1,'question_ids':{'set_or_change':'0xffe0','clear':'0xffe1','verify':'0xffe2'},'package_bytes':len(data),'package_sha256':sha(build/'management.pack'),'forms_bytes':len(forms),'string_header_bytes':header_size,'languages':['en-US'],'strings':texts,'source_sha256':sha(Path(__file__)),'header_sha256':sha(header),'official_reference_sha256':{n:sha(REF/n)for n in ['UefiInternalFormRepresentation.h','HiiDatabase.h','provenance.json']}}
(build/'management_package.json').write_text(json.dumps(r,indent=2)+'\n');print(json.dumps({'status':r['status'],'package_bytes':len(data)}))
