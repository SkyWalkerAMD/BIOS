"""Generate an independent management HII package, not a bootable BIOS."""
from pathlib import Path
import hashlib
import json
import struct
import uuid

HERE = Path(__file__).resolve().parent
OUT = HERE / 'build'
OUT.mkdir(exist_ok=True)
def header(n,kind):return struct.pack('<I',n|(kind<<24))
def action(prompt,help_,qid):return bytes([12,15])+struct.pack('<5HBH',prompt,help_,qid,0,0xffff,4,0)
texts = ['English','Ai Tweaker Password','Independent password for Ai Tweaker.',
         'Set or change password','Authenticate the existing password to replace it.',
         'Clear password','Authenticate the existing password to disable the lock.',
         'Verify password','Unlock Ai Tweaker for the current BIOS session.',
         'No overclocking values are changed by these password actions.']
fg = uuid.UUID('a196a577-3c2a-41f5-bc6b-8019c9af956f')
pg = uuid.UUID('f032c97e-4d67-4d55-b89c-4b0b92494fab')
ifr = bytes([14,151])+fg.bytes_le+struct.pack('<HHB',2,3,0)
ifr += bytes([1,134])+struct.pack('<HH',1,2)
ifr += bytes([3,8])+struct.pack('<HHH',10,3,0)
ifr += action(4,5,0xffd0)+action(6,7,0xffd1)+action(8,9,0xffd2)+bytes([41,2,41,2])
forms = header(len(ifr)+4,2)+ifr
lang = b'en-US\0';size=4+4+4+32+2+len(lang)
blocks=b''.join(b'\x14'+t.encode('utf-16le')+b'\0\0'for t in texts)+b'\0'
strings=header(size+len(blocks),4)+struct.pack('<II',size,size)+bytes(32)+struct.pack('<H',1)+lang+blocks
body=forms+strings+header(4,223)
package=pg.bytes_le+struct.pack('<I',20+len(body))+body
(OUT/'management.pack').write_bytes(package)
(HERE/'management_package.h').write_text('/* Standalone management HII data. No native publication implied. */\nstatic const uint8_t w890_management_package[]={'+','.join(hex(b)for b in package)+'};\n',encoding='ascii')
result={'status':'GENERATED_HII_PACKAGE_NOT_CONNECTED_TO_NATIVE_UI','package_guid':str(pg),'formset_guid':str(fg),'form_id':1,
        'question_ids':[0xffd0,0xffd1,0xffd2],'bytes':len(package),'sha256':hashlib.sha256(package).hexdigest(),
        'texts':texts,'source_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}
(OUT/'management_package.json').write_text(json.dumps(result,indent=2)+'\n',encoding='utf8')
print(json.dumps({'status':result['status'],'bytes':len(package),'sha256':result['sha256']}))
