"""Prepare an I3-only clone of R8c transports. Never edit R8 or any CAP."""
from pathlib import Path
import hashlib
import json
import re
import shutil
import zlib

HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[1]
OLD=ROOT/'analysis/hero_remote_bios_r8'
SOURCE=HERE/'source';SOURCE.mkdir(parents=True,exist_ok=True)
records=[]
def write_copy(name, data=None):
    src=OLD/'source'/name;p=SOURCE/name;p.parent.mkdir(parents=True,exist_ok=True)
    original=src.read_bytes();data=original if data is None else data
    p.write_bytes(data);records.append({'source':str(src.relative_to(ROOT)),'destination':name,
        'source_sha256':hashlib.sha256(original).hexdigest(),'destination_sha256':hashlib.sha256(data).hexdigest()})
for name in ('common.c','crc.c','efi_min.h','gzip.c','gzip.h','http_frame.h','network.h','pin.h','probe_core.h','r2.h','tcp.c','loader.c','certificate.h','kvm.h'):
    write_copy(name)
for folder in ('compat','vendor'):
    for p in (OLD/'source'/folder).rglob('*'):
        if p.is_file():write_copy(str(p.relative_to(OLD/'source')))
network=(OLD/'source/network.c').read_text(encoding='utf-8')
network=network.replace('static int target(void){detect_board();return same(report.board,"ROG MAXIMUS Z790 HERO")&&same(report.bios,"3107");}',
                        'static int target(void){return i3_target_valid();}')
network=network.replace('C=QR / V=text', 'C=QR / V=text')
write_copy('network.c',network.encode())
p=SOURCE/'network.h';p.write_text(p.read_text(encoding='utf-8').replace('void say(const char *);','int i3_target_valid(void);\nvoid i3_identity_log(void);\nvoid say(const char *);'),encoding='utf-8')
kvm=(OLD/'source/kvm.c').read_text(encoding='utf-8').replace('HERO-REMOTE-BIOS-R8-QR1','HERO-INVENTORY-I3-QR1').replace('HERO-REMOTE-R8-QR1','HERO-INVENTORY-I3-QR1').replace('HERO Remote BIOS R8','HERO Inventory I3').replace('HERO REMOTE BIOS R8','HERO INVENTORY I3').replace('R8 log viewer','I3 log viewer')
write_copy('kvm.c',kvm.encode())
tls=(OLD/'source/tls_client.c').read_text(encoding='utf-8')
begin=tls.index('static const char *get_requests[]=')
end=tls.index('static unsigned resource;',begin)
tls=tls[:begin]+tls[end:]
tls=tls.replace('HANDLE nic=network_candidate();if(!nic||private_tls_active()||tcp_is_active())return ERR(15);',
'''if(!pinned)return ERR(15);
 if(audit_len+40000>=sizeof(audit)){logtext("I3_AUDIT_CAPACITY_STOP_CAPTURE_EXISTING_LOG\\r\\n");return ERR(4);}
 HANDLE nic=network_candidate();if(!nic||private_tls_active()||tcp_is_active())return ERR(15);''')
begin=tls.index('static ES get_with_policy(')
tls=tls[:begin]+'''/* Fixed GET-only inventory resources. No writer, body, caller URL, redirects,
 * BIOS settings/registries, credentials or pending settings queue. */
static const char *resources[]={
 "/redfish/v1/",
 "/redfish/v1/Systems/Self",
 "/redfish/v1/Systems/Self/Processors",
 "/redfish/v1/Systems/Self/Memory",
 "/redfish/v1/Oem/Ami/InventoryData",
 "/redfish/v1/Oem/Ami/InventoryData/Status",
 "/redfish/v1/oem/ami/inventory/crc"};
static int append_text(UN *n,const char *s){UN z=0;while(s[z])z++;if(z>=sizeof(request_buffer)-*n)return 0;memcpy(request_buffer+*n,s,z);*n+=z;request_buffer[*n]=0;return 1;}
static ES make_request(unsigned id){
 if(id>=sizeof(resources)/sizeof(resources[0]))return ERR(2);
 UN n=0;request_buffer[0]=0;
 if(!append_text(&n,"GET ")||!append_text(&n,resources[id])||!append_text(&n," HTTP/1.1\\r\\nHost: 169.254.0.17\\r\\nAccept: application/json;charset=utf-8\\r\\nOData-Version: 4.0\\r\\nAccept-Encoding: identity\\r\\nConnection: close\\r\\n"))return ERR(4);
 if(id==4&&!append_text(&n,"BiosRedfishVersion: 1.8.0\\r\\nBiosRtpVersion: 1.8.a\\r\\n"))return ERR(4);
 if(!append_text(&n,"\\r\\n"))return ERR(4);return 0;
}
ES private_tls_resource(unsigned id,TLS_REPLY *reply){
 if(!reply)return ERR(2);memset(reply,0,sizeof(*reply));
 if(private_tls_active())return ERR(15);ES e=make_request(id);if(FAILED(e))return e;
 e=exchange_with_policy(1,id,request_buffer);if(!FAILED(e))*reply=last_reply;return e;
}
ES private_tls_get_pinned(void){TLS_REPLY reply;return private_tls_resource(0,&reply);}
ES private_tls_read_inventory(void){
 for(unsigned id=1;id<sizeof(resources)/sizeof(resources[0]);id++){
  logtext("I3_READ_RESOURCE ");logtext(resources[id]);logtext("\\r\\n");
  TLS_REPLY reply;ES e=private_tls_resource(id,&reply);status("I3_RESOURCE_RESULT",e);
  if(FAILED(e))return e;status("I3_RESOURCE_HTTP_STATUS",reply.status);
 }
 logtext("I3_READONLY_INVENTORY_BATCH_COMPLETE\\r\\n");return 0;
}
'''
write_copy('tls_client.c',tls.encode())
(SOURCE/'tls_client.h').write_text('''#ifndef HERO_I3_TLS_CLIENT_H
#define HERO_I3_TLS_CLIENT_H
#include "network.h"
typedef struct {unsigned status;const char *body;UN length;} TLS_REPLY;
ES private_tls_get_pinned(void);
ES private_tls_read_inventory(void);
ES private_tls_resource(unsigned,TLS_REPLY *);
ES private_tls_cleanup(void);
int private_tls_active(void);
#endif
''',encoding='utf-8')

# Bind the exact public peer certificate supplied for .71, not a credential.
cert=ROOT/'analysis/hero_ipmi_continued_live_20261108/assets/bmc-71-public-leaf.der'
der=cert.read_bytes();assert hashlib.sha256(der).hexdigest()=='6b70b607ed2817f451a6edf733d4edd7e95c55ff6dbf704c0bf10e52dc223353'
(SOURCE/'peer_certificate.h').write_text('/* .71 provisioned public leaf; exact DER pin, no private key. */\nstatic const uint8_t pinned_leaf[]={\n'+''.join(','.join('0x%02x'%b for b in der[i:i+16])+',\n' for i in range(0,len(der),16))+'};\n',encoding='utf-8')

capture=ROOT/'analysis/hero_ipmi_continued_live_20261108/hero71-smbios-i1.TXT'
data=capture.read_text(encoding='utf-8');raw=bytes.fromhex(data.split('TABLE_HEX_BEGIN\n')[1].split('TABLE_HEX_END')[0])
assert len(raw)==int(re.search(r'TABLE_USED=([0-9A-F]+)',data)[1],16)
assert zlib.crc32(raw)==int(re.search(r'TABLE_CRC32=([0-9A-F]+)',data)[1],16)
at=0;uuid_values=[]
while at<len(raw):
    typ,size=raw[at:at+2];end=raw.index(b'\0\0',at+size)+2
    if typ==1:assert size>=24;uuid_values.append(raw[at+8:at+24])
    at=end
    if typ==127:break
assert at==len(raw) and len(uuid_values)==1
uuidraw=uuid_values[0];assert uuidraw!=bytes(16) and uuidraw!=b'\xff'*16
(SOURCE/'target_identity.h').write_text('/* Exact raw Type1 UUID from .71 I1 capture. */\nstatic const uint8_t target_uuid[16]={'+','.join('0x%02x'%b for b in uuidraw)+'};\n',encoding='utf-8')

# Reuse the independently tested SMBIOS bounded parser from I1.
i1=ROOT/'analysis/hero_inventory_collect_20261108/source'
header=(i1/'collector.h').read_text(encoding='utf-8').replace('COLLECTOR_H','SMBIOS_BOUNDED_H').replace('#include "efi_min.h"','#include "r2.h"')
header=header.replace('#define W(x) ((C16 *)L##x)\n','')
(SOURCE/'smbios_bounded.h').write_text(header,encoding='utf-8')
(SOURCE/'smbios.c').write_text((i1/'smbios.c').read_text(encoding='utf-8').replace('#include "collector.h"','#include "smbios_bounded.h"'),encoding='utf-8')

(HERE/'staged-drivers').mkdir(exist_ok=True)
for p in (OLD/'staged-drivers').iterdir():
    if p.is_file():shutil.copyfile(p,HERE/'staged-drivers'/p.name)
build=(OLD/'build.py').read_text(encoding='utf-8')
build=build.replace("'publish'","'identity','smbios'")
build=build.replace('HERO_R8.TAG','HERO_I3.TAG').replace('HERO-REMOTE-R8','HERO-INVENTORY-I3').replace('HERO_REMOTE_R8','HERO_INVENTORY_I3').replace('HERO-REMOTE-BIOS-R8.iso','HERO-INVENTORY-I3-READONLY.iso')
start=build.index("report={'version':")
end=build.index("(OUT/'build.json')",start)
build=build[:start]+'''report={'version':'I3-readonly','mode':'Explicit RAM USB + fixed-pin internal TLS, seven fixed GET resources only; no inventory or BIOS writes','target':'HERO3107 with exact .71 raw SMBIOS Type1 UUID and leaf certificate','artifacts':artifacts,'iso_sha256':sha(output),'iso_bytes':output.stat().st_size,'sources':{p.relative_to(OUT/'source').as_posix():sha(p) for p in (OUT/'source').rglob('*') if p.is_file()},'commands':commands}
'''+build[end:]
(HERE/'build.py').write_text(build,encoding='utf-8')
decoder=(OLD/'decode_captures.py').read_text(encoding='utf-8')
decoder=decoder.replace('HERO-REMOTE-R8-QR1','HERO-INVENTORY-I3-QR1').replace('HERO-REMOTE-BIOS-R8','HERO-INVENTORY-I3').replace('R8','I3')
decoder=decoder.replace('(?:BUILD=I3[a-z]-[A-Z0-9-]+\\r\\n)?','BUILD=I3-71-PINNED-GET-ONLY\\r\\n')
(HERE/'decode_captures.py').write_text(decoder,encoding='utf-8')
for item in records:
    item['destination_sha256']=hashlib.sha256((SOURCE/item['destination']).read_bytes()).hexdigest()
(HERE/'provenance.json').write_text(json.dumps({'copied_sources':records,'certificate_sha256':hashlib.sha256(der).hexdigest(),
 'capture_sha256':hashlib.sha256(capture.read_bytes()).hexdigest(),'raw_type1_uuid':uuidraw.hex(),
 'rules':'No writes outside this new directory. No old publication/catalog source copied.'},indent=2)+'\n',encoding='utf-8')
print(json.dumps({'prepared':True,'target_uuid_raw':uuidraw.hex(),'certificate_bytes':len(der)}))
