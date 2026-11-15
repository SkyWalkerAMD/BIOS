from pathlib import Path
import shutil
OUT=Path(__file__).resolve().parent
ROOT=OUT.parents[1]
src=OUT/'source'
for name in ('depex_probe.c','depex_probe.h'):
    shutil.copyfile(ROOT/'analysis/hero_inventory_collect_20261108/firmware_probe/depex_probe_20261108'/name,src/name)
for name in ('inventory_legacy71.c','inventory_legacy71.h','legacy71_json.h','catalog71.h'):
    shutil.copyfile(ROOT/'analysis/hero_inventory_20261108/native'/name,src/name)
for name in ('source/common.c','source/r2.h','source/kvm.c','source/app.c','decode_captures.py','test_tls_client.c','test_network.c','test_tcp.c'):
    p=OUT/name;s=p.read_text();s=s.replace('131073','1048577').replace('131072','1048576');p.write_text(s)
p=src/'app.c';s=p.read_text().replace('#include "tls_client.h"','#include "tls_client.h"\n#include "depex_probe.h"\n#include "inventory_legacy71.h"')
s=s.replace('\\I3LOG000.TXT','\\I3B000.TXT').replace("name[6]='0'+i/100;name[7]='0'+i/10%10;name[8]='0'+i%10;","name[4]='0'+i/100;name[5]='0'+i/10%10;name[6]='0'+i%10;")
s=s.replace('static ES save_new_log(void){','static void dp_append(void *ctx,const char *bytes,size_t n){\n (void)ctx;char buffer[160];while(n){size_t take=n<159?n:159;memcpy(buffer,bytes,take);buffer[take]=0;logtext(buffer);bytes+=take;n-=take;}\n}\nstatic ES save_new_log(void){')
s=s.replace('B=GET inventory C=QR V=text L=new file Q then Q=exit','B=GET inventory I=publication preflight W then W=one item\\r\\nC=QR V=text L=new file Q then Q=exit')
s=s.replace("&&k!='B')","&&k!='B'&&k!='I'&&k!='W')")
s=s.replace('network_inventory();usb_inventory();tls_inventory();}','network_inventory();usb_inventory();tls_inventory();status("I3B_DEPEX_DIAGNOSTIC",depex_probe(gST,dp_append,0));status("I3B_INVENTORY_SOURCE_EXACT",i3_inventory_source_valid());}')
s=s.replace('else if(k==\'B\')status("INVENTORY_READONLY_GET",private_tls_read_inventory());','''else if(k=='B')status("INVENTORY_READONLY_GET",private_tls_read_inventory());
  else if(k=='I'){
   if(!watchdog_disabled){say("UEFI application watchdog could not be disabled; publication unavailable.\\r\\n");continue;}
   status("I3B_INVENTORY_PREFLIGHT",inventory_legacy71_preflight());
  }
  else if(k=='W'){
   if(!watchdog_disabled||!i3_inventory_source_valid()){status("I3B_PUBLICATION_RUNTIME_OR_SOURCE_REFUSED",ERR(15));continue;}
   say("Publish one pending System/CPU/DIMM inventory item, then verify it.\\r\\nPress W again to apply; any other key cancels. No automatic retry.\\r\\n");
   int confirm=key();if(confirm=='W'||confirm=='w'){
    status("I3B_INVENTORY_STEP",inventory_legacy71_step());
    status("I3B_INVENTORY_STATE",inventory_legacy71_state());status("I3B_INVENTORY_DONE_MASK",inventory_legacy71_completed_mask());
   }
  }''')
p.write_text(s)
p=src/'tls_client.c';s=p.read_text().replace('status("PTLS_HANDSHAKE_RECORD",rx[0]);n=sizeof(tx);e=tls->build(tls,rx,in,tx,&n);status("PTLS_HANDSHAKE_STEP",e);','n=sizeof(tx);e=tls->build(tls,rx,in,tx,&n);if(FAILED(e)){status("PTLS_HANDSHAKE_RECORD",rx[0]);status("PTLS_HANDSHAKE_STEP",e);}')
s=s.replace('PTLS_ENCRYPT_GET','PTLS_ENCRYPT_HTTP').replace('PTLS_GET_SENT','PTLS_HTTP_SENT').replace('TLS handshake succeeded. Reading selected resource.','TLS handshake authenticated. Sending the selected request.')
s=s.replace('if(method&&(!i3_publication_runtime_ready()||!i3_inventory_source_valid()))return ERR(15);','if(method&&(!i3_publication_runtime_ready()||!i3_inventory_source_valid()))return ERR(15);\n if(method&&audit_len+640000>=sizeof(audit)){logtext("I3B_WRITE_REFUSED_RESERVE_FOR_READBACK_AND_FINAL_VERIFY\\r\\n");return ERR(4);}')
p.write_text(s)
p=OUT/'build.py';s=p.read_text().replace("'vendor/qrcodegen'","'depex_probe','inventory_legacy71','vendor/qrcodegen'").replace("'kvm','qrcodegen'","'kvm','depex_probe','inventory_legacy71','qrcodegen'")
s=s.replace('seven fixed GET resources only; no inventory or BIOS writes','13 fixed GET resources; explicit single-item System PATCH or CPU/DIMM POST plus readback; no BIOS settings writes')
p.write_text(s)
