from pathlib import Path
O=Path(__file__).resolve().parent
p=O/'test_tls_client.c';s=p.read_text()
s=s.replace('static int failure,checks,good,','static int source_ok=1,runtime_ok=1;\nint i3_inventory_source_valid(void){return source_ok;}\nint i3_publication_runtime_ready(void){return runtime_ok;}\nstatic int failure,checks,good,')
s=s.replace('good=1;app_sends','source_ok=runtime_ok=1;good=1;app_sends').replace('i<7;i++','i<13;i++').replace('i=7;i<24;i++','i=13;i<24;i++')
s=s.replace('return failure;','''/* Publication allowlist, exact body and If-Match bytes. */
 for(unsigned method=0;method<5;method++)for(unsigned id=0;id<16;id++){
  reset();const char *body=method?"{}":0;UN bytes=method?2:0;const char *etag=method==2?"W/\\\"fresh\\\"":0;
  ES e=private_tls_inventory_exchange(method,id,body,bytes,etag,&r);
  int allowed=(method==0&&id<13)||(method==1&&(id==2||id==3))||(method==2&&id==1);
  CK(allowed?(!e&&app_sends==1&&r.status==200):(e==ERR(2)&&!creates&&!app_sends));
 }
 reset();CK(!make_inventory_request(2,1,"{}",2,"W/\\\"fresh\\\""));active_request=request_buffer;
 const char patch_expected[]="PATCH /redfish/v1/Systems/Self HTTP/1.1\\r\\nHost: 169.254.0.17\\r\\nAccept: application/json;charset=utf-8\\r\\nOData-Version: 4.0\\r\\nAccept-Encoding: identity\\r\\nConnection: close\\r\\nIf-Match: W/\\\"fresh\\\"\\r\\nContent-Type: application/json;charset=utf-8\\r\\nContent-Length: 2\\r\\n\\r\\n{}";
 CK(request_length()==sizeof(patch_expected)-1&&eq(active_request,patch_expected,sizeof(patch_expected)-1));
 const char *bad_tags[]={"","bad\\r\\nx: y","bad\\n","bad\\t","\\177"};
 for(unsigned i=0;i<sizeof(bad_tags)/sizeof(bad_tags[0]);i++){reset();CK(private_tls_inventory_exchange(2,1,"{}",2,bad_tags[i],&r)==ERR(2)&&!creates&&!app_sends);}
 reset();CK(private_tls_inventory_exchange(2,1,"{}",2,0,&r)==ERR(2));
 reset();CK(private_tls_inventory_exchange(1,2,"{\\0}",3,0,&r)==ERR(2));
 reset();CK(private_tls_inventory_exchange(1,2,0,2,0,&r)==ERR(2));
 reset();CK(private_tls_inventory_exchange(1,2,"x",4097,0,&r)==ERR(2));
 reset();source_ok=0;CK(private_tls_inventory_exchange(2,1,"{}",2,"x",&r)==ERR(15)&&!creates&&!app_sends);
 reset();runtime_ok=0;CK(private_tls_inventory_exchange(1,2,"{}",2,0,&r)==ERR(15)&&!creates&&!app_sends);
 reset();audit_len=sizeof(audit)-640000;CK(private_tls_inventory_exchange(1,2,"{}",2,0,&r)==ERR(4)&&!creates&&!app_sends);
 reset();audit_len=sizeof(audit)-640001;CK(!private_tls_inventory_exchange(1,2,"{}",2,0,&r)&&app_sends==1);
 reset();handshake_reject=1;CK(private_tls_inventory_exchange(1,3,"{}",2,0,&r)==ERR(26)&&!app_sends);
 reset();wire[67]^=1;CK(private_tls_inventory_exchange(2,1,"{}",2,"x",&r)==ERR(26)&&!app_sends);
 return failure;''')
p.write_text(s)
p=O/'test_tls_client.py';s=p.read_text().replace('seven fixed GET resources only','13 fixed GET paths, only System PATCH and CPU/DIMM collection POST').replace("'invalid resource IDs and null replies refused'","'invalid resource IDs and null replies refused','all method/resource allowlist combinations','exact If-Match and Content-Length with injection refusal','exact-source/watchdog failure refuses writes before TLS allocation','640000 bytes reserved for post-write readback','write never sent when pin or cryptographic handshake fails'")
p.write_text(s)
p=O/'run_vm.py';s=p.read_text().replace("('d','u','n','p','b')","('d','u','n','p','b','i','w')")
s=s.replace("text=serial();start=text.index(b'KVM_LOG_BEGIN\\r\\n')+len(b'KVM_LOG_BEGIN\\r\\n');end=text.index(b'KVM_LOG_END\\r\\n',start);log=text[start:end]","assert b'KVM_LOG_BEGIN' not in serial();assert b'I3B_UEFI_APPLICATION_WATCHDOG_DISABLE=0x0000000000000000' in serial()")
s=s.replace('restored,meta=decoder.assemble(frames);assert restored==log','restored,meta=decoder.assemble(frames);assert restored.startswith(b\'HERO-INVENTORY-I3B\\r\\nBUILD=I3B-71-LEGACY-INVENTORY\\r\\nRUN=\');assert b\'I3B_UEFI_APPLICATION_WATCHDOG_DISABLE=0x0000000000000000\' in restored;assert restored.count(b\'I3_TARGET_71_VERIFIED=0x0000000000000000\')==8')
p.write_text(s)
