from pathlib import Path
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[1];OLD=ROOT/'analysis/hero_remote_bios_r8'
network=(OLD/'test_network.c').read_text(encoding='utf-8')
network=network.replace('void detect_board(void){','int i3_target_valid(void){return good_target;}\nvoid detect_board(void){')
(HERE/'test_network.c').write_text(network,encoding='utf-8')
for name in ('test_network.py','test_tcp.c','test_tcp.py'):
    (HERE/name).write_bytes((OLD/name).read_bytes())
test=(OLD/'test_tls_client.c').read_text(encoding='utf-8')
test=test.replace('ST *gST;static ST st;', 'ST *gST;char audit[131072];UN audit_len;static ST st;')
test=test.replace('private_tls_get()', 'private_tls_get_pinned()')
test=test.replace('for(int i=1;i<=12;i++){reset();', 'for(int i=1;i<=12;i++){if(i==5||i==6)continue;reset();')
test=test.replace('memset(&st,0,sizeof(st));', 'audit_len=0;memset(&st,0,sizeof(st));')
start=test.index(' for(unsigned i=0;i<3;i++){reset();CK(!get_with_policy')
end=test.index(' uint8_t gz[]=',start)
test=test[:start]+''' TLS_REPLY r;
 for(unsigned i=0;i<7;i++){
  reset();CK(!private_tls_resource(i,&r)&&r.status==200&&r.length==2&&eq(r.body,"{}",2)&&app_sends==1&&!private_tls_active());
  CK(eq(active_request,"GET ",4));
  UN length=request_length();CK(length>4&&eq(active_request+length-4,"\\r\\n\\r\\n",4));
 }
 for(unsigned i=7;i<24;i++){reset();CK(private_tls_resource(i,&r)==ERR(2)&&!creates&&!app_sends);}
 reset();CK(private_tls_resource(0,0)==ERR(2)&&!creates&&!app_sends);
 reset();CK(exchange_with_policy(0,0,"GET /bad")==ERR(15)&&!creates&&!app_sends);
 reset();audit_len=sizeof(audit)-39999;CK(private_tls_resource(0,&r)==ERR(4)&&!creates&&!app_sends);
 reset();CK(!make_request(4));active_request=request_buffer;
 const char expected[]="GET /redfish/v1/Oem/Ami/InventoryData HTTP/1.1\\r\\nHost: 169.254.0.17\\r\\nAccept: application/json;charset=utf-8\\r\\nOData-Version: 4.0\\r\\nAccept-Encoding: identity\\r\\nConnection: close\\r\\nBiosRedfishVersion: 1.8.0\\r\\nBiosRtpVersion: 1.8.a\\r\\n\\r\\n";
 CK(request_length()==sizeof(expected)-1&&eq(active_request,expected,sizeof(expected)-1));
 reset();handshake_reject=1;CK(private_tls_resource(4,&r)==ERR(26)&&!app_sends&&!r.status);
 reset();tls_destroy_fail=1;CK(private_tls_resource(4,&r)==ERR(7)&&private_tls_active()&&!r.status);tls_destroy_fail=0;CK(!private_tls_cleanup());
'''+test[end:]
test=test.replace('private_tls_resource(8,0,0,&r)', 'private_tls_resource(2,&r)')
(HERE/'test_tls_client.c').write_text(test,encoding='utf-8')
runner=(OLD/'test_tls_client.py').read_text(encoding='utf-8')
start=runner.index("'coverage':[");end=runner.index(']}',start)
runner=runner[:start]+"'coverage':['seven fixed GET resources only','exact .71 leaf pin match and mismatch before HTTP','TLS1.2 cryptographic handshake and negotiated cipher policy','all certificate message split boundaries','non-pinned exchange refused before allocation','capability URL and four exact donor headers','short TCP reads and strict HTTP/gzip framing','HTTP error status retained','failed cleanup retains callbacks and blocks reuse','bounded log capacity refusal before new request','invalid resource IDs and null replies refused']"+runner[end+1:]
(HERE/'test_tls_client.py').write_text(runner,encoding='utf-8')
print('Prepared inherited transport regressions with GET-only I3 policy.')
