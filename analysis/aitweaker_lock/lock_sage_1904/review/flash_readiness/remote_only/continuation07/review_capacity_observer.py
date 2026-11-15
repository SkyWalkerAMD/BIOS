"""Offline AST/delta review and isolated observation-branch fault tests.
Never import/run live helper or JS operation; no socket/backend/image access.
"""
from pathlib import Path
import ast,copy,datetime,hashlib,importlib.util,json,struct,sys
HERE=Path(__file__).resolve().parent;REMOTE=HERE.parent;SAGE=REMOTE.parents[2];HD=REMOTE/'media_writeback_client01';HW=SAGE/'remote_172_20_2_162';sha=lambda p:hashlib.sha256(Path(p).read_bytes()).hexdigest()
old=HD/'live_writeback03.py';new=HD/'live_writeback04.py';opold=HW/'operations/hdmedia_writeback03_session.mjs';opnew=HW/'operations/hdmedia_writeback04_session.mjs';delta=json.loads((HERE/'capacity_observer_delta.json').read_text())
assert sha(new)==delta['helper_sha256'] and sha(opnew)==delta['operation_sha256']
a=ast.parse(old.read_text());b=ast.parse(new.read_text())
def observer(tree):
 out=[]
 for n in ast.walk(tree):
  if isinstance(n,ast.If) and isinstance(n.test,ast.Compare) and ast.unparse(n.test)=='response is not None':out.append(n)
 assert len(out)==1;return out[0]
before=observer(a);after=observer(b);assert len(before.body)==1 and len(after.body)==2 and ast.dump(before.body[0])==ast.dump(after.body[0])
normalized=copy.deepcopy(b);normalized.body[0]=copy.deepcopy(a.body[0]);s=observer(normalized);s.body=copy.deepcopy(before.body)
removed=0
for n in ast.walk(normalized):
 if isinstance(n,ast.Dict):
  for i,k in list(enumerate(n.keys))[::-1]:
   if isinstance(k,ast.Constant) and k.value=='capacity_sends':n.keys.pop(i);n.values.pop(i);removed+=1
assert removed==1 and ast.dump(a,include_attributes=False)==ast.dump(normalized,include_attributes=False)
assert opnew.read_bytes().replace(b'live_writeback04.py',b'live_writeback03.py')==opold.read_bytes()
# Compile only the new response-if AST and the existing safe public projection.
block=compile(ast.fix_missing_locations(ast.Module(body=[copy.deepcopy(after)],type_ignores=[])),'<isolated after-send observer>','exec')
pubtree=ast.parse((HD/'observed_auth_adapter.py').read_text());pub=next(n for n in pubtree.body if isinstance(n,ast.FunctionDef) and n.name=='public_frame_fields');public_namespace={'struct':struct};exec(compile(ast.fix_missing_locations(ast.Module(body=[copy.deepcopy(pub)],type_ignores=[])),'<isolated public projection>','exec'),public_namespace)
spec=importlib.util.spec_from_file_location('observer_review_pure',HD/'review_legacy_data/bounded_legacy.py');pure=importlib.util.module_from_spec(spec);sys.modules[spec.name]=pure;spec.loader.exec_module(pure)
auth=bytearray(108);auth[:8]=b'IUSB    ';struct.pack_into('<I',auth,12,76);auth[28:32]=b'K3Y!';auth[41]=0xf1;auth[62]=1
session=pure.bind_session(bytes(auth),tls_verified=True,authenticated=True,image_sha256=pure.IMAGE_SHA256,image_bytes=pure.IMAGE_BYTES);request=bytearray(auth);request[41]=0x25;request=bytes(request);response=pure.serialize_response(pure.normalize_request(session,request))
rows=[]
def run(name,req,reply,send_error=False,expect_count=0,expect_match=None):
 report={'capacity_sends':[]};sent=[]
 class Socket:
  def sendall(self,value):
   assert not report['capacity_sends'],'Observation must occur after sendall'
   sent.append(value)
   if send_error:raise OSError('synthetic send failure')
 ns={'frame':req,'response':reply,'sock':Socket(),'report':report,'datetime':datetime.datetime,'timezone':datetime.timezone,'public_frame_fields':public_namespace['public_frame_fields']}
 try:exec(block,ns);error=False
 except OSError:error=True
 assert error==send_error and len(report['capacity_sends'])==expect_count
 if reply is None:assert not sent
 else:assert len(sent)==1 and sent[0] is reply
 if expect_count:
  entry=report['capacity_sends'][0];assert entry['sendall_returned'] and entry['expected_capacity_bytes_match']==expect_match
  assert entry['capacity8_hex']==('00007fff00000200' if expect_match else None)
  assert set(entry)=={'utc','frame_bytes','sendall_returned','expected_capacity_bytes_match','capacity8_hex','fields'}
  permitted={'bytes','version','header_length','device_type','protocol','direction','instance','payload_length','opcode','header_signature_matches'};assert set(entry['fields'])<=permitted
  encoded=json.dumps(entry);assert 'K3Y!' not in encoded and 'TOP_SECRET_TEST_MARKER' not in encoded and (reply.hex() if reply else 'not a frame') not in encoded
 rows.append({'name':name,'pass':True,'send_calls':len(sent),'observations':len(report['capacity_sends']),'match':expect_match})
run('successful_exact_current_pure_reply',request,response,expect_count=1,expect_match=True)
run('send_exception_no_success_observation',request,response,send_error=True)
run('none_response_no_send_or_observation',request,None)
other=bytearray(request);other[41]=0x1a;run('noncapacity_request_not_logged',bytes(other),response)
bad=bytearray(response);bad[61:69]=b'SECRET!!';run('unexpected_payload_redacted',request,bytes(bad),expect_count=1,expect_match=False)
bad=bytearray(response);sentinel=b'TOP_SECRET_TEST_MARKER!';bad[69:69+len(sentinel)]=sentinel;run('private_padding_and_key_never_logged',request,bytes(bad),expect_count=1,expect_match=True)
run('wrong_length_hides_capacity_data',request,response+b'TOP_SECRET_TEST_MARKER',expect_count=1,expect_match=False)
bad=bytearray(response);bad[41]=0x1a;run('wrong_response_opcode_hides_data',request,bytes(bad),expect_count=1,expect_match=False)
bad=bytearray(response);bad[:8]=b'REDACTED';run('wrong_signature_public_mismatch_only',request,bytes(bad),expect_count=1,expect_match=False)
for length in [0,8,31,32,41,61,68,69,100]:run('short_response_'+str(length),request,response[:length],expect_count=1,expect_match=False)
report={'status':'NO_BLOCKING_FINDING_FOR_PROPOSED_OFF_HOST_OBSERVATION','utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'review_scope':'Only new helper04 vs immutable03 and operation04 vs03, plus exact added AST branch with synthetic pure replies. No network/BMC/image backend/device execution and no helper/operation edits.',
 'hashes':{'helper04':sha(new),'helper03':sha(old),'operation04':sha(opnew),'operation03':sha(opold),'delta':sha(HERE/'capacity_observer_delta.json'),'public_projection':sha(HD/'observed_auth_adapter.py'),'pure_serializer':sha(HD/'review_legacy_data/bounded_legacy.py')},
 'verified_delta':{'entire_python_AST_equal_after_removing_only_docstring_change_capacity_list_and_new_postsend_observation':True,'first_sendall_statement_unchanged_and_precedes_observation':True,'operation_only_changes_fixed_helper_filename03to04':True,'protocol_security_image_lifetime_budget_stop_cleanup_logic_unchanged':True},
 'focused_tests':rows,'focused_case_count':len(rows),
 'logging_boundary':['Only request opcode25 selects the new log path.','Successful sendall must return before any positive observation is appended; send failure creates no misleading success record.','Only exact expected8capacity bytes are rendered; unexpected bytes yield null.','Public projection excludes keybytes28..31, token/auth buffers and other-user IP bytes. Synthetic sentinels in key/padding were not logged.','No complete frame is retained or printed.','New list is bounded by existing8192command and600second limits; it is not an unbounded socket recorder.'],
 'preserved_operation_preconditions':['Native host power_status0 must be read before start.','Virtual CD button must indicate detached; HD/CD session counters must equal the already-reviewed idle128 encoding.','Only exact helper path is spawned and caller-provided expected hash must match; windowsHide is true.','Credentials remain only in the existing child stdin handoff; stdout parsing and stderr byte counting are unchanged.','Operation contains no host power-on/reboot or CD mount command. Parent controls brief lifetime and subsequent readback/cleanup.'],
 'evidence_limits':['sendall_returned proves local socket submission completed, not that BMC parsed/applied the geometry or acknowledged it.','expected_capacity_bytes_match checks shape/signature/opcode/capacity bytes; it is not a general frame validity or remote success claim.','public_frame_fields omits status@53 and declaredtransfer@57. Their fixed values remain source-bound by unchanged serializer; this minimal observer does not directly record them.','This review authorizes no firmware update, arbitrary disk/backend, additional host boot or interpretation of frontendopcode25 as hostSG_IO count.'],
 'finding_summary':'No actual blocker found for the parent proposed brief same-image attachment with hostOff, noCD/nohostboot, thenstop andcleanup. Existing fixed16MiB/512 and write-budget/protocol safeguards are unchanged.','review_script_sha256':sha(__file__)}
(HERE/'capacity_observer_review.json').write_text(json.dumps(report,indent=2),encoding='utf8');print(json.dumps({'status':report['status'],'cases':len(rows),'report_sha256':sha(HERE/'capacity_observer_review.json'),'helper_sha256':sha(new),'operation_sha256':sha(opnew)}))
