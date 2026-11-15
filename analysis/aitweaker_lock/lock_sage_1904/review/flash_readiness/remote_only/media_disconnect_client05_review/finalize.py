"""Bind only new helper05 offline review; never start its live main function."""
from pathlib import Path
import hashlib, json, shutil, zipfile
HERE=Path(__file__).resolve().parent;REMOTE=HERE.parent
CASE=REMOTE.parents[2];HW=CASE/'remote_172_20_2_162'
CLIENT=REMOTE/'media_writeback_client01'
def file(p):
    b=p.read_bytes()
    return {'path':str(p),'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest()}
def load(p):return json.loads(p.read_text(encoding='utf8'))
helper=CLIENT/'live_writeback05.py';op=HW/'operations/hdmedia_writeback05_session.mjs'
hh=file(helper)['sha256'];oh=file(op)['sha256']
assert hh=='5dffcd939577ad7faf460a9bbd9ebf2065ebf1d9664b9a8ac41ef7d296c07e75'
assert oh=='381a1fa3d2bbe49d4d29f7671f35a5fd03077ab22889e0860ae4d50bbcff7af3'
tests={n:load(HERE/n) for n in ['helper_tests.json','session_tests.json','arm_f7_tests.json']}
assert [tests[n]['cases'] for n in tests]==[31,18,4]
for j in tests.values():assert j['status']=='PASS' and j['helper_sha256']==hh
assert tests['session_tests.json']['operation_sha256']==oh
assert tests['helper_tests.json']['test_source_sha256']==file(HERE/'test_helper05.py')['sha256']
assert tests['session_tests.json']['test_sha256']==file(HERE/'test_session05.mjs')['sha256']
assert tests['arm_f7_tests.json']['test_sha256']==file(HERE/'test_arm_f7.py')['sha256']
inputs=[helper,op,CLIENT/'observed_session03.py',CLIENT/'hdmedia_offline.py',
        CLIENT/'observed_auth_adapter.py',CLIENT/'review_legacy_data/bounded_legacy.py',
        REMOTE/'media_reconnect_review07/reconnect_review.json',
        REMOTE/'media_reconnect_review07/manifest.json',
        REMOTE/'media_reconnect_review07/replay_disconnect.py',
        REMOTE/'media_attach_review02/replay_capacity.py',
        REMOTE/'media_attach_review02/backend/usr/local/bin/hdserverapp',
        REMOTE/'media_writeback_review/JViewer.jar']
prior={
    CLIENT/'live_writeback04.py':'1f83f12403636e9764f3cc90350880b6bfa7b15ea0610e220a1106b5e0bd4f43',
    REMOTE/'media_geometry_review06/geometry_review.json':'df07bf5c111f3c207b382c91196170df87baffc64500303b214ba6e4f99e698f',
    REMOTE/'media_reconnect_review07/reconnect_review.json':'c689cb9773c32e35302d016ef0d6ee9b698f70eb28531dc4e206813232eb68bf',
    REMOTE/'media_reconnect_review07/manifest.json':'714e568a84a07f6637aa7c70a28210b822cfcc86af09beaabdbdd7fa957070f7',
    REMOTE/'bmc_restart_review01/restart_review.json':'b5e1d402175335e529f1f9e19900d1325a4468ae2350166770c2b54d3c7456a0',
}
for p,expected in prior.items():assert file(p)['sha256']==expected
image=REMOTE/'media_writeback_review/blank_test/WRITEBACK02.img'
assert image.stat().st_size==16777216
assert file(image)['sha256']=='df7fa016a0f4be496d3d446db558e8de15f537aa9953faff20b4ae0c6132b4b6'
snap=HERE/'reviewed_sources';snap.mkdir(exist_ok=True)
for p in [helper,op,HERE/'test_helper05.py',HERE/'test_arm_f7.py',HERE/'test_session05.mjs',HERE/'F7Oracle.java']:
    shutil.copyfile(p,snap/p.name)
refs=HERE/'vendor_serialization';refs.mkdir(exist_ok=True)
for name in ['com.ami.iusb.protocol.IUSBSCSI.javap.txt','com.ami.kvm.imageredir.IUSBHeader.javap.txt','com.ami.iusb.protocol.PacketMaster.javap.txt']:
    p=REMOTE/'media_writeback_review'/name;inputs.append(p);shutil.copyfile(p,refs/name)
with zipfile.ZipFile(REMOTE/'media_writeback_review/JViewer.jar') as z:
    classes={n:hashlib.sha256(z.read(n)).hexdigest() for n in [
      'com/ami/iusb/protocol/IUSBSCSI.class','com/ami/kvm/imageredir/IUSBHeader.class',
      'com/ami/iusb/protocol/PacketMaster.class','com/ami/iusb/HarddiskRedir.class']}
report={
 'status':'OFFLINE_VERIFIED_CANDIDATE_NOT_LIVE_TESTED',
 'scope':'New helper05 and new owning session operation only. No BMC/network/device action, no real image backend write, no firmware or BMC configuration modification. Existing helper04 and frozen reports unchanged.',
 'inputs':[file(p) for p in inputs],
 'vendor_java_class_sha256':classes,
 'client_changes':[
   'Existing fixed target, certificate, 16MiB disposable image, 1MiB write budget, auth and bounded legacy request processing remain inherited/pinned.',
   'Parent STOP or 600-second lifetime in an authenticated ACTIVE instance0 triggers exactly one fresh62-byte F7 command before TLS context closure.',
   'Use a new zeroed VendorWriter, original IUSBHeader(30), opcode247 and original prebuffered final header rewrite. No auth key, token or retained response data is copied.',
   'F7 send timeout1s; after successful send wait at most2s and16384bytes for receive-only observation. No block reads/writes/flush, no replies, no reconnect, no resend while draining.',
   'Peer closure, server stop, protocol failure or missing/closed/nonzero owned session do not send F7. All ordinary main exits still close owned local resources.',
   'New operation pins the exact new helper SHA. Start keeps hostOff/CDdetached/idleHD+CD/uniqueauthorizedcookie/freshtoken gates, and rechecks hostOff/CDdetached immediately before spawn. Old helper ownership cannot be mistaken for helper05.',
 ],
 'wire':{
   'opcode_hex':'F7','meaning':'MEDIA_SESSION_DISCONNECT','frame_bytes':62,'declared_payload_bytes':30,
   'header_version_hex':'010020','device_type':5,'protocol':1,'direction':128,'instance':0,
   'packet_source':'Fresh-buffer original Java sendCommandToMediaServer(PacketMaster, ByteBuffer, null, 247), confirmed by actual vendor serializer with memory-only PacketMaster override.',
   'frame':file(HERE/'f7-public-frame.bin'),
   'no_secret_payload':'Frame is a public constant with zero key/data and no token. Header checksum follows vendor two-write behavior; do not replace it with a guessed wire checksum rule.',
 },
 'ordering_and_failure':{
   'normal':'Parent STOP/lifetime -> one F7 sendall -> bounded receive-only wait -> TLS socket close -> local image close/final hash report.',
   'send_failure':'Record exception type only, zero retry, close owned socket/image.',
   'receive_timeout':'Record SENT_DRAIN_DEADLINE and close; no inferred acknowledgement.',
   'receive_error':'Record sendall_returned separately from drain error and close.',
   'eof':'Record peer_eof_observed. It is transport closure, not independent proof of actual NBD/gadget cleanup.',
   'observable_fields':['attempts','sendall_returned','peer_eof_observed','drained_bytes','status','protocol_ack_validated=false','server_slots_cleared_verified=false'],
   'no_apply_ack':'Original selected F7 branch does not provide a validated apply ACK. Neither sendall nor EOF nor an idle UI alone proves the backing slot has been cleared.',
 },
 'actual_arm_result':{
   'positive':'Exact newly serialized F7 enters original receiver0x17054 then branch0x15E08: hdisk_stop boundary -> nbd_disconnect -> socket/session cleanup. Both synthetic gadget/NBD slot fields become-1.',
   'negative':'Truncated and oversized declared length do not reach the explicit F7 cleanup branch.',
   'important_limit':'Original receiver/dispatch/common cleanup executes in Unicorn. NBD, gadget, filesystem, thread, network and session service boundaries are audited stubs. No live state or actual driver clearing was observed.',
 },
 'tests':{n:file(HERE/n)|{'cases':j['cases'],'status':j['status']} for n,j in tests.items()},
 'test_total_cases':53,
 'java_execution_scope':'Only F7Oracle invokes original serialization constructors/methods. MemoryMaster overrides sendPacket and has no real socket; connectVmedia, JViewer main, native JNI and client redirection are never invoked.',
 'not_established':[
   'helper05 authentication or F7 delivery on the actual BMC',
   'Server-side gadget/NBD clear operation success on this machine',
   'Correction of current geometry or optical boot failure',
   'A shared HD/CD NBD slot or causal link between helper04 closure and CD failure',
   'Capacity negotiation, file writeback, firmware backup/recovery, or flash readiness',
 ],
 'reviewed_future_run_boundary':'Parent may review and then start/stop the owned helper05 only with hostOff and CDdetached. Read resulting facts and standard media status afterward; do not treat source strings as permission for shell/sysfs/service cleanup. No runtime action was performed here.',
 'frozen_prior_inputs_unchanged':[file(p) for p in prior],
 'disposable_image_unchanged':file(image),
}
(HERE/'helper05_review.json').write_text(json.dumps(report,indent=2)+'\n')
rows=[]
for p in sorted(HERE.rglob('*')):
    if not p.is_file() or p.name=='manifest.json' or '__pycache__' in p.parts:continue
    e=file(p);e['path']=str(p.relative_to(HERE));rows.append(e)
(HERE/'manifest.json').write_text(json.dumps({'scope':'New helper05 offline candidate only; external inputs separately pinned in helper05_review.json. No live cleanup result.','files':rows},indent=2)+'\n')
print(json.dumps({'report':file(HERE/'helper05_review.json'),'manifest':file(HERE/'manifest.json'),'artifacts':len(rows)}))
