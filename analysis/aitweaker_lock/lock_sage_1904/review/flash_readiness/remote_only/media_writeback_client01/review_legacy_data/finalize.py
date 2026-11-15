"""Freeze offline evidence; no adapters outside this directory are modified."""
from pathlib import Path
import datetime,hashlib,json,zipfile
HERE=Path(__file__).resolve().parent;CLIENT=HERE.parent;REMOTE=CLIENT.parent;ROOT=HERE.parents[7]
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
def ev(p):return dict(path=str(p),bytes=p.stat().st_size,sha256=sha(p))
def save(p,v):p.write_text(json.dumps(v,indent=2,ensure_ascii=False)+'\n',encoding='utf-8')
v=json.loads((HERE/'bounded_verification.json').read_text(encoding='utf-8'))
assert v['status']=='PASS_PURE_LEGACY_ADAPTER_OFFLINE_ONLY'
assert sha(HERE/'bounded_legacy.py')==v['adapter_sha256']=='163bca4e30aec052d0604a47077a436f2fa2931115d35d76c741cc4d27fcdab5'
assert sha(HERE/'verify_bounded.py')==v['test_sha256']
assert v['positive_cases']==314 and v['negative_cases']==522
for p,h in v['immutable_inputs_unchanged'].items():assert sha(Path(p))==h
native=json.loads((HERE/'native_dispatch.json').read_text())
assert sha(HERE/'native_dispatch.py')==native['test_sha256']
refs=json.loads((HERE/'reference/sources.json').read_text())+[json.loads((HERE/'reference/target_core_sbc.json').read_text())]
for r in refs:assert sha(HERE/'reference'/r['path'])==r['sha256']
obsdir=ROOT/'analysis/aitweaker_lock/lock_sage_1904/remote_172_20_2_162'
observations=[obsdir/'hdmedia-ordinary-observation-1793683389185.json',obsdir/'hdmedia-mode-sense-observation-1793683934451.json']
mode=json.loads(observations[1].read_text())['result']
assert mode['authentication_accepted'] and mode['exact_TUR_response_sent'] and not mode['image_opened'] and not mode['disk_backend_used']
assert mode['ordinary']['session_header_matches_auth'] and mode['ordinary']['legacy_header_reserved_all_zero']
jar=REMOTE/'media_writeback_review/JViewer.jar';dll=REMOTE/'media_writeback_review/javaharddiskwrapper-win64.dll'
classes={}
with zipfile.ZipFile(jar) as z:
    for n in ['com/ami/kvm/imageredir/IUSBHeader.class','com/ami/iusb/protocol/IUSBSCSI.class','com/ami/iusb/protocol/HarddiskProtocol.class','com/ami/iusb/protocol/PacketMaster.class','com/ami/iusb/HarddiskRedir.class','com/ami/iusb/vHarddiskMonitorThread.class']:
        classes[n]=hashlib.sha256(z.read(n)).hexdigest()

report=dict(status='FROZEN_OFFLINE_BOUNDED_LEGACY_ADAPTER_HARDWARE_DATA_PATH_UNVERIFIED',
 created_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
 adapter=ev(HERE/'bounded_legacy.py'),verification=ev(HERE/'bounded_verification.json'),
 scope='Pure frame validation, normalization and response serialization only. No network, filesystem, native DLL loading, image backend or firmware access in the adapter. Public primary source retrieval was confined to reference files; no BMC contact was made by this task.',
 provenance=dict(Java=ev(jar),DLL=ev(dll),class_sha256=classes,parent_metadata=[ev(p) for p in observations],references=refs),
 API=[
  dict(name='bind_session(auth_reply, tls_verified=True, authenticated=True, image_sha256=IMAGE_SHA256, image_bytes=16777216)',result='Immutable Session with verified legacy profile, private opaque header key and fixed auth tail. Requires caller-provided proof flags and exact image profile; it performs no TLS/login/image verification itself.'),
  dict(name='normalize_request(session, raw)',result='Immutable Plan: action, opcode, lba, count, write_data, fixed_data, response_data_bytes, status, declared_response_bytes, canonical, next_session, padding_kind, opaque_direction.'),
  dict(name='serialize_response(plan, data=None, operation_succeeded=True)',result='Legacy response bytes, or None forF7. Revalidates the entire immutable plan, requires exact read length/fixed control data, preserves original CDB/sequence/key, and zeroes32 padding bytes.')
 ],
 caller_contract=[
  'Use only the existing literal regular-file PinnedImage backend for WRITEBACK02.img. This library never receives or selects a filesystem/device path.',
  'Verify same owned TLS/session/F1 authentication and actual pristine image identity outside the library. Do not route a different connection or instance into the bound session.',
  'On normalization success, commit session=plan.next_session BEFORE external read/write/flush. Reservation is not refunded on failure. Do not reuse an earlier Session to bypass cumulative budget.',
  'control: use fixed_data directly, without backend access. read: supply image.read(lba,count) result. write: call image.write(lba,count,write_data), including existing fsync/readback checks, before serializing zero-data acknowledgement. flush: require successful image.flush before reply.',
  'reply_then_stop(F6): send its fixed non-image response then close the owned session/backend. stop_without_reply(F7): close without sending a response.',
  'Unknown frames, malformed data, short/failed I/O, serialization errors, socket EOF and byte-budget exhaustion must stop and close; do not retry, reconnect or silently widen framing.',
  'canonical is an internal compatibility representation only; never send it directly to BMC. Preserve original Plan for legacy response. The old engine MODE SENSE allocation slice is not used for the fixed control response.',
  'After real writeback testing, close/unmount the owned backend and reopen the literal image read-only to independently verify WRBACK.TXT, marker, image size, filesystem content and hashes.'
 ],
 bounded_request_rules=dict(
  physical_header='Exactly32 physical bytes even though headerLen byte10 is0. Signature IUSB plus4 spaces; version0/0/headerLen0; payload length@12 must equal wire_length-32; instance/device/protocol/caps/client fields@16..23 equal the bound all-zero F1 profile; key@28..31 equals bound opaque key. Sequence@24..27 is echoed, not used as a path or authorization.',
  frame_size=dict(minimum=61,maximum=131134),
  nonwrite_tail='Only61 bytes;62 with one zero byte;108 with exactly47 all-zero bytes OR exactly the verified F1 tail (61=0,62=1,63..107=0). Arbitrary extra padding is rejected, and76-byte payload is not declared a universal SCSI layout.',
  write_tail='WRITE10 requires exactly61+count*512 bytes, declaration@57 equals count*512 and all bytes from61 are payload. No62+size padding, no108-byte-tail stripping, no arbitrary trailing data.',
  CDB='Only explicit opcode whitelist and bounded flags. READ10/WRITE10 LBAbe32 atCDB2, countbe16 atCDB7; READ12 LBAbe32 atCDB2,countbe32 atCDB6. Disallowed protection/reserved/control fields reject.',
  image=dict(bytes=16777216,sector_bytes=512,blocks=32768),
  transfers=dict(min_sectors=1,max_read_sectors=255,max_write_sectors=256,total_reserved_write_bytes=1048576,max_commands=8192),
  requested_read_length='Little-endian64 at32 must be0 or the bounded command amount. MODE SENSE additionally allows its8-bit allocation value; response is still the native fixed4-byte header.',
  direction='Byte40 remains opaque, exactly as in tested native dispatch; all256 values are synthetic-tested to remain a READ for read opcode. It never selects read/write, target or count. Nonzero values have not been observed on hardware.',
  status='Incoming status@53 must0. Any contradiction between opcode, bounded CDB, declared bytes, physical payload or finite tail shape rejects before backend use.'),
 commands=[
  dict(opcode='00',action='control',physical_data_bytes=0,status='0',evidence='Native0x38a0 readiness branch to0x34e0; no block read/write.'),
  dict(opcode='1A',action='control',physical_data_hex='03000000',status='0',evidence='Native returns4-byte writable MODE SENSE header for allocation0 and255, confirmed actual bytes. Old engine allocation slicing would return0 for this observed request and is intentionally bypassed.'),
  dict(opcode='25',action='control',physical_data_bytes=8,status='0',evidence='Fixed READ CAPACITY lastLBA32767/block512, matches native initialized16MiB image.'),
  dict(opcode='1B/1E',action='control',physical_data_bytes=0,status='0',evidence='Native no-op success branch; library issues no actual media eject/reset/unlock operation.'),
  dict(opcode='28/A8',action='read',physical_data_bytes='count*512',status='0 after exact backend result',evidence='Standard CDB semantics plus image/wire bounds. READ12 vendor truncation defect is not emulated; see deliberate differences.'),
  dict(opcode='2A',action='write',physical_data_bytes=0,status='0 only after external durable success',evidence='Strict exact payload/count/budget; actual backend remains parent-owned and literal-file-bound.'),
  dict(opcode='35',action='flush',physical_data_bytes=0,status='0 after successful backend flush',evidence='Design extension from existing bounded engine; original native image dispatch returnsunsupported, not claimed equivalent.'),
  dict(opcode='F3',action='control',physical_data_bytes=0,status='0x200501',evidence='vHarddiskMonitorThread sendsF3 keepalive to server after inactivity; incomingF3 goes through native defaultunsupported branch. It never maps to image I/O.'),
  dict(opcode='F4',action='control',physical_data_hex='80',declared_transfer_bytes=0,status='0x200501',evidence='Native defaultunsupported+JNI61 bytes; HarddiskRedir.run bytecode63..138 adds USB-image drive type80 at61, changes native length62, and writesint31 atoffset11. Serializer reproduces resulting checksum seed31 and94-byte legacy wire response.'),
  dict(opcode='F6',action='reply_then_stop',physical_data_bytes=0,status='0x200501',evidence='Native defaultunsupported; HarddiskRedir.run marks killed then reaches sendPacket. Adapter closes immediately after reply instead of relying on later monitor shutdown.'),
  dict(opcode='F7',action='stop_without_reply',physical_data_bytes=0,evidence='HarddiskRedir.run bytecode194..209 flags service restarted then returns before response send.'),
 ],
 response_rules=dict(
  size='93+physical_data_bytes, payload_length@12=61+physical_data_bytes, headerLen remains0, direction@19=80.',
  buffer='Java capacity131134:255-sector response130653 fits;256-sector response131165 is explicitly rejected before read. WRITE256 request131133 fits and its acknowledgement is only93.',
  data='Copy original request metadata/CDB through52; status@53, declared transfer@57, physical data@61. F4 is the sole supported declared0/physical1 special case.',
  padding='Fresh zeroed buffer and all32 bytes after physical response data zero. Header session key retained only at28..31; no retained token/other-IP/request payload in padding.',
  checksum='Actual Java IUSBHeader.write algorithm: new length/direction, prior checksum included in sum, full fresh-zero output capacity. F4 prior checksum seed is31 from Java putInt atoffset11.'),
 deliberate_differences=[
  'All response padding is cleared. Original native62-byte copy leaks first WRITE payload byte into a zero-data ACK at61; stock retained Java buffer may expose more old bytes. Oracle applies the same explicit padding clear before actual Java serialization.',
  'READ12 uses standard32-bit count (Linuxv6.12 target_core_sbc.c transport_get_sectors_12 at239 and READ_12 dispatch at799). Native0x38a0 reads only high16 bits: actual dispatch replay ofcount2 produces0;count65536 produces1. Adapter rejects65536 and correctly limits ordinary counts to255.',
  '0x35 flush invokes only the existing parent-owned regular-image fsync path and acknowledges success only after it returns. Original native dispatch has no0x35 case.',
  'Finite padding patterns, image/budget/command bounds, strict reserved CDB fields and response-size checks are intentionally stricter than stock Java/native.',
  'F6 ends adapter session after reply; stock Java marks a killed flag and relies on surrounding lifecycle to stop.'
 ],
 validation=dict(positive_cases=314,negative_cases=522,real_Java_response_comparisons=15,real_Java_capacity_boundaries=3,native_dispatch_cases=20,
  important_cases=['Mode Sense allocation0/255 fixed4','All256 opaque-direction values never change READ action','TUR/read/control61/62/fixed108 finite tails','WRITE exact payload only and extra byte/tail refusal','Last image sector and crossing end','READ255 versus rejected256; WRITE256 permitted','Eight128KiB write reservations reach1MiB, next write rejected','F4 status/declared0/physical80/checksum31','F6/F7 session closes','Unknown opcodes and all tested malformed tails/header/CDB/status/declarations reject','Short/extra/mutable read data and operation failure cannot produce success','Plan tampering rejected; old client code/artifacts unchanged'],
  native_scope='Actual DLL dispatch0x38a0 and control routines; file-size scalar and read/write helper boundaries are synthetic memory fixtures, not actual Windows I/O. No native DLL is loaded into the host.',
  Java_scope='Only protocol/header classes loaded; no HarddiskRedir/PacketMaster/GUI/native disk library instantiated. Java output compared after deliberate padding clearing.'),
 limitations=[
  'Parent has observed one successful exact TUR response followed by MODE SENSE metadata. This adapter has not been connected to BMC or tested against real READ/WRITE traffic.',
  'No new firmware modification, SPI access, full backup or recovery capability is established.',
  'Other runtime request shapes may still reject; changing acceptance requires new evidence, not silent fallback.',
  'Calling flags and immutable state are a coordination contract. This pure library cannot enforce TLS ownership, image pinning, external durable I/O or correct caller state commitment.',
  'Transport stream buffering must independently enforce131134-byte frames and close on malformed/truncated data; this API accepts only complete immutable frames.'
 ])
save(HERE/'legacy_data_review.json',report)
files=[p for p in HERE.rglob('*') if p.is_file() and p.name!='manifest.json' and '__pycache__' not in p.parts]
manifest=dict(status=report['status'],adapter_sha256=sha(HERE/'bounded_legacy.py'),artifacts=[ev(p) for p in sorted(files,key=str)],unchanged_inputs=v['immutable_inputs_unchanged'])
save(HERE/'manifest.json',manifest)
print(json.dumps(dict(adapter_sha256=sha(HERE/'bounded_legacy.py'),review_sha256=sha(HERE/'legacy_data_review.json'),manifest_sha256=sha(HERE/'manifest.json'),artifacts=len(files)),indent=2))
