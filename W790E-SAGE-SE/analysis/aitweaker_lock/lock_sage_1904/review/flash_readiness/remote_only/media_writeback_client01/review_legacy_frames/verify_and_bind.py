"""Bounded offline Java/native oracles and pure-function rejection fixtures."""
from pathlib import Path
import dataclasses,datetime,hashlib,json,struct,subprocess,sys,zipfile
HERE=Path(__file__).resolve().parent
CLIENT=HERE.parent
REMOTE=CLIENT.parent
ROOT=HERE.parents[7]
REF=REMOTE/'media_writeback_review'
JAVA=Path('D:/JAVA/jdk-27/bin')
sys.path.insert(0,str(ROOT/'tools/pydeps'))
import pefile
from legacy_tur_once import LegacyTurReject,respond_once
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
def evidence(p):return dict(path=str(p),bytes=p.stat().st_size,sha256=sha(p))
def save(p,v):p.write_text(json.dumps(v,indent=2,ensure_ascii=False)+'\n',encoding='utf-8')
jar=REF/'JViewer.jar';dll=REF/'javaharddiskwrapper-win64.dll'
assert sha(jar)=='32be6d97032587e1490d2f34ee04a98cd89875e7196936fb2fec5e0440bc3b98'
assert sha(dll)=='0fcc9ee5629d653c9621e057df39c69fb3ef04fba85106d667123d172e25a14a'
before={str(p):sha(p) for p in [CLIENT/'hdmedia_offline.py',CLIENT/'verify_offline.py',CLIENT/'client_review.json',jar,dll]}
compilecmd=[str(JAVA/'javac.exe'),'-cp',str(jar),'LegacyFrameOracle.java']
subprocess.run(compilecmd,check=True,cwd=HERE,capture_output=True)
cmd=[str(JAVA/'java.exe'),'-Xlog:class+load=info:file=class_load.log','-Xlog:library=info:file=library_load.log','-cp',str(HERE)+';'+str(jar),'LegacyFrameOracle']
proc=subprocess.run(cmd,check=True,cwd=HERE,capture_output=True,text=True,encoding='utf-8')
(HERE/'java_oracle_stdout.txt').write_text(proc.stdout,encoding='utf-8')
(HERE/'java_oracle_stderr.txt').write_text(proc.stderr,encoding='utf-8')
classlog=(HERE/'class_load.log').read_text(encoding='utf-8')
liblog=(HERE/'library_load.log').read_text(encoding='utf-8')
for denied in ['com.ami.iusb.HarddiskRedir','com.ami.iusb.protocol.PacketMaster','com.ami.kvm.jviewer.gui.SinglePortKVM','com.ami.kvm.jviewer.gui.JViewerApp','com.ami.vmedia.VMApp']:
    assert denied not in classlog,denied
assert 'javaharddiskwrapper' not in liblog.lower()
parses={};responses={};keyed=None
for line in proc.stdout.splitlines():
    parts=line.split('|')
    if parts[0]=='PARSE':parses[parts[1]]=None if parts[2]=='null' else list(map(int,parts[2:]))
    elif parts[0]=='RESPONSE':responses[parts[1]]=dict(constructed_data_len=int(parts[2]),wire_bytes=int(parts[3]),frame=bytes.fromhex(parts[4]))
    elif parts[0]=='KEYED_DIGEST':keyed=(int(parts[1]),parts[2])
assert len(parses)==9 and len(responses)==4 and keyed
assert parses['legacy_F1_108']==[241,76,0,1,76,108]
assert parses['legacy_TUR_108_auth_tail']==[0,76,0,-1,76,108]
assert parses['legacy_TUR_62']==[0,30,0,-1,30,62]
assert parses['legacy_TUR_61']==[0,29,0,-1,29,61]
assert parses['legacy_F3_108_auth_tail']==[243,76,0,-1,76,108]
assert parses['legacy_F1_107_truncated_other_IP'] is None
assert parses['legacy_TUR_109_nonzero_tail']==[0,77,0,-1,77,109]
assert responses['legacy_TUR_zero_seed']['wire_bytes']==93
assert responses['legacy_TUR_retained_seed']['frame'][62:]==b'\xa5'*31
assert responses['canonical_TUR_retained_seed']['wire_bytes']==61
assert responses['legacy_capacity8_retained_seed']['wire_bytes']==101
nativeproc=subprocess.run([sys.executable,'-B','-X','utf8',str(HERE/'replay_native.py')],check=True,cwd=HERE,capture_output=True,text=True,encoding='utf-8')
(HERE/'native_replay_stdout.txt').write_text(nativeproc.stdout,encoding='utf-8')
native=json.loads((HERE/'native_replay.json').read_text(encoding='utf-8'))
assert native['status']=='PASS_NATIVE_BYTES_SYNTHETIC_MEMORY_ONLY' and len(native['cases'])==5

def pair():
    a=bytearray(108);a[:8]=b'IUSB    ';struct.pack_into('<I',a,12,76);a[41]=0xf1;a[62]=1
    r=bytearray(a);r[41]=0;return bytes(a),bytes(r)
a,r=pair();result=respond_once(a,r,authenticated=True,consumed=False)
assert result.response==responses['legacy_TUR_zero_seed']['frame']
assert result.consumed and not result.opens_or_touches_image and not result.permits_other_legacy_frames
assert result.response[61:]==b'\0'*32 and result.response[32:61]==b'\0'*29
assert len(result.response)==93 and struct.unpack_from('<I',result.response,12)[0]==61
assert a==pair()[0] and r==pair()[1]
ak=bytearray(a);rk=bytearray(r)
for b in [ak,rk]:b[11]=0x5a;b[28:32]=bytes([0x11,0x22,0x33,0x44])
keyed_result=respond_once(bytes(ak),bytes(rk),authenticated=True,consumed=False)
assert len(keyed_result.response)==keyed[0] and hashlib.sha256(keyed_result.response).hexdigest()==keyed[1]
assert keyed_result.response[28:32]==bytes(ak[28:32]) and keyed_result.response[61:]==b'\0'*32
rejects=0
def reject(auth,request,**state):
    global rejects
    try:respond_once(auth,request,authenticated=state.get('authenticated',True),consumed=state.get('consumed',False))
    except LegacyTurReject:rejects+=1;return
    raise AssertionError('unexpected acceptance')
for side in (0,1):
    for pos in range(108):
        for bit in range(8):
            frames=[bytearray(a),bytearray(r)];frames[side][pos]^=1<<bit
            reject(bytes(frames[0]),bytes(frames[1]))
for state in [dict(authenticated=False),dict(authenticated=1),dict(authenticated=None),dict(consumed=True),dict(consumed=0),dict(consumed=None)]:reject(a,r,**state)
for n in [0,32,61,62,107,109,131134]:reject((a+b'\0'*131134)[:n],(r+b'\0'*131134)[:n])
reject(bytearray(a),r);reject(a,bytearray(r))
for off in [8,9,10,16,17,18,19,20,21,22,23,24,25,26,27]:
    aa,rr=bytearray(a),bytearray(r);aa[off]=rr[off]=1;reject(bytes(aa),bytes(rr))
reject(a,r,consumed=result.consumed)
try:result.consumed=False
except dataclasses.FrozenInstanceError:pass
else:raise AssertionError('mutable result')
for p,h in before.items():assert sha(Path(p))==h

obs=ROOT/'analysis/aitweaker_lock/lock_sage_1904/remote_172_20_2_162/hdmedia-ordinary-observation-1793683389185.json'
observed=json.loads(obs.read_text(encoding='utf-8'))['result']
assert not observed['image_opened'] and not observed['disk_commands_handled'] and observed['owned_socket_closed']
ordinary=observed['ordinary'];assert ordinary['bytes']==108 and ordinary['payload_length']==76 and ordinary['opcode']=='00'
assert ordinary['trailing_matches_auth'] and ordinary['declared_data_length']==ordinary['requested_read_length']==ordinary['scsi_status']==ordinary['request_sequence']==0
assert ordinary['cdb']=='0'*24
classes={}
with zipfile.ZipFile(jar) as z:
    for n in ['com/ami/kvm/imageredir/IUSBHeader.class','com/ami/iusb/protocol/IUSBSCSI.class','com/ami/iusb/protocol/HarddiskProtocol.class','com/ami/iusb/protocol/PacketMaster.class','com/ami/iusb/HarddiskRedir.class']:
        classes[n]=hashlib.sha256(z.read(n)).hexdigest()
pe=pefile.PE(str(dll));function_bytes=[]
for entry in [0x15a0,0x31b0,0x3470,0x34e0,0x38a0]:
    ranges=[(e.struct.BeginAddress,e.struct.EndAddress) for e in pe.DIRECTORY_ENTRY_EXCEPTION if e.struct.BeginAddress<=entry<e.struct.EndAddress or (entry==0x38a0 and 0x38a0<e.struct.BeginAddress<0x3f81)]
    kind='PE_RUNTIME_FUNCTION_unwind_ranges_not_assumed_source_function_extent'
    if not ranges:ranges=[(entry,0x3270)];kind='fixed_leaf_code_review_span_to_next_known_entry_not_unwind_boundary'
    for start,end in ranges:
        data=pe.get_data(start,end-start)
        function_bytes.append(dict(entry_RVA=hex(entry),review_start_RVA=hex(start),review_end_RVA_exclusive=hex(end),boundary_kind=kind,bytes=len(data),sha256=hashlib.sha256(data).hexdigest()))
report=dict(status='OFFLINE_BOUNDARY_AND_SINGLE_TUR_PROPOSAL_VERIFIED_SERVER_ACCEPTANCE_UNKNOWN',
 created_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
 inputs=dict(JViewer=evidence(jar),DLL=evidence(dll),classes_sha256=classes,native_function_byte_ranges=function_bytes,parent_metadata_observation=evidence(obs)),
 observed=dict(scope='Read only of parent-owned capture; this task did not connect to BMC.',ordinary=ordinary,auth_status='Parent reports verified F1 status1; no credentials or raw session-key values copied into this report.'),
 framing=[
  dict(source='PacketMaster.receivePacket(boolean)',bytecode='83..227',finding='Read exactly32 header bytes, then little-endian uint32 DataPacketLen at absolute12; read that many further bytes. Incoming headerLen byte10 does not reposition payload.'),
  dict(source='IUSBHeader.read',bytecode='0..232',finding='Only8-byte IUSB signature compared; major/minor/headerLen/deviceType/protocol/direction/instance are decoded, without fixed-value validation.'),
  dict(source='HarddiskProtocol.getPacket',bytecode='0..35',finding='Header read then IUSBSCSI(header) then readData on remaining buffer. Underflow returns null.'),
  dict(source='IUSBSCSI.readData',bytecode='0..180',finding='Allocates header DataPacketLen bytes; payload9=absolute41 opcode, payload13=absolute45 Lba byte. For F1 only, payload30=absolute62 status, payload31..75=absolute63..107 other-IP. Ordinary opcode ignores that trailing special layout.'),
  dict(source='No generic76-byte padding rule',finding='Real Java oracle accepts ordinary TUR payload29,30,76,77;76 is the observed F1-sized buffer, not a proved universal SCSI request size or an allowed amount of arbitrary write padding.'),
 ],
 packet_fields=[dict(offset=0,length=32,name='physical IUSB header'),dict(offset=12,length=4,name='little-endian IUSB payload byte count'),dict(offset=24,length=4,name='request sequence'),dict(offset=28,length=4,name='session header key; kept opaque, not reported'),dict(offset=32,length=8,name='requested-read-length area; zero in parent observation, not used by tested native TUR'),dict(offset=40,length=1,name='SCSI direction byte; zero observed'),dict(offset=41,length=12,name='CDB; all zero for observed TUR'),dict(offset=53,length=4,name='native status/sense tuple, little-endian'),dict(offset=57,length=4,name='SCSI data length, little-endian'),dict(offset=61,length='variable',name='SCSI data start; this observed47-byte tail matches earlier F1 tail and is not disk payload')],
 classification=dict(proven='Opcode00 enters image dispatch readiness path0x38a0 ->0x34e0 ->0x3470. It uses synthetic GetFileSizeEx in replay; no ReadFile or WriteFile occurs. Explicit vendor keepalive constant in IUSBSCSI isF3.',
                     inference='The parent observation is consistent with a readiness query constructed from the earlier F1-sized buffer; identical trailing status1/zeroIP supports retained padding. Its origin and timing purpose cannot be proven from one metadata observation.',
                     not_proven=['That00 is a heartbeat','That all ordinary frames use zero headers or108 bytes','That any response is accepted by BMC','That a successful TUR establishes persistence or readiness of actual media']),
 response_boundary=dict(native='Copies first62 bytes, preserves first32 header, sets native status@53 and transfer bytes@57; JNI returns61+data.',java='preBuffered constructor sets dataLen=limit-headerLen. With headerLen0 and native limit61, final writePacket uses93 bytes and IUSB payload61; with headerLen32 it uses61 bytes and payload29.',
   oracle='Confirmed exact real Java responses: legacy TUR93, canonical TUR61, legacy capacity response101. Nonzero retained seed leaks31 bytes after native byte61 in TUR; this proposal zeroes the entire32-byte response padding.',
   proposal='Do not normalize request header to32 or feed it into ordinary parser. Pure respond_once returns a fresh93-byte legacy reply matching Java zero-initialized output, with status0/dataLen0, direction80 and checksum algorithm matching actual Java. Original session header key remains only at28..31.',
   difference_from_uninitialized_stock='Padding is deterministically zero instead of old output-buffer contents. Native command data/status/header semantics and final lengths are preserved; server acceptance of this deterministic padding is not yet observed.'),
 suggested_policy=dict(action='Respond once through separately reviewed parent adapter, rather than silently swallow, if the exact predicate matches and parent elects to exercise it.',reason='HarddiskRedir.run bytecode17..228 receives each ordinary packet, executes native dispatch, and sends a reply. No opcode00 swallow branch exists.',
   predicate='Same authenticated owned session; unused first-TUR window; exact108 bytes/header payload76; equal32-byte auth/request headers; legacy fields/instance/seq0; request differs from verified F1 only at opcodeF1->00; body32..61 all0; byte62=1;63..107 all0.',
   mutation_scope='No image/backend is opened; no read/write/flush callback; returning this control response grants no other legacy acceptance. Mark consumed before sending; a second or changed legacy frame still rejects.',
   missing_observation='Capture current raw equality/predicate outcomes without reporting key/cookie/token values. Existing parent metadata does not independently list checksum/serverCaps/deviceNo/interfaceNo/clientData/header-key equality; candidate gates them exactly and may refuse.'),
 pure_function=dict(file=evidence(HERE/'legacy_tur_once.py'),positive_Java_byte_oracles=2,single_bit_rejection_cases=1728,total_rejections=rejects,immutable_consumed_state=True,caller_must_commit_consumed_state=True,zero_response_tail=True,opaque_header_key_retained=True,real_secret_values_used=False),
 verification=dict(Java_parser_cases=len(parses),Java_response_cases=len(responses)+1,native_cases=len(native['cases']),class_and_native_load_logs='No HarddiskRedir/PacketMaster/GUI classes or native harddisk DLL loaded; actual DLL bytes executed only inside Unicorn.',existing_client_inputs_unchanged=before),
 limitations=['No BMC/network/physical media access in this task.','No generic legacy data-frame, READ or WRITE parser change is proposed.','The pure function relies on parent-owned authenticated state and one-shot state commitment; it is not an authentication implementation.','Dropping this control request could stall an outstanding request; replying may cause later enumeration, so session lifecycle and later-frame rejection remain owned by parent.'])
save(HERE/'legacy_frames_review.json',report)
files=[p for p in HERE.iterdir() if p.is_file() and p.name!='manifest.json']
manifest=dict(status=report['status'],artifacts=[evidence(p) for p in sorted(files,key=str)],immutable_input_sha256=before)
save(HERE/'manifest.json',manifest)
print(json.dumps(dict(status=report['status'],Java_parser_cases=len(parses),Java_response_cases=len(responses)+1,native_cases=len(native['cases']),pure_function_rejections=rejects,review_sha256=sha(HERE/'legacy_frames_review.json'),manifest_sha256=sha(HERE/'manifest.json'),function_sha256=sha(HERE/'legacy_tur_once.py')),indent=2))
