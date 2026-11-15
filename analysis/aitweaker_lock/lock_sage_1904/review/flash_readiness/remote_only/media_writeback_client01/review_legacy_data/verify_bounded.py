"""Pure framing regressions, actual Java serialization and native dispatch.
No socket, real image backend, device or BMC access occurs in this script.
"""
from pathlib import Path
import ast,dataclasses,hashlib,json,struct,subprocess,sys
from bounded_legacy import *
HERE=Path(__file__).resolve().parent;CLIENT=HERE.parent;REF=CLIENT.parent/'media_writeback_review';JAVA=Path('D:/JAVA/jdk-27/bin')
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
def save(p,v):p.write_text(json.dumps(v,indent=2)+'\n',encoding='utf-8')
inputs=[CLIENT/'hdmedia_offline.py',CLIENT/'client_review.json',CLIENT/'review_legacy_frames/legacy_tur_once.py',REF/'JViewer.jar',REF/'javaharddiskwrapper-win64.dll']
before={str(p):sha(p) for p in inputs}
assert before[str(REF/'JViewer.jar')]=='32be6d97032587e1490d2f34ee04a98cd89875e7196936fb2fec5e0440bc3b98'
subprocess.run([str(JAVA/'javac.exe'),'-cp',str(REF/'JViewer.jar'),'LegacyDataOracle.java'],cwd=HERE,check=True,capture_output=True)
cmd=[str(JAVA/'java.exe'),'-Xlog:class+load=info:file=java_class_load.log','-Xlog:library=info:file=java_library_load.log','-cp',str(HERE)+';'+str(REF/'JViewer.jar'),'LegacyDataOracle']
java=subprocess.run(cmd,cwd=HERE,check=True,capture_output=True,text=True,encoding='utf-8')
(HERE/'java_oracle.txt').write_text(java.stdout,encoding='utf-8');(HERE/'java_stderr.txt').write_text(java.stderr,encoding='utf-8')
oracles={};overflow=[]
for line in java.stdout.splitlines():
    bits=line.split('|')
    if bits[0]=='PASS':oracles[bits[1]]=(int(bits[2]),bits[3])
    elif bits[0]=='CAPACITY_REJECT':overflow.append(bits[1])
assert len(oracles)==16 and overflow==['read256_overflow','one_over_capacity']
assert 'NATIVE_PADDING_COPY|write1_ack|90' in java.stdout and 'NATIVE_PADDING_COPY|write256_ack|90' in java.stdout
assert oracles['exact_capacity_boundary'][0]==MAX_FRAME
classlog=(HERE/'java_class_load.log').read_text(encoding='utf-8')
for name in ['com.ami.iusb.HarddiskRedir','com.ami.iusb.protocol.PacketMaster','com.ami.kvm.jviewer.gui.JViewerApp','com.ami.vmedia.VMApp']:assert name not in classlog
assert 'javaharddiskwrapper' not in (HERE/'java_library_load.log').read_text().lower()
subprocess.run([sys.executable,'-B','-X','utf8','native_dispatch.py'],cwd=HERE,check=True,capture_output=True)
native=json.loads((HERE/'native_dispatch.json').read_text());assert len(native['cases'])==20
monitor=subprocess.run([str(JAVA/'javap.exe'),'-classpath',str(REF/'JViewer.jar'),'-c','-p','com.ami.iusb.vHarddiskMonitorThread'],check=True,capture_output=True,text=True,encoding='utf-8')
(HERE/'vHarddiskMonitorThread.javap.txt').write_text(monitor.stdout,encoding='utf-8')

def auth():
    b=bytearray(108);b[:8]=b'IUSB    ';b[11]=0x5a;struct.pack_into('<I',b,12,76)
    b[28:32]=b'\x11\x22\x33\x44';b[41]=0xf1;b[62]=1;return bytes(b)
def session():return bind_session(auth(),tls_verified=True,authenticated=True,image_sha256=IMAGE_SHA256,image_bytes=IMAGE_BYTES)
def pattern(n):return bytes((i^0x5a)&255 for i in range(n))
def request(op,count=0,alloc=0,lba=1,shape='auth-tail',opaque=0,requested=0):
    n=61+count*512 if op==0x2a else {'none':61,'single-zero':62,'auth-tail':108,'zero-tail':108}[shape]
    b=bytearray(n);b[:32]=auth()[:32];struct.pack_into('<I',b,12,n-32);struct.pack_into('<I',b,24,7);struct.pack_into('<Q',b,32,requested);b[40]=opaque;b[41]=op
    if op in (0x28,0x2a,0xa8):
        b[43:47]=lba.to_bytes(4,'big')
        if op==0xa8:b[47:51]=count.to_bytes(4,'big')
        else:b[48:50]=count.to_bytes(2,'big')
    if op==0x1a:b[45]=alloc
    if op==0x2a:struct.pack_into('<I',b,57,count*512);b[61:]=pattern(count*512)
    elif shape=='auth-tail':b[62]=1
    return bytes(b)
def mutate(b,offset,value,width=1):
    a=bytearray(b);a[offset:offset+width]=value.to_bytes(width,'little');return bytes(a)

positive=[];negative=[]
def accept(name,r,s=None,data=None,oracle=None):
    s=session() if s is None else s;p=normalize_request(s,r)
    if p.action=='read' and data is None:data=pattern(p.response_data_bytes)
    wire=serialize_response(p,data)
    assert p.next_session.commands==s.commands+1
    assert len(p.canonical)==61+len(p.write_data)
    assert p.canonical[8:11]==b'\1\0\x20' and p.canonical[17:20]==b'\5\1\0'
    if wire is not None:
        assert len(wire)<=MAX_FRAME and len(wire)==93+p.response_data_bytes
        assert wire[61+p.response_data_bytes:]==b'\0'*32 and wire[28:32]==r[28:32]
        assert wire[24:28]==r[24:28] and wire[32:53]==r[32:53]
        assert struct.unpack_from('<I',wire,57)[0]==p.declared_response_bytes
        if oracle:assert (len(wire),hashlib.sha256(wire).hexdigest())==oracles[oracle],name
    else:assert p.opcode==0xf7 and not p.next_session.active
    positive.append(dict(name=name,opcode=f'{p.opcode:02X}',action=p.action,request_bytes=len(r),response_bytes=len(wire) if wire is not None else None,write_reservation=p.next_session.reserved_write_bytes,padding=p.padding_kind,oracle=oracle))
    return p
def reject(name,fn):
    try:fn()
    except Reject:negative.append(name);return
    raise AssertionError('not rejected: '+name)
def refuse(name,r,s=None):reject(name,lambda:normalize_request(session() if s is None else s,r))

fixtures=[('tur',0,0,0),('mode_alloc0',0x1a,0,0),('mode_alloc255',0x1a,0,255),('capacity',0x25,0,0),('startstop',0x1b,0,0),('prevent',0x1e,0,0),('flush_serializer',0x35,0,0),('F3_native_unsupported',0xf3,0,0),('F4_USB_type',0xf4,0,0),('F6_reply_before_stop',0xf6,0,0),('read1',0x28,1,0),('read255',0x28,255,0),('read12_two_serializer',0xa8,2,0),('write1_ack',0x2a,1,0),('write256_ack',0x2a,256,0)]
for name,op,count,alloc in fixtures:accept(name,request(op,count,alloc),oracle=name)
accept('F7_no_response_and_stopped',request(0xf7))
for op in (0x00,0x1a,0x25,0x28,0xa8,0xf4):
    for shape in ('none','single-zero','auth-tail','zero-tail'):accept(f'shape_{op:02x}_{shape}',request(op,1 if op in (0x28,0xa8) else 0,shape=shape))
for value in range(256):
    p=accept('opaque_direction_'+str(value),request(0x28,1,opaque=value))
    assert p.action=='read' and p.count==1 and p.next_session.reserved_write_bytes==0
for op in (0x28,0x2a,0xa8):accept('last_block_'+str(op),request(op,1,lba=32767))
accept('read_expected_length_metadata',request(0x28,2,requested=1024))
accept('mode_allocation_metadata255',request(0x1a,alloc=255,requested=255))
for flag in (8,16,24):accept('bounded_WRITE10_flags_'+str(flag),mutate(request(0x2a,1),42,flag))
for op in range(256):
    if op not in OPCODES:refuse('unknown_opcode_'+str(op),request(op))
for op in (0x28,0x2a,0xa8):
    for count in (0,257):refuse('block_count_'+str(op)+'_'+str(count),request(op,count))
    for lba,count in [(32768,1),(32767,2),(0xffffffff,1)]:refuse('bounds_'+str(op)+'_'+str(lba),request(op,count,lba=lba))
    refuse('metadata_length_conflict_'+str(op),request(op,1,requested=513))
refuse('READ10_256_wire_overflow',request(0x28,256));refuse('READ12_256_wire_overflow',request(0xa8,256))
refuse('READ12_high16_truncation_bypass_blocked',request(0xa8,65536))
for shape in ('auth-tail','zero-tail'):
    b=request(0x28,1,shape=shape)
    for off in range(61,108):
        for bit in (1,128):
            changed=mutate(b,off,b[off]^bit)
            if off==62 and bit==1:accept('known_tail_transition_'+shape,changed)
            else:refuse(f'tail_{shape}_{off}_{bit}',changed)
for n in (0,31,60,63,107,109,MAX_FRAME+1):
    b=(request(0x28,1)+b'\0'*(MAX_FRAME+1))[:n]
    if n>=32:b=mutate(b,12,n-32,4)
    refuse('bad_wire_size_'+str(n),b)
for off,val in [(8,1),(9,1),(10,32),(16,1),(17,5),(18,1),(19,128),(20,1),(21,1),(22,1),(23,1),(28,0xee),(31,0xee)]:refuse('header_'+str(off),mutate(request(0x28,1),off,val))
refuse('nonzero_status',mutate(request(0x28,1),53,1))
refuse('bad_iusb_length',mutate(request(0x28,1),12,77,4))
refuse('read_declared_payload_nonzero',mutate(request(0x28,1),57,512,4))
for off,val in [(42,0x20),(47,1),(50,1),(51,1),(52,1)]:refuse('bad_READ10_CDB_'+str(off),mutate(request(0x28,1),off,val))
for off in (51,52):refuse('bad_READ12_CDB_'+str(off),mutate(request(0xa8,1),off,1))
for off,val in [(42,1),(43,0x40),(44,1),(46,1),(47,1)]:refuse('bad_MODE_CDB_'+str(off),mutate(request(0x1a),off,val))
for op in (0,0x25,0x35,0xf3,0xf4,0xf6,0xf7):refuse('control_CDB_'+str(op),mutate(request(op),42,1))
refuse('stop_power_condition',mutate(request(0x1b),45,0x10));refuse('prevent_bad_bits',mutate(request(0x1e),45,2))
write=request(0x2a,1)
for data in [write[:-1],write+b'\0',write+b'\0\1'+b'\0'*45,mutate(write,57,511,4),mutate(write,57,513,4)]:
    data=mutate(data,12,len(data)-32,4);refuse('write_exact_payload_'+str(len(negative)),data)
refuse('WRITE_disguised108_tail',mutate(request(0x28,1),41,0x2a))
for flag in (False,1,None):reject('unverified_TLS_'+str(flag),lambda flag=flag:bind_session(auth(),tls_verified=flag,authenticated=True,image_sha256=IMAGE_SHA256,image_bytes=IMAGE_BYTES))
reject('wrong_image_hash',lambda:bind_session(auth(),tls_verified=True,authenticated=True,image_sha256='0'*64,image_bytes=IMAGE_BYTES))
reject('wrong_image_size',lambda:bind_session(auth(),tls_verified=True,authenticated=True,image_sha256=IMAGE_SHA256,image_bytes=IMAGE_BYTES+512))
refuse('wrong_active_state',request(0),dataclasses.replace(session(),active=False))
refuse('command_bound',request(0),dataclasses.replace(session(),commands=MAX_COMMANDS))
refuse('negative_budget',request(0),dataclasses.replace(session(),reserved_write_bytes=-1))
refuse('bad_budget_type',request(0),dataclasses.replace(session(),reserved_write_bytes=True))
refuse('budget_over_cap',request(0),dataclasses.replace(session(),reserved_write_bytes=WRITE_BUDGET+1))
s=session()
for i in range(8):
    p=accept('budget_reserved_chunk_'+str(i),request(0x2a,256),s);s=p.next_session
assert s.reserved_write_bytes==WRITE_BUDGET
refuse('ninth_write_budget_rejected',request(0x2a,1),s)
for op in (0xf6,0xf7):
    p=normalize_request(session(),request(op));refuse('no_commands_after_session_stop_'+str(op),request(0),p.next_session)
rp=normalize_request(session(),request(0x28,1))
for data in (b'',pattern(511),pattern(513),bytearray(pattern(512))):reject('short_extra_mutable_read_'+str(len(negative)),lambda data=data:serialize_response(rp,data))
reject('failed_external_IO_not_success',lambda:serialize_response(rp,pattern(512),operation_succeeded=False))
reject('missing_read_data',lambda:serialize_response(rp))
reject('forged_plan',lambda:serialize_response(dataclasses.replace(rp,count=2),pattern(512)))
mode=normalize_request(session(),request(0x1a));reject('mode_zero_length_old_engine_bug',lambda:serialize_response(mode,b''))
wp=normalize_request(session(),write);reject('WRITE_ack_with_payload',lambda:serialize_response(wp,b'x'))
f4=normalize_request(session(),request(0xf4));wire=serialize_response(f4)
assert wire[61:62]==b'\x80' and wire[62:]==b'\0'*32
assert struct.unpack_from('<I',wire,53)[0]==0x200501 and struct.unpack_from('<I',wire,57)[0]==0 and len(wire)==94
assert not any(x in repr(rp) for x in ['11223344','IUSB','canonical=','request=','auth_header='])
for node in ast.walk(ast.parse((HERE/'bounded_legacy.py').read_text())):
    if isinstance(node,(ast.Import,ast.ImportFrom)):
        names=[node.module] if isinstance(node,ast.ImportFrom) else [a.name for a in node.names]
        assert all(n in ('dataclasses','struct') for n in names)
for p,h in before.items():assert sha(Path(p))==h
report=dict(status='PASS_PURE_LEGACY_ADAPTER_OFFLINE_ONLY',adapter_sha256=sha(HERE/'bounded_legacy.py'),test_sha256=sha(Path(__file__)),positive_cases=len(positive),negative_cases=len(negative),java_response_oracles=15,java_capacity_boundary_oracles=3,native_dispatch_cases=20,positive=positive,negative=negative,
            explicit_bounds=dict(image_bytes=IMAGE_BYTES,sector=SECTOR,read_sectors_max=255,write_sectors_max=256,total_write_reservation=WRITE_BUDGET,wire_capacity=MAX_FRAME),immutable_inputs_unchanged=before,
            limitations=['No live server or physical media acceptance.','Protocol metadata direction is opaque; opcode and bounded CDB alone select read/write. Nonzero direction is synthetic only.',
                         'Parent must commit next_session before external I/O, pin the actual literal image, and close on any parser/backend/serialization exception.',
                         'Native READ12 high16-bit truncation is intentionally not copied; adapter uses standard32-bit count and strict bound.',
                         'Native sync-cache is unsupported; adapter preserves explicitly successful backend flush semantics from the existing bounded engine.'])
save(HERE/'bounded_verification.json',report)
print(json.dumps({k:report[k] for k in ['status','adapter_sha256','positive_cases','negative_cases','java_response_oracles','java_capacity_boundary_oracles','native_dispatch_cases']},indent=2))
