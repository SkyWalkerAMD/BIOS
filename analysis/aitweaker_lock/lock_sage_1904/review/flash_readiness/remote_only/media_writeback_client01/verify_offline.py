"""Synthetic protocol/file tests only. Never calls PinnedImage() or a socket."""
from pathlib import Path
import ast, datetime, hashlib, json, os, struct, unittest.mock as mock
import hdmedia_offline as h

HERE = Path(__file__).resolve().parent
cases = []

def sha(p): return hashlib.sha256(p.read_bytes()).hexdigest()
def check(name, fn):
    fn(); cases.append({'name': name, 'passed': True})
def rejects(fn):
    try: fn()
    except (h.Reject, OSError): return
    raise AssertionError('expected refusal')
def assert_eq(a, b): assert a == b, (a, b)

def request(opcode, *, data=b'', lba=0, count=0, instance=0, extra_zero=True):
    body = bytearray(29)
    struct.pack_into('<I', body, 0, count*512)
    struct.pack_into('<I', body, 4, 0x12345678)
    body[8] = 0x80 if opcode in (0x28, 0xa8) else 0
    body[9] = opcode
    struct.pack_into('>I', body, 11, lba)
    if opcode == 0xa8: struct.pack_into('>I', body, 15, count)
    else: struct.pack_into('>H', body, 16, count)
    struct.pack_into('<I', body, 25, len(data))
    body += data
    if not data and extra_zero: body += b'\0'
    header = bytearray(32); header[:8] = b'IUSB    '
    header[8:11] = b'\x01\0\x20'; header[17:19] = b'\x05\x01'; header[23] = instance
    struct.pack_into('<I', header, 12, len(body))
    struct.pack_into('<I', header, 24, 7)
    frame = header+body; frame[11] = -sum(frame) & 255
    return bytes(frame)

def auth_reply(status=1, instance=0):
    frame = bytearray(request(0xf1, instance=instance))
    frame.extend(b'\0'*(108-len(frame))); frame[62] = status
    struct.pack_into('<I', frame, 12, len(frame)-32)
    return bytes(frame)

def active(image=None):
    image = image or h.MemoryImage(b'\0'*h.PINNED_SIZE)
    engine = h.IUSBEngine(lambda: image)
    gate = h.TunnelGate(b'SYNTHETIC_HD_SUCCESS\r\n\r\n'); gate.accept(b'SYNTHETIC_HD_SUCCESS\r\n\r\n')
    engine.start(gate, 'SYNTHETIC_TOKEN_ONLY_0123456789')
    engine.handle(auth_reply())
    return engine, image

def java_comparison():
    oracle = dict(line.strip().split('=',1) for line in (HERE/'synthetic_java_oracle.txt').read_text().splitlines())
    for t in (0,1):
        generated = h.VendorWriter().auth('SYNTHETIC_TOKEN_ONLY_0123456789',t)
        assert generated.hex() == oracle[f'auth{t}']
    assert h.VendorWriter().media_info().hex() == oracle['media_fresh']
    retained=h.VendorWriter();retained.auth('SYNTHETIC_TOKEN_ONLY_0123456789')
    assert retained.media_info().hex() == oracle['media_after_auth0']
    # Reproduce exactly the synthetic Java setup then IUSBSCSI final send.
    w=h.VendorWriter(); w.header_write(541,573); w.buffer[19]=0; w.buffer[23]=0
    struct.pack_into('<I',w.buffer,24,7); w.buffer[41]=0x28
    struct.pack_into('<I',w.buffer,53,0); struct.pack_into('<I',w.buffer,57,512)
    w.buffer[61:573]=bytes(i^0xa5 for i in range(256))*2
    assert w.finalize(573).hex() == oracle['read_response']

check('official_Java_header_packet_oracle_auth0_auth1_media_and_response_exact',java_comparison)
def tunnel_frames():
    a,b=h.single_port_requests('192.0.2.1','SYNTHETIC_COOKIE')
    assert a==b'CONNECT 192.0.2.1:443 HTTPS/1.1\r\n cookie SYNTHETIC_COOKIE\r\n\r\n'
    assert b==b'JVIEWER HDMEDIA cookie SYNTHETIC_COOKIE\r\n\r\n'
check('exact_two_single_port_TLS_plaintext_records',tunnel_frames)
for name,fn in [
 ('unknown_tunnel_success_not_accepted',lambda:h.TunnelGate().accept(b'OK')),
 ('tunnel_ERROR_not_accepted',lambda:h.TunnelGate(b'ERROR\r\n').accept(b'ERROR\r\n')),
 ('CRLF_cookie_rejected',lambda:h.single_port_requests('192.0.2.1','a\r\nb')),
 ('CRLF_host_rejected',lambda:h.single_port_requests('192.0.2.1\r\n','abc')),
 ('negative_HD_port_never_used',lambda:h.single_port_requests('192.0.2.1','abc',-2147483205)),
 ('different_service_not_configurable',lambda:h.single_port_requests('192.0.2.1','abc',5123)),
]: check(name,lambda fn=fn:rejects(fn))

def denied_auth(status):
    calls=[]; e=h.IUSBEngine(lambda:calls.append('opened'))
    gate=h.TunnelGate(b'SYNTHETIC_OK'); gate.accept(b'SYNTHETIC_OK')
    e.start(gate,'SYNTHETIC_TOKEN'); rejects(lambda:e.handle(auth_reply(status)))
    assert e.state=='STOPPED' and not calls
for status in (0,3,5,8,13,255): check(f'auth_status_{status}_no_backend_open',lambda s=status:denied_auth(s))
def before_auth():
    calls=[];e=h.IUSBEngine(lambda:calls.append('opened'))
    rejects(lambda:e.handle(request(0x2a,data=b'X'*512,count=1)))
    assert not calls and e.state=='STOPPED'
check('command_before_auth_never_opens_image',before_auth)
def auth_pending_write():
    calls=[];e=h.IUSBEngine(lambda:calls.append('opened'))
    gate=h.TunnelGate(b'SYNTHETIC_OK');gate.accept(b'SYNTHETIC_OK')
    e.start(gate,'SYNTHETIC_TOKEN')
    rejects(lambda:e.handle(request(0x2a,data=b'X'*512,count=1)))
    assert not calls and e.state=='STOPPED'
check('AUTH_PENDING_rejects_write_without_backend_open',auth_pending_write)
def broken_factory():
    def fail():raise OSError('synthetic')
    e=h.IUSBEngine(fail);g=h.TunnelGate(b'SYNTHETIC_OK');g.accept(b'SYNTHETIC_OK')
    e.start(g,'SYNTHETIC_TOKEN');rejects(lambda:e.handle(auth_reply()))
    assert e.state=='STOPPED'
check('image_open_error_leaves_session_stopped',broken_factory)
def wrong_auth_instance_changed():
    e,m=active();rejects(lambda:e.handle(request(0x28,count=1,instance=1)))
    assert m.closed and m.reads==m.writes==0
check('assigned_media_instance_pinned',wrong_auth_instance_changed)

payload=bytes(range(256))*2
def write_read_endpoints():
    e,m=active()
    for lba in (0,32767):
        response=e.handle(request(0x2a,data=payload,lba=lba,count=1))
        assert len(response)==61 and response[53:57]==b'\0'*4
        response=e.handle(request(0x28,lba=lba,count=1))
        assert response[61:]==payload and len(response)==573
        assert response[19]==0x80 and response[36:40]==struct.pack('<I',0x12345678)
        assert response[24:28]==struct.pack('<I',7)
    assert len(m.data)==h.PINNED_SIZE and m.written_bytes==1024
check('WRITE10_READ10_first_and_last_sector_exact',write_read_endpoints)
def read12():
    e,m=active();m.data[512:1024]=payload
    assert e.handle(request(0xa8,lba=1,count=1))[61:]==payload
check('READ12_big_endian_LBA_and_32bit_count',read12)
def zero_length():
    e,m=active();r=e.handle(request(0x2a,lba=32768,count=0,extra_zero=False))
    assert len(r)==61 and m.written_bytes==0
check('zero_length_command_stays_inside_image',zero_length)
for lba,count in [(32768,1),(32767,2),(0xffffffff,1),(0,257)]:
    def bad(lba=lba,count=count):
        e,m=active();rejects(lambda:e.handle(request(0x28,lba=lba,count=count)))
        assert m.closed and m.reads==m.writes==0
    check(f'reject_full_range_{lba}_{count}',bad)
for count in (-1,257,2**64):check(f'reject_count_{count}',lambda c=count:rejects(lambda:h.block_range(0,c)))
check('reject_negative_LBA',lambda:rejects(lambda:h.block_range(-1,1)))
def payload_mismatch():
    e,m=active();rejects(lambda:e.handle(request(0x2a,data=b'X'*511,count=1)))
    assert m.writes==0 and m.closed
check('WRITE10_exact_payload_required',payload_mismatch)
def budget():
    m=h.MemoryImage(b'\0'*h.PINNED_SIZE);data=b'X'*(256*512)
    for i in range(8):m.write(0,256,data)
    rejects(lambda:m.write(0,1,payload));assert m.written_bytes==h.MAX_WRITE_BUDGET
check('total_write_budget_one_MiB',budget)
def unsupported():
    for op in (4,0xaa,0x3b,0xff):
        e,m=active();r=e.handle(request(op));assert struct.unpack_from('<I',r,53)[0]==0x200501
        assert m.writes==m.reads==0
check('format_WRITE12_vendor_write_no_file_mutation',unsupported)
def capacity():
    e,m=active();r=e.handle(request(0x25));assert r[61:]==struct.pack('>II',32767,512)
check('fixed_16MiB_capacity',capacity)
def f4():
    e,m=active();r=e.handle(request(0xf4));assert len(r)==62 and r[-1]==0x80
    assert struct.unpack_from('<I',r,57)[0]==0 and m.writes==0
check('vendor_F4_drive_mode_response_without_disk_IO',f4)
for op in (0xf1,0xf2,0xf7):
    def stop(op=op):
        e,m=active();rejects(lambda:e.handle(request(op)));assert m.closed and e.state=='STOPPED'
    check(f'session_change_{op}_stops',stop)

frame=request(0x28,lba=1,count=1)
for chunk_size in (1,2,7,31,32,61):
    def fragmented(n=chunk_size):
        d=h.FrameDecoder();r=[]
        for i in range(0,len(frame),n):r+=d.feed(frame[i:i+n])
        assert r==[frame];d.eof()
    check(f'fragmented_frame_{chunk_size}_bytes',fragmented)
def coalesced():
    d=h.FrameDecoder();assert d.feed(frame+frame)==[frame,frame]
check('coalesced_frames_preserved',coalesced)
for length in (0,28,h.MAX_FRAME,0xffffffff):
    def invalid(length=length):
        d=h.FrameDecoder();b=bytearray(frame[:32]);struct.pack_into('<I',b,12,length)
        rejects(lambda:d.feed(bytes(b)));assert d.failed
    check(f'bound_before_allocation_{length}',invalid)
def truncated():
    d=h.FrameDecoder();d.feed(frame[:-1]);rejects(d.eof);assert d.failed
check('EOF_midframe_stops',truncated)
for off,value in [(0,0),(8,2),(9,1),(10,31),(17,1),(18,2),(19,0x80)]:
    def bad_header(off=off,value=value):
        e,m=active();b=bytearray(frame);b[off]=value
        rejects(lambda:e.handle(bytes(b)));assert m.closed and m.reads==m.writes==0
    check(f'wrong_header_{off}_stops_before_IO',bad_header)

def path_tests():
    for path in [Path('\\\\.\\PhysicalDrive0'),Path('\\\\?\\GLOBALROOT\\Device\\Harddisk0'),
                 Path('C:/Windows/System32/config/SYSTEM'),Path('WRITEBACK02.img'),HERE/'WRITEBACK02.img',
                 Path(str(h.PINNED_IMAGE)+':stream')]:
        rejects(lambda path=path:h.validate_literal_image_path(path))
check('all_non_literal_paths_rejected_before_open',path_tests)
def actual_identity_read_only():
    h.validate_literal_image_path(h.PINNED_IMAGE)
    assert sha(h.PINNED_IMAGE)==h.PINNED_SHA256
check('original_image_regular_identity_and_hash_read_only',actual_identity_read_only)

# Exercise low-level bounded writes only on a newly created local synthetic file.
# Do not invoke PinnedImage.__init__ (which is reserved for parent coordination).
fixture_dir=HERE/'synthetic_files';fixture_dir.mkdir(exist_ok=True)
fixture=fixture_dir/'WRITEBACK02.img'
def fake_owned_file():
    fixture.write_bytes(b'\0'*h.PINNED_SIZE)
    p=h.PinnedImage.__new__(h.PinnedImage);p.fd=os.open(fixture,os.O_RDWR|getattr(os,'O_BINARY',0))
    s=os.fstat(p.fd);p.identity=(s.st_dev,s.st_ino);p.closed=False;p.written_bytes=0;p.locked=False
    return p
def local_rw():
    p=fake_owned_file()
    try:p.write(32767,1,payload);assert p.read(32767,1)==payload;p.flush()
    finally:p.close()
    assert fixture.stat().st_size==h.PINNED_SIZE
check('synthetic_regular_file_flush_reopen_readback',local_rw)
def short_write():
    p=fake_owned_file();real=os.write;calls=[]
    def partial(fd,data):calls.append(len(data));return real(fd,data[:len(data)//2])
    with mock.patch.object(h.os,'write',partial):rejects(lambda:p.write(0,1,payload))
    assert p.closed and calls==[512]
check('short_file_write_closes_no_retry_no_success',short_write)
def fsync_error():
    p=fake_owned_file()
    with mock.patch.object(h.os,'fsync',side_effect=OSError('synthetic')):rejects(lambda:p.write(0,1,payload))
    assert p.closed
check('flush_error_closes_no_success',fsync_error)
def short_read():
    p=fake_owned_file()
    with mock.patch.object(h.os,'read',return_value=b'\0'*511):rejects(lambda:p.read(0,1))
    assert p.closed
check('short_file_read_closes',short_read)
def image_resize():
    p=fake_owned_file();os.ftruncate(p.fd,1)
    try:rejects(lambda:p.write(0,1,payload))
    finally:p.close()
check('unexpected_file_size_rejected',image_resize)
def backend_error_stops():
    class Broken(h.MemoryImage):
        def write(self,*args):self.writes+=1;raise OSError('synthetic')
    e,m=active(Broken(b'\0'*h.PINNED_SIZE))
    rejects(lambda:e.handle(request(0x2a,data=payload,count=1)))
    rejects(lambda:e.handle(request(0x2a,data=payload,count=1)))
    assert e.state=='STOPPED' and m.closed and m.writes==1
check('backend_failure_closes_and_prevents_command_retry',backend_error_stops)
def reviewed_java_only():
    loaded=(HERE/'synthetic_class_load.log').read_text()
    library=(HERE/'synthetic_library_load.log').read_text()
    assert 'com.ami.kvm.imageredir.IUSBHeader source:' in loaded
    assert 'com.ami.iusb.protocol.IUSBSCSI source:' in loaded
    for name in ('HarddiskRedir','JViewerApp','SinglePortKVM','VMApp'):
        assert name not in loaded
    assert 'javaharddisk' not in library.lower()
check('JVM_observed_packet_classes_only_no_vendor_native_library',reviewed_java_only)

tree=ast.parse((HERE/'hdmedia_offline.py').read_text())
imports=[]
for node in ast.walk(tree):
    if isinstance(node,ast.Import):imports.extend(n.name for n in node.names)
    elif isinstance(node,ast.ImportFrom):imports.append(node.module)
assert not any(n in ('socket','ssl','requests','urllib','subprocess','ctypes') for n in imports)
assert sha(h.PINNED_IMAGE)==h.PINNED_SHA256
report={'status':'PASS_OFFLINE_PROTOCOL_AND_BOUNDED_IMAGE_ONLY','created_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),
        'case_count':len(cases),'cases':cases,'source_sha256':sha(HERE/'hdmedia_offline.py'),
        'verification_source_sha256':sha(Path(__file__)),'java_oracle_source_sha256':sha(HERE/'ProtocolOracle.java'),
        'java_oracle_output_sha256':sha(HERE/'synthetic_java_oracle.txt'),
        'java_class_load_log_sha256':sha(HERE/'synthetic_class_load.log'),
        'java_library_load_log_sha256':sha(HERE/'synthetic_library_load.log'),
        'network_calls':0,'native_vendor_Dll_loads':0,'pinned_image_write_opens':0,'pinned_original_sha256_after':sha(h.PINNED_IMAGE),
        'real_image_unchanged':True,'real_HD_session_established':False,
        'file_backend_boundary':'Real file read/write/error methods used only with a synthetic fixture handle; literal live-image constructor/exclusive-lock integration not executed.',
        'limits':['Tunnel success response bytes are not established; no live transport adapter exists.',
                  'SCSI/instance/direction assumptions are derived from shipped client, not a live HD capture.',
                  'Only pure Java protocol classes executed; no GUI/HarddiskRedir/JNI wrapper loaded.',
                  'A 16MiB disposable writeback test does not provide a complete SPI backup or recovery path.']}
(HERE/'offline_regression.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
print(json.dumps({'status':report['status'],'case_count':len(cases),'report_sha256':sha(HERE/'offline_regression.json')}))
