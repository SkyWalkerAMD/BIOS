"""Bind the offline HDMEDIA engine, shipped Java evidence and adaptation gaps."""
from pathlib import Path
import datetime, hashlib, json, struct, zipfile
HERE=Path(__file__).resolve().parent
REMOTE=HERE.parent
OLD=REMOTE/'media_writeback_review'
CASE=REMOTE.parents[2]
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def ref(p):return {'path':str(p.resolve()),'bytes':p.stat().st_size,'sha256':sha(p)}
jar=OLD/'JViewer.jar'
assert sha(jar)=='32be6d97032587e1490d2f34ee04a98cd89875e7196936fb2fec5e0440bc3b98'

def constant_pool(b):
    count=struct.unpack_from('>H',b,8)[0];i=10;k=1;cp={}
    while k<count:
        t=b[i];i+=1
        if t==1:
            n=struct.unpack_from('>H',b,i)[0];i+=2;cp[k]=b[i:i+n].decode('utf8','replace');i+=n
        elif t in (3,4,9,10,11,12,17,18):i+=4
        elif t in (5,6):i+=8;k+=1
        elif t in (7,8,16,19,20):cp[k]={'tag':t,'index':struct.unpack_from('>H',b,i)[0]};i+=2
        elif t==15:i+=3
        else:raise ValueError('unsupported constant')
        k+=1
    return cp

classes={}
with zipfile.ZipFile(jar) as z:
    for name in ['com/ami/kvm/jviewer/gui/SinglePortKVM.class','com/ami/kvm/imageredir/IUSBHeader.class',
                 'com/ami/iusb/protocol/IUSBSCSI.class','com/ami/iusb/protocol/PacketMaster.class',
                 'com/ami/iusb/HarddiskRedir.class','com/ami/kvm/jviewer/videorecord/URLProcessor.class']:
        classes[name]=hashlib.sha256(z.read(name)).hexdigest()
    cp=constant_pool(z.read('com/ami/kvm/jviewer/gui/SinglePortKVM.class'))
    tunnel_constants={str(k):cp[cp[k]['index']] for k in (77,81,83,84,85,87)}
assert tunnel_constants=={'77':'\r\n\r\n','81':' ','83':'JVIEWER ','84':' cookie ','85':' HTTPS/1.1\r\n','87':'CONNECT'}
tests=json.loads((HERE/'offline_regression.json').read_text())
assert tests['source_sha256']==sha(HERE/'hdmedia_offline.py')
assert tests['verification_source_sha256']==sha(HERE/'verify_offline.py')
assert all(c['passed'] for c in tests['cases'])
live=CASE/'remote_172_20_2_162/browser-read-200.json'
live_obj=json.loads(live.read_text())
assert live_obj['path']=='/api/settings/media/instance' and live_obj['status']==200
baseline=OLD/'blank_test/baseline.json';base=json.loads(baseline.read_text())
image=Path(base['path']);assert sha(image)==base['sha256_before_test']
evidence=[]
for name in ['com.ami.kvm.jviewer.gui.SinglePortKVM.javap.txt','com.ami.iusb.HarddiskRedir.javap.txt',
             'com.ami.iusb.protocol.PacketMaster.javap.txt','com.ami.iusb.protocol.IUSBSCSI.javap.txt',
             'com.ami.kvm.imageredir.IUSBHeader.javap.txt','com.ami.kvm.jviewer.gui.StandAloneConnectionDialog.javap.txt']:
    evidence.append(ref(OLD/name))
evidence += [ref(HERE/'URLProcessor.javap.txt'),ref(OLD/'decoded/libs/media/iusb-scsi-packet.js')]
native=REMOTE/'jviewerhd_decompile'
for pattern in ['1800038a0-*.c','1800031b0-*.c','1800031a0-*.c','1800015a0-*.c']:
    evidence.append(ref(next(native.glob(pattern))))
artifacts=[ref(HERE/n) for n in ['hdmedia_offline.py','verify_offline.py','offline_regression.json','ProtocolOracle.java',
           'ProtocolOracle.class','synthetic_java_oracle.txt','synthetic_class_load.log','synthetic_library_load.log','URLProcessor.javap.txt']]
report={
 'status':'OFFLINE_PROTOCOL_ENGINE_TESTED_LIVE_TUNNEL_ADAPTER_AND_HD_ACCEPTANCE_NOT_ESTABLISHED',
 'created_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),
 'scope':'No device or BMC contact, login, media mount, power action, firmware access or update. Only local synthetic tests.',
 'inputs':{'official_JViewer':ref(jar),'class_sha256':classes,'parent_captured_media_settings':ref(live),
           'media_settings_observed_by_parent':live_obj['data'],'blank_image':ref(image),'baseline':ref(baseline)},
 'transport':{
   'mode':'SinglePortKVM service HDMEDIA, using parent-owned TLS to existing HTTPS endpoint; no dedicated-HD port guessing.',
   'exact_request_1_ascii':'CONNECT <host>:<secWebPort> HTTPS/1.1\r\n cookie <webSessionToken>\r\n\r\n',
   'exact_request_2_ascii':'JVIEWER HDMEDIA cookie <webSessionToken>\r\n\r\n',
   'ordering':'TLS socket is created first. Both request records are written/flushed sequentially before the Java code reads its tunnel reply.',
   'constant_pool_indices':tunnel_constants,
   'bytecode_methods':'SinglePortKVM.setHTTPConnect offsets58-146 selects TLS mode2; doTunnelHandshake offsets5-118 emits both records; FormHttpRequest offsets14-78 assembles request1.',
   'TLS_boundary':'Actual TLS certificate identity, timeout, raw socket and HTTP/custom tunnel reply framing must be owned by parent. This module imports neither socket nor ssl and contains no connector.',
   'negative_ports':'Observed hd_port=-1 and hd_secure_port=-2147483205 are never passed to a socket. The unsigned arithmetic of the latter is 0x800001BB, but this report does not assert undocumented flag semantics. SinglePortKVM uses its separately supplied web/tunnel ports.',
   'secure_channel_zero':'This field belongs to the media-settings response. It does not by itself determine the SinglePortKVM TLS constructor flag; the offline candidate explicitly models the existing HTTPS route.',
   'success_reply_unknown':'Stock Java ReadFromConnectedSock only rejects ERROR and relies on available() to bound the reply. No exact positive HDMEDIA response from the target is present. TunnelGate therefore rejects by default until parent supplies independently observed exact success bytes; test reply is labelled SYNTHETIC.',
   'no_auto_retry':True
 },
 'required_ephemeral_inputs':[
   {'name':'webSessionToken','source':'Parent-owned current authenticated web session, matching the Set-Cookie value before semicolon (normally QSESSIONID=<value>).','use':'CONNECT and JVIEWER HDMEDIA cookie fields only. URLProcessor.getValue trims the substring; SinglePortKVM does not add a cookie name itself.'},
   {'name':'KVM/media token','source':'Fresh /api/kvm/token result from the same authorized session, obtained by parent only.','use':'F2 authentication at offset63. This is not the web cookie, CSRF token or account password.'},
   {'name':'token_type','source':'Explicit selected JViewer token mode. Default web-backed type0 produces160-byte total frame; reviewed type1 produces272.','use':'Controls payload length128/240. Byte62 remains0 in the shipped SendAuth_SessionToken method for either type.'},
   {'name':'requested_HD_device','source':'Existing num_hd=1 settings; first requested device index0.','use':'Auth byte23=0; drive/client-data byte22=0x80 for USB image mode.'},
   {'name':'server_assigned_instance','source':'Authenticated F1 reply byte23.','use':'Pin every later request to that assigned instance, not an inferred global index.'},
   {'name':'exact_tunnel_success_reply','source':'Still missing; must be recorded/validated by parent before allowing the offline engine into AUTH_PENDING.'}
 ],
 'IUSB_layout':{
   'header_size':32,'signature_ascii':'IUSB    ','version':[1,0],'length_endian':'little',
   'offsets':{'8':'major','9':'minor','10':'header length32','11':'legacy checksum','12..15':'payload length',
              '16':'serverCaps','17':'deviceType5','18':'protocol1','19':'direction0 inbound/0x80 outbound candidate gate',
              '20':'deviceNo','21':'interfaceNo','22':'clientData/USB drive byte','23':'instance','24..27':'sequence','28..31':'key',
              '32..35':'requested read length','36..39':'tag','40':'data direction','41..52':'12-byte SCSI command',
              '53..56':'SCSI status/sense tuple','57..60':'SCSI data length little-endian','61..':'SCSI data'},
   'auth':'F2 at41, type-dependent total160/272, zero at62, token at63. Then F8 total322 with little-endian client type4 at62 and NUL-terminated filename at66 in a256-byte field.',
   'auth_acceptance':'Require F1 opcode and status1 at62; shipped parser also reads45-byte other-IP text starting63, so candidate requires108-byte reply. All other states/lengths reject before backend factory.',
   'checksum':'Actual Java IUSBHeader.write sums the entire current buffer limit including the prior checksum. PacketMaster clears limit to131134 capacity on final send. Candidate mirrors this retained-buffer algorithm; five real Java oracle outputs match exactly. It does not invent a standard checksum validation on receive; structural bounds and parent TLS are separate.',
   'native_response_evidence':'Native image executor RVA38A0 copies first62 request bytes, sets status via31B0 at53 and data length via31A0 at57; JNI15A0 returns data_length+61.'
 },
 'implementation':{
   'file':ref(HERE/'hdmedia_offline.py'),'executable_network_connector':False,
   'normal_order':['parent TLS+tunnel success','engine.start -> F2 thenF8','F1/status1 -> backend factory','bounded SCSI responses','parent stream close and engine.stop'],
   'supported_core_operations':['TEST UNIT READY','READ CAPACITY10 fixed32768x512','READ10','READ12','WRITE10','MODE SENSE6 minimal','SYNCHRONIZE CACHE10','no-op START/STOP/PREVENT','F4 legacy drive byte response'],
   'unsupported_policy':'Unknown/format/write12/vendor write requests yield illegal-request tuple and never touch the image. Session restart/reauth or malformed/out-of-range frames stop and close, without retry.',
   'image_boundary':'Only the literal pinned WRITEBACK02.img regular-file path; no configurable path, physical disk name, UNC, alternate stream, symlink/reparse path or multiply linked file. Verify fstat identity, size and baseline before any data operation; Windows exclusive range lock.',
   'io_boundary':'512-byte sectors; LBA+count bounded against32768 sectors before I/O; max256 sectors/request; exact payload count; lifetime1MiB write budget. Full write/flush/readback checked; any short/failed write terminates and never reports success.',
   'original_image_RW_constructor_tested':False,
   'original_image_unchanged':True,
   'serial_owner_requirement':'One parent-owned reader/dispatcher thread per engine; no concurrent handle() or file operations.'
 },
 'tests':{'report':ref(HERE/'offline_regression.json'),'case_count':tests['case_count'],
          'Java_oracle':'Executed only IUSBHeader/IUSBSCSI and their basic protocol parents/exceptions. JVM load logs show no HarddiskRedir/SinglePortKVM/JViewerApp/VMApp and no vendor native harddisk DLL.',
          'local_files':'Synthetic regular-file handle only for read/write/short-I/O/flush-error tests. Real WRITEBACK02.img read-only identity/hash verified unchanged.'},
 'evidence':evidence,'artifacts':artifacts,
 'remaining_before_claiming_real_writeback':[
   'Parent validates exact TLS/tunnel success bytes without new authentication sessions, blind retries or BMC configuration changes.',
   'Parent provides current web-cookie token and distinct media token only in memory; no command line/log persistence.',
   'Observe/authenticate actual F1 reply and verify strict length, device/protocol/direction/instance assumptions; unsupported values stop instead of broadening automatically.',
   'Review and exercise literal-image exclusive-open integration; no automatic use of native physical-drive APIs.',
   'UEFI identifies exact label+IDENTIFY.TXT marker, writes only the agreed <=4096-byte WRBACK.TXT payload, flushes and closes.',
   'After disconnect, reopen image read-only and verify exact payload hash, unchanged marker/size and filesystem health. SCSI status alone is insufficient.'
 ],
 'not_established':['Live HDMEDIA connection or authenticated media mount','Real UEFI writeback','Full SPI backup','Recoverability or flash acceptance'],
 'review_script':ref(Path(__file__))
}
dest=HERE/'client_review.json';dest.write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
print(json.dumps({'status':report['status'],'path':str(dest),'sha256':sha(dest),'tests':tests['case_count']}))
