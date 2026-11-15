"""Bind offline attach-path observations without claiming hardware success."""
from pathlib import Path
from datetime import datetime,timezone
import hashlib,json
HERE=Path(__file__).resolve().parent;REMOTE=HERE.parent;SAGE=REMOTE.parents[2]
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def bind(p):return {'path':str(p.resolve()),'sha256':sha(p),'bytes':p.stat().st_size}
def main():
    old=REMOTE/'media_writeback_review'
    cap=json.loads((HERE/'capacity_replay.json').read_text());kvm=json.loads((HERE/'kvm_state_replay.json').read_text())
    assert cap['status']==kvm['status']=='PASS' and cap['case_count']==18 and len(kvm['cases'])==4
    oracle=[json.loads(s) for s in (HERE/'shared_buffer_oracle.jsonl').read_text(encoding='utf-8-sig').splitlines()]
    expected={'TUR_after_F8':(93,0),'MODE_after_TUR':(97,0),'CAPACITY_after_MODE':(101,0)}
    for name,pair in expected.items():
        x=next(r for r in oracle if r['name']==name);assert (x['wire_bytes'],x['header_len'])==pair
    assert next(r for r in oracle if r['name']=='KVM_MEDIA_1')['hex']=='1800000000000100'
    hardware=REMOTE/'media_writeback_client01/runs/20261103_055010/result.json'
    hwlog=SAGE/'remote_172_20_2_162/hardware-writeback01-1793685297057/hardware-log.txt'
    # Resolve through known review root rather than infer a different user's tree.
    if not hwlog.exists():
        hwlog=next(p for p in HERE.parents if p.name=='lock_sage_1904')/'remote_172_20_2_162/hardware-writeback01-1793685297057/hardware-log.txt'
    h=json.loads(hardware.read_text());assert h['opcode_counts']=={'F1':1,'00':1,'1A':1,'25':1,'F3':17}
    observations=[
      {'id':'java-order','classification':'verified_static','evidence':'HarddiskRedir.startRedirection bytecode39..69,358..374,753..765,1142..1179',
       'finding':'F2 token auth, then F8 media info, then recv F1. On success store instance, open image, then start run thread. No proactive F4/insert call in this method.'},
      {'id':'drive-type','classification':'verified_static','evidence':'IUSBRedirSession.startDeviceRedirection bytecode103..118; HarddiskRedir.SendAuth byte22/23',
       'finding':'Image branch uses drive type0x80; F2 places that byte at22 and requested device index at23. Server may allocate the final instance; observed instance0 is preserved by response headers.'},
      {'id':'F8-client','classification':'verified_static','evidence':'IUSBSCSI.getClientType bytecode0..10; SendMediaInfo bytecode198..205',
       'finding':'VMApp returns4; JViewer/KVM returns2. Existing client_type4 matches standalone virtual-media application and does not need the JViewer media-state notification.'},
      {'id':'kvm-notification','classification':'verified_static_and_local_ARM_replay','evidence':'KVMClient.MediaRedirectionState; adviser table0x3E2A4 slot15; ARM handler0x19754..0x1978C',
       'finding':'Non-VMApp start sends IVTP type24,size0,status1 only if KVM redirection is active; stop sends status0. Backend writes session+0x10C and, for1, resets KVM timer via0x21050. This handler performs no USB/NBD/media attach.',
       'official_start_hex':'1800000000000100','official_stop_hex':'1800000000000000','not_an_instruction_to_send':True},
      {'id':'retained-buffer','classification':'verified_local_Java_packet_execution_with_modeled_JNI_writes','evidence':'SharedBufferOracle.java/shared_buffer_oracle.jsonl plus prior original native dispatch evidence',
       'finding':'The same131134-byte direct buffer afterF2/F8 still yields headerLen0 and93/97/101-byte TUR/MODE/CAPACITY responses. No implicit headerLen32 normalization. Stock retained padding includes stale filename bytes; current zero-padding policy removes these while preserving capacity data.'},
      {'id':'receive-capacity','classification':'verified_static_and_local_ARM_replay','evidence':'hdserverapp0x17054 receiver,0x12E68 dispatch,capacity_replay.json18cases',
       'finding':'Receiver reads physical32-byte header then DataPacketLen@12. Capacity handler reads BE32 lastLBA@61 and blockSize@65. Both101-byte legacy and69-byte canonical fixtures reach identical NBD/gadget boundaries with512-byte blocks and32768blocks. Extra32-byte padding is not the cause of zero geometry in these functions.'},
      {'id':'attach-state','classification':'verified_static','evidence':'hdserverapp0x1506C F8 branch; worker0x14234; dispatch0x12E68; gadget start0x17DEC',
       'finding':'AcceptedF8 stores media metadata and starts state3(TUR),5(MODE),4(CAPACITY). Capacity calls nbd_init, then sets removable/read-only policy and starts hddisk gadget. No extra client F4/insert command is required by this path.'},
      {'id':'post-capacity-failure','classification':'verified_local_fault_fixture_and_static_inference','evidence':'capacity_replay nbd_failure/gadget_failure; libnbd nbd_init0x2AAC and nbd_client0x163C (ELF-relative)',
       'finding':'SyntheticNBD-init or gadget-start failures leave state0 with no active disk; main dispatcher ignores this routine return, while socket heartbeat processing remains separate. This can explain a live session with no data requests, but no such backend failure was observed directly on the BMC.'},
      {'id':'usb-identity','classification':'verified_static','evidence':'hdserverapp0x17840 literal pool;0x17DEC literal pool',
       'finding':'OriginalHD gadget config sets VID046B/PIDFF31, productVirtual HDisk Device, LUN cdrom=0. AfterNBD it writes the /dev/nbdN backing path and binds UDC1e6a0000.usb-vhub:p2. These literals provide a read-only inventory discriminator; they do not prove current runtime configuration.'},
      {'id':'actual-v3','classification':'observed_parent_hardware_evidence','evidence':str(hardware),
       'finding':'F1/00/1A/25 once plus17F3, no protocol error, no backend image reads/writes/flushes, pristine hash unchanged. WB01 safely refused due no exact filesystem match. CountsUSBIO8/BIO8/SFS3 alone do not identify individualUSBHD presence, media state or its binding.'},
    ]
    report={
      'status':'OFFLINE_ATTACH_PATH_REVIEW_COMPLETE_HARDWARE_HD_ATTACHMENT_UNRESOLVED',
      'utc':datetime.now(timezone.utc).isoformat(),'scope':'Local Java/native/BMC firmware review only. No network,BMC login,configuration,media mount,flash,raw device access or original artifact modification.',
      'observations':observations,
      'next_step':{'decision':'Build a separate read-only UEFI USB/BlockIO/SFS inventory, preserving all WB01 selection gates and existing HDv3 client.',
                   'reason':'Discriminate missing046B:FF31 versus presentUSB/noBlockIO versus media-not-present versus wronggeometry versus noSFS. Existing log omits those per-handle associations.',
                   'required_fields':['USB deviceVID/PID/class andinterface class/subclass/protocol','bounded fullDevicePath','per-handle USB_IO/BlockIO/SFS association','BlockIOmedia id/present/removable/readOnly/logical/cache/blockSize/lastBlock'],
                   'do_not_change':['F8clientType4','KVMcontrol notification','responseheaderLen/length solely to guess compatibility','16MiB/512/marker writeback contract'],
                   'if_device_absent':'With an authorized read-only backend diagnostic channel, inspect NBD and hddisk configfs binding plus service logs. No such channel established here; do not issue shell configuration writes or service restarts.'},
      'limits':['PublicBMC1.1.57 image backend was analyzed; deployed backend binary has not been read back.','ARM tests replaceNBD/kernel/configfs boundaries with synthetic fixtures; they do not prove physical attach.','Java oracle uses reviewed packet/header classes and bytecode-equivalent shared-buffer writes, not the full GUI/native socket process.','No checksum/status relaxation is proposed from the permissive original receiver.','Two2048-byte SFS entries are not attributed conclusively without device paths; no hardware file write pass is claimed.'],
      'validation':{'ARM_capacity_cases':18,'ARM_KVM_media_cases':4,'Java_shared_buffer_records':len(oracle)},
      'evidence':[bind(p) for p in [hardware,hwlog,old/'JViewer.jar',old/'javaharddiskwrapper-win64.dll',
           old/'com.ami.iusb.HarddiskRedir.javap.txt',old/'com.ami.iusb.IUSBRedirSession.javap.txt',old/'com.ami.iusb.protocol.IUSBSCSI.javap.txt',
           old/'com.ami.iusb.protocol.PacketMaster.javap.txt',HERE/'backend_manifest.json',HERE/'capacity_replay.json',HERE/'kvm_state_replay.json',
           HERE/'shared_buffer_oracle.jsonl',HERE/'adviser_command_table.json',HERE/'KVMClient.javap.txt',HERE/'IVTPPktHdr.javap.txt']]}
    (HERE/'attach_review.json').write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n',encoding='utf8')
    paths=[]
    for p in sorted(HERE.rglob('*')):
        if not p.is_file() or p.name=='manifest.json' or any(x.startswith('ghidra_') for x in p.relative_to(HERE).parts):continue
        paths.append(bind(p))
    (HERE/'manifest.json').write_text(json.dumps({'status':'FROZEN_OFFLINE_REVIEW','artifacts':paths},ensure_ascii=False,indent=2)+'\n',encoding='utf8')
    print(json.dumps({'report_sha256':sha(HERE/'attach_review.json'),'manifest_sha256':sha(HERE/'manifest.json'),'artifacts':len(paths)}))
if __name__=='__main__':main()
