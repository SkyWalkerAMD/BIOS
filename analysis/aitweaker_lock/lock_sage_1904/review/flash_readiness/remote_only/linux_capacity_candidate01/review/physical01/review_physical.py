"""Independent decode and bounded offline helper/geometry comparison only.

Does not import/run live helpers, contact BMC, change frozen artifacts, or open
any device/image backend. Synthetic pure frames have no real auth/token bytes.
"""
from pathlib import Path
import ast,datetime,hashlib,importlib.util,json,re,struct,sys,zlib
HERE=Path(__file__).resolve().parent;LC=HERE.parents[1];REMOTE=LC.parent;SAGE=REMOTE.parents[2];ROOT=next(p for p in LC.parents if (p/'tools/pydeps').is_dir());HW=SAGE/'remote_172_20_2_162';HD=REMOTE/'media_writeback_client01'
sha=lambda p:hashlib.sha256(Path(p).read_bytes()).hexdigest()
def load(name,path):
 spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec);sys.modules[name]=module;spec.loader.exec_module(module);return module
p3=load('lc_physical_p3',ROOT/'analysis/aitweaker_lock/probe_p3_kvm/decode_captures.py')
semantic=load('lc_physical_semantic',LC/'decode_linux_log.py')
capture=HW/'hardware-linux-capacity01-1793698923920';png=capture/'page-01.png';wire=p3.read_image(png);log,meta=p3.assemble([wire],require_inventory=False)
assert meta=={'pages':1,'bytes':633,'crc32':'FDE3FBC9','sha256':'fdd7431a595d46a6456f1059b3f012aea46423b0a7da59af756b47673dece345'}
assert wire==(capture/'page-01.frame').read_bytes() and log==(capture/'hardware-log.txt').read_bytes()
result=semantic.decode(log);parent=json.loads((capture/'manifest.json').read_text());assert result==parent['semantic']
assert result['status']=='CAPACITY_OBSERVED' and result['checks']=='1FF' and result['modules']==8 and result['userspace_rc10_calls']==2 and result['target']=='1-13.2:1.0'
assert result['packets'][1]['data8']=='0004000000000400' and result['last_lba']==262144 and result['block_bytes']==1024
(HERE/'independently_restored.frame').write_bytes(wire);(HERE/'independently_restored.txt').write_bytes(log);(HERE/'semantic_result.json').write_text(json.dumps(result,indent=2),encoding='utf8')
helper_file=HD/'runs/20261103_093929/result.json';helper=json.loads(helper_file.read_text());assert helper['script_sha256']==sha(HD/'live_writeback03.py')
assert helper['authenticated'] and helper['socket_closed'] and helper['image_closed'] and helper['status']=='SESSION_ENDED_WITHOUT_PROTOCOL_ERROR'
assert helper['opcode_counts']=={'F1':1,'00':1,'1A':1,'25':1,'F3':12} and helper['frames']==16
assert all(helper[k]==0 for k in ['backend_read_calls','backend_write_calls','backend_flush_calls','backend_written_bytes','reserved_write_bytes'])
assert helper['final_image_bytes']==16777216 and helper['final_image_sha256']=='df7fa016a0f4be496d3d446db558e8de15f537aa9953faff20b4ae0c6132b4b6'
# Verify the exact four dependency hashes pinned by the deployed helper without
# importing that helper (which contains networking and image-opening code).
tree=ast.parse((HD/'live_writeback03.py').read_text());pinned=None
for node in ast.walk(tree):
 if isinstance(node,ast.Dict):
  try:value=ast.literal_eval(node)
  except (ValueError,TypeError):continue
  if isinstance(value,dict) and 'review_legacy_data/bounded_legacy.py' in value:pinned=value;break
assert pinned and len(pinned)==4
for name,digest in pinned.items():assert sha(HD/name)==digest
pure=load('lc_physical_bounded',HD/'review_legacy_data/bounded_legacy.py')
arm=load('lc_physical_existing_arm_replay',REMOTE/'media_attach_review02/replay_capacity.py')
frames=[]
for index,key in enumerate([b'\0'*4,b'\x11\x22\x33\x44']):
 auth=bytearray(108);auth[:8]=b'IUSB    ';struct.pack_into('<I',auth,12,76);auth[28:32]=key;auth[41]=0xf1;auth[62]=1
 session=pure.bind_session(bytes(auth),tls_verified=True,authenticated=True,image_sha256=pure.IMAGE_SHA256,image_bytes=pure.IMAGE_BYTES)
 request=bytearray(auth);request[41]=0x25;plan=pure.normalize_request(session,bytes(request));reply=pure.serialize_response(plan)
 assert plan.action=='control' and len(reply)==101 and reply[61:69]==bytes.fromhex('00007fff00000200') and reply[69:]==bytes(32)
 assert struct.unpack_from('<I',reply,12)[0]==69 and struct.unpack_from('<I',reply,57)[0]==8 and reply[10]==0 and struct.unpack_from('<I',reply,53)[0]==0
 replay=arm.run('current_pinned_helper_synthetic_key_'+str(index),reply,fragment=7)
 nbd=[c for c in replay['calls'] if c['call']=='nbd_init_boundary'];assert nbd==[{'call':'nbd_init_boundary','block_size':512,'block_size_high':0,'blocks':32768,'blocks_high':0,'readonly':0,'result':0}]
 assert replay['receive_return']==replay['process_return']==0 and replay['final_state']==1 and replay['remaining']==0
 # Keys are synthetic, but still do not publish the header key field.
 frames.append({'case':index,'synthetic_not_network_capture':True,'helper_component_sha256':sha(HD/'review_legacy_data/bounded_legacy.py'),'response_bytes':len(reply),'header_length_field':reply[10],'payload_length_field':struct.unpack_from('<I',reply,12)[0],'status':struct.unpack_from('<I',reply,53)[0],'declared_data_bytes':struct.unpack_from('<I',reply,57)[0],'capacity_payload_offset':61,'capacity_payload_hex':reply[61:69].hex(),'zero_tail_bytes':32,'actual_public_ARM_backend_replay':replay})
(HERE/'current_helper_capacity_replay.json').write_text(json.dumps({'status':'PASS','hardware_network_or_image_access':False,'cases':frames,'scope':'Actual pinned current pure helper serializer into existing public1.1.57 ARM receive/dispatch instructions; NBD/gadget boundaries are synthetic. Not captured on-wire bytes or running BMC code.'},indent=2),encoding='utf8')
oldcap=HW/'hardware-capacity02-1793693198416/hardware-log.txt';old=oldcap.read_text();section=re.search(r'HANDLE_BEGIN=0003\n(.*?)HANDLE_END=0003',old,re.S)[1];values=dict(line.split('=',1) for line in section.splitlines() if '=' in line)
assert values['USB_VID']=='046B' and values['USB_PID']=='FF31';dp=bytes.fromhex(values['DP_HEX']);offset=0;usb_ports=[];pci=[]
while offset<len(dp):
 typ,sub=dp[offset:offset+2];n=struct.unpack_from('<H',dp,offset+2)[0];assert n>=4 and offset+n<=len(dp)
 if (typ,sub)==(3,5):assert n==6;usb_ports.append({'uefi_zero_based_port':dp[offset+4],'linux_one_based_port':dp[offset+4]+1,'interface':dp[offset+5]})
 if (typ,sub)==(1,1):assert n==6;pci.append({'device':dp[offset+5],'function':dp[offset+4]})
 offset+=n
assert [p['linux_one_based_port'] for p in usb_ports]==[13,2] and pci[-1]=={'device':20,'function':0}
assert int(values['MEDIA_BLOCK_BYTES'],16)==result['block_bytes'] and int(values['MEDIA_LAST_BLOCK'],16)==result['last_lba']
annotation=REMOTE/'continuation07/linux_poweroff_record_annotation.json';poweroff=HW/'inventory-poweroff-1793698968766.json';media_cleanup=HW/'media-cleanup-1793699048206.json';boot_cleanup=HW/'inventory-cleanup-1793699063889.json'
assert all(json.loads(media_cleanup.read_text())['verified'].values());assert all(json.loads(boot_cleanup.read_text())['verified'].values())
payload=json.loads((LC/'payload_manifest.json').read_text());assert all(sha(LC/r['path'])==r['sha256'] for r in payload['files'])
report={'status':'INDEPENDENT_PHYSICAL_PNG_AND_CAPACITY_RESULT_CONFIRMED','utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'reviewer_actions':'Existing file reads, original PNG QR decode, pure helper frame generation, and existing ARM synthetic-memory replay only. No BMC/network/hardware action, image backend access or frozen/capture mutation.',
 'hardware_operator':'Parent performed the physical diagnostic and cleanup. This reviewer checked its saved evidence offline.',
 'transport':{**meta,'png_sha256':sha(png),'frame_bytes':len(wire),'frame_sha256':hashlib.sha256(wire).hexdigest(),'saved_frame_and_log_equal':True,'parent_semantics_equal':True},'semantic':result,
 'payload_binding':{'payload_manifest_sha256':sha(LC/'payload_manifest.json'),'all265_hashes_match':True,'production_initrd_sha256':payload['production_initramfs_sha256'],'decoder_sha256':sha(LC/'decode_linux_log.py'),'loader_media_manifest_sha256':sha(LC/'loader/candidate/media_manifest.json'),'limit':'QR reports runtime checks and results; it does not itself carry a full executable hash. Separate parent deployment and fixed loader contract establish artifact selection.'},
 'helper_binding':{'result_path':str(helper_file.relative_to(ROOT)),'result_sha256':sha(helper_file),'started_utc':helper['started_utc'],'finished_utc':helper['finished_utc'],'script_sha256':helper['script_sha256'],'dependencies_verified':pinned,'frame_count':helper['frames'],'opcode_counts':helper['opcode_counts'],'backend_read_calls':0,'backend_write_calls':0,'backend_flush_calls':0,'final_image_bytes':helper['final_image_bytes'],'final_image_sha256':helper['final_image_sha256'],'socket_and_image_closed':True},
 'three_different_observations':{'linux_probe':'Two explicit SG_IO RC10 operations: first exact current UNIT ATTENTION06/29/00 with untouched8byte data; the sole permitted repeat succeeds with8actual response bytes0004000000000400.','client_frontend':'One opcode25 control request in the entire HD helper session, alongside startup00/1A and keepalives. Its count is NOT the count of Linux/USB host RC10 operations.','image_backend':'Zero image read/write/flush operations. READ CAPACITY is not proof of reading even one disk data block or a successful writeback path.'},
 'geometry_comparison':{'expected_fixed_image':{'bytes':16777216,'block_bytes':512,'last_lba':32767,'rc10_hex':'00007fff00000200'},'observed_physical_device':{'block_bytes':1024,'last_lba':262144,'rc10_hex':'0004000000000400','implied_bytes':268436480,'description':'256MiB plus1024bytes'},'previous_uefi_cache_same_values':True,'uefi_device_path_hex':values['DP_HEX'],'pci_nodes':pci,'usb_port_mapping':usb_ports,'linux_target':'1-13.2:1.0','path_conclusion':'The same controller and hub-port sequence is consistent across UEFI and Linux; USB bus-number allocation is OS-specific.'},
 'narrowed_conclusion':['A successful fresh Linux-owned RC10 repeats the previous UEFI BlockIO geometry. A purely OEM UEFI cached-field or fallback explanation is therefore insufficient for the new result.','Mismatch exists at the device-facing USB/SCSI capacity boundary on this run. FAT formatting and WB geometry filtering are downstream and cannot explain those8capacity bytes.','The current pinned helper pure serializer still emits expected512/32768 geometry; feeding that exact synthetic response into the already-reviewed public ARM backend still reaches NBD boundary512/32768. No precise helper framing/byte-order misparse is identified by this bounded review.','The running BMC can answer host RC10 from local gadget/backing metadata without a new frontend opcode25. Aggregate counts and original gadget implementation are consistent with this, but no live BMC state trace proves which backing object or capacity-setting step differed.'],
 'existing_code_evidence':{'Java_native':'Prior original Windows JNI/native and shared-buffer Java execution show16MiB capacity00007fff00000200 and legacy101B headerLen0 reply. See media_attach_review02/attach_review.json and shared_buffer_oracle.jsonl.','backend_public_image':'hdserverapp receive0x17054 and capacity dispatch0x12e68 read physicalpayload61/65 BE, then last+1,blockSize. Current2synthetic replay cases agree.','NBD_public_image':'Existing libnbd replay shows intended NBD_SET_BLKSIZE512/NBD_SET_SIZE_BLOCKS32768, but return values are ignored; no live ioctl failure was observed.','gadget_public_image':'Existing original kernel fsg_lun_open/READ CAPACITY replay uses backing inode/queue geometry.1024is an NBD default clue; it does not by itself account for262145blocks.'},
 'unknowns':['No exact outgoing opcode25 response bytes were captured from this live socket; source/hash binding and pure replay establish generation logic, not server-side application acknowledgement.','Running BMC binaries/kernel have not been read back and matched to public1.1.57 artifacts.','Active NBD slot/sysfs size/logical_block_size, geometry ioctl return values and active gadgetLUN backing path remain unobserved.','No disk block read/write, filesystem writeback, full SPI backup or firmware deployment was established.'],
 'minimum_next_evidence':['Keep fixed16MiB/512 image and WB gates unchanged.','If further live observation is approved by the parent, record only public response metadata for the startup25 before send: total length,headerLen,payload/declaration lengths,status and bytes61..68; exclude auth/session key fields.','Prefer already available read-only backend diagnostics exposing NBD/gadget size and backing-slot state; no speculative format/geometry change or raw BOT operation follows from this report.'],
 'cleanup':{'poweroff_record_sha256':sha(poweroff),'media_cleanup_sha256':sha(media_cleanup),'boot_cleanup_sha256':sha(boot_cleanup),'annotation_sha256':sha(annotation),'host_off':True,'cd_detached':True,'owned_helper_reaped':True,'HD_CD_idle':True,'temporary_boot_settings_restored':True,'correction':'The generic poweroff record says no OS running; retained annotation correctly states that the reviewed RAM-only Linux PID1 was running, while installed Rocky Linux was not.'},
 'preserved_guards':['No increase of image size or write budget.','No acceptance of1024/262144 by WB.','No change to frozen frontend/BMC/BIOS binaries or payload265.']}
inputs=[capture/'manifest.json',png,capture/'page-01.frame',capture/'hardware-log.txt',helper_file,HD/'live_writeback03.py',*[HD/n for n in pinned],oldcap,poweroff,media_cleanup,boot_cleanup,annotation,LC/'payload_manifest.json',LC/'loader/candidate/media_manifest.json',REMOTE/'media_attach_review02/attach_review.json',REMOTE/'media_attach_review02/shared_buffer_oracle.jsonl',REMOTE/'media_attach_review02/capacity_replay.json',REMOTE/'media_attach_review02/replay_capacity.py',REMOTE/'media_geometry_review03/geometry_review.json',REMOTE/'media_geometry_review03/nbd_client_replay.json',REMOTE/'media_geometry_review03/kernel_geometry_replay.json']
report['inputs']=[{'path':str(p.relative_to(ROOT)),'bytes':p.stat().st_size,'sha256':sha(p)} for p in inputs]
(HERE/'hardware_review.json').write_text(json.dumps(report,indent=2),encoding='utf8')
files=[p for p in HERE.rglob('*') if p.is_file() and p.name!='manifest.json'];manifest={'hardware_review_sha256':sha(HERE/'hardware_review.json'),'files':[{'path':p.relative_to(HERE).as_posix(),'bytes':p.stat().st_size,'sha256':sha(p)} for p in sorted(files)]};(HERE/'manifest.json').write_text(json.dumps(manifest,indent=2),encoding='utf8')
print(json.dumps({'status':report['status'],'review_sha256':sha(HERE/'hardware_review.json'),'manifest_sha256':sha(HERE/'manifest.json'),'transport':meta,'probe_rc10':2,'helper_startup_opcode25':1,'observed_geometry':[result['last_lba'],result['block_bytes']],'pure_helper_backend_replays':len(frames)},indent=2))
