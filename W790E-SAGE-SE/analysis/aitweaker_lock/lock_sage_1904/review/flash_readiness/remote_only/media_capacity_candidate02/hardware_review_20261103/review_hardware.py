"""Independent offline decode of all original CAP02 PNGs. No device/network IO.
The capture manifest, frozen candidate and production helper are read only.
"""
from pathlib import Path
import datetime,hashlib,json,re,sys,zlib
HERE=Path(__file__).resolve().parent;CAP=HERE.parent
ROOT=next(p for p in HERE.parents if (p/'tools/pydeps').is_dir())
HW=ROOT/'analysis/aitweaker_lock/lock_sage_1904/remote_172_20_2_162'
SHOT=HW/'hardware-capacity02-1793693198416'
HD=CAP.parent/'media_writeback_client01';RUN=HD/'runs/20261103_080418'
sys.path[:0]=[str(CAP),str(ROOT/'analysis/aitweaker_lock/probe_p3_kvm'),str(ROOT/'tools/kvm-pydeps')]
from decode_captures import read_image,parse_frame,assemble
from decode_capacity_log import parse
import zxingcpp
sha=lambda p:hashlib.sha256(Path(p).read_bytes()).hexdigest()
load=lambda p:json.loads(Path(p).read_text(encoding='utf8'))
save=lambda p,v:Path(p).write_text(json.dumps(v,indent=2,ensure_ascii=False)+'\n',encoding='utf8')
cap_manifest=load(CAP/'candidate_manifest.json');capture=load(SHOT/'manifest.json')
assert sha(CAP/'candidate_manifest.json')=='fc0a85597a2adca66f7572634208783e22ed1d2a589d64c5b7cbb2c6fe09fc3d'
assert all(sha(CAP/x['path'])==x['sha256'] for x in cap_manifest['artifacts'])
assert all(sha(SHOT/name)==digest for name,digest in capture['files'].items())
frozen_before={p:sha(p) for p in [CAP/'candidate_manifest.json',SHOT/'manifest.json',SHOT/'semantic_result.json',RUN/'result.json']}
frames=[];pages=[]
pngs=sorted(SHOT.glob('page-*.png'));assert len(pngs)==10
for index,png in enumerate(pngs,1):
    raw=read_image(png);frame=parse_frame(raw);saved=SHOT/f'page-{index:02}.frame'
    assert frame['page']==index and frame['pages']==10 and raw==saved.read_bytes()
    frames.append(raw);pages.append({'png':str(png.relative_to(ROOT)),'png_sha256':sha(png),
      'decoded_frame_bytes':len(raw),'decoded_frame_sha256':hashlib.sha256(raw).hexdigest(),
      'page':frame['page'],'pages':frame['pages'],'offset':frame['offset'],'payload_bytes':len(frame['data']),
      'payload_crc32':f'{zlib.crc32(frame["data"]):08X}','original_saved_frame_equal':True})
log,meta=assemble(frames,require_inventory=False)
assert meta=={'pages':10,'bytes':7439,'crc32':'4DA3D8A7','sha256':'bb3c60189de9809083831374494ddd4aea26250ee7ea48370eb52d09b020c70a'}
assert log==(SHOT/'hardware-log.txt').read_bytes()
semantic=parse(log);assert semantic==load(SHOT/'semantic_result.json')
assert semantic['complete'] and not semantic['overflow'] and not semantic['enumeration_uncertain']
assert semantic['reported']==semantic['union']==9 and semantic['target_count']==1 and semantic['command_count']==0
assert not semantic['rc10_valid_response'] and not semantic['rc10_success'] and semantic['blocked_reason']=='NO_STANDARD_SCSI_IO'
assert semantic['test_status']=='8000000000000003'
target=[x for x in semantic['handles'] if x.get('TARGET_ID_MATCH')=='1'];assert len(target)==1;target=target[0]
assert target['index']==3 and target['MEDIA_BLOCK_BYTES']=='00000400' and target['MEDIA_LAST_BLOCK']=='0000000000040000'
assert target['USB_VID']=='046B' and target['USB_PID']=='FF31' and target['SFS_PUBLISHED']=='0'
assert all(target[k]=='8000000000000003' for k in ['SCSI_IO_STATUS','EXT_SCSI_PASS_THRU_STATUS','ATA_PASS_THRU_STATUS'])
located={name:{'status':status,'count':int(count,16)} for name,status,count in re.findall(rb'^(LOCATE_[A-Z_]+)=([0-9A-F]{16})\r\nRETURNED_HANDLES=([0-9A-F]{4})\r\n',log,re.M)}
located={k.decode():{'status':v['status'].decode(),'count':v['count']} for k,v in located.items()}
assert located=={'LOCATE_USB_IO':{'status':'0000000000000000','count':8},'LOCATE_SCSI_IO':{'status':'800000000000000E','count':0},'LOCATE_EXT_SCSI_PASS_THRU':{'status':'0000000000000000','count':1},'LOCATE_ATA_PASS_THRU':{'status':'800000000000000E','count':0}}
ext=[x for x in semantic['handles'] if x.get('EXT_SCSI_PASS_THRU_STATUS')=='0000000000000000'];assert len(ext)==1 and ext[0]['index']==8
assert b'ASSOCIATION_HANDLE=0008\r\nASSOCIATION_KIND=0\r\n' in log
helper=load(RUN/'result.json')
assert helper['script_sha256']==sha(HD/'live_writeback03.py')
assert helper['status']=='SESSION_ENDED_WITHOUT_PROTOCOL_ERROR' and helper['end_reason']=='parent_stop'
assert helper['socket_closed'] and helper['image_closed'] and helper['authenticated'] and helper['image_opened']
assert helper['opcode_counts']=={'F1':1,'00':1,'1A':1,'25':1,'F3':26}
assert all(helper[k]==0 for k in ['backend_read_calls','backend_write_calls','backend_flush_calls','backend_written_bytes','reserved_write_bytes'])
pristine=CAP.parent/'media_writeback_review/blank_test/WRITEBACK02.img'
assert helper['final_image_bytes']==pristine.stat().st_size==16777216
assert helper['final_image_sha256']==sha(pristine)=='df7fa016a0f4be496d3d446db558e8de15f537aa9953faff20b4ae0c6132b4b6'
cleanup=load(HW/'inventory-cleanup-1793693626282.json');media=load(HW/'media-cleanup-1793693623095.json');logout=load(HW/'inventory-session-logout-1793693639431.json')
assert all(cleanup['verified'].values()) and all(media['verified'].values()) and logout['status']==200
assert media['hd_active_sessions']==media['cd_active_sessions']==128
assert cleanup['boot']['BootSourceOverrideEnabled']=='Disabled' and cleanup['boot']['BootSourceOverrideTarget']=='None'
inputs=[CAP/'candidate_manifest.json',CAP/'build/BOOTX64.EFI',CAP/'build/SAGE1904-MEDIA-CAPACITY02.iso',CAP/'decode_capacity_log.py',
  ROOT/'analysis/aitweaker_lock/probe_p3_kvm/decode_captures.py',Path(zxingcpp.__file__),SHOT/'manifest.json',SHOT/'hardware-log.txt',SHOT/'semantic_result.json',RUN/'result.json',HD/'live_writeback03.py',
  HD/'review_legacy_data/bounded_legacy.py',pristine,HW/'inventory-cleanup-1793693626282.json',HW/'media-cleanup-1793693623095.json',HW/'inventory-session-logout-1793693639431.json',
  CAP.parent/'media_oem_usb_review04/oem_geometry_review.json',CAP.parent/'media_oem_usb_review04/uhcd_decompile/0000995c-FUN_0000995c.c',
  CAP.parent/'media_geometry_review03/geometry_review.json',CAP.parent/'media_attach_review02/attach_review.json']
bound=[{'path':str(p.relative_to(ROOT)),'bytes':p.stat().st_size,'sha256':sha(p)} for p in inputs]
report={
 'status':'INDEPENDENT_ORIGINAL_PNG_DECODE_AND_HARDWARE_NEGATIVE_RESULT_CONFIRMED',
 'reviewed_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),
 'review_scope':'Offline read of existing PNGs, frozen parser, helper/cleanup records and previously extracted firmware evidence only; no BMC/network/host command, no source or capture modification.',
 'hardware_evidence_scope':'Parent performed the hardware run. This reviewer independently decoded the original PNG bytes and checked stored semantic, helper and cleanup records; it did not observe/control the machine live.',
 'transport':{**meta,'all_original_pngs_decoded':True,'all_page_crcs_valid':True,'whole_log_crc_valid':True,'matches_original_frames':True,'matches_saved_log':True,'matches_root_semantic_result':True,'pages':pages},
 'candidate_binding':{'frozen_manifest_sha256':sha(CAP/'candidate_manifest.json'),'frozen_artifacts_checked':len(cap_manifest['artifacts']),
  'all_frozen_artifact_hashes_unchanged':True,'efi_sha256':sha(CAP/'build/BOOTX64.EFI'),'iso_sha256':sha(CAP/'build/SAGE1904-MEDIA-CAPACITY02.iso'),
  'limitation':'The QR log identifies CAP02 behavior but does not embed a cryptographic self-hash. Stored candidate/ISO hashes are verified separately; linkage to which ISO the operator mounted also relies on the parent run records.'},
 'semantic':{'inventory_complete':True,'enumeration_uncertain':False,'handles':9,'unique_target_count':1,'target_handle':3,
  'target_vid_pid':'046B:FF31','target_interface_hex':target['USB_INTERFACE_HEX'],'target_device_path_hex':target['DP_HEX'],
  'media_present':True,'media_writable':True,'block_size':1024,'last_block':262144,'derived_capacity_bytes':(262144+1)*1024,'sfs_published':False,
  'target_scsi_io':False,'target_ext_scsi':False,'target_ata_passthru':False,'scsi_executable_owner_count':0,
  'command_count':0,'rc10_valid_response':False,'rc10_success':False,'reason':'NO_STANDARD_SCSI_IO','status_hex':'8000000000000003'},
 'important_scope_correction':{
  'finding':'Ext SCSI PassThru is NOT globally absent. One provider exists on handle8, but its path is unrelated to the target USB branch; no target-associated pass-through exists.',
  'global_locations':located,'ext_handle':8,'ext_device_path_hex':ext[0]['DP_HEX'],'association_kind':0,
  'path_comparison':'Ext provider is under PCI device0x17/function0; target USB path is under PCI device0x14/function0 then USB nodes. This is a different branch, not an ancestor. No target number/LUN or supported routing from it to the USB target is established.'},
 'helper_binding':{'result_path':str((RUN/'result.json').relative_to(ROOT)),'result_sha256':sha(RUN/'result.json'),
  'started_utc':helper['started_utc'],'finished_utc':helper['finished_utc'],'script_matches_result_hash':True,
  'status':helper['status'],'end_reason':helper['end_reason'],'opcode_counts':helper['opcode_counts'],'socket_closed':True,'image_closed':True,
  'backend_read_calls':0,'backend_write_calls':0,'backend_flush_calls':0,'backend_written_bytes':0,'reserved_write_bytes':0,
  'image_bytes':16777216,'final_and_current_image_sha256':sha(pristine),
  'separation':'The helper saw one opcode25 in its F1/00/1A/25 initialization/control exchange. CAP02 explicitly issued zero commands. The helper25 must never be counted as a probe-issued RC10 or proof of a fresh host-side capacity read.',
  'timestamp_limit':'The retained helper result aggregates opcodes and session start/end only; it has no per-frame timestamp. Initialization attribution is consistent with the previously reviewed BMC startup sequence and parent run chronology, not independently timestamped by this result.'},
 'cleanup_binding':{'scope':'Existing parent readback records only; no fresh request by this reviewer.',
  'verified_host_off':True,'verified_cd_detached':True,'verified_hd_cd_idle':True,'active_session_encoding':{'hd':128,'cd':128},
  'temporary_boot_settings_restored':True,'boot_order_and_boot_next_unchanged':True,'session_logout_http_status':200,
  'not_claimed':'No assertion that every BIOS NVRAM byte is unchanged.'},
 'remaining_uefi_capacity_paths':[
  {'path':'SCSI_IO ExecuteScsiCommand','assessment':'No published handle in this boot; cannot use CAP02 command path. Confirmed runtime negative.'},
  {'path':'Ext SCSI PassThru','assessment':'One global provider is present but on an unrelated PCI branch. No existing supported target association/routing is established; cannot direct this provider at the USB device.'},
  {'path':'ATA PassThru','assessment':'No published handle in this boot and no association to the USB target. Not an available route.'},
  {'path':'BlockIO media fields / SFS','assessment':'BlockIO fields are already read and repeat cached1024/262144. They are not an independent RC10 response. Target SFS is absent. Existing block-read/writeback geometry guards remain applicable; no block-data read was added.'},
  {'path':'EFI_DISK_INFO','assessment':'Prior original Uhcd publication installs DiskInfo alongside BlockIO. Its standardized inquiry/identify/sense/IDE-location methods are not a general SCSI command entry point or a documented independent USB capacity query. CAP02 did not enumerate DiskInfo at runtime; no fresh raw-capacity route has been established.'},
  {'path':'AMI private DXE/SMM dispatch','assessment':'Original firmware static/replay evidence contains capacity parsing/refresh via private internal functions. No stable, independently audited public transaction-ownership/dispatch contract has been established. Calling internal functions or inducing refresh/reset is not an already supported safe capacity path.'},
  {'path':'USB_IO raw BOT','assessment':'USB_IO exists, but direct BOT injection bypasses the bound storage driver. Explicitly excluded; no fallback implemented or suggested.'},
  {'path':'Legacy EFI_SCSI_PASS_THRU / other unenumerated private protocols','assessment':'CAP02 did not enumerate the old non-extended SCSI pass-through GUID or every OEM protocol. Their absence is not proved. Existing evidence does not establish their availability, target linkage or a supported query route; therefore no ready-to-use route can be claimed.'}
 ],
 'bounded_conclusion':'No already available and verified owner-preserving UEFI path for a fresh capacity command to this target remains in the present evidence. This is narrower than claiming every possible UEFI protocol is absent. The actual8-byte device capacity response is still unknown;1024/262144 remains cached BlockIO metadata.',
 'not_established':['A fresh CAP02 RC10 response','Physical USB-wire response bytes or CSW','Origin of the incorrect cached geometry','Successful filesystem writeback','Full SPI backup or firmware flash readiness'],
 'potential_followup':'If further work is chosen, the already proposed RAM-only Linux with automount/network disabled and its own USB storage driver could provide exclusive driver-owned SG_IO capacity observation. It remains a design option, not implemented or validated by this review.',
 'inputs':bound
}
(HERE/'independently_restored_log.txt').write_bytes(log)
save(CAP/'hardware_review.json',report)
assert all(sha(p)==digest for p,digest in frozen_before.items())
assert all(sha(SHOT/name)==digest for name,digest in capture['files'].items())
assert all(sha(CAP/x['path'])==x['sha256'] for x in cap_manifest['artifacts'])
save(HERE/'review_manifest.json',{'files':{p.relative_to(CAP).as_posix():sha(p) for p in [Path(__file__),HERE/'independently_restored_log.txt',CAP/'hardware_review.json']},'capture_manifest_unchanged':True,'candidate_manifest_unchanged':True})
print(json.dumps({'status':report['status'],'pages':len(pages),'bytes':meta['bytes'],'crc32':meta['crc32'],'sha256':meta['sha256'],'target_count':1,'probe_rc10_commands':0,'global_ext_scsi_providers':1,'target_associated_ext_scsi':0,'hardware_review_sha256':sha(CAP/'hardware_review.json'),'review_manifest_sha256':sha(HERE/'review_manifest.json')},indent=2))
