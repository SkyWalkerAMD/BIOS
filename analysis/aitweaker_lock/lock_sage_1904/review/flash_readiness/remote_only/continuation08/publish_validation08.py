"""Aggregate completed C08 diagnostics only; user task and RAM installer continue.

No BMC, media helper, firmware or device operations. Old C07 evidence is read-only.
"""
from pathlib import Path
from datetime import datetime,timezone
import hashlib,json,sys,zlib
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent;READY=HERE.parents[1]
WORK=next(p for p in HERE.parents if (p/'tools/pydeps').is_dir())
REMOTE=HERE.parent;HW=READY.parents[1]/'remote_172_20_2_162'
D04=READY/'native13_split_candidate/installer_design04'
sys.path.insert(0,str(WORK/'analysis/aitweaker_lock/probe_p3_kvm'))
from decode_captures import read_image,assemble
def read(p):return json.loads(p.read_text(encoding='utf8'))
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def bound(p):
    p=p.resolve();assert p.is_relative_to(WORK)
    return {'path':str(p),'bytes':p.stat().st_size,'sha256':sha(p)}
def save(p,o):p.write_text(json.dumps(o,ensure_ascii=False,indent=2)+'\n',encoding='utf8')
def verify(value,base):
    count=0
    if isinstance(value,dict):
        if 'path' in value and 'sha256' in value:
            p=Path(value['path']);p=(p if p.is_absolute() else base/p).resolve()
            assert p.is_relative_to(WORK) and sha(p)==value['sha256'],str(p)
            n=value.get('bytes',value.get('size'));assert n is None or p.stat().st_size==n,str(p)
            count+=1
        for v in value.values():count+=verify(v,base)
    elif isinstance(value,list):
        for v in value:count+=verify(v,base)
    return count
def checked_manifest(p,digest,base):
    assert sha(p)==digest,str(p)
    return {'manifest':bound(p),'file_bindings_rechecked':verify(read(p),base),'all_match':True}
def main():
    prior=HERE.parent/'continuation07/validation07_result.json'
    assert sha(prior)=='38f97a4d61c7d33b114179ef0896f45cd46ae6b6d10a2c092ce3acc8aa610dfc'
    status=read(HERE/'work_status.json')
    assert status['controller_session_id']==33429 and status['controller_still_open'] is False and status['controller_exit_code']==0
    assert not status['temporary_boot_restoration_pending'] and not status['hd_helper_running'] and status['cd_detached']
    assert status['manager_restart_attempts']==2 and not status['release_ready'] and status['firmware_uploads']==status['firmware_flashes']==0
    snap=HERE/'publication08_inputs';snap.mkdir(exist_ok=True)
    frozen_work=snap/'closed_work_status.json'
    if frozen_work.exists():assert frozen_work.read_bytes()==(HERE/'work_status.json').read_bytes()
    else:frozen_work.write_bytes((HERE/'work_status.json').read_bytes())
    manifests={
      'prerequisite04_candidate':checked_manifest(D04/'prerequisite_probe04/prerequisite04_manifest.json','1c70adb50d8e17c2672b091c4bc0ab8fa201a5035b3bfda1a67e017fb3033ba9',D04/'prerequisite_probe04'),
      'prerequisite04_independent':checked_manifest(D04/'prereq04_hardware_review/manifest.json','0dbcd093e28753ee0f6f8bd29fdc44773e2e11664f65d4c1575ebacc2fe88e66',WORK),
      'restart_static':checked_manifest(REMOTE/'bmc_restart_review01/manifest.json','54ae46b12553581889780b69f8a44b71f11c327cbb1f9c0040ec081bbfed846c',REMOTE/'bmc_restart_review01'),
      'helper05':checked_manifest(REMOTE/'media_disconnect_client05_review/manifest.json','cec421f0d500840f7e36635417dc319ed9c01973dcad5d5718ff07abdd3479ee',REMOTE/'media_disconnect_client05_review'),
      'cd_capacity':checked_manifest(REMOTE/'cd_capacity_review08/manifest.json','ee899987590cc87e02814187fcd0a1ba583de320c332dc367bcdd53d249e5dd3',WORK),
      'boot_restoration':checked_manifest(REMOTE/'boot_override_review09/manifest.json','1f76c248db4b019ab8dcce6a6eaf7820aa6a63f24f19333d034a57a99bdc0419',WORK)
    }
    p04path=D04/'prereq04_hardware_review/hardware_review.json'
    assert sha(p04path)=='30a11a8907970b14f64fffdcb9f9afa281c732bb9fda8ef63ecc95c890a9c2cc'
    p04=read(p04path);assert p04['status']=='PASS_RECORDED_PHYSICAL_OWNED_RAM_PREREQUISITE_ONLY'
    assert not p04['native_password_hardware_pass'] and not p04['native_installation_authorized'] and not p04['flash_ready']
    assert p04['owned_results']['both_owned_allocations_freed'] and p04['owned_results']['AMITSE_and_Setup_original_text_hashes_unchanged']
    assert p04['owned_results']['completion']=={'RetainedOwnedPages':0,'EBSObserved':0,'ResidentHoldRequired':0,'PrerequisiteEventClose.status':0,'Warnings':0}
    capture=HW/'hardware-native13-prerequisite04-1793704790283'
    cm=read(capture/'manifest.json');assert (cm['pages'],cm['bytes'],cm['crc32'])==(16,12125,'54DC8D8D')
    for name,digest in cm['files'].items():assert sha(capture/name)==digest,name
    frames=[]
    for n in range(1,17):
        frame=read_image(capture/f'page-{n:02d}.png');assert frame==(capture/f'page-{n:02d}.frame').read_bytes();frames.append(frame)
    raw,transport=assemble(frames,require_inventory=False)
    assert raw==(capture/'hardware-log.txt').read_bytes()
    assert (len(raw),f'{zlib.crc32(raw):08X}',hashlib.sha256(raw).hexdigest())==(12125,'54DC8D8D','2af56b709f22663d502de32f4e7b22a4e49f256ad6f57deea1168b1af4958c91')
    assert read_image(HW/'inventory-before-poweroff-1793704905975.png')==frames[-1]
    restart_reviews=[REMOTE/'bmc_restart_review01/restart_review.json',REMOTE/'bmc_restart_review01/physical_outcome_review.json']
    restart=read(restart_reviews[1]);assert all(restart['checks'].values());verify(restart,WORK)
    attempts=[HERE/'interrupted_attempt01_review/interruption_review.json',HERE/'post_restart_media_review/attempts_review.json']
    a1,a2=map(read,attempts);verify(a1,WORK);verify(a2,WORK)
    assert a1['status']=='INTERRUPTED_ATTEMPT_NO_POST_RESTART_CAPACITY_RESULT'
    assert a2['status']=='NO_NEW_DIAGNOSTIC_EXECUTION_EVIDENCE_IN_REVIEWED_LINUX2_AND_P04_ATTEMPTS'
    r2i=HW/'manager-restart08-1793704149205-intent.json';r2r=HW/'manager-restart08-1793704149205-result.json'
    i2,r2=map(read,[r2i,r2r]);assert r2['post_attempts']==1 and r2['http_status']==202 and r2['intent_sha256']==sha(r2i)
    assert i2['action']=='/redfish/v1/Managers/Self/Actions/Manager.Reset' and i2['request']=={'ResetType':'ForceRestart'} and i2['automatic_retries']==0
    assert i2['before']['host_power']=='Off' and i2['before']['native_power']==0
    mon2=HERE/'restart_reachability_1793704130137.json';monitor=read(mon2)
    assert monitor['observed_down_then_up'] and monitor['samples'][-1]['up'] and all(x['certificate_matches'] for x in monitor['samples'] if x['up'])
    after2p=HW/'manager-restart08-capability-1793704391712.json';after2=read(after2p)
    assert after2['system']['PowerState']=='Off' and after2['power']['data']['power_status']==0
    assert after2['system']['BiosVersion']=='1904' and after2['managers'][0]['FirmwareVersion']=='1.01.57'
    helperp=REMOTE/'media_writeback_client01/runs/20261103_110804_helper05/result.json';helper=read(helperp)
    assert sha(helperp)==status['helper05_physical_sha256']=='419b7c79b6c8e61bbd317d21b6ccbc0cee545c327895b5f7b0d3cadda789b94e'
    assert helper['script_sha256']==sha(REMOTE/'media_writeback_client01/live_writeback05.py')
    assert helper['authenticated'] and helper['socket_closed'] and helper['image_closed']
    assert helper['backend_read_calls']==helper['backend_write_calls']==helper['backend_flush_calls']==helper['backend_written_bytes']==0
    hstop=helper['normal_disconnect'];assert hstop['attempts']==1 and hstop['sendall_returned'] and hstop['peer_eof_observed']
    assert not hstop['protocol_ack_validated'] and not hstop['server_slots_cleared_verified']
    helperreview=REMOTE/'media_disconnect_client05_review/helper05_review.json';verify(read(helperreview),WORK)
    assert read(helperreview)['test_total_cases']==53
    cdreview=REMOTE/'cd_capacity_review08/cd_capacity_review.json';cd=read(cdreview)
    assert cd['tests']['cases']==8 and cd['tests']['status']=='PASS'
    oldtrace=HW/'cd-observer08-1793703687797.jsonl';newtrace=HW/'cd-observer08-1793704514587.jsonl'
    old=[json.loads(x) for x in oldtrace.read_text().splitlines()];new=[json.loads(x) for x in newtrace.read_text().splitlines()]
    assert len(old)==34 and not any(x.get('opcode') in ['a8','28'] for x in old)
    assert len(new)==88 and sum(x.get('opcode')=='a8' and x.get('direction')=='received' for x in new)==24 and sum(x.get('opcode')=='a8' and x.get('direction')=='sent' for x in new)==24
    assert p04['cd_transport']['READ12_requests']==p04['cd_transport']['READ12_responses']==24
    restorep=HW/'media-override-restored09-1793705154680.json';cleanp=HW/'media-cleanup-1793705192913.json';logoutp=HW/'inventory-session-logout-1793705211151.json'
    restore,clean,logout=map(read,[restorep,cleanp,logoutp])
    assert restore['sd_restored'] and not restore['active_restored'] and not restore['verified']
    assert restore['override_disabled_in_both_views'] and restore['host_off'] and restore['unrelated_boot_fields_unchanged']
    assert restore['outcome']=='SD_RESTORED_ACTIVE_VIEW_DIFFERS_NO_EXTRA_MUTATION' and restore['patch_attempts']==1 and restore['http_status']==204
    assert not restore['boot_order_patch_sent'] and not restore['active_self_patch_sent']
    assert restore['after']['active']['BootOrder']==restore['after']['settings']['BootOrder']==['Boot0000','Boot0006','Boot0007','Boot0002','Boot0003','Boot0004','Boot0005']
    assert restore['after']['active']['BootNext'] is restore['after']['settings']['BootNext'] is None
    assert all(clean['verified'].values()) and clean['power']['data']['power_status']==0 and clean['hd_active_sessions']==clean['cd_active_sessions']==128 and not clean['owned_helper_running']
    assert logout['status']==200 and not logout['credentials_or_session_identifiers_saved']
    assert restore['finished_utc']<clean['utc']<logout['utc']==status['closed_utc']
    image=READY/'native12_safety_review/implementation/build/integration_native12_review/W790E-SAGE-SE-1904-NATIVE12-INTERNAL-UNSIGNED-NOT-RELEASE-READY.review.bin'
    assert sha(image)=='b1223ca05cf9630382e5fc014457d3c6343aaf7d970b58e5769950200f65ac02'
    blank=REMOTE/'media_writeback_review/blank_test/WRITEBACK02.img';assert sha(blank)==helper['final_image_sha256']=='df7fa016a0f4be496d3d446db558e8de15f537aa9953faff20b4ae0c6132b4b6'
    result={
      'generated_utc':datetime.now(timezone.utc).isoformat(),'status':'C08_DIAGNOSTIC_SESSION_CLOSED_TASK_CONTINUES_NOT_RELEASE_READY',
      'target':'ASUS Pro WS W790E-SAGE SE BIOS1904','diagnostic_session_complete':True,'task_complete':False,
      'task_continues_in':'continuation08_local_native_installer_development','release_ready':False,'production_release_completed':False,
      'firmware_upload_performed':False,'firmware_flashing_performed':False,'physical_password_ui_acceptance':False,
      'native_interceptor_installed_or_executed':False,'full_machine_spi_backup':False,'recovery_verified':False,
      'completed_diagnostic_captures':1,'raw_QR_pages_verified':16,'failed_or_interrupted_boot_attempts_without_new_diagnostic_result':3,
      'prior_continuation07_preserved':bound(prior),'internal_image_unchanged':bound(image),'disposable_image_unchanged':bound(blank),
      'frozen_manifest_bindings':manifests,'binding_count_is_not_unique_file_count':True,
      'prerequisite04':{'independent_review':bound(p04path),'capture_manifest':bound(capture/'manifest.json'),'log':bound(capture/'hardware-log.txt'),
        'transport':transport,'raw_pages_redecoded_here':16,'pre_poweroff_last_page_also_decoded':True,
        'two_owned_allocation_cycles_passed':True,'fixed_six_byte_code_executed_in_owned_code_page':True,
        'original_texts_and_eight_target_page_permission_snapshots_unchanged':True,'both_allocations_freed':True,
        'native_hooks_provider_password_ui_executed':False,'complete_browser_idle_proven':False,
        'observed_outer_return_rva':'0x960C','prior_C07_outer_return_rva':'0x2D7D',
        'scope':'Actual standard CPU Arch attributes and owned-page execution/readback/semantic restoration/free only. No OEM-page write, detour, provider start, password operation or deliberate RO/NX fault.'},
      'failed_attempts':{'first_linux_interruption':bound(attempts[0]),'linux_retry_and_initial_P04':bound(attempts[1]),
        'new_linux_capacity_result':False,'counted_as_diagnostic_passes':False,
        'scope':'Installed Rocky login screenshots and session records show no new diagnostic execution result. They do not prove every unobserved instant. Clock jump/authentication loss correlation does not establish a unique cause.'},
      'standard_bmc_restarts':{'count':2,'first_outcome_review':bound(restart_reviews[1]),'second_intent':bound(r2i),'second_result':bound(r2r),
        'second_monitor':bound(mon2),'second_after_capability':bound(after2p),'both_standard_force_restart':True,
        'factory_reset_performed':False,'second_down_utc':next(x['utc'] for x in monitor['samples'] if not x['up']),
        'second_up_utc':monitor['finished_utc'],'limits':'Off and configuration sampled before/after; not continuous power monitoring. Manager clock changed. No restart is itself proof of media teardown or firmware acceptance.'},
      'helper05_normal_disconnect':{'review':bound(helperreview),'physical_result':bound(helperp),'local_mock_and_ARM_cases':53,
        'F7_attempts':1,'sendall_returned':True,'peer_eof_observed':True,'server_slot_clear_acknowledgement':False,
        'host_off_CD_detached_scope_reported_by_operator':True,'backend_read_write_flush_calls':[0,0,0],'writeback_verified':False},
      'cd_recovery':{'offline_review':bound(cdreview),'local_original_ARM_cases':8,'old_trace':bound(oldtrace),'new_trace':bound(newtrace),
        'old_trace_has_read_requests':False,'new_READ12_request_response_counts':[24,24],'new_response_payload_bytes_sum':1445888,
        'boot_menu_and_complete_P04_execution_observed':True,'no_media_boost_change_reported_by_operator':True,
        'unique_root_cause_established':False,'HD_geometry_fixed':False,
        'scope':'Ordinary CD path recovered after normal cleanup and second BMC restart in a CD-only workflow. Metadata cannot prove a full ISO transfer/hash; optical recovery does not validate HD geometry/file writeback or identify which action caused recovery.'},
      'cleanup':{'operator_closed_status_snapshot':bound(frozen_work),'boot_override_restore':bound(restorep),'media_and_power':bound(cleanp),'logout':bound(logoutp),
        'host_off_at_readback':True,'CD_HD_idle_at_readback':True,'owned_helper_reaped':True,'SD_restored':True,'active_Self_restored':False,
        'active_and_SD_override_disabled':True,'BootNext_null_in_both_views':True,'known_virtual_CD_option_present':True,
        'other_boot_properties_unchanged_during_restore':True,'all_firmware_NVRAM_bytes_unchanged_claimed':False,
        'controller_session_id':33429,'controller_exit_code_reported_by_operator':0,'logout_HTTP_status':200,'as_of_utc':logout['utc'],
        'scope':'Timestamped closing readback. SD=Disabled/Legacy/None; active Self=Disabled/UEFI/Cd. Both disabled. No whole-NVRAM equivalence or future-state claim.'},
      'native_installer_work':{'ongoing':True,'selected_firmware_image_remains':'NATIVE12_INTERNAL_UNSIGNED_NOT_RELEASE_READY',
        'separate_split_candidate_validation_transferred_to_N12':False,'native_installer_hardware_pass':False,
        'scope':'Independent split allocation, provider and RAM transaction work continues in separate directories; mutable in-progress sources are not frozen or accepted by this diagnostic publication.'},
      'summary_zh':'第8轮已完成一轮自有内存前置条件实测，回收16页二维码（12,125字节，CRC54DC8D8D）。两组独立分配完成权限切换、读写、恢复及释放；其中代码页执行固定六字节代码，数据页未执行。原厂代码及8个目标页的权限快照未变。此前三次启动尝试没有取得新的诊断执行结果，已单独保留。完成两次标准BMC重启及正常F7断开后，CD-only流程恢复了A8读取、启动菜单枚举和P04执行，但不能确定唯一原因，也未证明虚拟硬盘几何或文件写回已修好。本轮未安装原生拦截、运行provider或密码界面，未上传或刷写固件。11:26:51 UTC结束记录确认关机、介质空闲、辅助进程退出和BMC会话注销；SD已恢复Disabled/Legacy/None，当前Self仍Disabled/UEFI/Cd，两者均禁用覆盖。真实RAM安装器继续开发，正式版验收尚未完成。',
      'three_major_gaps_zh':[
        '自有内存服务前置条件已实测；真实原生挂钩、provider、独立密码UI、首次Del/F2和完整保存/回滚仍未实机验收。',
        'CD启动通路已恢复；HD几何和文件写回仍未通过，尚无机器专属完整SPI备份及可用恢复验证。',
        'NATIVE12仍为UNSIGNED内部映像，完整更新信任链、实际写入范围的数据保留和可恢复刷写尚未验收。'],
      'publication_boundary':'Completed C08 diagnostic device session only. User task and local installer development continue. No new firmware release or flashing authorization.',
    }
    links=[HERE/'publish_validation08.py',frozen_work,p04path,D04/'prereq04_hardware_review/manifest.json',D04/'prerequisite_probe04/prerequisite04_manifest.json',
      *restart_reviews,*attempts,HERE/'post_restart_media_review/attempts_manifest.json',helperreview,REMOTE/'media_disconnect_client05_review/manifest.json',
      cdreview,REMOTE/'cd_capacity_review08/manifest.json',REMOTE/'boot_override_review09/boot_override_review.json',REMOTE/'boot_override_review09/manifest.json']
    result['evidence_links']=[{'path':p.relative_to(READY).as_posix(),'sha256':sha(p)} for p in links]
    save(HERE/'validation08_result.json',result)
    print(json.dumps({'status':result['status'],'raw_QR_pages':16,'bound_manifest_references':sum(x['file_bindings_rechecked'] for x in manifests.values()),'release_ready':False,'task_complete':False,'output':str(HERE/'validation08_result.json')},ensure_ascii=False))
if __name__=='__main__':main()
