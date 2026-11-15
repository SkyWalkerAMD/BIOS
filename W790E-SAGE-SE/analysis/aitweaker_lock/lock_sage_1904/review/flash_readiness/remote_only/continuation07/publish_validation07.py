"""Publish C07 as a historical evidence round; perform no remote operations.

All source, capture and previous-release files are read only. The sole output is
validation07_result.json. The requested production release continues in C08.
"""
from datetime import datetime, timezone
from pathlib import Path
import hashlib,json,sys,zlib

HERE=Path(__file__).resolve().parent
READY=HERE.parents[1]
WORK=HERE.parents[6]
HW=READY.parents[1]/'remote_172_20_2_162'
NATIVE=READY/'native13_split_candidate'
LINUX=READY/'remote_only/linux_capacity_candidate01'
GEO=READY/'remote_only/media_geometry_review06'
CLIENT=READY/'remote_only/media_writeback_client01'
sys.path.insert(0,str(WORK/'analysis/aitweaker_lock/probe_p3_kvm'))
from decode_captures import read_image,assemble
sys.path.insert(0,str(LINUX))
from decode_linux_log import decode as decode_linux

def read(p):return json.loads(p.read_text(encoding='utf-8'))
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def bound(p):
    p=p.resolve();assert p.is_relative_to(WORK)
    return {'path':str(p),'bytes':p.stat().st_size,'sha256':sha(p)}
def save(p,value):p.write_text(json.dumps(value,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')

def manifest(p,expected,key,base,count):
    assert sha(p)==expected,str(p)
    data=read(p);assert len(data[key])==count
    for item in data[key]:
        f=Path(item['path']);f=(f if f.is_absolute() else base/f).resolve()
        assert f.is_relative_to(WORK) and f.stat().st_size==item['bytes'] and sha(f)==item['sha256'],str(f)
    return {'manifest':bound(p),'verified_file_bindings':count,'all_match':True}

def capture(folder,pages,length,crc,digest):
    folder=folder.resolve();m=read(folder/'manifest.json')
    assert (m['pages'],m['bytes'],m['crc32'],m['sha256'])==(pages,length,crc,digest)
    for name,h in m['files'].items():
        p=(folder/name).resolve();assert p.is_relative_to(folder) and sha(p)==h
    assert len(list(folder.glob('page-*.png')))==pages
    frames=[]
    for i in range(1,pages+1):
        decoded=read_image(folder/f'page-{i:02d}.png')
        assert decoded==(folder/f'page-{i:02d}.frame').read_bytes()
        frames.append(decoded)
    raw,transport=assemble(frames,require_inventory=False)
    assert raw==(folder/'hardware-log.txt').read_bytes()
    assert (len(raw),f'{zlib.crc32(raw):08X}',hashlib.sha256(raw).hexdigest())==(length,crc,digest)
    return {'manifest':bound(folder/'manifest.json'),'log':bound(folder/'hardware-log.txt'),
            'transport':transport,'raw_png_pages_independently_decoded':pages,
            'saved_frames_and_log_equal':True,'bound_transport_files':len(m['files'])}

def verify_input_records(data,key='inputs'):
    for item in data.get(key,[]):
        p=Path(item['path']);p=(p if p.is_absolute() else WORK/p).resolve()
        assert p.is_relative_to(WORK) and p.stat().st_size==item['bytes'] and sha(p)==item['sha256'],str(p)

def main():
    frozen={
        'entry01':manifest(NATIVE/'entry_probe/entry_context_manifest.json','44ff44bce5f374147f838316cf8027ac0c472b2b95d56a908d35fd0eedb51437','artifacts',NATIVE,86),
        'entry02':manifest(NATIVE/'entry_probe02/entry_context02_manifest.json','92b625201440644d061c25e3eab4111b042db765731d4837df13641e676c02e7','artifacts',NATIVE,87),
        'entry03':manifest(NATIVE/'entry_probe03/entry_context03_manifest.json','56bff292b3fe57b8d29888129e2db854d91f79ef61e546aa901234d4297dbc6c','artifacts',NATIVE,110),
        'linux_payload':manifest(LINUX/'payload_manifest.json','d95d73120917924f230c7c819132cb13d7ffb4ca52f2f5c958c00fd25e01746e','files',LINUX,265),
        'linux_loader':manifest(LINUX/'loader/loader_manifest.json','03749d2e36d203e6af459b93621579721443ac0aca5aaa90b849460cc2ff2247','files',LINUX/'loader',437),
    }
    assert sum(v['verified_file_bindings'] for v in frozen.values())==985
    additional={
        'entry03_independent_review':manifest(NATIVE/'entry03_hardware_review_manifest.json','cda6cdde9a335feef1ddfe295e4bdce7b65242e0840c03c3db844077b7f4b4cc','artifacts',NATIVE,8),
        'linux_physical_review':manifest(LINUX/'review/physical01/manifest.json','680772ce6f53d38bf776561a2ba1f17e227d584c54e13aaf6121eda4900d5612','files',LINUX/'review/physical01',6),
        'geometry06':manifest(GEO/'manifest.json','27fbd86cf9bb31f1f38c653cd0732d339e41a96cbb7dee10277c5aa64d0af71d','files',GEO,46),
    }
    captures={
        'entry01':capture(HW/'hardware-native13-entry-1793696498298',8,5726,'F0CA537A','5afe0c3adb224f8a25627c15766d99a5cc29ad7c8eaa9fa3df231b1eef9faf12'),
        'entry02_successful_retry':capture(HW/'hardware-native13-entry02-1793698042583',9,6681,'EB17EA84','8d71d035b5e8d9929aede2edc758c48b30a98c9ae25031d1b237403e536941e6'),
        'entry03':capture(HW/'hardware-native13-entry03-1793699303328',10,7124,'F05C1C96','609056637bb727cfcf01032e3b50730f989edf5f2782bb290b793ff57770909f'),
        'linux_capacity01':capture(HW/'hardware-linux-capacity01-1793698923920',1,633,'FDE3FBC9','fdd7431a595d46a6456f1059b3f012aea46423b0a7da59af756b47673dece345'),
    }
    assert sum(v['raw_png_pages_independently_decoded'] for v in captures.values())==28
    ep1=read(NATIVE/'entry_hardware_readonly_review.json');ep2=read(NATIVE/'entry02_hardware_readonly_review.json');ep3=read(NATIVE/'entry03_hardware_readonly_review.json')
    assert all(r['same_as_parent_log'] for r in [ep1,ep2,ep3])
    assert ep1['observed_core']['loaded_image_size']=='0x21000' and ep1['expected_original_core']['pe_size_of_image']=='0x20e60'
    assert ep2['observed']['core_complete_normalized_text_passed'] and ep2['observed']['native_parent_return_rva']=='0xa8e6'
    assert ep3['observed']['core_complete_normalized_text_passed'] and ep3['observed']['native_launch_complete_function_hash_passed']
    assert ep3['observed']['outer_return_rva']=='0x2d7d' and ep3['observed']['original_detour_sites_passed']==12
    assert not any(ep3[k] for k in ['browser_absence_proven','installation_authorized','installer_run','provider_started'])
    interrupted=read(HERE/'entry02_attempt01_interrupted.json')
    assert not interrupted['probe_result_observed'] and not interrupted['firmware_upload_or_flash']
    physical=read(LINUX/'review/physical01/hardware_review.json');verify_input_records(physical)
    sem=decode_linux(Path(captures['linux_capacity01']['log']['path']).read_bytes())
    assert sem==physical['semantic'] and sem['complete'] and sem['capacity_valid'] and sem['dmi_match']
    assert (sem['userspace_rc10_calls'],sem['last_lba'],sem['block_bytes'],sem['modules'])==(2,262144,1024,8)
    assert sem['probe_storage_writes']==sem['probe_block_reads']==sem['probe_resets']==0
    assert sem['packets'][0]['sense']=='700006000000000A00000000290000000000'
    assert sem['packets'][1]['data8']=='0004000000000400'
    helper_paths=[CLIENT/'runs/20261103_093929/result.json',CLIENT/'runs/20261103_095724/result.json']
    helpers=[read(p) for p in helper_paths]
    for helper in helpers:
        assert helper['socket_closed'] and helper['image_closed']
        assert helper['backend_read_calls']==helper['backend_write_calls']==helper['backend_flush_calls']==helper['backend_written_bytes']==0
        assert helper['final_image_bytes']==16777216 and helper['final_image_sha256']=='df7fa016a0f4be496d3d446db558e8de15f537aa9953faff20b4ae0c6132b4b6'
    observer=helpers[1];assert len(observer['capacity_sends'])==1
    sent=observer['capacity_sends'][0]
    assert sent['frame_bytes']==101 and sent['sendall_returned'] and sent['expected_capacity_bytes_match']
    assert sent['capacity8_hex']=='00007fff00000200' and sent['fields']['header_length']==0
    geometry=read(GEO/'geometry_review.json');verify_input_records(geometry,'external_evidence')
    assert geometry['new_results']['actual_ARM_cases']==8 and geometry['new_results']['status']=='PASS'
    assert geometry['status']=='BOUNDED_OFFLINE_REVIEW_COMPLETE_EXACT_LIVE_GEOMETRY_ORIGIN_UNRESOLVED'
    work=read(HERE/'work_status.json');assert work['current_boot']=='NONE_HOST_OFF_FINAL_C07'
    assert work['controller_still_open'] is False and work['controller_exit_code']==0 and not work['cleanup_pending']
    clean_path=HW/'inventory-cleanup-1793699974550.json';media_path=HW/'media-cleanup-1793699963082.json';logout_path=HW/'inventory-session-logout-1793700281719.json';restore_path=HW/'boot-once-1793699187749.json'
    assert sha(clean_path)=='e69f1a96ca85129fe24ced571049a0715e92a20eb574f2cde12909106598cbcc'==work['last_cleanup_sha256']
    assert sha(logout_path)=='e41fe874c0a1b3faed7588bf9b07b92393abcc988b4e8ef8d7cc0d4f968bf279'==work['last_logout_sha256']
    clean,media,logout,restore=map(read,[clean_path,media_path,logout_path,restore_path])
    assert all(clean['verified'].values()) and all(media['verified'].values())
    assert clean['native_power']['data']['power_status']==media['power']['data']['power_status']==0
    assert not media['owned_helper_running'] and media['hd_active_sessions']==media['cd_active_sessions']==128
    assert media['media_button']==clean['media_button']=='Start Media'
    for field in ['BootNext','BootOrder','BootSourceOverrideEnabled','BootSourceOverrideMode','BootSourceOverrideTarget']:assert clean['boot'][field]==restore['before'][field],field
    assert observer['finished_utc']<media['utc']<clean['utc']<logout['utc']
    assert logout['status']==200 and logout['credentials_or_session_identifiers_saved'] is False
    image=READY/'native12_safety_review/implementation/build/integration_native12_review/W790E-SAGE-SE-1904-NATIVE12-INTERNAL-UNSIGNED-NOT-RELEASE-READY.review.bin'
    assert sha(image)=='b1223ca05cf9630382e5fc014457d3c6343aaf7d970b58e5769950200f65ac02'
    disposable=READY/'remote_only/media_writeback_review/blank_test/WRITEBACK02.img'
    assert disposable.stat().st_size==16777216 and sha(disposable)=='df7fa016a0f4be496d3d446db558e8de15f537aa9953faff20b4ae0c6132b4b6'
    result={
        'generated_utc':datetime.now(timezone.utc).isoformat(),'target':'ASUS Pro WS W790E-SAGE SE BIOS 1904',
        'status':'HISTORICAL_VALIDATION07_COMPLETE_NOT_RELEASE_READY','current_round_complete':True,'task_continues_in':'continuation08',
        'production_release_completed':False,'firmware_upload_performed':False,'firmware_flashing_performed':False,
        'physical_password_ui_acceptance':False,'native_interceptor_installed_or_executed':False,'full_machine_spi_backup':False,'recovery_verified':False,
        'completed_diagnostic_captures':4,'raw_QR_pages_verified':28,'interrupted_attempts_without_result':1,
        'frozen_file_bindings_verified':985,'binding_count_is_not_unique_file_count':True,'frozen_evidence':frozen,
        'independent_review_manifests':additional,'captures':captures,
        'native_entry':{'entry01_review':bound(NATIVE/'entry_hardware_readonly_review.json'),'entry02_review':bound(NATIVE/'entry02_hardware_readonly_review.json'),'entry03_review':bound(NATIVE/'entry03_hardware_readonly_review.json'),
            'entry01_result':'Core LoadedImage allocation was exactly page-rounded; original strict size guard refused before Core header/hash. This is a valid diagnostic refusal, not an identity pass.',
            'entry02_result':'Precise two-size metadata policy passed exact original PE/text/relocation checks and one AMITSE parent frame.',
            'entry03_result':'Bounded chain: Core return88AF -> AMITSE returnA8E6 -> outer return2D7D in BootNext branch. No arbitrary ancestor scan.',
            'browser_absence_proven':False,'installer_run':False,'provider_started':False,'original_detour_sites_matched':12,
            'limit':'Original outer function also contains conditional browser and reentry paths. This chain does not establish all outer frames are idle, actual CPU write permissions, exclusive allocation or safe install/rollback.'},
        'interrupted_entry02':{'record':bound(HERE/'entry02_attempt01_interrupted.json'),'probe_result_observed':False,'counted_as_diagnostic_pass':False,'installed_OS_reached':True,'recovery':'Parent reconnected, observed installed Rocky Linux login, used orderly shutdown and restored temporary boot fields before retry.'},
        'linux_capacity':{'independent_review':bound(LINUX/'review/physical01/hardware_review.json'),'semantic':sem,'helper_result':bound(helper_paths[0]),
            'expected_image_bytes':16777216,'expected_last_lba':32767,'expected_block_bytes':512,'geometry_matches_expected':False,
            'file_writeback_verified':False,'helper_image_reads_writes_flushes':[0,0,0],
            'command_boundary':'Two PID1 SG_IO RC10 calls are distinct from the helper startup opcode25 count and Linux driver scan/recovery commands. Capacity response does not read a disk data block.',
            'boot_effects':'Linux ran its reviewed RAM PID1 and performed ordinary device initialization and ExitBootServices; no zero-system-effect claim.',
            'poweroff_annotation':bound(HERE/'linux_poweroff_record_annotation.json')},
        'later_off_host_observer':{'result':bound(helper_paths[1]),'review':bound(HERE/'capacity_observer_review.json'),'capacity_send':sent,
            'host_boot_in_this_observation':False,'image_reads_writes_flushes':[0,0,0],
            'limit':'A later host-Off session submitted expected bytes successfully to its socket. It is not same-session evidence of the earlier mismatch, remote application acknowledgement or a successful writeback.'},
        'geometry_review':{'report':bound(GEO/'geometry_review.json'),'actual_ARM_cases':8,
            'finding':'Pinned code supports cached-LUN geometry surviving a backing-size change and several unchecked status/async-attach paths. Synthetic replay demonstrates possible mechanisms.',
            'exact_live_root_cause_established':False,'running_backend_binary_identity_matched':False},
        'internal_image_unchanged':bound(image),'disposable_image_unchanged':bound(disposable),
        'cleanup':{'snapshot_scope':'Historical C07 final readbacks only; not the current host/BMC state after C08 begins.',
            'boot_and_power':bound(clean_path),'virtual_media':bound(media_path),'logout':bound(logout_path),'boot_restore_baseline':bound(restore_path),
            'operator_work_status':bound(HERE/'work_status.json'),'host_off_at_readback':True,'CD_HD_idle_at_readback':True,'helper_reaped_at_readback':True,
            'boot_order_and_temporary_settings_restored_at_readback':True,'controller_exit_code_reported_by_operator':0,'controller_session_id':80491,
            'logout_HTTP_status':200,'as_of_utc':logout['utc'],'all_bios_nvram_bytes_unchanged_claimed':False},
        'summary_zh':'第7轮完成4次免刷诊断回收，共28页二维码，并复核985条文件绑定（不是985个独立文件）。原生入口观察已追到AMITSE的BootNext分支，但没有安装拦截或运行密码界面。Linux实际发出的两次RC10先返回UNIT ATTENTION、后返回容量，仍为1024字节扇区和LastLBA 262144，与16 MiB/512字节镜像不符。另一次EP2因会话失效、光驱断开而未取得探针结果，已单独保留。后续关机状态下的辅助客户端记录到预期容量字节发送完成，不能证明BMC已应用。第7轮末的读取记录确认主机关机、CD/HD卸载、临时启动设置恢复和会话退出；这是历史快照，不代表第8轮开始后的当前状态。未上传或刷写固件，任务按第8轮继续。',
        'three_major_gaps_zh':[
            '尚未实机验收原生拦截、独立密码设置/解锁、首次Del/F2及其他入口，也未证明完整浏览器空闲与安全安装条件。',
            '虚拟硬盘几何仍不匹配；尚未验证文件写回，也未取得这台机器的完整SPI备份。',
            '实际固件更新链的信任接受、数据保留及可用恢复路径尚未验证。'],
        'publication_boundary':'C07 observations are complete and historical. C08 continues the user task. No impossibility claim, current-machine-state claim, production release or flash authorization follows.',
        'public_reference':'https://uefi.org/specs/UEFI/2.11/07_Services_Boot_Services.html',
    }
    links=[HERE/'publish_validation07.py',HERE/'work_status.json',HERE/'entry_probe_parent_review.json',HERE/'entry_probe02_parent_review.json',HERE/'entry_probe03_parent_review.json',HERE/'linux_payload_parent_review.json',HERE/'linux_loader_parent_review.json',HERE/'linux_capture_wrapper_review.json',HERE/'entry02_attempt01_interrupted.json',HERE/'linux_poweroff_record_annotation.json',HERE/'capacity_observer_review.json',HERE/'capacity_observer_delta.json',
        NATIVE/'entry_hardware_readonly_review.json',NATIVE/'entry02_hardware_readonly_review.json',NATIVE/'entry03_hardware_readonly_review.json',NATIVE/'entry03_hardware_review_manifest.json',LINUX/'review/physical01/hardware_review.json',LINUX/'review/physical01/manifest.json',GEO/'geometry_review.json',GEO/'manifest.json',*helper_paths]
    links.extend(Path(v['manifest']['path']) for v in frozen.values())
    result['evidence_links']=[{'path':p.relative_to(READY).as_posix(),'sha256':sha(p)} for p in links]
    result['prior_continuation06_preserved']=bound(READY/'remote_only/continuation06/validation06_result.json')
    save(HERE/'validation07_result.json',result)
    print(json.dumps({'status':result['status'],'raw_QR_pages_verified':28,'frozen_file_bindings_verified':985,'additional_review_bindings_verified':60,'historical_cleanup_verified':True,'release_ready':False,'task_continues':'continuation08'},ensure_ascii=False))

if __name__=='__main__':main()
