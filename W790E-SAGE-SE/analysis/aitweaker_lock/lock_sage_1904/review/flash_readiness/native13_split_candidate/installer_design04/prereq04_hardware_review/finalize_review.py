"""Freeze the P04 physical prerequisite result and its bounded transport window."""
from pathlib import Path
from collections import Counter
import hashlib
import json
import sys

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
ROOT = next(p for p in HERE.parents if (p / 'tools/kvm-pydeps').is_dir())
SAGE = ROOT / 'analysis/aitweaker_lock/lock_sage_1904'
HW = SAGE / 'remote_172_20_2_162'
REMOTE = SAGE / 'review/flash_readiness/remote_only'
C08 = REMOTE / 'continuation08'
P04 = HERE.parent / 'prerequisite_probe04'
PRIOR = HERE.parent / 'prereq04_independent_review'
CAPTURE = HW / 'hardware-native13-prerequisite04-1793704790283'


def sha(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()


def read(p):
    return json.loads(p.read_text(encoding='utf8'))


def bind(p):
    p = p.resolve()
    assert p.is_relative_to(ROOT.resolve())
    return {'path': str(p), 'bytes': p.stat().st_size, 'sha256': sha(p)}


def write(p, obj):
    with p.open('x', encoding='utf8', newline='\n') as f:
        f.write(json.dumps(obj, ensure_ascii=False, indent=2) + '\n')


def verify():
    m = read(HERE / 'manifest.json')
    for row in m['inputs'] + m['artifacts']:
        p = Path(row['path'])
        assert p.stat().st_size == row['bytes'] and sha(p) == row['sha256'], p
    r = read(HERE / 'hardware_review.json')
    assert r['native_password_hardware_pass'] is False and r['native_installation_authorized'] is False
    assert r['flash_ready'] is False and r['publication08_complete'] is False
    assert sha(HERE / 'hardware_review.json') == m['review_sha256']
    print(json.dumps({'status': 'PASS_FROZEN_P04_PHYSICAL_REVIEW',
                      'input_bindings': len(m['inputs']), 'own_artifact_bindings': len(m['artifacts']),
                      'review_sha256': m['review_sha256'], 'manifest_sha256': sha(HERE / 'manifest.json')}))


def main():
    if '--verify-only' in sys.argv:
        verify();return
    assert not (HERE / 'manifest.json').exists()
    decoded = read(HERE / 'decode_result.json')
    assert decoded['status'] == 'PASS_INDEPENDENT_HARDWARE_QR_AND_SEMANTIC_RECONSTRUCTION'
    assert decoded['sha256'] == sha(HERE / 'independently_decoded.log') == '2af56b709f22663d502de32f4e7b22a4e49f256ad6f57deea1168b1af4958c91'
    assert [r['bindings_verified'] for r in decoded['candidate_manifests']] == [97,38]
    inputs = [P04 / 'prerequisite04_manifest.json', P04 / 'build/SageNative13Prerequisite04.efi',
              P04 / 'build/SAGE-N13-OWNED-PREREQUISITE04.iso', P04 / 'source/owned_fixture.inc',
              P04 / 'source/pagewalk.inc', P04 / 'source/launch_frame.inc', P04 / 'source/targets.h',
              PRIOR / 'review_manifest.json', PRIOR / 'independent_review.json',
              C08 / 'prerequisite04_parent_review.json', CAPTURE / 'manifest.json',
              HW / 'operations/capture_native13_prerequisite04.mjs', HW / 'read_native13_prerequisite04_qr.py',
              HW / 'operations/observe_cd08.mjs',
              HW / 'cd-observer08-1793704514587.jsonl', HW / 'cd-observer08-1793704514587.jsonl.json',
              HW / 'setup-reset08-1793704577157.json', HW / 'inventory-poweroff-1793704906231.json',
              HW / 'inventory-before-poweroff-1793704905975.png', HW / 'inventory-before-poweroff-1793704905975.frame',
              HW / 'media-cleanup-1793704971716.json',
              HW / 'hardware-native13-entry03-1793699303328/hardware-log.txt',
              HW / 'hardware-native13-entry03-1793699303328/manifest.json',
              REMOTE / 'cd_capacity_review08/cd_capacity_review.json',
              C08 / 'post_restart_media_review/physical_helper05_cd_review/physical_review.json',
              C08 / 'post_restart_media_review/physical_helper05_cd_review/manifest.json']
    for name in read(CAPTURE / 'manifest.json')['files']:
        inputs.append(CAPTURE / name)
    for stem in ['screen-283-current','screen-285-setup-before-reset08','screen-286-boot-watch','screen-287-current']:
        inputs += [HW / (stem+'.png'), HW / (stem+'.json')]
    assert len(set(inputs)) == len(inputs)
    assert sha(P04 / 'build/SageNative13Prerequisite04.efi') == 'a8a828427a412eaffb36bc244a91175507a940238ae30c51c3e64d0520fea800'
    assert sha(P04 / 'build/SAGE-N13-OWNED-PREREQUISITE04.iso') == '852ed9fdbf39cad8764bf0b1cf21c2b3fb1b95f939c9536e13ad22dbf943307c'
    assert sha(HW / 'operations/observe_cd08.mjs') == '56791daa59378c410b11b1755a06b52df8a75988459ac5c287c40f3badcd410b'
    old = read(HW / 'hardware-native13-entry03-1793699303328/manifest.json')
    old_log = HW / 'hardware-native13-entry03-1793699303328/hardware-log.txt'
    assert sha(old_log) == old['sha256'] == '609056637bb727cfcf01032e3b50730f989edf5f2782bb290b793ff57770909f'
    assert b'LaunchOuterReturnRVA=0000000000002D7D\r\n' in old_log.read_bytes()
    trace = [json.loads(x) for x in (HW / 'cd-observer08-1793704514587.jsonl').read_text(encoding='utf8').splitlines() if x.strip()]
    summary = read(HW / 'cd-observer08-1793704514587.jsonl.json')
    assert summary['packets'] == len(trace) == 88 and summary['sockets'] == 1 and summary['truncated'] is False
    assert trace[0]['event'] == 'socket' and trace[-1]['event'] == 'closed'
    assert trace[-1]['pending_sent_bytes'] == trace[-1]['pending_received_bytes'] == 0
    assert all('unparsed' not in x for x in trace)
    frames = [x for x in trace if 'opcode' in x]
    counts = dict(sorted(Counter(x['direction']+':'+x['opcode'] for x in frames).items()))
    assert counts == {'received:25':1,'received:a8':24,'received:f1':1,'received:f3':16,
                      'sent:25':1,'sent:a8':24,'sent:f2':1,'sent:f3':16,'sent:f7':1,'sent:f8':1}
    reads = [x for x in frames if x['opcode'] == 'a8']
    read_responses = [x for x in reads if x['direction'] == 'sent']
    assert all(x['status'] == [0,0,0,0] for x in reads)
    assert all(x['data_length'] > 0 and x['bytes'] == 61+x['data_length'] for x in read_responses)
    total_read_payload = sum(x['data_length'] for x in read_responses)
    cap = [x for x in frames if 'capacity8' in x]
    assert len(cap) == 1 and cap[0]['capacity8'] == '0000201f00000800'
    f7 = [x for x in frames if x['opcode']=='f7']
    assert len(f7) == 1 and f7[0]['utc'] == '2026-11-03T11:22:00.366Z'
    assert trace[-1]['utc'] == '2026-11-03T11:22:00.445Z'
    poweroff = read(HW / 'inventory-poweroff-1793704906231.json')
    assert poweroff['diagnostic'] == {'total':12125,'crc':0x54DC8D8D,'page':16,'pages':16,'offset':11520}
    assert poweroff['before']['status'] == poweroff['result']['status'] == 200
    assert poweroff['before']['data']['power_status'] == 1 and poweroff['result']['data']['power_command'] == 0
    # Verify the power-off screenshot really encodes this run's final page again.
    from decode_hardware import parse
    from PIL import Image
    import zxingcpp
    with Image.open(HW / 'inventory-before-poweroff-1793704905975.png') as im:
        bars = zxingcpp.read_barcodes(im.convert('RGB'),formats=zxingcpp.BarcodeFormat.QRCode)
    assert len(bars) == 1
    final_frame = bytes(bars[0].bytes)
    assert final_frame == (HW / 'inventory-before-poweroff-1793704905975.frame').read_bytes()
    assert final_frame == (CAPTURE / 'page-16.frame').read_bytes()
    assert parse(final_frame)['page'] == 16
    cleanup = read(HW / 'media-cleanup-1793704971716.json')
    assert all(v is True for v in cleanup['verified'].values())
    assert cleanup['power']['status'] == cleanup['media']['status'] == 200
    assert cleanup['power']['data']['power_status'] == 0 and cleanup['media_button'] == 'Start Media'
    assert cleanup['owned_helper_running'] is False and cleanup['hd_active_sessions'] == cleanup['cd_active_sessions'] == 128
    reset = read(HW / 'setup-reset08-1793704577157.json')
    assert reset['status'] == 202 and reset['action'] == 'ForceRestart'
    assert reset['evidence_sha256'] == sha(HW / 'screen-283-current.png')
    r = {
        'status': 'PASS_RECORDED_PHYSICAL_OWNED_RAM_PREREQUISITE_ONLY',
        'scope': 'Independent offline reconstruction of the completed SAGE SE 1904 P04 run. No physical action by this reviewer. This is a prerequisite result, not native lock installation.',
        'candidate': {'efi':bind(P04 / 'build/SageNative13Prerequisite04.efi'),
                      'iso':bind(P04 / 'build/SAGE-N13-OWNED-PREREQUISITE04.iso'),
                      'candidate_bindings_rechecked':97,'prior_independent_bindings_rechecked':38},
        'qr': {'pages':16,'bytes':12125,'crc32':'54DC8D8D','sha256':decoded['sha256'],
               'every_original_png_decoded':True,'every_saved_frame_and_log_byte_matched':True,
               'scope_and_completion_markers_passed':True,'decoder_negative_cases':5,
               'additional_pre_poweroff_page16_redecoded':True},
        'identity': {'smbios_board':'Pro WS W790E-SAGE SE','bios':'1904',
                     'AMITSE_and_Setup_exact_original_text_hash_checks_pass':True,
                     'module_instances':decoded['modules'],
                     'candidate_binary_attestation_caveat':'The local ISO/EFI hashes and source bindings are checked. The saved log has compatible markers and expected original-module checks; it does not include a cryptographic self-measurement of the executing probe.'},
        'permissions': {'memory_attribute_protocol_available':False,
                        'cpu_page_walk_resolved_present_permissions':True,
                        'patch_sites':12,'unique_pages':8,'all_original_target_pages':
                        {'present':True,'rw':1,'nx':0,'user':0,'leaf_level':2,'leaf_bytes':2097152,'pat_index':0,'identity':True},
                        'cr0_wp_enabled':True,'cpu_state':decoded['cpu'],
                        'cpu_arch_locate_status':0,'cpu_arch_set_attributes_address':'0x614A23D0',
                        'actual_call_scope':'Eight standard CPU Arch attribute assignments, each limited to one middle 4096-byte page in a separate owned three-page allocation.'},
        'owned_results': {'cycles':decoded['owned_cycles'],'fixed_code_bytes':'b80433314ec3',
                          'fixed_code_return':'0x4E313304','only_boot_services_code_cycle_executed':True,
                          'both_owned_allocations_freed':True,'original_target_semantic_snapshots_unchanged':True,
                          'AMITSE_and_Setup_original_text_hashes_unchanged':True,
                          'completion':decoded['complete_status']},
        'entry_context': {'observed_workflow':'Selected UEFI: AMI Virtual CDROM0 1.00 (16MB) from the boot menu, then obtained the P04 screen.',
                          'native_StartImage_return_rva':'0xA8E6','recognized_outer_return_rva':'0x960C',
                          'prior_C07_entry03_outer_return_rva':'0x2D7D',
                          'outer_return_validated_against_exact_CALL_to':'0x9F78',
                          'bounded_chain':'Core StartImage, AMITSE launch and one exact outer return; no arbitrary stack scan.',
                          'AMITSE_stage':7,'app_pointer':0,'browser_idle_proven':False,
                          'interpretation':'This observed boot-menu context differs from the earlier BootNext entry03 return. The recognized return and stage/app values do not establish native-browser inactivity or authorize hooking.'},
        'cd_transport': {'summary':bind(HW / 'cd-observer08-1793704514587.jsonl.json'),
                         'trace':bind(HW / 'cd-observer08-1793704514587.jsonl'),
                         'started_utc':summary['started_utc'],'finished_utc':summary['finished_utc'],
                         'events':88,'protocol_frames':len(frames),'counts':counts,'truncated':False,
                         'capacity8_hex':'0000201f00000800','optical_capacity_bytes':16842752,
                         'READ12_requests':24,'READ12_responses':24,'response_payload_bytes_sum':total_read_payload,
                         'first_READ12_utc':reads[0]['utc'],'last_READ12_utc':reads[-1]['utc'],
                         'f7_sent_utc':f7[0]['utc'],'socket_closed_utc':trace[-1]['utc'],
                         'workflow_scope':'Parent ran CD-only after the second standard BMC restart. The observer is scoped to CD and cannot independently prove absence of every other transport.',
                         'limits':'Metadata shows READ12 traffic and response lengths/status; payload and A8 CDB addresses were deliberately not retained. Bytes summed can include repeats, and do not prove a full ISO transfer or hash. Startup RC10 alone is not host enumeration. The new menu plus complete diagnostic is the stronger execution evidence; no unique cause of earlier failure or later recovery is proven.'},
        'visual_review': [
            {'path':str(HW/'screen-286-boot-watch.png'),'observed':'Boot menu visibly includes UEFI: AMI Virtual CDROM0 1.00 (16MB).'},
            {'path':str(HW/'screen-287-current.png'),'observed':'That CD item is visibly highlighted.'},
            {'path':str(CAPTURE/'page-01.png'),'observed':'PREREQUISITE04; page 1/16; 12125 bytes; CRC 54DC8D8D.'},
            {'path':str(CAPTURE/'page-16.png'),'observed':'PREREQUISITE04; page 16/16; same length/CRC; last-page controls.'},
            {'path':str(HW/'inventory-before-poweroff-1793704905975.png'),'observed':'Same page 16/16 immediately before recorded power-off; independently decoded again.'}],
        'historical_cleanup': {'poweroff_utc':poweroff['utc'],'poweroff_status':200,
                               'cleanup_utc':cleanup['utc'],'recorded_checks':cleanup['verified'],
                               'HD_CD_idle_flags':[128,128],
                               'limit':'This only binds host Off/media/helper cleanup at 11:22:51.716 UTC. Final SD restoration, session logout and later/current state are separate parent records.'},
        'remaining_limits': [
            'No native password/UI/first-Del interception, OEM hook transaction or OEM-page write was attempted.',
            'Page-table bits and positive code/write readback are not deliberate RO-write or NX-execute fault tests.',
            'No AP rendezvous, cross-core TLB validation or instruction-cache coherency proof for a future OEM detour was performed.',
            'Standard attribute service TLB handling and allocator ownership are trusted contracts. A service may split large mappings; semantic restore does not require identical page-table topology, CR3, or internal allocation state.',
            'Foreign snapshots cover the eight target pages and original text hashes, not every firmware page or mutable global. Memory-map capability flags are not substituted for CPU effective permission bits.',
            'The read-only walker assumes the checked pre-virtual-map identity mapping model, rejects unsupported CR4 contexts, and does not make a general arbitrary-address memory-safety claim.',
            'The new context is recognized but does not prove browser inactivity. Extension space and image metadata changes remain unauthorized.',
            'HD geometry, file writeback, SPI backup, real flashing trust and recovery remain unverified by this CD-only prerequisite test.',
            'RAM, page tables/TLB and console/device state change during standard services; no zero-system-effects claim is made.'
        ],
        'native_password_hardware_pass':False,'native_installation_authorized':False,'flash_ready':False,
        'publication08_complete':False,'reviewer_remote_operations':0}
    write(HERE / 'hardware_review.json',r)
    summary_text = (
        'P04 已获得完整实机前置测试结果，但尚未安装或实测原生密码锁。\n\n'
        '独立重新解码 16 张原始 PNG，拼出 12,125 字节，CRC 54DC8D8D，SHA-256 2af56b709f22663d502de32f4e7b22a4e49f256ad6f57deea1168b1af4958c91；与父任务逐页 frame 和完整日志一致。冻结候选 97 项、既有独审 38 项绑定复核通过，原文件未改。\n\n'
        '本机 SAGE SE / BIOS 1904 的 AMITSE 和 Setup 原始代码校验通过。12 处目标位于 8 个独立 4 KiB 页，页表读回均为存在、可写、可执行、supervisor、2 MiB 映射叶子；CR0.WP 已开启。EFI Memory Attribute Protocol 不可用，但 CPU Arch 标准属性服务可定位且能调用。\n\n'
        'Code 与 Data 各申请 3 页，仅中间 1 页接受四次属性转换。两轮 RO+NX → RO+可执行 → RW+NX → 原始权限的读回和邻页检查全部通过；Code 页执行固定六字节函数返回 4E313304，Data 页未执行。两轮均恢复语义权限并 FreePages 成功。原厂 8 页权限快照与两模块 .text 哈希保持一致；保留页、EBS、驻留要求、Warnings 均为 0。\n\n'
        '本次由启动菜单选择 AMI Virtual CDROM，外层返回 RVA=960C，与早先 BootNext 的 2D7D 不同，均在已核对的固定调用路径内。stage=7 / app=null 不能证明原厂浏览器已经空闲，也不授权挂钩。\n\n'
        f'已关闭的 CD 观察窗口记录 88 个事件、86 帧，含 24 次 READ12 请求及 24 次响应，响应数据长度合计 {total_read_payload:,} 字节（可能包含重复读取，不等于完整 ISO 传输）。新菜单与完整 P04 日志确认本次已实际启动；没有证据可把恢复归因于唯一动作。F7 在 11:22:00.366 UTC 发送，11:22:00.445 连接关闭。11:22:51.716 回读为主机 Off、CD 脱离、自有 helper 已解除、HD/CD 空闲标志 128；最终 SD 恢复和退出会话由父任务另记。\n\n'
        '尚未测试故意触发 RO 写入或 NX 执行异常，未验证 AP/跨核 TLB 或未来原厂代码改写的缓存一致性；权限语义恢复不等于页表拓扑完全恢复。仍缺原生密码/Del 入口拦截、HD 正确几何与 SPI 备份，以及实际刷写信任和恢复验证。\n'
    )
    with (HERE/'README.txt').open('x',encoding='utf8',newline='\n') as f:f.write(summary_text)
    artifact_paths=sorted(p for p in HERE.rglob('*') if p.is_file() and p.name!='manifest.json')
    write(HERE/'manifest.json',{'status':'FROZEN_P04_PHYSICAL_PREREQUISITE_REVIEW',
                               'inputs':[bind(p) for p in inputs], 'artifacts':[bind(p) for p in artifact_paths],
                               'review_sha256':sha(HERE/'hardware_review.json'),
                               'scope':'Historical physical prerequisite only. Bindings are not unique-file or unique-test counts; C08 final publication remains separate.'})
    verify()


if __name__=='__main__':main()
