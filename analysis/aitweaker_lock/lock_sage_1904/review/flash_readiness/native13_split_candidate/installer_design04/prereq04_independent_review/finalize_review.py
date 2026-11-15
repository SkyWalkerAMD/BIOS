"""Publish or verify this independent local review; never writes the candidate."""
from pathlib import Path
import argparse, hashlib, json, re

HERE = Path(__file__).resolve().parent
PROBE = HERE.parent / 'prerequisite_probe04'
MANIFEST_SHA = '1c70adb50d8e17c2672b091c4bc0ab8fa201a5035b3bfda1a67e017fb3033ba9'
EFI_SHA = 'a8a828427a412eaffb36bc244a91175507a940238ae30c51c3e64d0520fea800'
ISO_SHA = '852ed9fdbf39cad8764bf0b1cf21c2b3fb1b95f939c9536e13ad22dbf943307c'
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
load = lambda p: json.loads(p.read_text(encoding='utf8'))


def verify_bindings(base, entries):
    names = set()
    for entry in entries:
        path = (base / entry['path']).resolve()
        assert path.is_relative_to(base.resolve()), path
        assert str(path).lower() not in names, path
        names.add(str(path).lower())
        assert path.stat().st_size == entry['bytes'] and sha(path) == entry['sha256'], path
    return len(entries)


def main():
    parser = argparse.ArgumentParser(); parser.add_argument('--verify-only', action='store_true'); args = parser.parse_args()
    candidate_manifest = PROBE / 'prerequisite04_manifest.json'
    assert sha(candidate_manifest) == MANIFEST_SHA
    manifest = load(candidate_manifest)
    count = verify_bindings(PROBE, manifest['artifacts']); assert count == 97
    assert manifest['entrypoint_iso_sha256'] == ISO_SHA
    if args.verify_only:
        own = load(HERE / 'review_manifest.json')
        reviewed = verify_bindings(HERE, own['artifacts'])
        assert own['candidate_manifest_sha256'] == MANIFEST_SHA
        print(json.dumps({'status': 'PASS_FROZEN_INDEPENDENT_REVIEW_RECHECK', 'candidate_bindings': count, 'review_bindings': reviewed, 'review_manifest_sha256': sha(HERE / 'review_manifest.json')}))
        return

    build = load(PROBE / 'build/build.json')
    for source in build['sources']:
        assert sha(PROBE / source['path']) == source['sha256'], source
    assert build['efi_sha256'] == EFI_SHA and build['iso_sha256'] == ISO_SHA
    own_walker = load(HERE / 'walker_final_result.json')
    assert own_walker['status'] == 'PASS_INDEPENDENT_COMPILED_WALKER' and own_walker['binary_sha256'] == EFI_SHA
    assert own_walker['case_count'] == len(own_walker['cases']) == 87 and all(case['passed'] for case in own_walker['cases'])
    own_boundary = load(HERE / 'map_final_boundary_replay.json')
    assert own_boundary['binary_sha256'] == EFI_SHA and len(own_boundary['cases']) == 3
    for case in own_boundary['cases']:
        assert not case['service_after_ending'] and case['expected_nonempty_service_path_observed'] and case['ending_flag_observed'] == 1
        assert case['returned_to_sentinel'] and case['return_value'] == 0
    transport = load(HERE / 'transport_binding_result.json')
    assert transport['status'] == 'PASS_INDEPENDENT_ISO_FAT_QR_BINDING' and transport['efi_sha256'] == EFI_SHA and transport['iso_sha256'] == ISO_SHA
    assert (transport['qr_pages'], transport['log_bytes'], transport['log_crc32']) == (6, 4071, '3A6F8B03')
    references = load(HERE / 'reference_binding_result.json')
    assert references['reference_count'] == 4
    for reference in references['references']:
        path = Path(reference['path']); raw = path.read_bytes()
        assert sha(path) == reference['sha256'] and len(raw) == reference['bytes']
        assert hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest() == reference['git_blob_sha']

    tests_path = PROBE / 'tests/verification.json'
    tests = load(tests_path)
    assert tests['efi_sha256'] == EFI_SHA and tests['case_count'] == len(tests['cases']) == 66
    assert tests['source_sha256'] == sha(PROBE / 'verify_prerequisite.py')
    logs, callback_cases, rows = {}, 0, []
    for case in tests['cases']:
        assert case['passed']
        if 'log_sha256' not in case:
            continue
        path = PROBE / 'tests' / (case['case'] + '.log')
        assert sha(path) == case['log_sha256']
        raw = path.read_bytes(); logs[case['case']] = raw
        assert raw.endswith(b'SAGE_NATIVE13_PREREQUISITE04_END\r\n') and b'LOG_COMPLETE=YES\r\n' in raw and b'LOG_OVERFLOW=NO\r\n' in raw
        assert case['no_boot_services_after_ending'] and case['zero_original_image_or_service_table_writes']
        for address, length, attrs in case['attribute_requests']:
            assert int(address, 16) == 0x7001000 and length == 4096 and int(attrs, 16) & ~0x24000 == 0
        if case['ending_callback_executed']:
            callback_cases += 1
            assert b'EBSObserved=0000000000000001\r\n' in raw and b'ResidentHoldRequired=0000000000000001\r\n' in raw
        rows.append({'case': case['case'], 'log_sha256': case['log_sha256'], 'attribute_request_count': len(case['attribute_requests']), 'ending_callback_executed': case['ending_callback_executed']})
    for name in ['neighbor_permission_change_retains_pages', 'attribute_error_step_4', 'close_event_failure_requires_resident_hold', 'post_service_original_text_mismatch_requires_hold']:
        assert b'ResidentHoldRequired=0000000000000001\r\n' in logs[name], name
    assert b'ResidentHoldRequired=0000000000000000\r\n' in logs['free_pages_failure_retains_pages']
    assert b'RetainedOwnedPages=0000000000000003\r\n' in logs['free_pages_failure_retains_pages']
    normal = logs['normal_code_and_data_owned_cycles']
    assert normal.count(b' ORIGINAL_OK\r\n') == 12 and b'OriginalUniquePatchPagesObserved=0000000000000008\r\n' in normal
    assert normal.count(b'PASS owned allocation cycle complete\r\n') == 2

    target_text = (PROBE / 'source/targets.h').read_text(encoding='utf8')
    patches = [(name, int(module), int(rva), int(size)) for name, module, rva, size in re.findall(r'\{"(gate_[^"]+)",(\d+)u,(\d+)u,(\d+)u,', target_text)]
    assert len(patches) == 12 and len({(module, rva // 4096) for name, module, rva, size in patches}) == 8
    assert all(rva // 4096 == (rva + size - 1) // 4096 for name, module, rva, size in patches)
    ovmf_dir = Path(transport['run'])
    visual = [{'path': str(ovmf_dir / name), 'sha256': sha(ovmf_dir / name), 'observed': note} for name, note in [
        ('qr-01.png', 'Manually viewed: PREREQUISITE04 title; page 1/6; 4071 bytes; CRC 3A6F8B03; readable complete QR and controls.'),
        ('text.png', 'Manually viewed: OWNED RAM ONLY title; complete text viewport and navigation instructions; expected OVMF target warnings.'),
        ('qr-06.png', 'Manually viewed: page 6/6 and final-page instruction; complete QR inside viewport.')]]
    resolved = [
        {'id': 'R1', 'finding': 'refresh_map originally could issue another boot service after a callback marked ending.', 'resolution': 'Check ending after GetMemoryMap, FreePool and AllocatePool; reject collector reentry. Final exact-byte three-path replay passes.'},
        {'id': 'R2', 'finding': 'Unverified permission restoration or foreign-state inconsistency must not return into native firmware.', 'resolution': 'Failed restore, foreign page/CPU-state mismatch, original text mismatch, event-close failure or ending keeps the application resident. A plain FreePages error retains restored, unreferenced owned pages.'},
        {'id': 'R3', 'finding': 'RW/NX alone did not cover U/S or SMEP/SMAP/PKE/CET/PKS.', 'resolution': 'Track effective U/S through every level, reject a user middle page, compare U/S on restore and conservatively reject all five unmodeled CR4 contexts.'},
        {'id': 'R4', 'finding': 'Known DxeCore/BdsArch image ranges were absent from suspicious allocation-return exclusions.', 'resolution': 'Validated extra module ranges are excluded; actual collector fault cases reject returned DxeCore/BdsArch addresses before write/service request.'},
        {'id': 'R5', 'finding': 'Inherited UI said ENTRY CONTEXT03 / READ ONLY although this probe writes owned RAM.', 'resolution': 'Final QR/text/exit labels identify PREREQUISITE04 and OWNED RAM ONLY; final screenshots manually reviewed.'},
    ]
    report = {
        'status': 'PASS_INDEPENDENT_REVIEW_BOUNDED_OWNED_RAM_PREREQUISITE',
        'review_blocks_bounded_prerequisite_probe': False,
        'physical_probe_run_by_this_review': False,
        'native_installation_ready': False, 'password_lock_hardware_pass': False, 'production_release': False,
        'candidate_manifest': str(candidate_manifest), 'candidate_manifest_sha256': MANIFEST_SHA, 'candidate_bindings_verified': count,
        'efi_sha256': EFI_SHA, 'iso_sha256': ISO_SHA,
        'source_review': {'files': ['source/preflight.c', 'source/pagewalk.inc', 'source/owned_fixture.inc', 'source/efi.h', 'source/targets.h', 'source/transport/kvm.c'],
                          'target_patch_sites': len(patches), 'unique_original_pages_for_aligned_images': 8, 'all_sites_fit_single_4k_page': True,
                          'standard_interfaces': 'CPU Arch SetMemoryAttributes full assignment on only owned middle page; MemoryAttribute Get on observed original pages is read-only; no MemoryAttribute Set/Clear call.',
                          'official_reference_blobs_rechecked': 4},
        'independent_execution': {'walker_cases': 87, 'map_callback_boundary_cases': 3, 'exact_compiled_efi': True, 'synthetic_cpu_environment_and_services': True},
        'author_test_evidence_reviewed': {'total_cases': 66, 'collector_log_cases': len(logs), 'walker_cases': 66 - len(logs), 'ending_callback_cases': callback_cases,
                                          'tests_sha256': sha(tests_path), 'collector_logs': rows,
                                          'scope': 'Author tests reviewed and bound to final EFI; not rerun here and not counted as 66 additional independent executions.'},
        'ovmf_evidence': {'qr_pages_independently_decoded': 6, 'bytes': 4071, 'crc32': '3A6F8B03', 'log_sha256': transport['log_sha256'],
                          'owned_code_and_data_cycles': 2, 'original_asus_patch_pages_observed': 0, 'fixed_code_return': '0x4E313304',
                          'clean_restore_free_recorded': True, 'exact_iso_and_fat_efi_binding': True, 'visual_review': visual},
        'resolved_review_findings': resolved,
        'remaining_limits': [
            'This is only an owned-RAM prerequisite probe; no native password, HII management UI, hook transaction, first Del-entry interception, or firmware flash is implemented or accepted by this review.',
            'Page-table reads assume the x64 pre-virtual-map identity mapping model. Each table page is bounded by a nonoverlapping readable EFI memory-map descriptor. Positive lower canonical addresses are supported; upper-half addresses are conservatively rejected.',
            'RO/NX/U/S/PAT readback is semantic, not proof of unchanged page-table topology. A standard service can split a large mapping and allocate its own page-table memory.',
            'The probe relies on the standard allocator ownership contract and the standard attribute service maintaining TLB state; known-range exclusions add checks but cannot prove an arbitrarily malicious firmware service safe.',
            'No deliberate RO write or NX execution fault is attempted. PTE checks do not independently prove cross-core or every stale TLB state. CR0.WP disabled means RO bits do not prove supervisor write enforcement.',
            'The exact OVMF boot exercised the generic CPU service and owned code but contained zero ASUS target pages. ASUS hardware behavior remains a separate physical probe.',
            'Standard services and the display change temporary RAM, page tables/TLB and device/console state. No zero-system-effects claim is made.',
            'The review is local-only and makes no statement about current BMC power/media state or flash trust/recovery readiness.'
        ],
        'evidence': [{'path': name, 'sha256': sha(HERE / name)} for name in ['walker_final_result.json', 'map_final_boundary_replay.json', 'transport_binding_result.json', 'reference_binding_result.json', 'independently_decoded_ovmf.log']],
    }
    (HERE / 'independent_review.json').write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n', encoding='utf8')
    text = f'''独立审查通过，范围仅限 prerequisite04 的自有临时内存前置测试。未发现阻止该限定探针继续实机验证的未解决代码问题。本轮没有访问 BMC、运行实机或授权原生安装；密码锁、首次 Del 入口和刷写仍未获得本报告验收。

已逐件核验候选冻结清单 97 项。EFI SHA-256：{EFI_SHA}；ISO SHA-256：{ISO_SHA}。ISO 的 El Torito 引导项、两份 FAT 和唯一的 /EFI/BOOT/BOOTX64.EFI 均已独立读取并绑定。

针对最终 EFI 字节，独立运行 87 个页表用例和 3 个内存地图回调边界用例；另审阅作者 66 项测试的脚本、结果与日志绑定。两组测试覆盖有重叠，不能相加声称为同一套独立覆盖率。页表用例含 4K/2M/1G、LA57、PAT、逐级 RW/NX/U/S 及保留位和错误地图；CET/SMEP/SMAP/PKE/PKS 均保守拒绝。

审查期间修正了 EBS 回调后继续调用服务的路径、恢复或外部状态异常后的驻留行为、额外 CPU 保护位、已知 Core/BDS 地址排除，以及旧的 READ ONLY 界面标题。最终原厂 12 个站点落在 8 个页内，均不跨 4K 页。属性设置只请求自有三页分配的中间页，原厂页保持观察范围。

最终 OVMF 的 6 张二维码已独立重组为 4071 字节，CRC 3A6F8B03，与 probe.log 和 debug 输出逐字节一致。两个代码/数据分配循环均记录恢复和释放成功，固定代码返回 0x4E313304；首末二维码及文本标题已目视核验。OVMF 中原厂页观测数为 0，这不能算作 ASUS 主板通过。

测试会改变临时 RAM，并通过标准固件服务改变该自有页的权限；服务可能拆分大页、分配页表并维护 TLB。检查的是恢复后的有效语义，不要求页表布局逐字节相同，也未故意触发只读写入或 NX 执行异常。依赖正常的标准内存服务合同和预虚拟映射的 x64 恒等映射模型，不能证明任意错误固件服务、所有跨核 TLB 状态或真实刷写恢复路径。

机器可读证据见 independent_review.json；本目录冻结清单见 review_manifest.json。历史初版/候选快照仅保留审查经过，最终判断绑定上述 EFI/ISO。
'''
    (HERE / 'README.txt').write_text(text, encoding='utf8')
    artifacts = []
    for path in sorted(HERE.rglob('*')):
        if not path.is_file() or path.name == 'review_manifest.json' or '__pycache__' in path.parts:
            continue
        artifacts.append({'path': str(path.relative_to(HERE)), 'bytes': path.stat().st_size, 'sha256': sha(path)})
    own = {'status': 'FROZEN_INDEPENDENT_PREREQUISITE_REVIEW', 'path_base': 'prereq04_independent_review',
           'candidate_manifest_sha256': MANIFEST_SHA, 'independent_review_sha256': sha(HERE / 'independent_review.json'), 'artifacts': artifacts}
    (HERE / 'review_manifest.json').write_text(json.dumps(own, indent=2) + '\n', encoding='utf8')
    print(json.dumps({'status': report['status'], 'candidate_bindings': count, 'independent_review_sha256': sha(HERE / 'independent_review.json'), 'review_artifacts': len(artifacts), 'review_manifest_sha256': sha(HERE / 'review_manifest.json')}, indent=2))


if __name__ == '__main__':
    main()
