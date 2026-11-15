"""Freeze/verify this independent supplement; does not boot or access any device."""
from pathlib import Path
import argparse,hashlib,json
HERE=Path(__file__).resolve().parent;D04=HERE.parent;ROOT=next(p for p in HERE.parents if (p/'tools/pydeps').is_dir())
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
FINAL='9115f1afbab01b624ed8e3da6cdba74c52e187785c77095e1544a6211a8dc6f3'
ISO='aca8533281df2d2432881a28441143baf104bc3655bc3309620c76055251ae78'
MAN=HERE/'independent_delivery_manifest.json';REPORT=HERE/'independent_delivery_review.json'
def row(p):
    p=Path(p).resolve();assert p.is_relative_to(ROOT)
    return {'path':str(p.relative_to(ROOT)).replace('\\','/'),'bytes':p.stat().st_size,'sha256':sha(p)}
def verify_rows(rows,base=ROOT):
    for r in rows:
        p=base/r['path'];assert p.stat().st_size==r['bytes']and sha(p)==r['sha256'],str(p)
def freeze():
    assert not MAN.exists()and not REPORT.exists(),'Frozen output already exists'
    delivery=json.loads((HERE/'delivery_structure_result.json').read_text());assert delivery['final_efi_sha256']==FINAL
    ui_path=HERE/'full_app_ui_9115f1afbab01b62/ui_test_result.json';ui=json.loads(ui_path.read_text())
    assert ui['actual_app_sha256']==ui['fixture_sha256']==FINAL and ui['cases']==122 and len(ui['results'])==122 and all(x['status']=='PASS'for x in ui['results'])
    vr_path=HERE/'final_binding_9115f1afbab01b62/latest_result.json';vr=json.loads(vr_path.read_text());v=vr['result']
    assert v['actual_app_sha256']==FINAL and v['status']=='PASS_ACTUAL_LOADED_APP_VALIDATOR_IN_OVMF'and v['checks']==85 and v['imports_started']is False and v['exit_code']==33
    assert len(v['relocations_tested'])==17 and len(v['active_mutations_tested'])==12 and len(v['padding_mutations_tested'])==10
    author=D04/'ram_transaction05/ram_candidate_manifest.json';p13=D04/'provider13/local_candidate_manifest.json'
    assert sha(author)=='1b9f3b1979855cf3a20b2101c84983854500f3f57f8fefbcdab6c3bf8cd20925'
    assert sha(p13)=='2f7738e0cdfdb75a9557cf8c7bba233d512c17ac63063fea23d8e77975566e8a'
    manifests=[];external=list(delivery['bindings'])
    for path in [author,p13]:
        data=json.loads(path.read_text());verify_rows(data['artifacts'],D04)
        manifests.append({'path':str(path.relative_to(ROOT)).replace('\\','/'),'sha256':sha(path),'verified_bindings':len(data['artifacts'])})
        external.extend(row(D04/a['path'])for a in data['artifacts']);external.append(row(path))
    external.extend(row(p)for p in [D04/'ram_transaction05/ram_candidate_review.json',D04/'ram_test05_delivery/BasePeCoff.official.c'])
    report={
      'status':'PASS_INDEPENDENT_LOCAL_REVIEW_NO_DELIVERY_BLOCKER_IN_SCOPE',
      'target':'ASUS Pro WS W790E-SAGE SE / BIOS 1904 only; candidate identity, not hardware execution',
      'final_efi_sha256':FINAL,'final_efi_bytes':170496,'final_iso_sha256':ISO,'final_iso_bytes':16842752,
      'hardware_operations_by_reviewer':False,'hardware_installer_or_password_acceptance_established':False,'firmware_release_ready':False,
      'candidate_manifests_verified':manifests,
      'ui_actual_full_app':{'result':row(ui_path),'cases':122,'scope':'Existing unchanged full-app UI functions and actual app_require_services are executed with Unicorn. Firmware/provider service endpoints and pure log sinks are explicit models. App entry and installer do not execute. No production source or binary is recompiled.','new_return_boundary_coverage':'TPL 8/16/31 after OEM SendForm and before/after provider.query all terminate in CPU hold before later variable/service/app work; EBS service-boundary injection is also covered.','source_sha256':'11839c994f66f089383a8ff86ef5bc261ae3f2b0581e3955b99dbaa1e3a4e865'},
      'actual_ovmf_validator':{'result':row(vr_path),'run':vr['run'],'assertions':85,'relocation_targets':17,'declared_content_mutations':12,'undefined_padding_mutations':10,'scope':'Standard OVMF LoadImage maps the exact full app and P13. Actual app read_cpu_env/refresh_map/provider_before_start bytes execute with real map/pagewalk. Imported app/P13 entries never start. Negative changes affect only an owned rebased provider clone; original P13 remains identical.','limits':'85 is a runtime assertion count including setup and restoration, not 85 independent adverse cases; it does not prove ASUS loader or native UI behavior.'},
      'delivery':{'result':row(HERE/'delivery_structure_result.json'),'reviewed_package_count':3,'current_candidate_package_count':1,'historical_package_count':2,'png_ppm_pairs':24,'raw_complete_snapshots':6,'final_run':'20261103_212825','final_raw_snapshots':[{'bytes':527,'crc32':'619F5213','snapshot_id':'0000000000000001'},{'bytes':527,'crc32':'DD693677','snapshot_id':'0000000000000002'}],'structure':'Independent raw FAT16 cluster/directory/FAT-copy/orphan checks and raw ISO ElTorito/catalog/directory checks. One EFI 0xEF no-emulation boot entry; only FAT file is /EFI/BOOT/BOOTX64.EFI and exactly equals final EFI. No legacy BIOS boot entry.','execution':'Recorded final QEMU command uses no NIC/host disk. Read-only OVMF code and optical image; per-run OVMF vars copy is the only writable emulated storage. Exact ISO ran to unsupported-platform refusal, QR/text transitions and key1/key2 unchanged journal.','visual_review':'Final refused-menu.png, text-view.png and qr-return.png manually viewed. Refusal is explicit, only Q is offered, mode/operation are zero; text complete and QR page 1/1 correctly identifies 527 bytes and CRC619F5213.','script_review':'Packager constrains input path and exact hash, preserves original EFI, creates a new hash-keyed package. Runner is bounded, uses captured source snapshots, records exact QEMU command, reaps QEMU and verifies input hashes unchanged.'},
      'historical_evidence':{'packages':['cabc716104efe637','cce126b2d995ab87'],'explanation':'These runs remain intact and are intermediate identities, even where the old cabc result used the word final. The original cabc packager/runner source snapshots were not present; their recorded hashes were retained without reconstructing them from newer sources.','ui_source_change':'The old 95d44821 session_ui.c is archived in ui_revision03/prior/session_ui.c. Its earlier frozen report remains historical: the externally referenced live source intentionally changed under the parent-authorized minimal TPL fix. No old frozen artifact was edited; this new report binds 11839c99 and actual full-app9115 results.','earlier_loadimage_finding':'The original whole-SizeOfImage hash rejected OVMF unspecified alignment/raw padding and rewritten ImageBase. New validator validates declared headers, sections and BSS, legal ImageBase normalization and exact relocation targets. Old discovery and ba5e/cce evidence remain separate and are not relabeled final.'},
      'remaining_limits':[
        'Final native transaction installation/removal and real ASUS password/entry behavior are not established by this local supplement. A production OVMF refusal is not a hardware pass.',
        'The earlier P13 real FormBrowser test opened a separate test formset via M. It does not prove a permanent Security menu insertion, cold boot integration, or direct Del/F2 protection.',
        'The UI model observes OC/MEM before/after reads and one exactly owned private-record deletion; it does not prove every internal OEM NVRAM write absent, nor atomic protection against hostile concurrent record replacement.',
        'The normal firmware-load and negative tests validate only their recorded OVMF CPU/map/loader configuration. AP/TLB races and hardware protection enforcement still require appropriate target evidence.',
        'This is a volatile native test candidate, not a flashable BIOS release. Flash trust, complete SPI backup and recovery verification are outside this review.'
      ]}
    REPORT.write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n')
    text='''本轮独立交付审查通过，范围内未发现阻断项。当前候选只有 EFI `9115f1af…` 与 ISO `aca85332…`；它是 SAGE SE 1904 的临时 RAM 测试工具，不是可刷写固件。

已直接执行最终完整应用中的 UI 函数，122 项模型断言全部通过，包括表单/接口返回后异常 TPL 与 ExitBootServices 边界。服务端点和日志输出为明确的模型，未把模型称为原厂 BIOS 实测。另在真实 OVMF 中标准 LoadImage 加载最终应用与冻结 P13，执行实际平台校验函数，85 项运行断言通过；覆盖 17 个重定位目标、12 个已声明内容修改、10 个未定义填充修改以及恢复检查。两个导入的 EFI 入口均未启动。

最终 ISO 原始 ElTorito 启动目录只有 EFI 入口。内部 FAT16 仅含 EFI/BOOT/BOOTX64.EFI，与最终编译输出逐字节相同。当前及两代历史包共 24 对 PNG/PPM 像素一致，6 个二维码快照的字节数、CRC 和文本一致。最终 OVMF 只到达不支持平台的拒绝页，1/2 键未改变操作日志；这不代表安装或密码测试成功。最终拒绝菜单、文本页、二维码已人工看图。

旧 cabc/cce/9ef 身份均不作为最终准入证据。早期 UI 源码和载入语义失败证据保留，新的最小 TPL 修正与最终完整应用单独绑定。作者最终清单 76 项、冻结 P13 清单 60 项均重新计算并匹配。

实机安装/回滚、原厂 Ai Tweaker 的实际拦截、永久 Security 菜单入口、直接 Del/F2 的开机集成仍需各自证据；临时 M 菜单和本地 OVMF 成功不能替代。刷写信任、完整 SPI 备份与恢复也不在本轮通过范围。本人没有连接或操作目标机器。
'''
    (HERE/'review_zh.md').write_text(text,encoding='utf-8')
    own=[HERE/n for n in ['verify_delivery.py','finalize_review.py','prepare_full_ui.py','delivery_structure_result.json','independent_delivery_review.json','review_zh.md']]
    for name in ['ui_revision03','full_app_ui_9115f1afbab01b62','final_binding_9115f1afbab01b62']:
        own.extend(p for p in (HERE/name).rglob('*')if p.is_file()and not any('zig-'in x or x=='__pycache__'for x in p.parts))
    allrows={x['path']:x for x in external+[row(p)for p in own]}
    manifest={'status':'FROZEN_INDEPENDENT_LOCAL_DELIVERY_SUPPLEMENT','path_base':'workspace root','final_efi_sha256':FINAL,'final_iso_sha256':ISO,'candidate_manifest_bindings_verified':76,'p13_manifest_bindings_verified':60,'note':'Counts of referenced manifests can overlap. Artifacts below are deduplicated by path; no physical acceptance or release approval is asserted.','artifacts':list(sorted(allrows.values(),key=lambda x:x['path']))}
    MAN.write_text(json.dumps(manifest,ensure_ascii=False,indent=2)+'\n')
    verify()
def verify():
    m=json.loads(MAN.read_text());verify_rows(m['artifacts'])
    print(json.dumps({'status':'PASS_FROZEN_INDEPENDENT_SUPPLEMENT','bindings':len(m['artifacts']),'manifest_sha256':sha(MAN),'review_sha256':sha(REPORT),'final_efi_sha256':FINAL,'final_iso_sha256':ISO}))
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--verify-only',action='store_true');a=p.parse_args();verify()if a.verify_only else freeze()
