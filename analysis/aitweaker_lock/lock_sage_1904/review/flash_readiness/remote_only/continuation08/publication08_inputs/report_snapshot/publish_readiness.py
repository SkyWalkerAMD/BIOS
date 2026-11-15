"""Summarize release gates without relabeling or rewriting EXP02 artifacts."""
from pathlib import Path
from datetime import datetime, timezone
import hashlib
import html
import json

HERE = Path(__file__).resolve().parent
CASE = HERE.parents[1]
BASE = CASE.parent

def read(path):
    return json.loads(path.read_text(encoding='utf-8'))

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def save(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2)+'\n', encoding='utf-8')

def verify_bound_tree(value):
    if isinstance(value, dict):
        if 'path' in value and 'sha256' in value:
            path = Path(value['path']).resolve()
            assert path.is_relative_to(BASE.resolve()) and sha(path) == value['sha256'], str(path)
            if 'bytes' in value: assert path.stat().st_size == value['bytes']
        for item in value.values(): verify_bound_tree(item)
    elif isinstance(value, list):
        for item in value: verify_bound_tree(item)

def main():
    capsule = read(HERE/'capsule_static_review.json')
    openssl = read(HERE/'openssl_signature_crosscheck.json')
    assert capsule['status'] == 'STATIC_REVIEW_COMPLETE_EXP02_FAILS_ORIGINAL_CAPSULE_SIGNATURE'
    assert openssl['static_review_sha256'] == sha(HERE/'capsule_static_review.json')
    assert openssl['status'] == 'PASS_ALL_FOUR_RESULTS_AGREE_WITH_PURE_PYTHON_VERIFIER'
    assert {c['name']: c['signature_valid'] for c in openssl['checks']} == {
        'original_firmware': True, 'exp02_firmware': False,
        'original_certificate': True, 'exp02_certificate': True,
    }
    candidate = read(HERE/'ebs_candidate/build/build.json')
    assert sha(HERE/'ebs_candidate/build/AiTweakerLock1904.efi') == candidate['candidate_driver_sha256']
    assert sha(HERE/'ebs_candidate/services.c') == candidate['candidate_source_sha256']
    selected_sha = candidate['candidate_driver_sha256']
    selected_scope = 'EBS handoff hardening only; isolated local candidate; not a signed or hardware-validated firmware release'
    late_path = HERE/'late_attach_candidate/candidate_summary.json'
    late = read(late_path) if late_path.exists() else None
    if late:
        assert late['status'] == 'PASS_LOCAL_SESSION_OWNER_CANDIDATE_NOT_DEPLOYED'
        for name, digest in late['files'].items():
            file = (late_path.parent/name).resolve()
            assert file.is_relative_to(late_path.parent.resolve()) and sha(file) == digest
        selected_sha = late['candidate_driver_sha256']
        assert sha(late_path.parent/'build/AiTweakerLock1904.efi') == selected_sha
        selected_scope = 'EBS and session-owner hardening; isolated local candidate, not accepted on physical firmware or approved for production flashing'
    integration_path = CASE/'lab/asus_review_exp03_ebs/integration_review.json'
    integration = read(integration_path) if integration_path.exists() else None
    if integration:
        assert late and integration['status'] == 'PASS_FULL_THREE_WAY_STRUCTURE_COMPARISON_INTERNAL_UNSIGNED_REVIEW_ONLY'
        assert integration['driver']['sha256'] == selected_sha
        for item in [*integration['images'].values(), integration['driver'],
                     *integration['independent_uefiextract_reports'].values(), integration['driver_binding_review']]:
            path = Path(item['path'])
            assert path.stat().st_size == item['bytes'] and sha(path) == item['sha256']
        assert integration['no_flash_or_signing_or_root_publication'] is True
        # Keep the original independent report immutable; mirror it for local report links.
        (HERE/'exp03_integration_review.json').write_bytes(integration_path.read_bytes())
    # These are findings, not authorizations to upload/flash or change host state.
    gates = [
        {'item':'原厂 CAP 签名', 'status':'未通过', 'detail':'原版两级签名通过；EXP02 的固件内容签名失败。Python 与 OpenSSL 独立结果一致。保留原签名头不能认证修改后的固件。'},
        {'item':'本机 BMC 更新路径', 'status':'仅完成只读核查', 'detail':'正常流程先上传完整 CAP 并调用 VerifySignature，成功后才进入固件主体上传和单独刷写确认。尚未向后端上传映像，未实测接受或拒绝。'},
        {'item':'完整备份与恢复', 'status':'未完成', 'detail':'尚未取得这台机器的完整 SPI 备份，也未验证独立恢复路径。BMC 配置备份不等于主板 BIOS/SPI 备份。'},
        {'item':'退出 UEFI 的故障处理', 'status':'已制作隔离修复候选', 'detail':'EXP02 在恢复 RuntimeServices 指针失败后仍继续退出。新候选提前恢复并核验，最终不可恢复时停止交接。未知第三方挂钩可能触发保守停止；其他组件在最终回调之后重新改写指针不在当前证明范围内。旧版硬件通过结论不能直接继承。'},
        {'item':'首次 Del/F2 自动拦截', 'status':'尚未实机验收', 'detail':'本地模拟已识别挂钩发生太晚及首次安装失败后不重试的边界。必须证明真实固件在第一次 Setup 访问前完成安装。'},
        {'item':'正常启动、保存和持久密码', 'status':'尚未实机验收', 'detail':'全局变量写保护与实际 OEM 保存/训练时序仍待验证；实际 ASUS NVRAM 跨冷启动保存和完整图形入口覆盖也未完成。'},
    ]
    evidence_names = [
        'capsule_static_review.json', 'openssl_signature_crosscheck.json',
        'before_exit_core_support.json', 'bmc_update_path_review.json',
        'bmc_rea_recovery.json', 'runtime_navigation/runtime_paths.json',
        'ebs_candidate/build/build.json', 'ebs_candidate/services.c', 'ebs_candidate/services.patch',
        'ebs_candidate/candidate_summary.json',
    ]
    if late:
        evidence_names.extend([
            'late_attach_candidate/candidate_summary.json',
            'late_attach_candidate/source_manifest.json',
            'late_attach_candidate/build/build.json',
            'late_attach_candidate/late_attach_regression.json',
            'late_attach_candidate/ebs_regression.json',
            'late_attach_candidate/full_regression/summary.json',
            'late_attach_build_binding_review.json',
            'entry_save_timing/entry_save_timing_review.json',
            'entry_save_timing/late_attach_candidate_review.json',
        ])
        gates[4] = {'item':'首次 Del/F2 自动拦截', 'status':'时序已缩小，尚未实机验收',
                    'detail':'原厂 BDS 常规路径先发 EndOfDxe、后进 Setup；已发现并修复初始化中途安装时错过会话入口的条件性缺口。首次发现已经到 stage5 而完全未安装挂钩、首次安装失败不重试仍保留，必须证明实际冷启动在第一次 Setup 前完成安装。'}
        gates[5] = {'item':'保存、正常启动和持久密码', 'status':'部分路径已证明，实机验收未完成',
                    'detail':'原始 F10 调用链先提交设置、后返回浏览器；但 OEM 保存循环不检查部分写入返回码，必须实际读回。正常启动中的受保护变量写入、ASUS NVRAM 密码跨冷启动保存及完整图形入口覆盖仍未验收。'}
        gates.append({'item':'无确认会话时的保护', 'status':'新候选已修复，本地回归通过',
                      'detail':'界面、HII、RouteConfig、密码持久化和 SetVariable 使用同一会话归属检查；无 wrapper 时残留 active/unlocked 不可授权。显式关闭锁的正常访问保持放行。新候选通过 269 项新增检查、83 项退出回归及原六组回归；未继承旧二进制实机结论。'})
    late_vm_path = HERE/'late_attach_candidate/ovmf_handoff_result.json'
    late_vm = read(late_vm_path) if late_vm_path.exists() else None
    if late_vm:
        assert late and late_vm['status'] == 'PASS' and late_vm['checks'] == 18
        assert late_vm['candidate_driver_sha256'] == selected_sha
        assert late_vm['candidate_services_obj_sha256'] == sha(HERE/'late_attach_candidate/build/services.obj')
        assert late_vm['fixture_source_sha256'] == sha(HERE/'late_attach_candidate/ovmf_handoff.c')
        assert late_vm['fixture_sha256'] == sha(HERE/'late_attach_candidate/ovmf_build/OVMF-EBS-ONLY.EFI')
        assert late_vm['debug_sha256'] == sha(Path(late_vm['debug_log']))
        evidence_names.extend(['late_attach_candidate/ovmf_handoff_result.json',
                               'late_attach_candidate/ovmf_handoff_binding.json',
                               'late_attach_candidate/ovmf_handoff.c',
                               'late_attach_candidate/run_ovmf_handoff.py'])
    if integration:
        evidence_names.append('exp03_integration_review.json')
        gates[0]['detail'] = '原版两级签名通过；EXP02、EXP03 保留的固件内容签名均失败。原始签名头不能认证修改后的固件；局部重新签名验证与完整 BMC 更新链的接受条件应分别判断。'
        gates.append({'item':'EXP03 内部映像集成', 'status':'结构校验通过，仍为 UNSIGNED',
                      'detail':'内嵌驱动精确匹配最新候选；22 个 ROM 区域完整覆盖，仅原容器所在区域变化，622 个原有非容器 FFS 保留。UEFIExtract、PE/FV/FFS 校验通过。它尚未签名、部署或完成永久锁实机验收。'})
    # Candidate tests are selected after their exact names and scope are reviewed.
    optional = HERE/'candidate_validation_selection.json'
    if optional.exists():
        for item in read(optional)['evidence']:
            path = (HERE/item['path']).resolve()
            assert path.is_relative_to(HERE.resolve()) and sha(path) == item['sha256']
            evidence_names.append(item['path'])
    remote_path = HERE/'remote_only/remote_result.json'
    remote = read(remote_path) if remote_path.exists() else None
    if remote:
        assert remote['firmware_flashing_performed'] is False
        assert remote['firmware_upload_performed'] is False
        for item in remote['evidence']:
            path = (HERE/item['path']).resolve()
            assert path.is_relative_to(HERE.resolve()) and sha(path) == item['sha256']
            evidence_names.append(item['path'])
        evidence_names.append('remote_only/remote_result.json')
        gates[1] = {'item':'本机 BMC 更新路径', 'status':'关键路径已追踪，整链实测未完成',
                    'detail':'官方 BMC 1.1.57 的前端与实机捕获逐字节一致，后台二进制尚未从实机读回。Enter/Prepare 会改变更新状态及 GPIO/SPI 归属；所审备份函数保存上传映像。原始 ARM 验签函数的四组本地回放表明：重新签名数据能通过局部 CAP 自洽检查；但后续还有条件启用的本地公钥验签分支，其实机开关未知。不能认定必须 OEM 私钥，也不能认定自签映像已可部署。没有进入更新流程。'}
        gates[2] = {'item':'完整备份与恢复', 'status':remote['backup_status_zh'], 'detail':remote['backup_detail_zh']}
        gates.insert(3, {'item':'免刷诊断上机测试', 'status':remote['inventory_status_zh'], 'detail':remote['inventory_detail_zh']})
        if 'media_status_zh' in remote:
            gates.append({'item':'BMC 虚拟硬盘文件写回', 'status':remote['media_status_zh'], 'detail':remote['media_detail_zh']})
    native_dir = HERE/'cold_entry_candidate/implementation/build/integration_native11_review'
    native_path = native_dir/'integration_review.json'
    native = read(native_path) if native_path.exists() else None
    provider = None
    if native:
        assert sha(native_path) == '25b32318780fc732b0837eb6f514cf38435cad34c47d6b9768e607306d9946f1'
        assert native['status'] == 'INTERNAL_NATIVE11_INTEGRATION_REVIEW_COMPLETE_NOT_RELEASE_READY'
        assert not native['flash_release_ready'] and native['no_upload_or_flash']
        verify_bound_tree(native)
        verification = read(Path(native['independent_verification']['path']))
        assert verification['all_image_bytes_accounted_for'] and verification['candidate_sha256'] == native['candidate']['sha256']
        provider_path = HERE/'native_provider_candidate/provider_review.json'
        assert sha(provider_path) == '88a092ca41e2ba8016d5ea180ac52af8409ecaede71246d5e2dc4002b800ab73'
        provider = read(provider_path)
        verify_bound_tree(provider)
        provider_manifest = HERE/'native_provider_candidate/candidate_manifest.json'
        assert sha(provider_manifest) == 'b92985730b1902b9f5786cf09a2902fe25d12e19e86c19a76f0ad80a56202f04'
        verify_bound_tree(read(provider_manifest))
        assert native['provider_sha256'] == provider['efi']['sha256']
        for name, digest in native['modules'].items():
            assert provider['bound_static_modules'][name]['module_sha256'] == digest
        guard_path = Path(native['native_guard_review']['path']); guard = read(guard_path)
        assert guard['guard_points'] == 11 and guard['frozen_module_sha256'] == native['modules']
        for entry in guard['evidence']:
            assert sha(guard_path.parent/entry['report']) == entry['sha256']
            assert sha(guard_path.parent.parent/entry['source']) == entry['source_sha256']
        evidence_names.extend([
            str(native_path.relative_to(HERE)).replace('\\','/'),
            str((native_dir/'verification.json').relative_to(HERE)).replace('\\','/'),
            str(guard_path.relative_to(HERE)).replace('\\','/'),
            'native_provider_candidate/provider_review.json',
            'native_provider_candidate/candidate_manifest.json',
        ])
        latest = {
            '原厂 CAP 签名': ('新映像未通过原签名', '原版映像及证书签名通过；最新 NATIVE11 内部映像保留的内容签名失败。局部自签验证不代表完整 BMC 更新链已接受。'),
            '退出 UEFI 的故障处理': ('新架构故障回归通过', '最新模块不替换 RuntimeServices 表。已先复现旧候选的 30 个结束边界反例，再修复并完成 58 个实际 EFI 边界检查；OVMF 的 41 项检查覆盖模块加载、provider 启动及退出撤销，不运行完整 ASUS GUI。'),
            '首次 Del/F2 自动拦截': ('原生拦截已整合，冷启动未验收', '11 处原生拦截随 AMITSE/Setup 静态存在；密码模块缺失或无有效会话时拒绝受保护访问。完整 DXE 调度、第一次 Del/F2 进入和图形界面尚未实机验证。'),
            '保存、正常启动和持久密码': ('有已知兼容性缺口', '已覆盖 Setup 路由、内存配置直接写入、F10 提交及 F5/菜单默认值入口；原厂保存循环会忽略部分拒绝返回码，可能显示成功。CMOS/缺失变量初始化、另一条直达协议路径、缺少安全页面时的退出及跨冷启动密码保存尚未验收。'),
            '无确认会话时的保护': ('新模块本地联合验证通过', '原生 wrapper 保存独立会话链，provider 校验归属后才授权。真实活跃但无 provider 的页面中，密码菜单更新会延后至空闲；旧错误已留存反例，新模块完成联合回放。'),
        }
        for gate in gates:
            if gate['item'] in latest: gate['status'], gate['detail'] = latest[gate['item']]
            if gate['item'] == 'EXP03 内部映像集成':
                gate['item'] = '历史 EXP03 映像'
                gate['detail'] = '内嵌历史 e41 动态驱动的结构校验记录保留；它与当前 NATIVE11 架构不同，不能套用最新模块的通过结论，也未获正式刷写验收。'
        gates.append({'item':'最新 NATIVE11 完整映像', 'status':'内部结构集成完成，非正式刷写版',
                      'detail':'67,112,960 字节；两处预定范围外逐字节相同，620 个其他原始 FFS 完全保留，两个原生模块与独立密码模块重新提取均匹配。PE/FV/FFS 校验通过，仍未验证 ASUS 整机冷启动、更新接受及恢复。'})
    native12_path = HERE/'native12_safety_review/implementation/build/integration_native12_review/integration_review.json'
    native12 = read(native12_path) if native12_path.exists() else None
    if native12:
        assert sha(native12_path) == '5a92157844fe769360fe4ea5bf77e220ad7ed07c8ea35621464535eb04f85173'
        assert native12['status'] == 'INTERNAL_NATIVE12_INTEGRATION_REVIEW_COMPLETE_NOT_RELEASE_READY'
        assert native12['no_upload_or_flash'] and not native12['flash_release_ready']
        verify_bound_tree(native12)
        provider12_path = HERE/'native_provider12_candidate/provider_review.json'
        assert sha(provider12_path) == '8c000b183f6e4b7abc2a751284e82418789a0ed72c9a6b0a2f237fb0c2e5dea7'
        provider = read(provider12_path); verify_bound_tree(provider)
        verify_bound_tree(read(Path(native12['provider_manifest']['path'])))
        parent = read(HERE/'native12_parent_review.json'); verify_bound_tree(parent)
        assert parent['status'] == 'PASS_PARENT_NATIVE12_BINDINGS_RANGES_AND_TEST_IDENTITY_NOT_RELEASE_ACCEPTANCE'
        assert parent['image']['sha256'] == native12['candidate']['sha256']
        assert provider['efi']['sha256'] == native12['provider_sha256']
        for name,digest in native12['guard_module_sha256'].items():
            assert provider['bound_static_modules'][name]['module_sha256'] == digest
        gates = [g for g in gates if g['item'] not in ('历史 EXP03 映像','最新 NATIVE11 完整映像')]
        for g in gates:
            if g['item'] == '原厂 CAP 签名':
                g['detail'] = '原版内容及证书签名通过；最新 NATIVE12 内部映像保留的内容签名失败。局部自洽验签不代表完整 BMC 更新链已接受。'
            elif g['item'] == '首次 Del/F2 自动拦截':
                g['detail'] = '12 处原生拦截已静态整合进 AMITSE/Setup；密码模块缺失或无有效会话时拒绝受保护访问。完整 DXE 调度、第一次 Del/F2 进入和 ASUS 图形界面仍未实机验证。'
            elif g['item'] == '保存、正常启动和持久密码':
                g.update(item='保存被拒绝后的退出处理',status='新增编译修复，六类入口回放通过',
                         detail='原保存循环仍完成既有处理，新作用域汇总 ACCESS_DENIED 并返回 FALSE。6 类入口的 24 个独立实际字节场景确认拒绝后不新设退出/重启标志；未改值及无关内存参数可保存。原有状态字节和部分 OEM 后处理仍需完整 GUI 验收，不声称保存具有原子性。')
        gates.extend([
            {'item':'密码持久化及界面恢复','status':'两次独立 UEFI 虚拟机启动通过',
             'detail':'实际 provider 经标准键盘完成设密、改密、错密拒绝、正确解锁、取消、认证清除和授权撤销；共享 OVMF VAR 的记录跨进程一致，画面/模式/属性/光标恢复共 169 检查通过。使用真实 OVMF 存储与控制台，OEM 浏览器主体为测试替身，尚非 ASUS 实机验收。'},
            {'item':'默认值协议路径','status':'来源已核实，保持原保护策略',
             'detail':'5F688 的已识别外部调用来自 Redfish ResetBios/defaultSD，不能称为已证明的清 CMOS 初始化。未添加缺失变量创建例外；另一条直达默认值协议可改 RAM 缓存，已测后续受保护提交仍被拒绝。正常冷启动及完整回调效果仍待验收。'},
            {'item':'最新 NATIVE12 完整映像','status':'内部集成及结构验证完成',
             'detail':'67,112,960 字节；仅两处预定范围改变，620 个其他原始 FFS 完全保留，两个原生模块与独立密码模块精确重提取匹配。原槽余 1,592 字节，其他外层 FFS 未移动。仍为内部 UNSIGNED 映像，不可按正式刷写版使用。'},
        ])
        for value in native12.values():
            if isinstance(value,dict) and 'path' in value and 'sha256' in value and str(value['path']).endswith('.json'):
                evidence_names.append(Path(value['path']).relative_to(HERE).as_posix())
        evidence_names.extend([native12_path.relative_to(HERE).as_posix(),
                               'native_provider12_candidate/provider_review.json',
                               'native12_parent_review.json','verify_native12_parent.py',
                               'save_feedback_review/feedback_verification.json',
                               'native_provider12_ui_simulation/raw_screenshot_verification.json'])
    continuation_path = HERE/'remote_only/continuation06/validation06_result.json'
    continuation = read(continuation_path) if continuation_path.exists() else None
    if continuation:
        assert continuation['status'] == 'VALIDATION_ROUND_COMPLETE_NEW_BLOCKERS_CONFIRMED_NOT_RELEASE_READY'
        assert not any(continuation[k] for k in ('production_release_completed', 'firmware_upload_performed',
                       'firmware_flashing_performed', 'physical_password_ui_acceptance',
                       'full_machine_spi_backup', 'recovery_verified'))
        assert native12 and continuation['internal_image_unchanged']['sha256'] == native12['candidate']['sha256']
        verify_bound_tree({k:v for k,v in continuation.items() if k != 'evidence_links'})
        for item in continuation['evidence_links']:
            p = (HERE/item['path']).resolve()
            assert p.is_relative_to(HERE.resolve()) and sha(p) == item['sha256']
            evidence_names.append(item['path'])
        evidence_names.extend([continuation_path.relative_to(HERE).as_posix(),
                               'remote_only/continuation06/work_plan.json'])
        for g in gates:
            if g['item'] == '本机 BMC 更新路径':
                g.update(status='后台路径已细化，整链接受仍未知',
                         detail='新增 35 个实际指令场景、101 项检查。局部 CAP 自洽验签与条件启用的驻留公钥分支不同；已定位配置来源和进程缓存，但未取得实机后台二进制及有效开关。所审接口没有已证实的完整无状态验证器；上传验签会改动暂存文件，未执行。不能认定自签已可部署，也不能断言只有 OEM 私钥一种路线。')
            elif g['item'] == '完整备份与恢复':
                g['detail'] += ' 新一轮探针确认当前目标设备没有标准 SCSI_IO 接口；仍未取得可用的文件回传或机器专属整片备份，未验证无 POST 时的恢复。'
            elif g['item'] == '免刷诊断上机测试':
                g['detail'] += ' 本轮另完成原生布局和容量接口两次只读诊断，回收 17 页二维码并逐页验证 CRC/哈希；这两次未启动密码模块或安装原生拦截。'
            elif g['item'] == 'BMC 虚拟硬盘文件写回':
                g.update(status='标准 SCSI 接口缺失，写回未通过',
                         detail='实机唯一匹配的 046B:FF31 设备仍报告 1024 字节扇区、LastLBA 262144，与 16 MiB/512 字节测试镜像不符。目标路径没有 SCSI_IO、扩展 SCSI 或 ATA 接口；系统另一个 PCI 分支存在无关联的扩展 SCSI 接口。CAP02 发出 0 条 SCSI 命令，辅助客户端初始化交换中的 25 计数不算新的容量读取。镜像保持原始哈希；其他驱动路线尚未验证。')
            elif g['item'] == '首次 Del/F2 自动拦截':
                g.update(status='实机 12 处原始位置匹配，拦截未执行',
                         detail='原版 1904 实机的 AMITSE/Setup 代码指纹、12 处补丁位置及接口身份匹配。当前原地追加方案所需的 9 页均已被 Boot Services 代码占用，未写入这些页。两种不改二进制的搬移/影子副本方案经实际代码回放也不适用；完整永久锁的 Del/F2 与 ASUS GUI 仍未验收。')
        gates.extend([
            {'item':'免刷原生拦截安装','status':'当前原地追加方案不可用',
             'detail':'相邻页占用是当前原厂 BIOS 运行布局的事实，不等同于静态集成映像的装载失败。独立分配 guard/state 的方案需要改代码、重新绑定并验证；现有 NATIVE12/P12 不能直接继承该新方案的结果。本轮没有执行密码设置或界面拦截实机测试。'},
            {'item':'BMC 更新范围与数据保留','status':'保留条件已查明，实机数据未校验',
             'detail':'正常更新请求覆盖 64 MiB，后台逐块比较后跳过相同块、擦写不同块，并非固定只写 16 MiB BIOS 区。NPB 保留依赖当前头部版本、上传表及源数据读取。原始 ARM 代码回放发现源读取失败后仍可能返回成功的反例；这不是本机发生损坏的证据，却说明头部/表/成功返回均不足以证明保留字节正确。没有进入更新流程。'},
        ])
    continuation07_path = HERE/'remote_only/continuation07/validation07_result.json'
    continuation07 = read(continuation07_path) if continuation07_path.exists() else None
    if continuation07:
        assert continuation07['status'] == 'HISTORICAL_VALIDATION07_COMPLETE_NOT_RELEASE_READY'
        assert continuation07['current_round_complete'] and continuation07['task_continues_in'] == 'continuation08'
        assert (continuation07['raw_QR_pages_verified'], continuation07['frozen_file_bindings_verified']) == (28, 985)
        assert continuation07['binding_count_is_not_unique_file_count']
        assert not any(continuation07[k] for k in ('production_release_completed', 'firmware_upload_performed',
                       'firmware_flashing_performed', 'physical_password_ui_acceptance',
                       'native_interceptor_installed_or_executed', 'full_machine_spi_backup', 'recovery_verified'))
        assert native12 and continuation07['internal_image_unchanged']['sha256'] == native12['candidate']['sha256']
        verify_bound_tree({k:v for k,v in continuation07.items() if k != 'evidence_links'})
        for item in continuation07['evidence_links']:
            p = (HERE/item['path']).resolve()
            assert p.is_relative_to(HERE.resolve()) and sha(p) == item['sha256']
            evidence_names.append(item['path'])
        evidence_names.append(continuation07_path.relative_to(HERE).as_posix())
        for g in gates:
            if g['item'] == '完整备份与恢复':
                g.update(status='仍未取得整片备份或验证恢复',
                         detail='第7轮Linux绕过原UEFI缺少标准SCSI接口的限制，实际取得新的容量响应，但仍与16 MiB/512字节测试镜像不符。辅助镜像未发生数据块读写，文件写回与机器专属完整SPI备份仍未完成；实际更新信任、数据保留及无POST恢复仍待验证。')
            elif g['item'] == '免刷诊断上机测试':
                g.update(status='第7轮完成4次诊断回收，共28页',
                         detail='三个原生入口探针分别回收8、9、10页，Linux容量诊断回收1页，逐页从原始PNG重解并核对CRC和哈希。EP1得到精确尺寸拒绝；EP2修订后核实Core和一层父调用；EP3进一步定位BootNext分支。另一次EP2因BMC会话失效、光驱断开而未取得结果，单独记录，不计为通过。第6轮17页原始证据保留。')
            elif g['item'] == 'BMC 虚拟硬盘文件写回':
                g.update(status='Linux新鲜容量响应仍不匹配，写回未通过',
                         detail='实机唯一046B:FF31设备由Linux sg0读取；第一次RC10为严格匹配的UNIT ATTENTION，唯一允许的重试返回LastLBA 262144、扇区1024字节。预期值为32767和512。后续另一段主机关机的观察确认客户端已向socket提交预期容量字节，但没有远端应用确认，不能合并成同会话证据。两个辅助客户端的镜像读/写/flush均为0。')
            elif g['item'] == '首次 Del/F2 自动拦截':
                g.update(status='入口链已缩小，原生拦截仍未实机执行',
                         detail='第7轮核实原版Core完整代码及重定位、AMITSE/Setup指纹和12处原始位置。有限栈读取追到Core返回88AF、AMITSE返回A8E6及外层2D7D的BootNext分支。外层函数还含浏览器及重入路径，不能由此证明所有祖先帧均空闲；未安装原生拦截、启动provider或进行首次Del/F2密码验收。')
            elif g['item'] == '免刷原生拦截安装':
                g.update(status='只读入口观察完成，安装条件尚未满足',
                         detail='原地追加所需相邻页仍被占用。独立分配guard/state、实际CPU页权限、回调生命周期和失败回滚需要另行实现和验证。EP1/EP2/EP3均不含安装器；入口观察不授权安装，也不代表永久固件映像无法装载。')
        gates.extend([
            {'item':'容量来源进一步定位','status':'8项原始ARM回放通过，实机根因未确定',
             'detail':'已证明所审代码存在LUN缓存几何、异步挂载以及忽略部分返回值的路径。合成内存回放说明这些机制可能维持旧几何，尚未读回并绑定运行中的BMC后台、活动NBD及LUN状态；不能认定某条机制就是本机故障原因。'},
            {'item':'第7轮清理历史快照','status':'当轮清理与退出已复核；第8轮继续',
             'detail':'2026-11-03 09:59:34 UTC的读取记录确认主机关机、CD/HD空闲及SD临时启动字段恢复；10:04:41 UTC会话DELETE返回200，操作记录确认控制进程退出码0。这些是第7轮结束时的状态，不描述后续第8轮的当前机器状态。'},
        ])
    continuation08_path = HERE/'remote_only/continuation08/validation08_result.json'
    continuation08 = read(continuation08_path) if continuation08_path.exists() else None
    if continuation08:
        assert continuation08['status'] == 'C08_DIAGNOSTIC_SESSION_CLOSED_TASK_CONTINUES_NOT_RELEASE_READY'
        assert continuation08['diagnostic_session_complete'] and not continuation08['task_complete']
        assert continuation08['raw_QR_pages_verified'] == 16 and continuation08['completed_diagnostic_captures'] == 1
        assert not any(continuation08[k] for k in ('release_ready', 'production_release_completed',
                       'firmware_upload_performed', 'firmware_flashing_performed', 'physical_password_ui_acceptance',
                       'native_interceptor_installed_or_executed', 'full_machine_spi_backup', 'recovery_verified'))
        assert native12 and continuation08['internal_image_unchanged']['sha256'] == native12['candidate']['sha256']
        assert continuation08['prior_continuation07_preserved']['sha256'] == sha(continuation07_path)
        verify_bound_tree({k:v for k,v in continuation08.items() if k != 'evidence_links'})
        for item in continuation08['evidence_links']:
            p = (HERE/item['path']).resolve()
            assert p.is_relative_to(HERE.resolve()) and sha(p) == item['sha256']
            evidence_names.append(item['path'])
        evidence_names.append(continuation08_path.relative_to(HERE).as_posix())
        gates = [g for g in gates if g['item'] != '第7轮清理历史快照']
        for g in gates:
            if g['item'] == '完整备份与恢复':
                g.update(status='CD诊断恢复，备份和恢复仍未完成',
                         detail='第8轮CD-only流程已恢复光驱读取并运行前置条件探针。这不证明虚拟硬盘几何已修好；没有新的Linux容量通过或文件写回结果，仍未取得机器专属完整SPI备份、验证无POST恢复。更新信任及数据保留也仍待验收。')
            elif g['item'] == '免刷诊断上机测试':
                g.update(status='第8轮P04前置条件实测通过，回收16页',
                         detail='从原始PNG重解16页、12,125字节日志并核对CRC54DC8D8D。两组自有分配完成标准权限切换、读写、语义恢复和释放；其中代码页执行固定六字节代码，数据页未执行。原厂文本与8个目标页权限快照未变。此前三次启动尝试没有新的诊断执行结果，单独保留。未运行原生挂钩、provider或密码UI。')
            elif g['item'] == 'BMC 虚拟硬盘文件写回':
                g.update(status='正常F7断开已观察，HD写回仍未通过',
                         detail='helper05在主机关机、CD断开条件下发送一次原厂F7，随后收到连接EOF；未取得后台槽位清除确认。后端数据读/写/flush仍为0，16MiB临时镜像哈希不变。CD恢复不能替代HD容量匹配或文件写回验收。')
            elif g['item'] == '首次 Del/F2 自动拦截':
                g.update(status='前置内存服务已实测，拦截仍未执行',
                         detail='P04核对原版模块和12处原始位置，并观察到启动菜单外层返回0x960C；此前BootNext分支为0x2D7D。这些有限上下文及stage/app值不证明浏览器完全空闲。未修改OEM页、安装拦截、启动provider或进行首次Del/F2密码验收。')
            elif g['item'] == '免刷原生拦截安装':
                g.update(status='自有内存前置条件通过，真实安装器继续开发',
                         detail='原地追加相邻页占用限制仍保留。P04仅在两组自有分配中验证权限和恢复，不是OEM挂钩安装，也未做RO写入/NX执行故障、AP同步或完整回滚验收。独立split/provider/事务安装器继续开发，其结果不自动转移到NATIVE12映像。')
            elif g['item'] == '容量来源进一步定位':
                g.update(status='CD已恢复实际读取，唯一根因未确定',
                         detail='旧CD观察只有控制帧；正常清理和第二次标准BMC重启后的CD-only观察出现24次A8请求及24次响应，随后启动菜单枚举并成功运行P04。8项原始ARM回放确认容量换算及后端边界，但不能认定HD残留、F7或重启中的某项就是唯一原因；也不等于整ISO传输哈希验证。')
        gates.extend([
            {'item':'第8轮BMC维护','status':'两次标准ForceRestart，未恢复出厂或更新固件',
             'detail':'两次均在关机条件下发出一次标准Manager.Reset，分别记录HTTPS断开/恢复及读回。BMC时钟曾跳变，与会话失效仅有时间相关性；不宣称时钟不变或持续电源监测。'},
            {'item':'第8轮结束与启动字段','status':'会话已关闭；SD恢复，当前Self保留禁用选择值',
             'detail':'截至2026-11-03 11:26:51 UTC，关机、CD/HD空闲、自有helper退出及注销HTTP200已核对，控制进程退出码0。SD为Disabled/Legacy/None，Self仍Disabled/UEFI/Cd；两者均禁用覆盖、BootNext为空，已知虚拟CD项重新出现。未发送BootOrder写入；不能宣称两个视图或全部NVRAM字节均恢复。'},
        ])
    evidence_names = list(dict.fromkeys(evidence_names))
    record = {
        'target':'ASUS Pro WS W790E-SAGE SE BIOS 1904',
        'generated_utc':datetime.now(timezone.utc).isoformat(),
        'requested_outcome':'Validated flashable production custom firmware',
        'status':'NOT_RELEASE_READY_SIGNATURE_AND_HARDWARE_ACCEPTANCE_GAPS',
        'release_ready':False, 'production_release_completed':False, 'firmware_upload_performed':False,
        'firmware_flashing_performed':False, 'host_power_or_configuration_changed':bool(remote and remote['maintenance_power_cycle_performed']),
        'exp02_capsule_sha256':openssl['candidate_sha256'],
        'candidate_driver_sha256':provider['efi']['sha256'] if provider else selected_sha,
        'prior_dynamic_candidate_driver_sha256':selected_sha,
        'prior_ebs_candidate_driver_sha256':candidate['candidate_driver_sha256'],
        'candidate_scope':'Static native guards plus independent provider; internal unsigned full image, not a hardware-accepted release.' if native else selected_scope,
        'gates':gates,
        'deployment_conditions':{
            'user_response':'目前仍然只能使用 BMC 和远程 KVM',
            'scope':'Continue within the existing BMC/KVM-only condition; no on-site recovery equipment or OEM signing capability has been supplied.',
            'question_pending':False,
            'remote_backup_route':'Under investigation; configuration/profile downloads do not count as full machine-specific SPI backups.',
        },
        'evidence':{name:{'sha256':sha(HERE/name)} for name in evidence_names},
        'public_sources':[
            'https://dlcdnets.asus.com/pub/ASUS/E25502_ASMB11-iKVM_UM_V3_WEB.pdf?model=RS720Q-E11-RS8U',
            'https://uefi.org/specs/UEFI/2.11/07_Services_Boot_Services.html',
        ],
    }
    if remote:
        record['remote_only_work'] = remote
        record['deployment_conditions']['remote_backup_route'] = remote['backup_detail_zh']
    if integration:
        record['internal_exp03_image'] = integration['images']['exp03']
        record['internal_exp03_image']['scope'] = 'Unsigned internal review image; not approved for flashing.'
        record['internal_exp03_integration_source'] = {'path': str(integration_path), 'sha256': sha(integration_path)}
    if native:
        record['internal_native11_image'] = native
        record['native_provider'] = {'path':str(HERE/'native_provider_candidate/provider_review.json'), 'sha256':sha(HERE/'native_provider_candidate/provider_review.json')}
    if native12:
        record['internal_native12_image'] = native12
        record['native_provider'] = {'path':str(provider12_path),'sha256':sha(provider12_path)}
        record['latest_internal_image_sha256'] = native12['candidate']['sha256']
    if continuation:
        record['latest_remote_validation'] = continuation
        record['public_sources'].append(continuation['public_reference'])
        record['deployment_conditions']['remote_backup_route'] = next(g['detail'] for g in gates if g['item'] == '完整备份与恢复')
    if continuation07:
        record['prior_remote_validation06'] = continuation
        record['latest_remote_validation'] = continuation07
        record['latest_completed_validation_round'] = 7
        record['active_continuation'] = 'continuation08'
        record['machine_state_scope'] = 'Only historical C07 readback is reported. C08 activity and current machine state are tracked separately.'
        record['three_major_gaps_zh'] = continuation07['three_major_gaps_zh']
    if continuation08:
        record['prior_remote_validation07'] = continuation07
        record['latest_remote_validation'] = continuation08
        record['latest_completed_validation_round'] = 8
        record['active_continuation'] = 'continuation08'
        record['current_work'] = 'local_native_installer_development'
        record['task_complete'] = False
        record['machine_state_scope'] = 'C08 closing readback at2026-11-03T11:26:51.151Z only; local installer work continues. SD restored, active Self differs with override Disabled in both. No whole-NVRAM or future-state claim.'
        record['three_major_gaps_zh'] = continuation08['three_major_gaps_zh']
        record['deployment_conditions']['remote_backup_route'] = next(g['detail'] for g in gates if g['item'] == '完整备份与恢复')
    save(HERE/'acceptance_status.json', record)
    rows = ''.join('<tr><td>'+html.escape(g['item'])+'</td><td>'+html.escape(g['status'])+'</td><td>'+html.escape(g['detail'])+'</td></tr>' for g in gates)
    links = ''.join('<li><a href="'+html.escape(name, quote=True)+'">'+html.escape(name)+'</a></li>' for name in evidence_names)
    validation = ''
    if optional.exists():
        validation = '<p>'+html.escape(read(optional)['summary_zh'])+'</p>'
    if late:
        validation += '<p>最新会话归属修复候选为 '+html.escape(selected_sha[:12])+'…，已单独完成 269 项新增检查、83 项退出回归及六组既有回归。新候选未继承旧二进制的整机或实机通过结论。</p>'
    if late_vm:
        validation += '<p>最新候选的实际 services.obj 也已重新完成 QEMU/OVMF 18 项退出交接检查，包括真实事件、指针/CRC 恢复及错误 MapKey 重试。该夹具没有运行 ASUS 导航和密码写入，会话判断使用明确的假实现；这不属于完整主板 BIOS 仿真或永久锁上机验收。</p>'
    if integration:
        validation += '<p>EXP03 内部 UNSIGNED 映像 SHA-256：<code>'+integration['images']['exp03']['sha256']+'</code>，共 '+format(integration['images']['exp03']['bytes'], ',')+' 字节。文件已生成并完成结构比对，仍不能按正式刷写版使用。</p>'
    if native:
        validation = '<p>最新 NATIVE11 内部映像 SHA-256：<code>'+native['candidate']['sha256']+'</code>。支持设置、修改和认证后清除独立密码的代码已与 11 处静态拦截整合；真实指令回放和 OVMF 的通过范围均记录在证据中。未执行完整 ASUS 图形 BIOS，因此不能将这些结果算作整机模拟或永久密码锁实机通过。</p><details><summary>历史候选验证（不代表最新映像通过）</summary>'+validation+'</details>'
    if native12:
        validation = '<p>最新 NATIVE12 内部映像 SHA-256：<code>'+native12['candidate']['sha256']+'</code>。独立密码模块、12 处静态拦截与保存拒绝反馈已整合，并通过结构、实际指令回放和两次 OVMF 启动验证。完整 ASUS GUI、冷启动、实际更新接受与可恢复刷写仍未验收。</p><p>早先“标题字符缺失”的视觉判断已由原始 PNG/PPM 像素验证纠正；标题实际完整，额外刷新实验未进入最终模块。</p><details><summary>历史候选记录（已由 NATIVE12 接续）</summary>'+validation.replace('最新 NATIVE11','历史 NATIVE11')+'</details>'
    activity = (remote['summary_zh'] if remote else '本轮核实了实际 BMC 更新流程、原厂签名、原始 DXE Core 退出事件，并制作了退出故障处理修复候选。没有上传或刷写固件，也没有重启或修改主机配置。')
    if native12 and remote:
        activity = '已制作含独立密码设置和 12 处原生拦截的完整内部映像，已补做真实 UEFI 存储与键盘操作的跨启动模拟。实机取得 4 KiB 描述符并定位到虚拟硬盘几何不匹配，仍未取得完整 SPI 备份或验证恢复路径。没有上传或刷写固件。主机已恢复到本次测试前的关机状态，虚拟介质卸载、临时启动设置恢复，BMC 会话已退出。'
    if continuation:
        activity = continuation['summary_zh']
        validation += '<p>本轮原生布局诊断和容量接口诊断均为只读观察。它们没有运行完整 ASUS 密码界面，也没有验证永久改版的 DXE 装载或冷启动。当前相邻页被占用限制免刷原地安装，不能据此推断固件集成映像一定无法装载。标准 SCSI 接口缺失只排除本次探针的既有接口路线，不代表所有 BMC/KVM 方案均不可能。</p>'
    if continuation07:
        activity = continuation07['summary_zh']
        gaps = ''.join('<li>'+html.escape(value)+'</li>' for value in continuation07['three_major_gaps_zh'])
        validation = '<p><strong>第7轮历史记录已完成，后续工作按第8轮继续。</strong>目前发布验收仍有三项主要缺口：</p><ul>'+gaps+'</ul><p>本轮复核的是86＋87＋110＋265＋437＝985条文件绑定，包含重复引用，不等于985个独立文件。另行核对了独立EP3、Linux实测和GEO6审查清单。Linux只读容量诊断执行过正常内核初始化和ExitBootServices，不能描述为对系统零影响。</p><details><summary>此前候选与第6轮历史记录（不代表当前机器状态）</summary>'+validation+'</details>'
    if continuation08:
        activity = continuation08['summary_zh']
        gaps = ''.join('<li>'+html.escape(value)+'</li>' for value in continuation08['three_major_gaps_zh'])
        validation = '<p><strong>第8轮诊断会话已关闭；真实RAM安装器仍在开发，任务尚未完成。</strong>发布仍需关闭以下三项主要缺口：</p><ul>'+gaps+'</ul><p>P04调用标准内存分配和CPU属性服务，会改变自有RAM、页表/TLB及控制台状态；通过范围是两组分配与8个目标页快照，不是全机状态零变化或原生密码功能验收。新的split候选与NATIVE12是不同二进制，不能交叉继承测试结论。</p><details><summary>第7轮及此前候选历史证据（原文件保留）</summary>'+validation+'</details>'
    page = f'''<!doctype html><html lang="zh-CN"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>W790E-SAGE SE 1904 正式版准入核查</title><style>body{{max-width:1100px;margin:32px auto;padding:0 24px;font:16px/1.7 system-ui,sans-serif;color:#172638}}table{{border-collapse:collapse;width:100%}}td,th{{border:1px solid #cad4de;padding:12px;text-align:left;vertical-align:top}}td:first-child{{min-width:130px}}td:nth-child(2){{min-width:140px}}a{{overflow-wrap:anywhere}}code{{overflow-wrap:anywhere}}</style>
<body><h1>W790E-SAGE SE 1904：正式版准入核查</h1>
<p><strong>尚未达到正式可刷写发布条件。</strong>{html.escape(activity)}</p>
<table><thead><tr><th>项目</th><th>当前结果</th><th>证据与限制</th></tr></thead><tbody>{rows}</tbody></table>
{validation}
<p>ASUS 手册列出了 BIOS OOB Update 和 BIOS Forced Update，并要求有效 CAP；这些功能的存在不代表接受修改后的签名或已验证恢复能力。参见 <a href="{record['public_sources'][0]}">ASUS ASMB11 官方手册</a>。UEFI 事件和退出约束参见 <a href="{record['public_sources'][1]}">UEFI 2.11 Boot Services</a>；本地同时追踪了此型号原版 DXE Core 的实际指令。</p>
<p>用户已确认目前仅有 BMC 和远程 KVM，按此条件继续评估。必须完成实际更新链验证、完整备份及可用恢复路径；最新修改映像保留的原签名已失效。4 KiB 描述符读取、局部自洽验签和配置备份均不能替代这些验收。</p>
<p>当前隔离候选驱动 SHA-256：<code>{record['candidate_driver_sha256']}</code>。该候选没有继承旧版实机测试的二进制身份，也不是已通过部署验收的正式 CAP。</p>
<details><summary>可复核的本地证据（{len(evidence_names)} 份）</summary><ul>{links}</ul></details></body></html>'''
    (HERE/'检查报告.html').write_text(page, encoding='utf-8')
    for path in [CASE/'requirements.json', BASE/'requirements.json']:
        requirements = read(path)
        requirements['production_release_work'] = {
            'status':record['status'], 'report':str(HERE/'检查报告.html'),
            'evidence':str(HERE/'acceptance_status.json'), 'release_ready':False,
            'new_isolated_driver_sha256':record['candidate_driver_sha256'],
            'existing_EXP02_release_preserved':True, 'flashing_performed':False,
        }
        if continuation07:
            requirements['production_release_work'].update(latest_completed_validation_round=7, active_continuation='continuation08')
        if continuation08:
            requirements['production_release_work'].update(latest_completed_validation_round=8, active_continuation='continuation08', current_work='local_native_installer_development', task_complete=False)
        save(path, requirements)
    print(json.dumps({'status':record['status'], 'evidence_files':len(evidence_names), 'report':str(HERE/'检查报告.html')}, ensure_ascii=False))

if __name__ == '__main__':
    main()
