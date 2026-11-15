"""Create a checked, offline review bundle. No device access or flashing.

Requires completed reports for the current driver; refuses stale test results.
Existing diagnostic artifacts are hash-checked and never rewritten.
"""
from pathlib import Path
import datetime, hashlib, html, json, zipfile

HERE=Path(__file__).resolve().parent
BASE=HERE.parent
ROOT=BASE.parents[1]
CASE=BASE/'hardware_20261102_W790_ACE_E9B906DF'
OUT=HERE/'review'
OUT.mkdir(exist_ok=True)

def sha(p):
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()

def read(p):
    return json.loads(Path(p).read_text(encoding='utf8'))

def save(p,value):
    Path(p).write_text(json.dumps(value,ensure_ascii=False,indent=2)+'\n',encoding='utf8')

def relative(p):
    return Path(p).relative_to(ROOT).as_posix()

build=read(HERE/'driver/build/build.json')
core=read(HERE/'core/test_report.json')
policy=read(HERE/'driver/build/policy_test.json')
adapter=read(HERE/'driver/build/adapter_emulation.json')
vm=read(HERE/'driver/build/vm_integration.json')
native=read(HERE/'lab/native_hooks_result.json')
image=read(HERE/'lab/asus_review/W790-ACE-1904-lock.review.json')
verification=read(HERE/'lab/asus_review/verification.json')
entropy=read(HERE/'driver/build/entropy_test.json')
abi=read(HERE/'driver/build/hii_abi_test.json')
hardware_dir=HERE/'remote_172_20_2_209'
hardware=read(hardware_dir/'hardware_summary.json')
driver=HERE/'driver/build/AiTweakerLock1904.efi'
candidate=HERE/'lab/asus_review/W790-ACE-1904-lock.review.bin'
digest=sha(driver)
assert digest==build['efi_sha256']==policy['driver_efi_sha256']==adapter['driver_sha256']==vm['driver_sha256']==image['driver_sha256']==verification['driver_sha256']
assert sha(candidate)==image['candidate_sha256']==verification['candidate_sha256']
assert digest==entropy['driver_sha256']==abi['driver_sha256']
assert abi['status']=='PASS' and all(c['passed'] for c in abi['cases'])
baseline_dir=HERE/'baselines/P5-445585c3'
baseline_archive=baseline_dir/'W790-ACE-1904-P5-hardware-review.zip'
assert sha(baseline_archive)=='3f88cc01a3aaa6f2e109f4ffa54560561a748314a2a6bf6ec6d275da15e09f81'
assert hardware['driver_sha256']==sha(baseline_dir/'AiTweakerLock1904.efi')=='445585c388d437a12bf331a42a216a88c7ae5104f7e91a086dc3bc4d8238b97a'
changed=[]
with zipfile.ZipFile(baseline_archive) as z:
    for name in build['sources']:
        path=HERE/name
        if z.read(relative(path))!=path.read_bytes():changed.append(Path(name).as_posix())
assert sorted(changed)==['driver/efi.h','driver/hii.c'],changed
revision={'status':'SOURCE_DELTA_VERIFIED','baseline_driver_sha256':hardware['driver_sha256'],'driver_sha256':digest,
 'production_sources_changed':sorted(changed),'change':'EFI_BROWSER_ACTION_REQUEST output corrected from UINT32 to UINTN; full-width reset verified with dirty upper bits and adjacent canaries',
 'current_binary_hardware_tested':False,'baseline_hardware_report':relative(hardware_dir/'hardware_summary.json'),
 'baseline_archive':relative(baseline_archive),'baseline_defect_report':relative(baseline_dir/'hii_abi_test.json'),
 'current_abi_cases':len(abi['cases'])}
save(OUT/'driver_revision.json',revision)
assert entropy['passed'] and all(c['passed'] for c in entropy['checks'])
assert hardware['status']=='RAM_ONLY_HARDWARE_TEST_PASSED_HOST_RESTORED'
for name,item in hardware['evidence_files'].items():assert sha(hardware_dir/name)==item['sha256']
assert core['status']==policy['status']==adapter['status']==verification['status']=='PASS'
assert native['all_passed'] and vm['all_passed'] and len(vm['groups'])==2
assert all(len(g['boots'])==3 and all(b['passed'] for b in g['boots']) for g in vm['groups'])
for name,expected in core['sources'].items():assert sha(HERE/'core'/name)==expected
for name,expected in build['sources'].items():assert sha(HERE/name)==expected
for name,expected in build.get('external_sources',{}).items():assert sha(ROOT/name)==expected
assert sha(CASE/'modules/AMITSE.efi')==native['module_sha256']==adapter['amitse_sha256']
run_matches=[p for p in (HERE/'driver/vm_runs').glob('*/result.json') if read(p)==vm]
assert len(run_matches)==1
run=run_matches[0].parent
for group in vm['groups']:
    folder=run/('readonly_iso' if group['readonly_iso'] else 'fat')
    for boot in group['boots']:
        log=folder/f"boot{boot['phase']}"/'debug.log'
        assert sha(log)==boot['debug_sha256']
        text=log.read_text(encoding='ascii')
        assert text.count('PASS ')==boot['checks'] and 'FAIL ' not in text
    if group['readonly_iso']:assert group['medium_sha256_before']==group['medium_sha256_after']

baseline={
 ROOT/'Pro-WS-W790E-SAGE-SE-ASUS-2003.zip':'d093fb2a045633eb7285a45606ea1548d9250982e266f7480193296ed8231845',
 ROOT/'Pro-WS-W790-ACE-ASUS-2003.zip':'4ca36875d8c37310fe4e6eaddfd59e2433d3c2dbaf1d9551d3ade59f4a1ee47d',
 ROOT/'Pro-WS-W890E-SAGE-SE-ASUS-0603.zip':'5bad35967954afb2f10123828e3698c1f36b413b21ce127f15778ed424997df8',
 BASE/'official_W790_ACE_1904/Pro-WS-W790-ACE-ASUS-1904.zip':'dcae6e446cfb475755b0a5118317e28e88fc9af7c917bf5cf29c6da1a5fd3e37',
 BASE/'official_W790_ACE_1904/W790_ACE_1904/Pro-WS-W790-ACE-ASUS-1904.CAP':'03e4330430b2510d5e9e5c9868ca64c730844992b82c6a272b815aef3d20bf29',
 BASE/'AiTweaker-P2-免刷写诊断.zip':'c06fafc804b6cedc74003459c49d18da53db7618d21edf72391dcfc2ac43ae64',
 BASE/'probe_p2/USB/EFI/BOOT/BOOTX64.EFI':'a16b2e7e0af6aa48cd375a3a3fbd77e58f60a50edd929751fcfe6951d6df64b5',
 BASE/'probe_p3_kvm/AiTweaker-P3-KVM.iso':'9279a099e8c08521a6b82107c81645f7f951c2137e48f39113f49e823057c8c3',
 BASE/'AiTweaker-实机采集工具包-USB与KVM.zip':'0e5da5393feab4162b20c1c6f9f4a7b9dd01d834279ac9abe5ad25bc1bf06a91',
 CASE/'AITWK-P3-W790-ACE-E9B906DF.TXT':'ce4e698ba353fcb7e7debce5662bd82c6913c83b88983bee186baedf3e86f2f6',
}
preserved=[]
for p,expected in baseline.items():
    actual=sha(p);assert actual==expected,(str(p),actual)
    preserved.append({'path':relative(p),'sha256':actual,'unchanged':True})
save(OUT/'preservation.json',{'status':'PASS','files':preserved})

evidence=[]
for p in sorted((HERE/'navigation/rea').glob('NAV-*.json')):
    s=read(p).get('structuredContent',{})
    if not s.get('evidence_id') or 'procedure' not in s.get('normalized_result',{}):continue
    proc=s['normalized_result']['procedure']
    assert s['subject']['digest']['sha256']==native['module_sha256']
    evidence.append({'path':relative(p),'file_sha256':sha(p),'evidence_id':s['evidence_id'],
      'address':proc['address'],'analyst_seed_name':proc['name'],
      'subject_sha256':s['subject']['digest']['sha256'],'provider':s['provider'],
      'relationship_coverage':s.get('relationship_coverage'),
      'classification':'REJECTED_PASSWORD_PROMPT_HYPOTHESIS_DEVICE_PATH_FORMATTER' if proc['address']=='0x408a0' else 'STATIC_REA_EVIDENCE_NOT_HARDWARE_EXECUTION'})
assert len(evidence)==18
save(OUT/'rea_evidence_index.json',{'entries':evidence,'seed_name_warning':'Candidate_* names are analyst assertions, not recovered vendor symbols. Indirect unresolved edges remain unknown. 0x408a0 is a device-path formatter, not an Ai Tweaker password prompt.'})

now=datetime.datetime.now(datetime.timezone.utc).isoformat()
checks=sum(b['checks'] for g in vm['groups'] for b in g['boots'])
matrix=[
 ('独立密码核心',f"{core['assertions']} 项断言通过",'实际编译 C 核心；存储、时钟、熵回调使用受控输入。验证摘要、KDF、凭据损坏、限速、会话和失败回滚。'),
 ('原厂机器码片段',f"{len(native['cases'])} 个用例通过",'Unicorn 中运行原始 AMITSE 的有限片段；验证入口 ABI、首次进入忽略返回值、正常导航拒绝和跳板。'),
 ('1904 实际驱动入口适配',f"{adapter['cases']} 个用例通过",'实际编译驱动与重定位原厂模块；主浏览器主体、密码输入结果和部分固件服务为桩。'),
 ('IFR 与拦截策略',f"{policy['assertions']} 项断言通过",'实际编译纯策略函数；原始 IFR 插入、重复/畸形输入、2,048 组固定种子随机输入和 Exit 例外。'),
 ('实际 UEFI 服务集成',f'6 次冷启动通过，{checks} 次检查', 'QEMU/OVMF：可写 FAT 与只读 ISO 各连续 3 次冷启动，共用各自的模拟 NVRAM。使用实际 UI、KDF、HII 和变量服务；不运行完整 ASUS 浏览器。'),
 ('CPU 取熵失败处理',f"{len(entropy['checks'])} 个用例通过",'运行编译后的 x64 取熵函数；故障注入覆盖 CPUID 支持判断、RDSEED 成功标志、重试上限和失败擦除。'),
 ('HII 回调 x64 输出 ABI',f"{len(abi['cases'])} 个用例通过",'实际编译回调在 Unicorn 中运行；64 位输出预填非零高位，检查完整清零和相邻内存。旧二进制的缺陷已独立复现。'),
 ('P5 基线免刷实机','41 项检查、15 项界面观察通过','对应旧驱动 445585c3，非本版 eb4d9b43。实际 AMITSE SendForm 文本浏览器；凭据仅存 RAM。主机已恢复。本版只修改两个生产源文件的回调输出类型并完成模拟回归，尚未再次实机运行。'),
 ('固件结构独立验证','UEFIExtract 通过','插入 PE 与最终 EFI 完全一致；保留压缩容器外的 631 个原有 FFS 文件。该结果不验证固件签名或实际启动。'),
]
paths=[
 ('浏览器整个会话','AMITSE RVA 0xE208，18 字节跳板','最外层进入重锁，最外层返回结束授权；嵌套调用保留当前会话。'),
 ('正常页面切换','0x62BC 分派，0x7CB30 回调槽','按原 ABI 接收旧 GUID/旧 Form 指针及新 GUID/新 Form 指针；拒绝受保护目标。'),
 ('首次进入 / 默认页面','0x34B7C 轮询，缓存接口 0x82998','在读取活动页面前检查并重定向；不依赖首次导航会忽略的拒绝返回值。'),
 ('重定向后的旧页面指针','PageRender 0x16AE0 / PageInput 0x16C70 / AppInput 0x121B8','补充渲染和输入拦截；拒绝输入返回 0，避免继续落入其他输入处理。'),
 ('收藏、配置导入、动态 OC 控件','27 个受保护 Form，1,989 个 Question；FrameInput 0x15370','扫描原 Setup HII 来源和变量存储，覆盖共用框架的模态输入；不能据此宣称所有搜索/EZ 私有路径已验证。'),
 ('实际变量提交','RouteConfig 与 Boot Services 期间 SetVariable','锁定时阻止 OCMR 改变；SocketMemoryConfig 仅保护 0x10、0xBD、0xBE 三字节；保持独立密码变量不受外部回调直接改写。'),
 ('Exit 页例外','Form 0x271B 的 DISABLE_IF TRUE','7 个永久禁用的旧字段仅在完整 17 字节描述符一致时豁免；这些变量的实际写入仍受保护。'),
]
limits=[
 '本版在 P5 实测基线上修正 HII 回调输出宽度（UINT32 改为 UINTN）。最新二进制已通过全部模拟回归，但未再次在实体板执行；历史免刷证据仍对应旧驱动，不能视为本版整包实测。',
 '当前仅适配 ASUS Pro WS W790-ACE / 1904。其他两款主板及 W790-ACE 2003 仍未完成密码锁适配。',
 '实现目标是固件内自动加载，覆盖直接 Del/F2 进 BIOS。已证明 OVMF 固件卷自动加载，以及实体板在维护应用运行时的 SMBIOS/模块识别、代码页挂接和 HII 发布；ASUS 开机 DXE 调度和直接 Del/F2 的加载时序仍未证明。',
 '实体板已在原厂 1904 固件中执行链接生产模块的 RAM 测试应用，验证了 AMITSE SendForm 文本浏览器；完整 ASUS 图形界面、直接 Del/F2 初始路径、搜索/EZ 非 HII 分支、直接硬件写入、SMM、缓存的 SetVariable 指针等仍不在已证明范围。',
 '变量拦截覆盖正常启动期间的受保护变化；实际 ASUS 正常开机、恢复默认值、内存训练等是否需要合法改写这些字段，尚需实机核对。不能把 VM 通过等同于无兼容性风险。',
 '独立变量在普通 Setup 默认值路径外，VM 已验证跨冷启动保存；实体测试凭据只存 RAM，真实 NVRAM 跨重启和 Load Defaults 是否保留仍待验证。具有特权的固件、外置编程器或能清空 NVRAM 的操作者不在这个菜单锁的防护承诺内。',
 'RNG、单调时钟、HII 安装或凭据出现故障时，已挂接的门控拒绝访问；若驱动自身未被加载或因版本指纹不符拒绝挂接，不能声称锁已生效。',
 '候选映像保留原始 4 KiB Capsule 头，但修改后的负载没有新的原厂有效签名。它不是可直接交给更新工具的正式 CAP；FlashBack/BMC 是否接受、Boot Guard 覆盖和恢复路径均未验证。',
 '用户已确认目前只有 BMC 虚拟光驱和远程 KVM，没有确认可用的现场恢复或外置编程器。已获授权维护重启并完成免刷测试，临时光驱和一次性引导均已清理、原启动顺序保持不变。未执行刷写或永久密码部署，不能由此证明直接 Del/F2 前会加载驱动或失败后可恢复。',
 '本轮阻止了 RuntimeServices 表的 76 次 SetVariable 请求；指定的 OCMR、SocketMemoryConfig、AiTweakerPassword1904 三个变量摘要一致。这不是整片 NVRAM/SPI 的前后逐字节核对；恢复系统仅确认到 Rocky Linux 登录界面，没有检查后台业务。',
]
spec=[
 ('REA','https://github.com/morluto/rea'),
 ('ASUS 官方 BIOS 下载页','https://www.asus.com/motherboards-components/motherboards/workstation/pro-ws-w790-ace/helpdesk_bios?model2Name=Pro-WS-W790-ACE'),
 ('UEFI HII / Config Access','https://uefi.org/specs/UEFI/2.11/35_HII_Configuration_Processing_and_Browser_Protocol.html'),
 ('EDK II GOP 枚举定义','https://raw.githubusercontent.com/tianocore/edk2/master/MdePkg/Include/Protocol/GraphicsOutput.h'),
 ('EDK II CPU Timer 协议','https://raw.githubusercontent.com/tianocore/edk2/master/MdePkg/Include/Protocol/Cpu.h'),
 ('PI 固件文件系统定义','https://uefi.org/specs/PI/1.10/V3_Code_Definitions.html'),
 ('Intel DRNG / RDSEED 指南','https://www.intel.com/content/www/us/en/developer/articles/guide/intel-digital-random-number-generator-drng-software-implementation-guide.html'),
]
review={'generated_utc':now,'target':'ASUS Pro WS W790-ACE BIOS 1904',
 'status':'EXPERIMENTAL_FIRMWARE_SIMULATED_BASELINE_HARDWARE_TESTED',
 'password_lock_code_implemented':True,'firmware_review_image_created':True,
 'automatic_activation_intended':True,'automatic_dispatch_verified_on':'Generic OVMF only',
 'hardware_password_lock_validated':False,'hardware_baseline_validated':True,'hardware_validation_scope':'Previous 445585c3 driver only: RAM-only native AMITSE SendForm text UI; current eb4d9b43 has simulated ABI fix and is not hardware tested',
 'persistent_hardware_password_lock_validated':False,'ready_for_hardware_test':False,'ready_for_hardware_test_scope':'Persistent firmware deployment is not ready; authorized RAM-only test already completed',
 'signed_flash_package_created':False,'physical_firmware_writes_performed':False,
 'driver_sha256':digest,'candidate_sha256':sha(candidate),
 'validation':{'core_assertions':core['assertions'],'native_original_cases':len(native['cases']),
   'adapter_cases':adapter['cases'],'policy_assertions':policy['assertions'],
   'integration_cold_boots':6,'integration_checks':checks,'integration_run':relative(run),
   'entropy_emulation_cases':len(entropy['checks']),'hardware_ram_checks':41,'hardware_ui_observations':15,'hardware_summary':relative(hardware_dir/'hardware_summary.json'),
   'hii_abi_cases':len(abi['cases']),'hardware_checks_apply_to':'P5 baseline 445585c3 only','driver_revision':relative(OUT/'driver_revision.json'),
   'independent_uefiextract':'PASS','all_final_driver_reports_match_sha256':True},
 'limits':limits,'rea_evidence_index':relative(OUT/'rea_evidence_index.json'),
 'prior_diagnostic_modes_preserved':['P2 USB TXT','P3 read-only ISO / KVM QR'],
 'confirmed_remote_capabilities':['BMC virtual optical media','Remote KVM'],
 'recovery_question_status':'ANSWERED_BMC_VIRTUAL_MEDIA_AND_KVM_ONLY',
 'recoverable_deployment_path_established':False}
save(OUT/'review_summary.json',review)

title='W790-ACE 1904 独立密码锁：实现、模拟与免刷实机验证'
intro='本版已生成完整修改 BIOS，并通过分层模拟和固件结构检查。在已通过免刷实测的 P5 基线上修正了 HII 回调的 64 位输出参数；最新二进制尚未再次实机运行。固件自动加载与永久密码部署仍未完成，映像没有新的原厂有效签名。'
behavior='Security 新增 Ai Tweaker Password 与 Clear Ai Tweaker Password 两项。独立密码长度为 8–128 个可打印 ASCII 字符；设置、修改、清除均在 BIOS 界面操作。首次未设置时 Ai Tweaker 保持锁定，需先到 Security 设置；修改和清除要求当前密码，明确清除后关闭保护。每个最外层 BIOS 会话首次访问受保护入口要求解锁，退出后清除授权。口令不明文存储，使用随机盐和 PBKDF2-HMAC-SHA256（600,000 轮）；128 字节版本化凭据保存在独立 NV/Boot-Service 变量中。记录摘要检测损坏，不作为对抗特权篡改的认证标签。'
vm_detail='生产 DXE 在模拟固件内自动启动，并对 OVMF 非目标主板拒绝 OEM 挂钩。另一个仅限 QEMU TCG 的应用链接相同服务、UI、HII、策略和密码核心对象，使用原始 1904 IFR/英文字符串包及受控 ConfigAccess 所有者。键盘输入由脚本提供，画面、HII、随机数、计时、SetVariable/GetVariable 和 ExitBootServices 为实际 OVMF 服务。验证密码建立、确认不一致、错误密码/等待、ESC、解锁、跨重启、修改、清除、重新设置及写入保护；六次均核对退出启动服务后的指针和运行时表 CRC。没有将这一测试写成完整 ASUS UI 仿真。'
fixes='模拟发现并修复了首次页面忽略导航状态、输入拒绝状态继续落入后续处理、核心故障清除 active 后门控失效、嵌套会话授权丢失、计时事件合并导致等待失真、GOP 保存操作号错误、Exit 旧字段误拦截，以及明确关闭保护后会话外配置回写仍被拒绝的问题。实机发现 EFI_RNG_PROTOCOL 不存在，新增经 CPUID 判断、检查成功标志、有限重试并在失败时擦除输出的 RDSEED 路径；已有 RNG 服务的错误不会被备用路径掩盖。最终 GOP 恢复、HII 路由和三个内存保护字节的 UEFI 服务检查通过。'
pack_detail=f'新驱动 {driver.stat().st_size:,} 字节。内层 FV 尾部扩大 36,864 字节，原内层 423 个 FFS 文件字节和偏移保持不变；重新压缩的容器仍放在原分配区间，余下 {image["outer_slot_padding_ffs_bytes"]} 字节成为合法填充 FFS。原完整映像 632 个 FFS，候选 634 个；除重压缩容器外的 631 个原文件按字节保留。独立 UEFIExtract 解包验证了新 PE、FFS 校验、依赖表达式及未新增未知段警告。'
refs='\n'.join(f'{name}: {url}' for name,url in spec)
txt=f'{title}\n生成时间（UTC）：{now}\n\n{intro}\n\n用户要求与实现\n{behavior}\n\n拦截路径\n'+ '\n'.join(' | '.join(x) for x in paths)+'\n\n验证范围\n'+'\n'.join(' | '.join(x) for x in matrix)+f'\n\nUEFI 实验边界\n{vm_detail}\n\n本轮修复\n{fixes}\n\n固件封装\n{pack_detail}\n\n仍需核对\n'+'\n'.join(f'{i+1}. {x}' for i,x in enumerate(limits))+f'\n\n最终文件 SHA-256\n驱动：{digest}\n离线候选：{sha(candidate)}\n\n原文件保留\n原始三个 ZIP、官方 1904 ZIP/CAP、P2 USB、P3 KVM ISO、双模式工具包及实机二维码恢复日志，共 {len(preserved)} 项基线均未改变。旧诊断包仍用于采集，里面没有本次密码锁。\n\nREA 证据\n本轮保存 18 份函数报告，逐份包含主体摘要、地址、证据 ID、提供者与覆盖限制。Candidate_* 名称属于分析标注；0x408A0 的“密码弹窗”猜测已否定，该函数是设备路径格式化函数。未解决的间接调用继续列为未知。\n\n材料位置\n{relative(OUT)}\n{relative(run)}\n\n复现\n参见审查包 README-先读.txt。构建工具和原始 BIOS 依赖沿用当前工作区；本包不是可启动介质，也不包含刷写命令。\n\n官方资料与工具\n{refs}\n'
report_txt=ROOT/'W790-ACE-1904-独立密码锁-离线验证报告.txt'
report_html=report_txt.with_suffix('.html')
report_txt.write_text(txt,encoding='utf8')
esc=html.escape
def table(head,rows):
    return '<table><thead><tr>'+''.join('<th>'+esc(x)+'</th>' for x in head)+'</tr></thead><tbody>'+''.join('<tr>'+''.join('<td>'+esc(str(x))+'</td>' for x in row)+'</tr>' for row in rows)+'</tbody></table>'
def link(name,url):return f'<a href="{esc(url,quote=True)}">{esc(name)}</a>'
body=f'<h1>{esc(title)}</h1><p class="muted">2026-11-02 · 目标仅限 Pro WS W790-ACE / 1904</p><div class="status"><strong>离线审查候选 · 尚未实机验证</strong><p>{esc(intro)}</p></div><h2>实现行为</h2><p>{esc(behavior)}</p><p>新增项目通过 HII/ConfigAccess 发布，接口约定参考 {link(*spec[2])}。</p><h2>已实现的入口拦截</h2>'+table(['入口','定位','处理'],paths)+'<h2>通过了哪些验证</h2>'+table(['层次','结果','可证明的范围'],matrix)+f'<h2>虚拟机与真实主板的边界</h2><p>{esc(vm_detail)}</p><h2>模拟中发现并修复的问题</h2><p>{esc(fixes)}</p><p>GOP 的 VideoToBuffer / BufferToVideo 操作值核对自 {link(*spec[3])}；计时接口核对自 {link(*spec[4])}。</p><h2>固件候选件</h2><p>{esc(pack_detail)}</p><p>封装结构依据 {link(*spec[5])}。结构校验通过不表示原厂 Capsule 签名仍然有效，也不证明主板会接受或启动。</p><h2>尚未解决的实机事项</h2><ol>'+''.join(f'<li>{esc(x)}</li>' for x in limits)+f'</ol><h2>证据与保留文件</h2><p>本轮使用 {link(*spec[0])} / Ghidra 保存 18 份函数报告。Candidate_* 为分析者命名；0x408A0 的密码弹窗假设已否定。间接调用的未知边没有当作完整覆盖。REA 证据索引、30 项入口测试、六次完整 VM 日志及独立解包结果均放入审查包。</p><p>原始三个 BIOS ZIP、{link(*spec[1])} 对应的 1904 ZIP/CAP、原 P2 USB、P3 KVM ISO 和双模式采集工具包共 {len(preserved)} 项基线保持不变。原来的文件日志和二维码取回方式均可继续使用；旧包仍是只读诊断工具。</p><h2>最终文件校验</h2>'+table(['文件','SHA-256'],[('AiTweakerLock1904.efi',digest),('W790-ACE-1904-lock.review.bin',sha(candidate))])+f'<p class="muted">生成时间 UTC：{esc(now)}。此报告只描述磁盘文件与模拟器结果；没有向实体固件写入。</p>'
body=body.replace('离线审查候选 · 尚未实机验证','修改版 BIOS · 本版模拟通过 · P5 基线已实测')
body=body.replace('此报告只描述磁盘文件与模拟器结果；没有向实体固件写入。','此报告包含磁盘、模拟器与 RAM 免刷实机证据；没有执行固件刷写或永久密码部署。')
report_html.write_text('<!doctype html><html lang="zh-CN"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>'+esc(title)+'</title><style>body{max-width:1100px;margin:40px auto;padding:0 24px 60px;color:#16273b;background:#f6f8fb;font:16px/1.8 "Microsoft YaHei",system-ui,sans-serif}h1{font-size:30px;line-height:1.4}h2{margin-top:32px;font-size:22px}p,li{overflow-wrap:anywhere}table{width:100%;border-collapse:collapse;background:white;margin:18px 0;font-size:14px;table-layout:fixed}th,td{padding:12px;text-align:left;vertical-align:top;border:1px solid #d6dfeb;overflow-wrap:anywhere}th{background:#e7effa}th:first-child{width:19%}.status{border-left:5px solid #9c6500;padding:18px 22px;background:#fff1d6;border-radius:5px}.status p{margin:6px 0}.muted{color:#53657a;font-size:14px}li{margin:8px 0}a{color:#1255a1}@media(max-width:650px){body{padding:0 12px}h1{font-size:25px}table{font-size:12px}th,td{padding:6px}}@media print{body{max-width:none;background:white;margin:0;font-size:11pt}table{font-size:9pt}h2{break-after:avoid}tr{break-inside:avoid}}</style><body>'+body+'</body></html>',encoding='utf8')

readme='''W790-ACE 1904 独立密码锁 — 离线审查材料

此包不是上机测试启动盘或正式刷写包。没有 EFI/BOOT 自动启动目录，没有刷写程序或刷写脚本。
review.bin 是未重新获得原厂有效签名的离线候选件；不要改名后直接交给更新工具。
AiTweakerLock1904.efi 为待审查驱动。VM-INTEGRATION-ONLY 的脚本密码只用于模拟器，与实体密码无关。
真实 BIOS 密码需用户在 Security 中自行设置，本包不预置实际密码。

阅读顺序：根目录 HTML/TXT 报告 → analysis/aitweaker_lock/lock_1904/review/review_summary.json
→ 测试结果、REA 证据索引、源码。manifest.json 为本归档逐文件 SHA-256。

复现使用当前 BIOS 工作区已有的工具，不要求在主板运行任何文件：
Python 3.14；Zig 0.14.1；pefile/capstone/unicorn；QEMU/OVMF；pyfatfs/pycdlib；UEFIExtract。
REA 静态证据由 REA 6.8.0 / Ghidra 12.1.4 产生，原始模块不变。
在工作区根目录用 Python 依次运行下列脚本：
1. analysis/aitweaker_lock/lock_1904/core/build_core.py 与 verify_core.py
2. analysis/aitweaker_lock/lock_1904/driver/build.py
3. driver/verify_policy.py 与 driver/verify_adapter.py（路径前缀同上）
   driver/verify_entropy.py 校验新增 CPU 取熵失败处理
4. driver/build_vm.py → driver/run_vm.py（仅 QEMU，约两分钟）
5. lab/build_asus_review.py → lab/verify_asus_review.py（仅磁盘文件）
6. analysis/aitweaker_lock/lock_1904/package_review.py
lab/native_hooks.py 为独立的原厂指令片段验证。
完整工具和原始官方 CAP 仍位于原工作区，没有在本归档重复分发；若在新目录复现，需要按脚本路径补齐这些依赖。

P5 基线驱动 445585c3 已完成 W790-ACE 1904 的 RAM 免刷实机测试，证据见实机验证报告和 remote_172_20_2_209/hardware_summary.json。
本版 eb4d9b43 只修正两个生产源文件中的 HII 回调输出宽度；新增 8 个机器码 ABI 用例，并完成全部模拟回归。本版二进制没有再次实机运行。
实体 AMITSE SendForm 文本界面中已验证 Security 项、密码设置/修改/清除、正常及初始入口拦截、会话重新锁定。
尚未验证固件自动调度、直接 Del/F2、完整 ASUS 图形/EZ/搜索私有入口、实体 NVRAM 跨重启、保存/默认值兼容性。
用户已确认目前只有 BMC 虚拟光驱和远程 KVM。可恢复部署途径尚未建立，不能把虚拟光驱启动等同于每次直接 Del/F2 前自动生效。
永久部署前需要确定实际可恢复部署途径，并完成上述验证；本次没有执行刷写或保存永久密码，指定三个变量的前后摘要一致。
维护重启和免刷测试已得到用户授权。主机已恢复 Rocky Linux 登录界面，虚拟光驱与一次性引导已清理，原启动顺序保持不变。
原 USB TXT 与 KVM QR 双模式诊断包保持原样，仍可用于收集后续只读信息。
'''
(OUT/'README-先读.txt').write_text(readme,encoding='utf8')

# Keep historical evidence objects intact; record the newly implemented scope
# separately instead of rewriting prior diagnostic releases as password locks.
current={'updated_utc':now,**review,'report':report_html.name,'review_directory':relative(OUT)}
for path in [BASE/'requirements.json',BASE/'delivery.json']:
    old=read(path)
    history=HERE/'review'/('prior_'+path.name)
    if not history.exists():save(history,old)
    old['active_target']='W790_ACE_1904'
    old['current_password_lock_candidate']=current
    old['password_lock_hardware_validated']=False
    old['password_lock_baseline_hardware_validated']=True
    old['password_lock_hardware_validation_scope']='P5 baseline 445585c3 only; latest ABI-corrected binary simulated, not hardware tested'
    old['persistent_password_lock_hardware_validated']=False
    old['password_lock_fully_delivered']=False
    old['ready_for_hardware_test']=False
    old['modified_review_image_created']=True
    old['implementation_status']=review['status']
    if path.name=='requirements.json':
        old['confirmed_by_user']['every_bios_entry_including_direct_del_f2']=True
        old['confirmed_by_user']['prioritize_w790_ace_1904']=True
        old['confirmed_by_user']['available_remote_capabilities']=['BMC virtual optical media','Remote KVM only']
        old['deferred_targets']=['W790_SAGE_2003','W790_ACE_2003','W890_SAGE_0603']
        old['original_proposed_details']=old.get('original_proposed_details',old.get('proposed_details_not_yet_implemented',[]))
        old['proposed_details_not_yet_implemented']=['Complete proprietary non-HII graphical/search/EZ/raw-write path proof','ASUS automatic firmware dispatch and direct Del/F2 entry','Persistent NVRAM/defaults and normal-boot compatibility','Accepted, recoverable deployment package']
        old['implemented_in_candidate']=['Independent BIOS Security password management','PBKDF2 salted credential','Outer browser-session lifetime','Initial and normal navigation gates','Page/input/modal frame gates','Protected variable writes','Offline firmware integration']
        old['confirmed_by_user']['maintenance_reboot_and_ram_test_authorized']=True
        old['next_required_external_evidence']='RAM-only native browser tests passed and host restored. Establish a recoverable firmware deployment path; validate automatic ASUS dispatch, direct Del/F2, graphical/private entries and persistent NVRAM/defaults. No flashing performed.'
    else:
        old['status']=review['status']
        old['password_lock_implemented']=True
        old['password_lock_implementation_scope']='Compiled driver, unsigned offline image and native AMITSE RAM-only hardware tests; persistent firmware deployment not complete.'
        old['modified_bios_created']=True
    save(path,old)

files=set()
for part in ['driver','core','lab']:
    files.update(p for p in (HERE/part).iterdir() if p.is_file() and p.suffix in {'.c','.h','.py','.json'})
files.update(p for p in (HERE/'navigation').iterdir() if p.is_file() and p.suffix in {'.json','.tsv','.mjs'})
files.update(p for p in (HERE/'navigation/rea').iterdir() if p.name.startswith('NAV-') and p.suffix in {'.json','.c'})
files.update([HERE/'package_review.py',driver,candidate,candidate.with_suffix('.json'),HERE/'lab/asus_review/verification.json'])
files.update(p for p in (HERE/'driver/build').iterdir() if p.suffix in {'.json','.map'})
files.update(p for p in run.rglob('*') if p.is_file() and p.suffix in {'.json','.log'})
files.update(p for p in OUT.iterdir() if p.is_file() and p.name!='archive.json')
files.update([report_txt,report_html,BASE/'requirements.json',BASE/'delivery.json'])
files.update([ROOT/'W790-ACE-1904-独立密码锁-实机验证报告.txt',ROOT/'W790-ACE-1904-独立密码锁-实机验证报告.html',hardware_dir/'hardware_summary.json',hardware_dir/'build_hardware_report.py'])
files.update(hardware_dir/name for name in hardware['evidence_files'])
files.update([baseline_dir/'hii_abi_test.json',baseline_dir/'build.json',baseline_dir/'AiTweakerLock1904.efi',baseline_dir/'driver.map',HERE/'package_bios.py'])
for name in ['capture_manifest.json','forms_1904.json','module_metadata.json','callback_dispatch_table.json','navigation_candidate.json','reconciliation.json','rea_evidence_index.json','verification.json','AITWK-P3-W790-ACE-E9B906DF.TXT']:
    files.add(CASE/name)
for name in ['Setup.efi','AMITSE.efi','Setup_IFR.json']:files.add(CASE/'modules'/name)
for pattern in ['*.json','*.c','*.txt']:
    files.update((CASE/'rea').glob(pattern))
files.update([BASE/'inspect_setup.py',BASE/'probe_p3_kvm/source/probe_core.c',BASE/'probe_p3_kvm/source/probe_core.h',BASE/'uefi_vm_20261015/disk_images.py'])
validation_folder=Path(verification['evidence_folder'])
files.update(p for p in validation_folder.iterdir() if p.is_file() and p.suffix in {'.txt','.json'})
assert all(p.is_file() and p.is_relative_to(ROOT) for p in files)
archive=BASE/'W790-ACE-1904-独立密码锁-离线审查包.zip'
entries={relative(p):{'bytes':p.stat().st_size,'sha256':sha(p)} for p in sorted(files)}
manifest={'status':'OFFLINE_REVIEW_ONLY_NOT_FOR_FLASHING','driver_sha256':digest,'candidate_sha256':sha(candidate),'files':entries}
with zipfile.ZipFile(archive,'w',zipfile.ZIP_DEFLATED,compresslevel=6) as z:
    z.writestr('README-先读.txt',readme)
    z.writestr('manifest.json',json.dumps(manifest,ensure_ascii=False,indent=2)+'\n')
    for p in sorted(files):z.write(p,relative(p))
with zipfile.ZipFile(archive) as z:
    assert z.testzip() is None
    for name,item in entries.items():assert hashlib.sha256(z.read(name)).hexdigest()==item['sha256']
    assert not any(name.upper().startswith('EFI/BOOT/') for name in z.namelist())
archive_report={'status':'PASS','archive':relative(archive),'bytes':archive.stat().st_size,'sha256':sha(archive),'entries_verified':len(entries),'bootable_media':False,'flash_package':False,'report':relative(report_html),'driver_sha256':digest,'candidate_sha256':sha(candidate)}
save(OUT/'archive.json',archive_report)
print(json.dumps(archive_report,ensure_ascii=True,indent=2))
