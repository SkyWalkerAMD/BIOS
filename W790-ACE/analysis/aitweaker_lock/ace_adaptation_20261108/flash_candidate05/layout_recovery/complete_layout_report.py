"""Bind the offline layout evidence, read-only inventory media and open gaps.

This script performs no hardware or network access and does not rebuild media.
Existing offline reports remain unchanged and retain their acquisition scope.
"""
from pathlib import Path
import hashlib
import json
import shutil

HERE = Path(__file__).resolve().parent
ROOT = next(p for p in HERE.parents if (p/'tools/pydeps').is_dir())
BASE = HERE.parents[1]
def sha(path): return hashlib.sha256(path.read_bytes()).hexdigest()
def load(path): return json.loads(path.read_text(encoding='utf8'))
def rec(path): return {'path': path.relative_to(ROOT).as_posix(), 'sha256': sha(path), 'bytes': path.stat().st_size}
def save(path, data): path.write_text(json.dumps(data, indent=2, ensure_ascii=False)+'\n', encoding='utf8')

layout = load(HERE/'layout_identity.json')
media = load(HERE/'probe/media_manifest.json')
assert media['status'] == 'READY_FOR_ROOT_REVIEW_LOCAL_VALIDATION_PASSED'
for item in media['files']:
    path = ROOT/item['path']; assert sha(path) == item['sha256'] and path.stat().st_size == item['bytes'], path
for item in layout['inputs'].values():
    path = ROOT/item['path']; assert sha(path) == item['sha256'] and path.stat().st_size == item['bytes'], path
for key in ['fit_report', 'preservation_report', 'backup_report']:
    item = layout[key]; assert sha(ROOT/item['path']) == item['sha256']
assert sha(ROOT/layout['difference']['changed_blocks']['path']) == layout['difference']['changed_blocks']['sha256']

legacy = ROOT/'analysis/aitweaker_lock/lock_sage_1904/review/flash_readiness/remote_only'
refdir = HERE/'reference_documents'; refdir.mkdir(exist_ok=True)
chipsec = '3ada8580d0bc5b7335afeed4e72092a043e5c877'
linux = '6628e7d4c6b25c8d18f1345e3a20d21829aae7e4'
flashrom = '0bc4b2ddb0f83e3829e8fad840ece804640c37f3'
references = []
for name, url, purpose in [
    ('pch_7xx.xml', f'https://github.com/chipsec/chipsec/blob/{chipsec}/chipsec/cfg/8086/pch_7xx.xml', 'Reference W790 LPC 7A8A and nominal 700-series SPI 7A24 IDs; not observed ACE hardware identity.'),
    ('spi0.xml', f'https://github.com/chipsec/chipsec/blob/{chipsec}/chipsec/cfg/8086/SPI/spi0.xml', 'PCI BAR0 register format.'),
    ('spibar0.xml', f'https://github.com/chipsec/chipsec/blob/{chipsec}/chipsec/cfg/8086/SPI/spibar0.xml', 'Allowed SPI status/range/protection register offsets and fields.'),
    ('spi-intel-pci.c', f'https://github.com/torvalds/linux/blob/{linux}/drivers/spi/spi-intel-pci.c', '7A24 and 7AA4 dispatch to the same CNL controller layout; implementation is reference only.'),
    ('spi-intel.c', f'https://github.com/torvalds/linux/blob/{linux}/drivers/spi/spi-intel.c', 'CNL register layout; a real flash READ requires transient FADDR/HSFSTS_CTL writes, which inventory05 never performs.')]:
    source = legacy/'spi_inventory_candidate04/source/reference_documents'/name
    target = refdir/name; shutil.copyfile(source, target)
    references.append({'url': url, 'snapshot': rec(target), 'copied_from': rec(source), 'purpose': purpose,
                       'provenance': 'Existing local archived primary-source snapshot; this turn web re-fetch returned Cache miss. Snapshot hash is explicit, upstream commit identity not independently re-fetched in this turn.',
                       'license': 'Preserved original notices. Reference material only; not linked into the new EFI.'})
source = legacy/'read_only_backup_design/references/flashrom-chipset-enable.c'
target = refdir/'flashrom-chipset-enable.c'; shutil.copyfile(source, target)
references.append({'url': f'https://github.com/flashrom/flashrom/blob/{flashrom}/chipset_enable.c', 'snapshot': rec(target), 'copied_from': rec(source),
                   'purpose': 'The captured enable paths can call BIOS_CNTL write routines. A read command alone is insufficient to claim initialization is register-write-free.',
                   'provenance': 'Existing archived primary-source snapshot, not executed or newly fetched.', 'license': 'Preserved original notices; not linked.'})
references += [
    {'url': 'https://uefi.org/specs/UEFI/2.11/14_Protocols_PCI_Bus_Support.html', 'purpose': 'EFI_PCI_IO Read/GetLocation ABI and separate read/write methods.', 'access': 'Opened successfully in this turn; used only for API semantics.'},
    {'url': 'https://cdrdv2-public.intel.com/599500/599500_FW_Interface_Table_BIOS_Spec_Rev1p6.pdf', 'purpose': 'FIT pointer, table format and entry types. Reference format, not physical target state.'},
    {'url': 'https://raw.githubusercontent.com/LongSoft/UEFITool/new_engine/common/descriptor.h', 'purpose': 'Descriptor format and conventional region names. Slot9 is conventionally Device expansion2; its ACE-specific purpose remains unknown.'},
    {'url': 'https://raw.githubusercontent.com/LongSoft/UEFITool/new_engine/common/intel_fit.h', 'purpose': 'Independent implementation of FIT entry identifiers.'},
    {'url': 'https://raw.githubusercontent.com/LongSoft/UEFITool/new_engine/common/ffs.h', 'purpose': 'AMI signed Capsule GUID and ROM image/layout offset fields.'},
    {'url': 'https://edc.intel.com/content/www/us/en/design/products-and-solutions/processors-and-chipsets/700-series-chipset-family-platform-controller-hub-datasheet-volume-1-of/004/spi0-for-flash/', 'purpose': 'Intel 700-series SPI host access background; not an ACE hardware measurement.'},
    {'url': 'https://www.intel.com/content/www/us/en/developer/articles/technical/software-security-guidance/resources/key-usage-in-integrated-firmware-images.html',
     'purpose': 'Firmware authentication and fused key hierarchy background. Its stated platform-generation coverage is not proof of this W790 policy.'},
    {'url': 'https://dlcdnets.asus.com/pub/ASUS/mb/LGA4677/Pro_WS_W790-ACE/J21702_Pro_WS_W790-ACE_UM_V2_WEB.pdf?model=Pro+WS+W790-ACE',
     'purpose': 'Actual ACE manual: 512Mb ROM and local USB BIOS FlashBack port/button, PWW790A.CAP. Does not establish BMC remote control or modified-Capsule acceptance.',
     'access_note': 'The English manual URL opened in earlier review resolved to this Japanese ACE manual; language and URL are recorded explicitly.'}
]
save(HERE/'references.json', {'scope': 'Primary format/API/layout references and locally archived source; no SAGE live observation is used as ACE hardware evidence.', 'references': references})

proposal = {
    'status': 'STAGE1_MEDIA_LOCAL_VALIDATED_REAL_HARDWARE_COLLECTION_OWNED_BY_ROOT',
    'stage1': {'media_manifest': rec(HERE/'probe/media_manifest.json'), 'read_only_scope': media['limits'],
               'expected_source_identity': media['source_bundle_sha256'], 'hardware_completed_by_this_agent': False,
               'can_resolve': ['Whether exact ACE1904/CPUID identity and the known PCI provider/controller IDs are exposed.',
                              'Current PCI location, existing BAR0 and Command/BIOS_CNTL values without altering them.',
                              'If PCI_IO supports reads, BFPR/HSFSTS/FRAP/FREG0..5/PR0..4 values and first unsupported/error status.'],
               'cannot_resolve': ['Actual component density, full SPI image bytes, FREG slot9 permission, live FIT/KM/BPM/IBB or Boot Guard fuse state.',
                                  'A read error is not a proof of hardware flash protection; the protocol can itself be unsupported.',
                                  'Firmware update signature acceptance, power-loss recovery or preservation of all unit-specific data.']},
    'stage2_not_implemented': {
        'name': 'Whole-device readback feasibility after the actual stage1 log',
        'preconditions': ['Use observed ACE identity and a verified controller API/layout; no SAGE BAR/address fallback.',
                          'Define and independently review any transient controller writes required for READ. Such writes are different from flash program/erase but are outside inventory05.',
                          'Confirm actual capacity/component count and addressable range. The public descriptor declares one64MiB device but is not a measurement.',
                          'Account for every region, including nonempty slot9. FRAP low8 region fields alone do not establish slot9 readability.',
                          'Use a transport with explicit offsets, per-chunk length/status/hash, retries, bounded timeout and end-to-end SHA256.'],
        'allowed_future_flash_operation_if_separately_reviewed': 'READ only; not currently authorized or implemented by this artifact.',
        'forbidden_assumptions': ['Do not substitute public CAP bytes or FF for unreadable ranges.',
                                  'Do not call a CPU-mapped 16MiB BIOS window a64MiB SPI backup.',
                                  'Do not assume read-only CLI intent guarantees initialization performs no configuration writes.',
                                  'Do not take equal length, one SHA or a successful exit code as proof that every flash read succeeded.'],
        'acceptance': ['Every byte offset0..capacity-1 acquired with successful status and no gaps/overlap/duplicate substitutions.',
                       'Two complete acquisitions with corresponding byte/hash comparison, handling mutable NV separately and preserving both originals.',
                       'Independent parse of each received dump: descriptor, every declared region, expected BIOS1904 identity, FIT, mutable stores.',
                       'The machine-received and workstation-received whole-file hashes match and all source chunks remain available.'],
        'transport_obstacle': {'qr_payload_bytes_per_page': 768, 'pages_for_declared_64MiB': (67108864+767)//768,
                               'explanation': 'QR is practical for small inventory evidence, not a full64MiB readback at87382 pages. Current read-only CD cannot receive a firmware-created dump. A separately reviewed writable destination or network receiver is still required.'}
    },
    'recovery_requirement': {
        'reported_available': 'Only188 BMC; no on-site programmer, no prior whole-device backup and no signing channel per parent/user.',
        'physical_FlashBack': 'ACE manual describes local USB port/button operation. Physical access/control is unavailable in the current task and remote BMC activation has not been demonstrated.',
        'KVM_virtual_CD_limit': 'Works only while host firmware can initialize and boot. Its current availability is not recovery after BIOS execution failure.',
        'complete_backup_alone_is_sufficient': False,
        'needed': 'An actually accessible, supported recovery route that can write the exact required format if the host BIOS no longer executes, plus preserved unit data.'
    }
}
save(HERE/'read_only_probe_proposal.json', proposal)

text = '''ACE 1904 固件布局、保留范围与恢复证据

当前结论：review.bin 是改过内容但保留原 Capsule 头的审查产物，尚不能称为可刷写 BIOS。
本目录已完成独立原字节布局/FIT/差异核实，并制作了仅采集寄存器的 inventory05 介质。
本报告不是更新器接受测试、完整备份或恢复验收。实机采集由主线程单独安排并保留独立日志。

原厂输入 SHA256 03e4330430b2510d5e9e5c9868ca64c730844992b82c6a272b815aef3d20bf29。
review.bin SHA256 1e5e7db497949016855afd0575a6d4dfedf633ec52b644ed8fa3c60d3bc54c4e。
二者均为 67112960 字节：4096 字节 AMI Aptio signed Capsule 头 + 67108864 字节 Intel 固件映像。
扩展名 .bin 不改变格式；不能把该文件直接当无头 SPI 映像或16MiB BIOS区域。
Capsule GUID 为4a3ca68b-7723-48fb-803d-578cc1fec44d，ROM映像偏移0x1000。
头部未改，内部内容已变，本审查未做新的签名验证；未重签不能推导厂商更新器会接受它。
字段格式参照 UEFITool 主源，详见 references.json。

以下均为去掉 Capsule 头之后的原始偏移：
0x00000000..0x00000FFF  Descriptor，4096字节。
0x00001000..0x00692FFF  ME，6889472字节。
0x00693000..0x02FFFFFF  region9，43438080字节；常规名称 Device expansion2，但本板具体用途未证明。
0x03000000..0x03FFFFFF  BIOS，16777216字节。
四区无缝覆盖64MiB。region9 中有3700039个非FF字节，不能当填充丢弃。
原厂 descriptor 声明一个64MiB组件；尚未实测芯片容量或布局。
原UEFIExtract report的Descriptor行基址与原字节签名位置不一致，本解析以CAP0x1010处描述符签名和原始表字段为准。

全部改动位于 CAP偏移0x3181078、raw偏移0x3180078、原长3586976字节的一个DXE压缩容器。
实际改变3572932字节，涉及876个4KiB原始块；容器之前和之后逐字节相同。
内层423个原FFS在原偏移原字节保留，新增驱动GUID97f9cf3d-1209-4c68-a827-e547d0531904。
嵌入的驱动精确对应生产463b94139cb64207e1b756965ebb9ca3513250c8712bbbcd20798fd317dec904。
ME、descriptor、region9和其余原始FV均未改；这是相对公开原厂CAP的结论，不是相对188当前存储。

原厂和review的FIT指针位于物理0xFFFFFFC0，内容指向0xFF84F100，对应raw0x384F100。
引用的48字节FIT只有头和两项微码，CPU签名806F3/806F8；两微码整体校验和为0，字节和FIT均未改。
没有被该FIT引用的startup ACM、KM、BPM；未能得到BPM定义的IBB区间，不能宣称改动一定在IBB之外。
原文件及展开的DXE中未见相关manifest签名，也不能据此宣称实机Boot Guard关闭。
FIT格式参考Intel规范：https://cdrdv2-public.intel.com/599500/599500_FW_Interface_Table_BIOS_Spec_Rev1p6.pdf
实机FIT/manifest、熔丝、配置、verified/measured boot状态仍未知；inventory05不执行未经确认的RDMSR。

原厂NVAR store位于CAP0x3011078，所在FV为CAP0x3011000、长度0x80000，review保留其原字节。
这只是工厂参考变量存储；188当前变量、DMI序列号、UUID、密钥、授权数据和网卡NVM/MAC尚未完整采集。
descriptor中GbE区禁用，不代表网卡持久数据不存在。ACE板的网卡/独立BMC/TPM存储也不能由主SPI映像完整代替。
未来设备专用候选应从可靠的本机dump生成，所有非目标范围必须按本机原字节保留；不要用公开CAP重置这些区域。

已审的历史硬件模块/二维码记录、bmc_readonly字段和RAM04三个命名变量比较都不是整片SPI备份。
截至本报告准备时，根代理确认无188整片备份；目前仅有BMC，无现场编程器、已知签名渠道。
用户可用的KVM和虚拟CD依赖主BIOS仍能执行，不能证明写坏BIOS后可恢复。
ACE手册确实描述USB BIOS FlashBack端口和物理按钮，文件名PWW790A.CAP；现有条件未证明能带外触发该物理流程。
手册来源：https://dlcdnets.asus.com/pub/ASUS/mb/LGA4677/Pro_WS_W790-ACE/J21702_Pro_WS_W790-ACE_UM_V2_WEB.pdf?model=Pro+WS+W790-ACE
该手册也不证明改过内容的Capsule能通过认证、或FlashBack会保留所有个性化数据。

inventory05 采用 EFI_PCI_IO，按已暴露设备和BAR进行有限读取；没有SAGE地址、RootBridge/CPU_IO2旁路、PCI使能或SPI cycle。
API来源：https://uefi.org/specs/UEFI/2.11/14_Protocols_PCI_Bus_Support.html
全部源码、EFI、ISO、116组实际EFI故障测试、2组OVMF/QR验证由probe/media_manifest.json精确绑定。
本地仿真控制器值不证明188状态。完整日志保留actual_component_capacity=null、FLASH_BYTES_ACQUIRED=0、BootGuard.live_policy=UNKNOWN。
若实际EFI_PCI_IO.Mem.Read不支持，只能记录“不支持”；不能称为闪存硬件禁止读取，也不能自行切换裸地址读取。

真正整片readback还需要：观测到的控制器支持、所有区读权限、实际容量、严格只读flash操作实现、可接收64MiB的传输链路。
控制器READ本身通常需要临时写地址/控制寄存器，此程序完全未实现；这与flash编程/擦除不同，但须另行审查。
纯二维码传64MiB需87382页；当前只读CD也不能接收输出，因此不能把现有小日志链路当整片备份交付链路。
任何读失败都必须保留失败状态，不可用FF或原厂CAP填补。两次完整读取、逐块状态与哈希、收发端全文件哈希和独立解析都是验收输入。
即使取得完整备份，也仍需能在主BIOS失效后实际执行的恢复途径。

可复核入口：analyze_layout.py；它只读取固定哈希的原厂/审查文件并生成离线报告，不做硬件动作。
媒体验证入口：probe/verify_inventory.py、probe/verify_ovmf.py、probe/finalize_manifest.py。
总证据绑定入口：complete_layout_report.py；不重建EFI/ISO。Windows运行时使用本机Python3.14完整路径。
layout_identity.json中的hardware_read_performed/probe_or_iso_created字段仅描述最初离线解析这一步；后续媒体状态单独见media_manifest.json。
'''
(HERE/'README-布局与恢复.txt').write_text(text, encoding='utf8')
files = [HERE/name for name in ['analyze_layout.py', 'layout_identity.json', 'changed_blocks_4k.json', 'fit_boot_guard_reference.json',
          'preservation_ranges.json', 'backup_gap_assessment.json', 'references.json', 'read_only_probe_proposal.json',
          'README-布局与恢复.txt', 'complete_layout_report.py', 'probe/media_manifest.json']]
files += sorted(refdir.glob('*'))
summary = {'status': 'OFFLINE_LAYOUT_VERIFIED_INVENTORY_MEDIA_LOCAL_VALIDATED_RECOVERY_NOT_ESTABLISHED',
           'source': layout['inputs']['official_cap'], 'review': layout['inputs']['review_cap_with_bin_extension'], 'driver': layout['inputs']['driver'],
           'inventory_efi': media['efi'], 'inventory_iso': media['iso'], 'hardware_acquisition_performed_by_this_agent': False,
           'inventory_media_local_validation': {'cases': 116, 'ovmf_cases': 2, 'qr_and_escape': 'PASS', 'manifest': rec(HERE/'probe/media_manifest.json')},
           'claim_boundary': {'bare_SPI': False, 'BIOS_only': False, 'capsule_with_64MiB_payload': True,
                              'public_reference_preserved_outside_one_DXE_container': True,
                              'live_unit_full_backup_available': False, 'live_BootGuard_state_known': False,
                              'modified_capsule_signature_acceptance_proven': False, 'dead_BIOS_recovery_proven': False,
                              'ready_for_flash': False},
           'files': [rec(path) for path in files]}
save(HERE/'layout_recovery_summary.json', summary)
print(json.dumps({'summary': rec(HERE/'layout_recovery_summary.json'), 'readme': rec(HERE/'README-布局与恢复.txt'),
                  'probe_manifest': rec(HERE/'probe/media_manifest.json'), 'status': summary['status']}, indent=2))
