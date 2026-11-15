"""Assemble evidence-backed component update/recovery review. Offline only."""
from pathlib import Path
import hashlib
import json

HERE = Path(__file__).resolve().parent
BASE = HERE.parent
ROOT = next(p for p in HERE.parents if (p / 'tools/rea-runtime').is_dir())

def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def artifact(path):
    return {'path': str(path.relative_to(ROOT)), 'sha256': digest(path), 'bytes': path.stat().st_size}

def main():
    ep = HERE / 'elf_callsite_evidence.json'
    ev = json.loads(ep.read_text(encoding='utf-8'))
    libs = ev['libraries']
    assert set(libs) == {'compamibios', 'compmanager', 'comphelper', 'comppdk'}
    for item in libs.values():
        assert digest(ROOT / item['path']) == item['sha256']
        assert digest(ROOT / item['ghidra_inventory_path']) == item['ghidra_inventory_sha256']
        for fn in item['functions'].values():
            assert digest(ROOT / fn['decompile_path']) == fn['decompile_sha256']
            assert digest(ROOT / fn['annotated_decompile_path']) == fn['annotated_decompile_sha256']
    dispatch = {x['command']: x['handler']['target_function'] for x in libs['compamibios']['amibios_command_dispatch']}
    assert dispatch[1] == 'bios_prepare_comp' and dispatch[7] == 'bios_backup_image'
    assert dispatch[8] == 'bios_perform_recovery' and dispatch[11] == 'verify_bios_signature'
    assert dispatch[14] == 'bios_exit_firmware_update'

    def fn(lib, name):
        return libs[lib]['functions'][name]

    def refs(*pairs):
        return [{'library': lib, 'function': name, **{key: fn(lib, name)[key] for key in ('elf_va', 'ghidra_va', 'bytes_sha256', 'decompile_path', 'decompile_sha256', 'annotated_decompile_path', 'annotated_decompile_sha256')}} for lib, name in pairs]

    def calls(lib, name):
        return {x.get('target_name') for x in fn(lib, name)['call_sites']}

    def strings(lib, name):
        return {x['target_string'] for x in fn(lib, name)['literal_references'].values() if 'target_string' in x}

    assert 'ActiveHostSPIDriver' in calls('compamibios', 'bios_prepare_comp')
    assert {'access', 'unlink', 'find_bios_spi_device'} <= calls('compamibios', 'bios_prepare_comp')
    assert not any((x or '').startswith(('flash_', 'erase')) for x in calls('compamibios', 'bios_prepare_comp'))
    assert {'/var/bios.bin', '/var/biossig.bin'} <= strings('compamibios', 'bios_prepare_comp')
    assert {'/sys/class/gpio/gpio%d/direction', '/sys/class/gpio/gpio%d/value', 'out'} <= strings('comppdk', 'PDK_SwitchBIOSFlash')
    assert 'write' in calls('comppdk', 'PDK_SwitchBIOSFlash')
    assert 'rename' in calls('compamibios', 'bios_backup_image')
    assert 'mv %s %s' in strings('compamibios', 'bios_verify_flash')
    assert {'/var/bios.bin', '/mnt/sdmmc0p%d/recovery_bios.bin_tmp'} <= strings('compamibios', 'bios_verify_flash')
    assert 'flash_bios_image' in calls('compamibios', 'do_bios_recovery')
    assert {'sigwrap_read', 'sigwrap_write', 'lseek'} <= calls('comppdk', 'PDK_ASUSBIOSConfiguration')

    ima = BASE / 'official_bmc/W7901157.ima'
    assert digest(ima) == '0eea0a707e9bcaa6da157db0c8c637b889c456889e0e550a7fb1756a528e565a'
    binding = json.loads((BASE / 'frontend_binding.json').read_text())
    assert binding['deployed_frontend_exact_match'] is True
    signature = json.loads((BASE.parent / 'capsule_static_review.json').read_text())
    assert signature['inputs']['original']['sha256'] == 'aba26bf927de341f1859dd6b5f35645564d5aea104fb26bcc7b5a98bcd96b0b3'
    assert signature['inputs']['exp02']['sha256'] == '95a95856ae9ed393c8ab313ae7763edf9d30534f423f77c894d11d7be6a46a0e'

    findings = [
        {
            'id': 'entry_mode_is_stateful_ipc',
            'finding': 'CMD_Enter_FW_Update_mode sends a component-manager command, creates /var/block_chassis_ops on successful status, and writes the returned firmware ID to /tmp/fwid. CMD_Exit_FW_Update_mode removes the chassis-operation block on successful reply.',
            'confidence': 'Confirmed native behavior in the inspected libraries.',
            'boundary': 'send_compmngr_command uses /var/pipe/comp_req_pipe and comp_res_pipe with a mutex. The receiving daemon implementation is outside this review; its additional effects cannot be excluded. Enter update mode is not a read-only capability query.',
            'evidence': refs(('compmanager', 'CMD_Enter_FW_Update_mode'), ('compmanager', 'CMD_Exit_FW_Update_mode'), ('comphelper', 'send_compmngr_command')),
        },
        {
            'id': 'prepare_switches_spi_hardware_before_flash',
            'finding': 'After firmware-session ID and feature checks, bios_prepare_comp calls ActiveHostSPIDriver(0), locates the BIOS SPI device, checks free memory, resets progress state and removes prior /var/bios.bin and /var/biossig.bin staging files. Its successful path keeps the host SPI driver active until later cleanup.',
            'hardware_path': [
                'ActiveHostSPIDriver(0) reads optional CE selection from /var/bios_cesel.',
                'SwitchGPIO(0) dynamically loads /usr/local/lib/libpdkapp.so and calls PDK_SwitchBIOSFlash(0).',
                "PDK_SwitchBIOSFlash writes 'out' to /sys/class/gpio/gpio15/direction, then writes the input digit ('0' in preparation) to /sys/class/gpio/gpio15/value.",
                'ActiveHostSPIDriver sleeps one second, then runs /sbin/modprobe host_spi_flash_hw ce_index=%d.',
                'ActiveHostSPIDriver(1) runs /sbin/rmmod host_spi_flash_hw, calls PDK_SwitchBIOSFlash(1) and clears in-memory ASUS header structures.',
            ],
            'early_flash_assessment': 'No direct flash_bios_image or erase call occurs in bios_prepare_comp, ActiveHostSPIDriver or PDK_SwitchBIOSFlash. This is not proof of zero flash side effects: kernel module initialization and imported lower-level routines were not exhaustively reviewed. GPIO and driver state mutations are independently confirmed and already make Prepare unsuitable for a read-only probe.',
            'error_handling': 'ActiveHostSPIDriver ignores the SwitchGPIO and safe_system return values and returns 0. A successful higher-level preparation response alone therefore cannot prove GPIO switching or module activation succeeded. Cleanup invokes the reverse path, but its success is likewise not established by this wrapper.',
            'evidence': refs(('compamibios', 'bios_prepare_comp'), ('compamibios', 'ActiveHostSPIDriver'), ('compamibios', 'SwitchGPIO'), ('comppdk', 'PDK_SwitchBIOSFlash'), ('compamibios', 'bios_exit_firmware_update')),
        },
        {
            'id': 'upload_stages_image_then_start_spawns_flash',
            'finding': 'bios_upload_comp writes uploaded bytes to /var/bios.bin; the first CAP chunk splits its 4096-byte header into /var/biossig.bin. file_write_data performs normal file fopen/fseek/fwrite. bios_start_update later calls BiosConfiguration and starts bios_flash, which opens MTD_Device and calls flash_bios_image.',
            'boundary': 'The component dispatcher distinguishes prepare, upload, start-update, verify and recovery. This separation does not turn the preceding GPIO/driver preparation into a read-only operation. No API was invoked to test any branch.',
            'evidence': refs(('compamibios', 'bios_upload_comp'), ('compmanager', 'file_write_data'), ('compamibios', 'bios_start_update'), ('compamibios', 'bios_flash')),
        },
        {
            'id': 'backup_is_staged_recovery_image_not_preflash_spi_dump',
            'finding': 'bios_backup_image only renames /mnt/sdmmc0p%d/recovery_bios.bin_tmp to /mnt/sdmmc0p%d/recovery_bios.bin. It performs no MTD read or whole-device copy.',
            'image_origin': 'On successful post-flash verification, when g_corefeatures + 0x350 is enabled and progress is not failed, bios_verify_flash moves /var/bios.bin to recovery_bios.bin_tmp. Otherwise its successful verification branch deletes /var/bios.bin. This is a retained staged firmware image, potentially carrying preserved regions, rather than a pre-update byte-for-byte snapshot of the installed SPI device.',
            'boundary': 'The live feature value, partition availability, presence, age and contents of recovery_bios.bin were not read. Other potential producers of this file were not exhaustively searched. The identified backup command by itself does not establish a download/export API or an available rollback image.',
            'evidence': refs(('compmanager', 'comp_backup_recovery_image'), ('compamibios', 'bios_backup_image'), ('compamibios', 'bios_verify_flash')),
        },
        {
            'id': 'selected_preservation_reads_exist_but_are_not_full_backup',
            'finding': 'BiosConfiguration opens MTD_Device as its first descriptor and /var/bios.bin as its second descriptor, then calls PDK_ASUSBIOSConfiguration. The board hook copies ranges described by the uploaded image Non Program Block table from MTD into the staged image, and reads the staged bytes back for comparison.',
            'boundary': 'These selected preservation reads are materially different from a full SPI backup. The selected offsets and lengths are image-header dependent. No raw complete image is exported here; malformed/missing metadata and feature conditions can change preservation behavior. This report does not certify the full preservation set for the current board state.',
            'evidence': refs(('compamibios', 'BiosConfiguration'), ('comppdk', 'PDK_ASUSBIOSConfiguration')),
        },
        {
            'id': 'recovery_implementation_is_a_flash_path_not_verified_safety_net',
            'finding': 'comp_perform_bios_recovery sends command 8 for component 2. The BIOS dispatch table maps command 8 to bios_perform_recovery, which creates a do_bios_recovery worker. That worker requires a nonempty recovery_bios.bin, finds the BIOS SPI device, opens it read/write and calls flash_bios_image using the recovery file and its length.',
            'boundary': 'This confirms a native recovery write mechanism exists. It does not prove an ASUS-supported exposed remote recovery route, a populated recovery image, sufficient flash coverage, successful hardware arbitration, or recovery from an arbitrary failure to POST. The reviewed worker does not itself establish all preparation prerequisites. Invoking it would be a write action, not a diagnostic probe.',
            'evidence': refs(('compmanager', 'comp_perform_bios_recovery'), ('compamibios', 'bios_perform_recovery'), ('compamibios', 'do_bios_recovery')),
        },
        {
            'id': 'normal_update_uses_existing_bios_metadata',
            'finding': 'bios_get_version reads ASUS metadata from both /var/bios.bin and MTD_Device. For the 64 MiB W790 image, it scans the staged image starting at 0x3000000; its MTD-side call scans 16 MiB from the same offset. PDK_GetASUSBIOSInfo searches for $BOOTEFI$ and returns failure if the marker is absent.',
            'boundary': 'The caller reports 0xf0 when it cannot obtain the current MTD BIOS metadata. The normal flow therefore depends on information read from the installed flash. This is evidence against assuming arbitrary corruption is recoverable, not proof that every missing-header case is impossible to recover; front-end/REST error handling and vendor-qualified fallback conditions are separate.',
            'evidence': refs(('compamibios', 'bios_get_version'), ('comppdk', 'PDK_GetASUSBIOSInfo')),
        },
        {
            'id': 'capsule_authentication_is_real_native_code',
            'finding': 'The BIOS command table maps signature verification to verify_bios_signature, which calls PDK_VerifyBiosSignature. The board hook reconstructs staged CAP data from /var/biossig.bin and /var/bios.bin and performs OpenSSL RSA/SHA-256 certificate and ROM-region digest verification. Its return status feeds the component response.',
            'boundary': 'This review reuses the existing independently validated original-CAP PASS / EXP02 firmware-signature FAIL evidence; it does not repeat signing experiments, patch verification, or exercise update endpoints. Native verifier presence does not qualify hidden force modes as vendor-supported recovery.',
            'evidence': refs(('compamibios', 'verify_bios_signature'), ('comppdk', 'PDK_VerifyBiosSignature')),
        },
    ]

    report = {
        'status': 'OFFLINE_REVIEW_COMPLETE_PREPARE_MUTATES_GPIO_NO_FULL_SPI_BACKUP_ESTABLISHED',
        'scope': 'Official ASUS W790E-SAGE SE BMC 1.1.57 component-manager, BIOS component and board hooks; no live backend or firmware execution.',
        'actions_performed': ['Read existing official BMC extraction.', 'Attempted REA open; preserved unsupported-target response.', 'Used installed Ghidra headless as offline fallback.', 'Cross-checked ELF dynamic symbols/relocations, ARM PLT call sites and constant-pool strings with a local parser and Capstone.', 'Assembled evidence and reviewed behavior.'],
        'actions_not_performed': ['No BMC connection or command.', 'No Enter/Prepare/Upload/Flash/Recovery endpoint call.', 'No GPIO, SPI or device access.', 'No host power operation.', 'No protection bypass or production firmware/code change.'],
        'inputs': {
            'official_bmc_image': artifact(ima),
            'official_live_frontend_binding': artifact(BASE / 'frontend_binding.json'),
            'public_vendor_recovery_review': artifact(BASE / 'vendor_recovery_review.json'),
            'existing_capsule_signature_review': artifact(BASE.parent / 'capsule_static_review.json'),
            'libraries': {k: {x: v[x] for x in ('path', 'size', 'sha256', 'ghidra_language')} for k, v in libs.items()},
        },
        'deployed_binding_limit': 'The official image version matches the recorded BMC version and its decompressed front-end bytes exactly match the captured deployed source.min.js. Extracted native libraries were not read back or hashed on the live BMC; direct deployed-backend byte equivalence is not claimed.',
        'address_convention': ev['address_convention'],
        'tools': {
            'rea_open_failure': artifact(HERE / 'rea/BIOS-open.json'),
            'fallback_reason': 'Installed REA Windows provider rejected ARM ELF; no retry, reconfiguration or installation was used.',
            'headless_launcher': artifact(BASE / 'run_headless.py'),
            'headless_postscript': artifact(BASE / 'BmcSelectedDecompile.java'),
            'ghidra': 'Installed ghidra_12.1.4_PUBLIC; Java 21; ARM:LE:32:v8 analysis.',
            'evidence_builder': artifact(HERE / 'build_component_evidence.py'),
            'report_builder': artifact(Path(__file__)),
        },
        'native_evidence': artifact(ep),
        'selected_function_count': sum(len(v['functions']) for v in libs.values()),
        'component_command_dispatch': dispatch,
        'findings': findings,
        'conclusion': {
            'read_only_prepare_probe_appropriate': False,
            'whole_spi_preupdate_backup_or_export_demonstrated': False,
            'native_recovery_writer_present': True,
            'remote_only_arbitrary_no_post_recovery_qualified': False,
            'exp02_official_signature_obstacle_resolved': False,
            'decision': 'Keep update/recovery state-changing endpoints untouched. Existing public documentation supports normal valid-CAP remote update, while the inspected native code does not establish a complete recoverable pre-update SPI backup or an approved no-POST fallback for this modified image.',
        },
        'remaining_evidence': [
            'Vendor-confirmed recovery procedure for this exact board/BMC when host firmware cannot POST, including required preconditions and supported image form.',
            'Vendor-supported complete machine-specific SPI readback/export capability and independent coverage/restore validation, if one exists.',
            'Live existence and verified coverage of any recovery image; currently not read and not inferred from file names.',
            'Daemon, driver and hardware success conditions before attempting any state-changing workflow.',
            'An authorized, supported means of obtaining an accepted modified firmware signature; the present EXP02 signature still fails.',
        ],
    }
    out = HERE / 'component_update_recovery_review.json'
    out.write_text(json.dumps(report, indent=2, ensure_ascii=False) + '\n', encoding='utf-8')
    note = HERE / 'component_update_recovery_review.md'
    note.write_text('''离线检查已确认：进入更新及 Prepare 会修改状态，不能用作只读探测。Prepare 会切换 GPIO15、装载 host_spi_flash_hw，并清理暂存文件；只在这些用户态函数内未见提前 erase/flash 调用，不代表已经证明所有下层动作都无写入。

命名为 BIOS backup 的函数仅将 recovery_bios.bin_tmp 改名为 recovery_bios.bin；已发现的暂存文件来源是在成功刷写验证后移动 /var/bios.bin。另有从 MTD 把指定 Non Program Block 区段复制进待刷映像的保留逻辑，但都不是刷写前全 SPI 导出。

确有原生 recovery worker 会把 recovery_bios.bin 写入 SPI。这说明实现中存在恢复写入逻辑；尚未证明实机有这个文件、覆盖范围充分、存在厂商支持的公开入口，或任何无法 POST 的损坏都可远程恢复。正常版本读取还会从现有 SPI 的 48 MiB 位置搜索 $BOOTEFI$ 元数据。

原版 CAP 与 EXP02 的验签结果继续沿用既有独立数学证据：EXP02 固件签名仍失败。没有调用 BMC、进入更新模式、上传、刷写或绕过校验。

精确库哈希、原生地址、调用点、字串重定位及带注释反编译分别见 component_update_recovery_review.json、elf_callsite_evidence.json 与 annotated_decompile/。Ghidra 地址比 ELF 链接地址多 0x10000；没有宣称这些地址是实机运行地址。
''', encoding='utf-8')
    print(json.dumps({'report': artifact(out), 'note': artifact(note), 'selected_functions': report['selected_function_count']}))

if __name__ == '__main__':
    main()
