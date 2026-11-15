"""Bind the three requested static recovery/export conclusions. No target I/O."""
from pathlib import Path
import hashlib
import json
import struct
import sys
import uuid

HERE = Path(__file__).resolve().parent
BASE = HERE.parent
ROOT = next(p for p in HERE.parents if (p / "tools/pydeps").is_dir())
sys.path.insert(0, str(ROOT / "tools/pydeps"))
import pefile

def ident(p):
    raw = p.read_bytes()
    return dict(path=p.relative_to(ROOT).as_posix(), bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())

def save(name, obj):
    p = HERE / name
    p.write_text(json.dumps(obj, indent=2, ensure_ascii=False)+"\n", encoding="utf-8")
    return ident(p)

def native(lib, name):
    d = json.loads((BASE / "bmc1313_native_evidence.json").read_text(encoding="utf-8"))["libraries"][lib]
    f = d["functions"][name]
    return dict(library_sha256=d["sha256"], function=name, elf_va=f["elf_va"], native_sha256=f["bytes_sha256"],
                decompile=ident(ROOT / f["decompile_path"]), annotated=ident(ROOT / f["annotated_path"]))

def main():
    module = BASE / "native_inputs/ReFlash-70e1a818-0.efi"
    mm = pefile.PE(str(module)).get_memory_mapped_image()
    table = struct.unpack_from("<6Q", mm, 0x7ab0)
    assert table == (0x26c8, 0x26bc, 0x27b4, 0x26bc, 0x26bc, 0x26bc)
    assert mm[0x26bc:0x26c7] == bytes.fromhex("48b80300000000000080c3")
    assert uuid.UUID(bytes_le=mm[0x77d0:0x77e0]) == uuid.UUID("86c77a67-0b97-4633-a187-49104d0685c7")
    rea = HERE / "rea/fmp"
    evidence = []
    for p in sorted((rea / "responses").glob("*.json")):
        raw = json.loads(p.read_text(encoding="utf-8"))
        assert not raw.get("error") and not raw.get("result", {}).get("isError"), p
        for c in raw.get("result", {}).get("content", []):
            if c.get("type") == "text":
                try:
                    d = json.loads(c["text"])
                except ValueError:
                    continue
                if isinstance(d, dict) and d.get("evidence_id"):
                    evidence.append(dict(evidence_id=d["evidence_id"], operation=d["operation"],
                                         parameters=d.get("parameters"), response=ident(p)))
    close = json.loads((rea / "close-status.json").read_text(encoding="utf-8"))
    assert close["process_exit_code"] == 0 and close["close_response_present"]
    fmp = save("fmp_getimage_review.json", dict(
        status="PROVED_ORIGINAL_ACE_SYSTEM_BIOS_FMP_GETIMAGE_ALWAYS_UNSUPPORTED",
        scope="Original ACE1904 ReFlash provider. Static REA and independent PE bytes, no firmware execution or live invocation.",
        module=ident(module), original_CAP_sha256="03e4330430b2510d5e9e5c9868ca64c730844992b82c6a272b815aef3d20bf29",
        discovery=ident(HERE / "fmp_guid_inventory.json"),
        provider_installation=dict(function_RVA="0xa1c", protocol_table_reference_RVA="0xca9", GUID_reference_RVA="0xcb7", InstallProtocolInterface_call_RVA="0xcc2", protocol_GUID="86c77a67-0b97-4633-a187-49104d0685c7", table_RVA="0x7ab0"),
        table=[dict(slot=i, offset=hex(i*8), method=n, target_RVA=hex(a)) for i, (n, a) in enumerate(zip(["GetImageInfo", "GetImage", "SetImage", "CheckImage", "GetPackageInfo", "SetPackageInfo"], table))],
        GetImage=dict(RVA="0x26bc", exact_bytes=mm[0x26bc:0x26c7].hex(), instructions=["mov rax,0x8000000000000003", "ret"], result="EFI_UNSUPPORTED", parameter_branches=0, flash_reads=0, exportable_ranges=[]),
        GetImageInfo=dict(RVA="0x26c8", descriptor_size="0x78", descriptor_count=1, descriptor_version=4, reported_image_size="0x04000000", reported_image_size_bytes=67108864, ImageTypeId=str(uuid.UUID(bytes_le=mm[0x7a28:0x7a38])), supported_and_setting_attributes=3,
                          qualification="64MiB is descriptor metadata. It is not a working GetImage implementation or measured current flash capacity."),
        consumer_correction="FmpCapsuleUpdate is a consumer that calls provider GetImageInfo and SetImage; it does not itself provide a system-flash GetImage service.",
        REA=dict(evidence=evidence, provenance=ident(rea / "provenance.json"), close=ident(rea / "close-status.json"), seed_policy="Explicit function seeds identify actual table targets missed by initial default analysis. Only analysis metadata changes; original bytes do not."),
        limits=["GUID scanning covered the original main DXE FV. Other FMP users/providers can describe peripheral firmware, not the complete ACE system SPI.", "No claim of current live protocol publication was made."]
    ))

    prepare = save("prepare_exit_review.json", dict(
        status="STATIC_NORMAL_FLOW_IDENTIFIED_NOT_READ_ONLY_NOT_PROVED_EXACTLY_REVERSIBLE",
        scope="Official 1.3.13 backend tied to the byte-identical current public frontend. No BMC request, driver load, GPIO change, firmware execution, upload, program or erase was performed by this reviewer.",
        current_binding=ident(BASE / "bmc1313_extraction_manifest.json"),
        reference_HTTP_sequence=[
            dict(step="EntryUpdateMode", method="PUT", path="/api/maintenance/bios/updatemode", frontend_application_data={}, result="unique_id", effect="Compmanager command1/component0 creates /var/FWmode with a31-bit random ID, sets g_FirmwareID; library touches /var/block_chassis_ops on success and writes /tmp/fwid."),
            dict(step="Prepare", method="PUT", path="/api/maintenance/bios/preparecomponents", frontend_application_data=dict(FWUPDATEID="the returned unique_id", COMPONENT_ID=2, IS_MMC=0, COMPONENT_DATA_LEN=67108864),
                 effect="REST writes /var/biosflashing=1 and removes /var/bios.bin before component validation; sends component2/command1. A complete67112960-byte CAP is rounded down to64MiB by normal frontend logic."),
            dict(step="ExitUpdateMode", method="PUT", path="/api/maintenance/bios/exitupdatemode", frontend_application_data=dict(FWUPDATEID="the same returned unique_id", COMPONENT_ID=2),
                 effect="REST first runs fixed driver/GPIO cleanup and unlinks /var/bios.bin, then sends command2/component0 to validate/remove FWmode; library removes chassis block on logical success, REST writes biosflashing=0.")],
        sequence_is_reference_only=True,
        prepare_admission=["Backend request ID must equal g_FirmwareID.", "Check_FeatureList returns byte1 from /conf/FeatureList.dat; missing file defaults to1. The backend requires exactly1.", "ActiveHostSPIDriver(0) is attempted, then find_bios_spi_device searches /proc/mtd for Host SPI Flash.", "sysinfo.freeram must be at least requested payload size. This is a RAM-size check, not comparison with current MTD capacity.", "Success clears upload counters, remembers requested length and removes bios.bin/biossig.bin. It returns echoed request metadata, not JEDEC ID, MTD size or flash bytes."],
        ActiveHostSPIDriver=dict(elf_va="0x2ec0", entry_zero=["rmmod host_spi_flash_hw; sleep2; SwitchGPIO(0); sleep1; remove rom_id.tmp; insmod exact archived host_spi_flash_hw.ko; sleep2", "Read nine bytes from /var/rom_id.tmp. Missing file or ID00FFFFFF triggers unload, sleep2, SwitchGPIO(2), reload and another probe.", "An ID/voltage table may also request the3.3V path after initial1.8V probing. All observed exits return0, including missing final rom_id.tmp."], entry_one=["rmmod host_spi_flash_hw", "SwitchGPIO(1)", "ClearASUSBiosHeader resets in-memory parsed-header structures, not SPI contents"], ignored_results=["safe_system rmmod/insmod/rm status", "SwitchGPIO return status", "short or failed ROM-ID fread"], consequence="A nominal success is not reliable evidence that each physical transition happened; stale named MTD can survive an unsuccessful unload."),
        GPIO=dict(provider="PDK_SwitchBIOSFlash ELF0x208c", source=ident(HERE / "pdk-0001208c-PDK_SwitchBIOSFlash.c"),
                  mode0=["If /conf/HWVersion.txt parses as4: GPIO44 out/high", "GPIO97 input; GPIO13 out/low; GPIO98 out/high; GPIO101 out/low; GPIO15 out/high; GPIO5 out/high, with fixed sleeps"],
                  mode2=["GPIO15 input; GPIO5 input; GPIO98 input; GPIO15 out/high; GPIO5 out/high, with fixed sleeps"],
                  mode1=["GPIO5 input; GPIO15 input; GPIO101 input; GPIO13 input; GPIO97 out/high; if HWVersion4 GPIO44 input"],
                  limitations=["Previous direction/value state is never captured.", "An open failure returns after earlier transitions; no internal rollback.", "write return values are ignored.", "GPIO98 is not restored by mode1.", "Normal REST Exit uses its own fixed gpiotool sequence5/15/101/13 input then97 out/high; it omits GPIO44 and98. Exact electrical polarity requires board design evidence."]),
        kernel=dict(module=ident(HERE / "host_spi_flash_hw.ko"), native=ident(HERE / "kernel_native_evidence.json"),
                    initializer=ident(BASE / "recovery_kernel_decompile/000117ec-ast_host_spi_flash_init.c"), probe=ident(BASE / "recovery_kernel_decompile/00011154-spi_flash_probe.c"),
                    behavior=["Creates host_spi character device; maps AST SPI registers0x1e630000 and AHB windows0x30000000/0x32000000; configures controller chip-select ranges and15MHz clock.", "reset_flash changes controller control-register bits; its name is not proof of a66h/99h chip reset command.", "Probe calls local helper that sends04h WRDI,06h WREN and polls05h status WEL; then sends9Fh JEDEC ID and writes /var/rom_id.tmp.", "Matches ID against compiled supported-chip table, creates named Host SPI Flash MTD and assigns read/write/erase callbacks.", "For matched capacity greater than16MiB, it attempts B7h enter4-byte mode after WREN and sets controller address mode.", "No program/erase callback is invoked in the inspected init/probe path. Opcode02h/erase callbacks exist for later MTD writes; mere callback registration does not execute them.", "init returns success without propagating spi_flash_probe result.", "Normal module exit unregisters/frees MTD and unmaps controller windows; neither exit nor spi_flash_remove calls exit_4byte_addr_mode or captures/restores prior SPI-controller state."],
                    address_mode_exit=ident(BASE / "recovery_kernel_decompile/000110a8-exit_4byte_addr_mode.c"), remove=ident(BASE / "recovery_kernel_decompile/00011528-spi_flash_remove.c"), exit=ident(BASE / "recovery_kernel_decompile/00011a34-ast_host_spi_flash_exit.c")),
        failure_paths=[
            "bios_prepare_comp calls ActiveHostSPIDriver(1) on all rejected paths including badID/feature failure/find-MTD failure/insufficientRAM; its return is ignored.",
            "Normal frontend invokes ExitUpdateMode on Prepare errors. That is best-effort fixed cleanup, not transactional restoration.",
            "REST Exit performs driver/GPIO effects before daemon FWUPDATEID validation. An invalid ID can therefore still affect the SPI path; no atomic ownership guarantee is inferred.",
            "Daemon Exit logs an unlink failure but can still report logical success; REST GPIO/system failures are not reflected in cc0.",
            "Entry random-generation/file-write failures can leave /var/FWmode; no reviewed normalGET retrieves/reconciles its exact owner ID.",
            "A timeout or interrupted request can leave chassis blocking, GPIO ownership, driver or address mode changed. No verified normal rollback/readback interface proving restoration was found in this scope."],
        conclusions=dict(program_or_erase_observed_in_reference_prepare_path=False, pure_read_only=False, exact_reversibility_proved=False,
                         prepare_success_proves="At most component-manager acceptance and observation of a named MTD under its unchecked lower-level operations; not a complete backup, fresh JEDEC measurement or64MiB capacity verification.",
                         electrical_connection_test="Driver probing can provide limited connection evidence if actual fresh JEDEC/MTD creation and cleanup are independently observed. Prepare/Exit responses alone do not supply that proof.",
                         independent_no_POST_recovery="The BMC-side path is not inherently dependent on host POST, but this static path does not prove the actual card-to-host SPI cable, chip selection, complete writable extent or successful recovery on188."),
        evidence=[native("rest", "putBIOSUpdateMode_func"), native("rest", "setBIOSPrepareComponents_func"), native("rest", "putBIOSExitUpdateMode_func"), native("bios", "bios_prepare_comp"), native("bios", "ActiveHostSPIDriver"), native("bios", "SwitchGPIO"), native("host", "find_bios_spi_device"), ident(HERE / "extended_literal_evidence.json")]
    ))

    routes = json.loads((HERE / "all_compiled_routes.json").read_text(encoding="utf-8"))
    exports = save("normal_flash_export_review.json", dict(
        status="NO_NORMAL_COMPLETE_CURRENT_SPI_EXPORT_IDENTIFIED_IN_REVIEWED_CURRENT_ROUTES",
        scope="Compiled REST route objects, selected actual handlers, current-identical frontend and existing current Redfish UpdateService analysis. Negative conclusion is bounded to inspected interfaces; no arbitrary-file path, exploit, SMASH escape or hidden override was used.",
        compiled_route_inventory=ident(HERE / "all_compiled_routes.json"), route_count=routes["count"],
        considered=[
            dict(route="GET /api/maintenance/download_config", handler="downloadBackupConfig_func ELF0xde414", output="/var/bkupconf as bmc-config.bak", conclusion="BMC configuration archive, no SPI acquisition in handler.", evidence=ident(HERE / "rest-000de414-downloadBackupConfig_func.c")),
            dict(route="GET /api/maintenance/downloaduserprofile", handler="downloadUserProfile_func ELF0x12c424", output="/conf/hi_user_profile/OOB.CMO", conclusion="Existing BIOS settings profile.", evidence=ident(HERE / "rest-0012c424-downloadUserProfile_func.c")),
            dict(route="POST /api/maintenance/downloaduserprofile_v2", handler="downloadUserProfile_v2_func ELF0x139f4c", output="Selected normal profile copied within /tmp/hi_user_profile_v2/fromBIOS to download.CMOS", conclusion="Normal profile selection only; no arbitrary-path use considered.", evidence=ident(HERE / "rest-00139f4c-downloadUserProfile_v2_func.c")),
            dict(route="PUT /api/maintenance/firmware/dwldfwimg", handler="dwldFWImage_func ELF0xe83b8", output="Calls libflash DownloadFwImage; sends command11 to flasher after preparation. Current frontend calls with PROTO_TYPE=TFTP in update flow.", conclusion="Download toward BMC/update engine, not an HTTP export of current flash; not a harmless GET.", evidence=ident(HERE / "rest-000e83b8-dwldFWImage_func.c"), library_evidence=ident(HERE / "flash-000143e0-DownloadFwImage.c")),
            dict(route="GET /api/maintenance/firmware/dwldfwstatus-progress", handler="dwldFWStatus_func ELF0xe88e4", output="Status fields from /var/flasher.progress", conclusion="Progress, not image bytes.", evidence=ident(HERE / "flash-00014aa4-GetDownloadProgress.c")),
            dict(route="GET /api/maintenance/biosversion", handler="getBIOSVersion_func / bios_get_version", output="Parsed uploaded and MTD ASUS version headers; backend requires same FWUPDATEID and staged bios.bin first.", conclusion="Metadata only, not complete SPI export. It opens MTD but responds with header records.", evidence=native("bios", "bios_get_version")),
            dict(route="BIOS component backup/recovery commands", output="bios_backup_image renames an existing recovery_bios.bin_tmp; recovery writes an already-present image", conclusion="No current-SPI backup creation or download was found.", evidence=ident(BASE / "backup_recovery_review.json")),
            dict(route="UEFI system BIOS FMP GetImage", output="EFI_UNSUPPORTED", conclusion="No complete or partial current system-flash export.", evidence=fmp)],
        normal_legal_access_limit="Normal SSH was reported by parent as restricted SMASHLITE. No Linux shell, host_spi file read or custom device-command route is assumed by this static review.",
        result="A complete owner-specific current SPI backup and independently verified restore path remain unestablished. A stock CAP, renamed image or settings archive does not satisfy either requirement.",
        BMC_access=False, arbitrary_paths=False, firmware_execution=False
    ))
    summary = save("recovery_extension_summary.json", dict(
        status="REQUESTED_THREE_STATIC_QUESTIONS_COMPLETED_LIMITS_RETAINED",
        FMP_GetImage="System BIOS provider always returns EFI_UNSUPPORTED; no range export.",
        Prepare_Exit="Normal route is identifiable and no program/erase call was observed in init/probe, but WREN/address-mode/controller/GPIO state changes and unchecked cleanup prevent claiming read-only or exact reversibility.",
        normal_complete_SPI_export="Not identified in inspected current interfaces; settings/download-update routes are not backups.",
        reports=[fmp, prepare, exports], hardware_access=False, production_source_changes=False,
        previous_update_path_reports_unchanged=True
    ))
    print(json.dumps(summary))

if __name__ == "__main__":
    main()
