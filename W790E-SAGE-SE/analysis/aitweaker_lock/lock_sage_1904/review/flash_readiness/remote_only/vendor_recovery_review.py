"""Assemble existing offline captures and consulted official documentation.

This does not contact a BMC, upload a capsule, enter update mode, execute
captured JavaScript, change protections, or perform any firmware write.
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
REVIEW = HERE.parent
BUNDLE_EVIDENCE = HERE / "vendor_bundle_evidence.json"
CAPSULE_EVIDENCE = REVIEW / "capsule_static_review.json"
UPDATE_EVIDENCE = REVIEW / "bmc_update_path_review.json"
ASMB11 = "https://dlcdnets.asus.com/pub/ASUS/E25502_ASMB11-iKVM_UM_V3_WEB.pdf?model=RS720Q-E11-RS8U"
BOARD_MANUAL = "https://dlcdnets.asus.com/pub/ASUS/mb/LGA4677/Pro_WS_W790E-SAGE_SE/E22125_Pro_WS_W790E_SAGE_SE_UM_V2_WEB.pdf?model=Pro+WS+W790E-SAGE+SE"
BOARD_PRODUCT = "https://www.asus.com/motherboards-components/motherboards/business/pro-ws-w790e-sage-se/"
BOARD_BIOS = "https://www.asus.com/supportonly/pro%20ws%20w790e-sage%20se/helpdesk_bios/"


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def file_record(path: Path) -> dict:
    return {"path": str(path), "sha256": sha(path.read_bytes()), "bytes": path.stat().st_size}


def main() -> None:
    bundle_evidence = json.loads(BUNDLE_EVIDENCE.read_text(encoding="utf-8"))
    bundle_path = Path(bundle_evidence["bundle"]["path"])
    bundle = bundle_path.read_bytes()
    assert sha(bundle) == bundle_evidence["bundle"]["sha256"] == "d623b1bef4383fefbbb7e615fc9490c9aebd01870f3bab0113c2b4cd039f1226"
    # Babel offsets count UTF-16 code units, including astral Unicode characters.
    utf16 = bundle.decode("utf-8").encode("utf-16-le")
    module_by_name = {m["name"]: m for m in bundle_evidence["modules"]}

    def exact_text(start: int, end: int) -> str:
        return utf16[start * 2:end * 2].decode("utf-16-le")

    def function(module_name: str, name: str) -> dict:
        module = module_by_name[module_name]
        assert sha(exact_text(module["start"], module["end"]).encode()) == module["sha256"]
        matches = [f for f in module["functions"] if f["name"] == name]
        assert len(matches) == 1, (module_name, name)
        node = matches[0]
        code = exact_text(node["start"], node["end"])
        return {"module": module_name, "module_sha256": module["sha256"], "function": name, "start_utf16": node["start"], "end_utf16": node["end"], "function_sha256": sha(code.encode()), "source": code}

    bindings = {
        "bmc_config_selection": function("views/maintenance/backup_config", "initialize"),
        "bmc_config_export": function("views/maintenance/backup_config", "save"),
        "profile_export_v1": function("views/maintenance/BIOSUserProfileUpdateView", "Download_UserProfile"),
        "profile_export_v2": function("views/maintenance/BIOSUserProfileView", "Download_UserProfile"),
        "profile_download_v2": function("views/maintenance/BIOSUserProfileView", "Download_File"),
        "normal_bios_start": function("views/maintenance/BIOSUpdateView", "Start"),
        "normal_bios_initialization": function("views/maintenance/BIOSUpdateView", "initialize"),
        "normal_bios_prepare": function("views/maintenance/BIOSUpdateView", "PrepareComponents"),
        "normal_bios_signature_verify": function("views/maintenance/BIOSUpdateView", "VerifySignature"),
        "normal_bios_flash": function("views/maintenance/BIOSUpdateView", "FlashBIOS"),
        "oob_start": function("views/maintenance/BIOSOOBUpdateView", "Start_OOB"),
        "controller_recovery_settings": function("views/maintenance/bmc_recovery", "initialize"),
    }
    assert 'bmc-config.bak' in bindings["bmc_config_export"]["source"]
    assert 'OOB.CMO' in bindings["profile_export_v1"]["source"]
    assert 'OOB.CMOS' in bindings["profile_export_v2"]["source"]
    assert 'Pro-WS-W790E-SAGE-SE' in bindings["normal_bios_initialization"]["source"]
    assert '/api/maintenance/bios/verifySignature' in bindings["normal_bios_signature_verify"]["source"]
    assert '/api/oob/start-lmedia' in bindings["oob_start"]["source"]
    capsule = json.loads(CAPSULE_EVIDENCE.read_text(encoding="utf-8"))
    assert capsule["inputs"]["original"]["sha256"] == "aba26bf927de341f1859dd6b5f35645564d5aea104fb26bcc7b5a98bcd96b0b3"
    assert capsule["inputs"]["exp02"]["sha256"] == "95a95856ae9ed393c8ab313ae7763edf9d30534f423f77c894d11d7be6a46a0e"
    assert capsule["original_signatures"]["firmware_signature"]["valid"] is True
    assert capsule["exp02_signatures"]["firmware_signature"]["valid"] is False
    record = {
        "status": "REVIEW_COMPLETE_REMOTE_UPDATE_DOCUMENTED_FULL_SPI_BACKUP_AND_POSTLESS_RECOVERY_NOT_QUALIFIED",
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "target": "ASUS Pro WS W790E-SAGE SE, BIOS 1904, ASMB11-iKVM, currently only BMC/KVM available",
        "scope": "Offline review of previously captured BMC front-end source, existing capsule signature evidence, and ASUS public documentation. No BMC request or firmware operation was performed.",
        "script": file_record(Path(__file__)),
        "evidence_files": {
            "captured_bundle": file_record(bundle_path),
            "offline_bundle_ast": file_record(BUNDLE_EVIDENCE),
            "prior_update_path_review": file_record(UPDATE_EVIDENCE),
            "existing_capsule_signature_review_not_reexecuted": file_record(CAPSULE_EVIDENCE),
        },
        "conclusion": {
            "public_vendor_bmc_bios_update_feature_exists": True,
            "public_vendor_full_host_spi_export_path_found": False,
            "machine_specific_full_spi_backup_obtained": False,
            "exact_board_bmc_recovery_after_arbitrary_no_post_failure_qualified": False,
            "onsite_flashback_feature_documented": True,
            "remote_only_recovery_gap_closed": False,
            "summary_zh": "ASUS 公开支持通过 BMC 的 BIOS Forced Update 更新有效 CAP；不能把它误写成完全没有远程更新功能。但公开手册和捕获前端尚不足以证明这台板在任意无法 POST 的损坏状态下可远程恢复，也未找到完整主机 SPI 导出流程。BMC 配置备份和 BIOS 设置档均不能替代现场 SPI 全量备份。",
        },
        "source_documents": [
            {
                "id": "asus_asmb11_v3",
                "title": "ASMB11-iKVM User Guide E25502, Revised Edition V3, November 2024",
                "url": ASMB11,
                "support_index": "https://www.asus.com/us/supportonly/asmb11-ikvm/helpdesk_manual/",
                "sections": [{"printed_page": "3-30", "pdf_page_index": 55, "topic": "Backup/Restore Configuration and active BMC firmware"}, {"printed_page": "3-31", "pdf_page_index": 56, "topic": "BIOS OOB Update and BIOS Forced Update"}],
                "observed": "Backup Configuration exports selected settings as .bak. BIOS OOB Update stages a valid CAP in virtual local storage for the host to consume after reset. BIOS Forced Update updates a valid CAP through BMC.",
                "does_not_establish": "No explicit full host SPI readback/export procedure or W790E-SAGE SE arbitrary no-POST recovery guarantee is given in these sections. The manual is ASMB11-wide, not an acceptance test of this individual machine.",
            },
            {
                "id": "asus_board_manual",
                "title": "Pro WS W790E-SAGE SE User Manual E22125, Revised Edition V2, June 2023",
                "url": BOARD_MANUAL,
                "sections": [{"printed_page": "2-23", "pdf_page_index": 68, "topic": "USB BIOS FlashBack"}, {"printed_page": "3-4", "pdf_page_index": 79, "topic": "CrashFree BIOS 3"}],
                "observed": "FlashBack uses the dedicated physical USB port and physical button while standby power is present, without entering the existing BIOS or OS. CrashFree recovers from an original or updated BIOS on USB storage.",
                "does_not_establish": "These instructions do not document a BMC command replacing the physical FlashBack button, nor guarantee that virtual CD media is accepted by an early recovery path.",
            },
            {
                "id": "asus_board_product",
                "title": "Pro WS W790E-SAGE SE product page, BIOS FlashBack section",
                "url": BOARD_PRODUCT,
                "observed": "ASUS explicitly says FlashBack can operate without memory or CPU, using USB storage and the button.",
                "does_not_establish": "This is the physical FlashBack feature; it is not evidence that BMC virtual media or keyboard input can invoke it remotely.",
            },
            {
                "id": "asus_board_bios",
                "title": "Pro WS W790E-SAGE SE BIOS & Firmware support page",
                "url": BOARD_BIOS,
                "observed": "The 1904 official ZIP is listed with SHA-256 1D01A9A3EFF7A264E4009281466E669A0631CEDF6095E101CED520F86FB9C480. Release notes name PWW790SG.CAP for USB FlashBack. Earlier 1202 notes explicitly reference BIOS OOB update in IPMI web UI.",
                "does_not_establish": "A generic official download is not a readback of the current machine's SPI, NVRAM, personalization, or other persistent controller state.",
            },
        ],
        "backup_artifact_distinctions": [
            {
                "kind": "BMC configuration backup",
                "files": ["bmc-config.bak"],
                "front_end_evidence": ["bmc_config_selection", "bmc_config_export"],
                "content_indicators": ["snmp", "kvm", "network", "ipmi", "ntp", "authentication", "syslog", "fan"],
                "meaning": "Selected management-controller configuration; the observed action saves selections then downloads a text/blob configuration file.",
                "host_spi_full_backup": False,
            },
            {
                "kind": "BIOS settings/profile export",
                "files": ["OOB.CMO", "OOB.CMOS", "Profile_N.CMO / user-description.CMO"],
                "front_end_evidence": ["profile_export_v1", "profile_export_v2", "profile_download_v2"],
                "meaning": "BIOS user profiles/CMOS settings, including individual and combined profile downloads. The front-end exposes profile copy/edit/merge operations.",
                "actual_profile_payload_acquired_in_this_review": False,
                "host_spi_full_backup": False,
                "limit": "Filename alone does not prove exact file internals, but neither the profile workflow nor its documentation establishes raw firmware, descriptor or ME-region readback.",
            },
            {
                "kind": "Official ASUS CAP",
                "file": "Pro-WS-W790E-SAGE-SE-ASUS-1904.CAP",
                "sha256": capsule["inputs"]["original"]["sha256"],
                "meaning": "Known official signed update input; not captured from this machine.",
                "host_spi_full_backup": False,
            },
            {
                "kind": "Machine-specific complete host SPI readback",
                "file": None,
                "meaning": "Would require the complete actual mapped flash contents with readable-region coverage, layout and integrity evidence; separate BMC/FRU information may live outside host SPI.",
                "vendor_documented_remote_export_identified": False,
                "obtained": False,
                "limit": "No supported export was found in the consulted official manuals or relevant captured modules. This is not a claim that no unpublished vendor service method exists.",
            },
        ],
        "recovery_path_comparison": [
            {
                "path": "Documented BIOS Forced Update menu / BIOSUpdateView normal CAP flow",
                "public_documentation": "asus_asmb11_v3 page 3-31",
                "model_match_in_captured_client": "Pro-WS-W790E-SAGE-SE occurs in BIOSUpdateView.arrVersion",
                "host_dependency": "Captured normal Start requires host power status Off. It requests BMC-side preparation, signature validation, upload, flash and image verification; it does not use the OOB virtual-media sequence.",
                "no_post_inference": "The powered-off host workflow is evidence that this path is intended to work without a running OS/Setup session. It is a plausible recovery channel for some firmware faults, but this alone does not qualify every no-POST/corruption case.",
                "important_unknowns": ["Actual backend implementation and writable/preserved sections", "Behavior when current board/version/project metadata is unreadable or damaged", "Recovery from failed writes and protection-policy failures", "Restoration of machine-specific persistent data"],
                "tested_on_this_machine": False,
                "qualified_as_recovery_backstop_for_custom_firmware": False,
            },
            {
                "path": "BIOS OOB Update / BIOSOOBUpdateView",
                "public_documentation": "asus_asmb11_v3 page 3-31",
                "host_dependency": "Host must execute enough firmware after reset to detect the staged virtual local storage and consume the update.",
                "qualified_for_no_post": False,
                "reason": "No cited source establishes availability if the failing host never reaches that updater path.",
            },
            {
                "path": "USB BIOS FlashBack",
                "public_documentation": "asus_board_manual page 2-23 and asus_board_product",
                "host_dependency": "Existing BIOS/OS execution is unnecessary; physical USB port/button and standby power are required by the documented procedure.",
                "remote_only_available_under_current_constraints": False,
                "reason": "No documented remote BMC substitute for inserting the USB device and operating the FlashBack button was found.",
            },
            {
                "path": "CrashFree BIOS 3 from USB",
                "public_documentation": "asus_board_manual page 3-4",
                "qualified_for_bmc_virtual_cd_in_no_post_state": False,
                "reason": "The public procedure covers USB recovery media. Recognition of a virtual CD and continued operation of the affected recovery firmware have not been established.",
            },
            {
                "path": "BMC recovery settings / bmc_recovery module",
                "front_end_evidence": ["controller_recovery_settings"],
                "qualified_as_host_bios_recovery": False,
                "reason": "This is named and routed as BMC recovery configuration, not a demonstrated host SPI backup/restore method. Merely shipping a module does not establish that it is enabled on this board.",
            },
        ],
        "force_mode_distinction": {
            "documented_menu": "BIOS Forced Update is the public feature name in the ASUS ASMB11 manual.",
            "internal_force_mode": "BIOSUpdateView defaults ForceMode to 0. Separate non-default branches relax checks and alter SECTION_FLASH; a missing-current-version condition can request this mode.",
            "not_equivalent": True,
            "hidden_mode_invoked": False,
            "statement": "The public menu's existence does not authorize treating undocumented internal ForceMode behavior as a supported recovery guarantee, an unsigned-image path, or a replacement for a backup.",
        },
        "signature_condition": {
            "review_reused": str(CAPSULE_EVIDENCE),
            "original_capsule_firmware_signature_valid": True,
            "exp02_capsule_firmware_signature_valid": False,
            "normal_captured_client_validates_cap_signature_before_payload_upload": True,
            "server_acceptance_tested": False,
            "consequence": "A documented path for valid official CAP recovery does not establish acceptance of EXP02's invalid factory signature. This review does not repeat cryptographic tests or attempt a bypass.",
        },
        "searched_scope": {
            "captured_amd_modules": bundle_evidence["module_count"],
            "focused_modules": [m["name"] for m in bundle_evidence["modules"]],
            "official_search_terms": ["ASMB11 BIOS Forced Update recovery", "W790E-SAGE SE BIOS BMC backup", "ASMB11 BIOS corrupted", "BIOS Forced Update POST", "ASUS BIOS dump BMC", "ASUS BIOS backup ipmitool"],
            "source_limit": "Only official ASUS manuals/product/support pages are relied on for vendor support. Search absence and front-end absence are not proof of backend impossibility.",
        },
        "remaining_evidence_needed": [
            "ASUS-supported full host SPI readback/export method for this exact model and installed BMC firmware, including readable coverage and integrity verification.",
            "Model-specific confirmation that the normal documented BIOS Forced Update can restore original 1904 after the relevant no-POST failure, including preserved/written sections and damaged metadata handling.",
            "A demonstrated recovery route independent of the modified host firmware, or physical FlashBack/service access if remote recovery is unavailable.",
            "Manufacturer-authorized signing/customization path remains separately necessary; a recovery route does not repair the invalid EXP02 capsule signature.",
        ],
        "source_function_bindings": bindings,
    }
    out = HERE / "vendor_recovery_review.json"
    out.write_text(json.dumps(record, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"status": record["status"], "output": str(out), "sha256": sha(out.read_bytes()), "bytes": out.stat().st_size}, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
