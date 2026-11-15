"""Build the reviewed, physical USB FlashBack-only candidate05 field package.

Reads pinned local sources. No network, device access, renaming of originals,
firmware signing, executable invocation, or overwriting of an existing package.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import zipfile

BASE = Path(__file__).resolve().parent.parent
WORKSPACE = BASE.parents[3]
OUT = Path(__file__).resolve().parent
CAP_BYTES = 67_112_960
HEADER_BYTES = 4096
CANDIDATE_SHA = "9b038c4eae111a985c5c5fef460f0874338d16764b0ead6f89a3e55c775f5455"
OFFICIAL_SHA = "03e4330430b2510d5e9e5c9868ca64c730844992b82c6a272b815aef3d20bf29"
PAYLOAD_SHA = "2dd240c1ddb8890500ce028bb7de25d2db8f687117f4c0d2a57ba400ffbe9809"
DRIVER_SHA = "71b05ebe21fd0b4de496fc9684f57e4acc79431e38a403dec9017501605eca98"
CANDIDATE_SOURCE = BASE / "lock_1904_candidate05/lab/asus_review/W790-ACE-1904-lock.review.bin"
OFFICIAL_SOURCE = WORKSPACE / "analysis/aitweaker_lock/official_W790_ACE_1904/W790_ACE_1904/Pro-WS-W790-ACE-ASUS-1904.CAP"
ENGINEERING_SOURCE = BASE / "engineering_signature/W790-ACE-1904-CANDIDATE05-ENGINEERING-NONOEM-NOT-FLASH-READY.CAP"
CANDIDATE_MEMBER = "01-CANDIDATE05-USB/PWW790A.CAP"
RECOVERY_MEMBER = "02-OFFICIAL1904-RECOVERY/PWW790A.CAP"


def sha(data):
    return hashlib.sha256(data).hexdigest()


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def pinned(path, expected):
    data = path.read_bytes()
    require(sha(data) == expected, f"Source identity mismatch: {path.name}")
    return data


def write_json(path, value):
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(value, stream, indent=2, ensure_ascii=False)
        stream.write("\n")


README = """W790 ACE 1904 / Ai Tweaker 独立密码 / 候选05
USB BIOS FlashBack 专用现场验证包

一、使用哪份文件
目标主板：ASUS Pro WS W790-ACE。基础版本：1904。
正常安装候选05：只复制 01-CANDIDATE05-USB/PWW790A.CAP 到 U 盘根目录。
原厂恢复尝试：使用 02-OFFICIAL1904-RECOVERY/PWW790A.CAP，单独存放或使用另一个标记清楚的 U 盘。
两份文件已经改好官方专用名称，无须运行 BIOSRenamer。不要把两个同名文件混在同一个根目录。
保留完整 CAP 文件；不要去掉开头4096字节，不要把 ZIP、ISO或目录本身当作刷写文件。

二、目前验证到哪里
本包已核对候选身份、完整CAP尺寸、原厂头、板型/FlashBack识别数据和包内SHA-256。
候选05生产密码核心已在本机通过关机再开机后的持久化、认证、改密和清除测试；测试记录已删除。
这些测试使用隔离控制台。永久DXE的原生Setup集成、FlashBack控制器接受、实际写入和刷后启动仍待现场验证。
这是修改固件。保留原厂CAP头不代表修改后内容仍有有效的ASUS固件签名。
本包仅供物理USB BIOS FlashBack；EZ Flash和带外网页更新不是本包的使用步骤。
原厂恢复文件是公开1904固件，不是这台机器的整片备份，不能保证恢复SHUANG定制内容、设置或全部机器专属数据。

三、复制前校验
在完整解压目录打开PowerShell，执行以下命令，只读核对全部清单文件及两份CAP：
  powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\\Verify-Package.ps1
该命令的执行策略仅用于本次校验进程，不更改系统策略。
也可在PowerShell手动检查：
  Get-FileHash -Algorithm SHA256 -LiteralPath '.\\01-CANDIDATE05-USB\\PWW790A.CAP'
候选SHA256：9b038c4eae111a985c5c5fef460f0874338d16764b0ead6f89a3e55c775f5455
原厂SHA256：03e4330430b2510d5e9e5c9868ca64c730844992b82c6a272b815aef3d20bf29
复制到U盘后，对U盘中的PWW790A.CAP再次核对相应SHA-256。两份CAP长度均为67,112,960字节。

四、现场FlashBack步骤
1. 准备至少1GB的U盘，MBR、单分区、FAT32；格式化会清空该U盘，先保存需要的数据。
2. 把选定的PWW790A.CAP放到U盘根目录，确认没有隐藏的第二个“.CAP”扩展名。
3. 主机关机，主板24针电源接好，PSU接市电且开关开启，保持待机供电。
4. 插入后置I/O的专用BIOS FlashBack USB口。面向后置面板、音频接口在右侧时，它是第二组竖排四个黑色USB口中的自上而下第二个。打开第5节链接中的本板手册第2-19页图，并以主板标识核对。BIOS按钮在面板最左侧下方；上方是Clear CMOS按钮。
5. 按住BIOS FlashBack按钮约3秒，见指示灯闪烁3次后松开，等待灯最终熄灭。
6. 更新期间保持供电和U盘连接，不开机、不清CMOS。通用FAQ中的约8分钟是估计，不是断电时限。
7. 正常灯灭后再开机，留出首次内存训练时间，按Del/F2进入BIOS，执行POSTFLASH-CHECKS.txt。

异常：约5秒闪烁后转为持续常亮，手册判为异常，不能算完成。记录灯态，核对专用端口、U盘格式、文件名和哈希；也可能是修改版未被控制器接受。持续闪烁时不要强制中断。不要自行更改CAP头或使用其他型号文件来尝试。
若候选写入结束后无法正常启动，可按同样官方流程尝试独立目录中的原厂1904恢复文件；本包不承诺已经验证整机恢复能力。

五、官方步骤和端口图
W790-ACE E22143手册，第2-19页（PDF55）、第2-21页（PDF57）：
https://dlcdnets.asus.com/pub/ASUS/mb/LGA4677/Pro_WS_W790-ACE/E22143_Pro_WS_W790-ACE_UM_V3_WEB.pdf#page=55
ASUS USB BIOS FlashBack FAQ：
https://www.asus.com.cn/support/faq/1038568/
FAQ可能使用其他主板作示例；本包文件名和端口以W790-ACE专用手册为准。

本包制作阶段没有执行现场FlashBack或再次连接带外。按用户安排，现场操作稍后进行。
"""

POSTFLASH = """候选05刷后原生功能验收（尚未执行）

先记录FlashBack灯态、耗时及首次启动结果。仅显示BIOS1904不能证明候选05功能已加载。

1. 直接从正常开机进入BIOS，不启动先前的RAM测试或密码测试工具。
2. 在Security中确认“Ai Tweaker Password”和“Clear Ai Tweaker Password”两项可见。
3. 若尚未配置密码，Ai Tweaker应提示先在Security设置。通过“Ai Tweaker Password”设定独立密码：8-128个可打印ASCII字符，两次输入一致；不与BIOS管理员密码或带外帐号自动共用。
4. 测试错误密码和Esc取消应保持拒绝，正确密码可进入Ai Tweaker。同一BIOS会话内再次进入可复用授权。
5. 完整退出Setup并重新进入，或关机再开机，检查重新要求认证、原密码仍有效。
6. 修改密码时提供当前密码，确认旧密码失效、新密码有效。“Clear Ai Tweaker Password”需要当前密码及Y确认，其含义是关闭此项保护。若最终要保留保护，测试后重新设置最终密码。
7. 初次验收只访问页面，不修改电压、频率或内存参数。确认其他页面、正常退出和既有系统启动仍可使用。

密码管理应显示成功或失败结果。若管理项缺失、输入正确仍反复拒绝、拒绝后仍可访问受保护页、出现冻结或启动异常，记录结果，不把此前离线/RAM测试当作该项通过。
记录截图时避免拍入口令明文；提交实际灯态、Main/Security界面和失败提示即可。无须把密码写入验收记录。

现场记录
日期/主板：
U盘中文件SHA256：
FlashBack起始/结束灯态与耗时：
首次POST/进入Setup：
两项Security管理入口：
设置/错误/取消/正确认证：
退出或重新开机后的重锁与持久化：
改密/清除/最终保护状态：
正常系统启动及异常现象：
"""

VERIFY = r'''# Read-only verification of this unpacked field package.
$ErrorActionPreference = 'Stop'
$packageRoot = [IO.Path]::GetFullPath($PSScriptRoot)
$manifestPath = Join-Path $packageRoot 'manifest.json'
$manifest = Get-Content -LiteralPath $manifestPath -Raw -Encoding UTF8 | ConvertFrom-Json
if ($manifest.schema -ne 'ace1904_flashback_field_package_v1') { throw 'Unexpected package schema' }
$fixed = @{
  '01-CANDIDATE05-USB/PWW790A.CAP' = '9b038c4eae111a985c5c5fef460f0874338d16764b0ead6f89a3e55c775f5455'
  '02-OFFICIAL1904-RECOVERY/PWW790A.CAP' = '03e4330430b2510d5e9e5c9868ca64c730844992b82c6a272b815aef3d20bf29'
}
$seen = @{}
foreach ($entry in $manifest.files) {
  $relative = [string]$entry.path
  if ($relative -notmatch '^[A-Za-z0-9_./-]+$' -or $relative.StartsWith('/') -or $relative.Split('/') -contains '..') { throw 'Unsafe manifest path' }
  if ($seen.ContainsKey($relative)) { throw 'Duplicate manifest path' }
  $seen[$relative] = $true
  $full = [IO.Path]::GetFullPath((Join-Path $packageRoot $relative))
  if (-not $full.StartsWith($packageRoot + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) { throw 'Path outside package' }
  $item = Get-Item -LiteralPath $full
  if ($item.PSIsContainer -or $item.Length -ne [long]$entry.bytes) { throw "Length mismatch: $relative" }
  $actualHash = (Get-FileHash -LiteralPath $full -Algorithm SHA256).Hash.ToLowerInvariant()
  if ($actualHash -ne [string]$entry.sha256) { throw "Hash mismatch: $relative" }
  if ($fixed.ContainsKey($relative)) {
    if ($item.Length -ne 67112960 -or $actualHash -ne $fixed[$relative]) { throw "CAP identity mismatch: $relative" }
  }
}
foreach ($relative in $fixed.Keys) { if (-not $seen.ContainsKey($relative)) { throw "Missing CAP: $relative" } }
$caps = @(Get-ChildItem -LiteralPath $packageRoot -File -Recurse -Filter '*.CAP')
if ($caps.Count -ne 2) { throw 'Expected exactly two separately stored CAP files' }
Write-Output ('PASS: ' + $seen.Count + ' manifest files and both exact CAP identities verified.')
Write-Output 'File verification is complete. Physical FlashBack acceptance and post-flash boot are not yet tested.'
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--selection-report", required=True)
    parser.add_argument("--selection-sha256", required=True)
    args = parser.parse_args()
    selection_path = (BASE / args.selection_report).resolve()
    require(selection_path.is_relative_to(BASE) and selection_path.is_file(), "Selection report must be in candidate05 workspace")
    require(len(args.selection_sha256) == 64, "Selection SHA256 required")
    selection = pinned(selection_path, args.selection_sha256)
    json.loads(selection.decode("utf-8-sig"))
    candidate = pinned(CANDIDATE_SOURCE, CANDIDATE_SHA)
    official = pinned(OFFICIAL_SOURCE, OFFICIAL_SHA)
    engineering = pinned(ENGINEERING_SOURCE, "e330039ecd2c334c4f9d502589e7f9503000b34462a7e21f6b97b1b581794d08")
    pinned(BASE / "lock_1904_candidate05/driver/build/AiTweakerLock1904.efi", DRIVER_SHA)
    for blob in (candidate, official, engineering):
        require(len(blob) == CAP_BYTES, "Full CAP length required")
        require(struct.unpack_from("<III", blob, 16) == (4096, 0x10001, CAP_BYTES), "CAP header mismatch")
    require(candidate[:HEADER_BYTES] == official[:HEADER_BYTES], "Original CAP header must be retained")
    require(candidate[HEADER_BYTES:] == engineering[HEADER_BYTES:], "Candidate05 payload mismatch")
    require(sha(candidate[HEADER_BYTES:]) == PAYLOAD_SHA, "Payload identity mismatch")
    evidence_sources = [
        ("flashback_packaging_review/source_review.json", "90afbaeda71ec23188f4778c9c6e4ad2b986bc7722342dd2443929c57642db36", "03-EVIDENCE/format-and-name-review.json"),
        ("flashback_instructions_review/flashback_instructions_review.json", "19108fdd37d909a619ad000e9dfc392cd24c18a9f12c1ad1b7aedce4b6eea991", "03-EVIDENCE/official-instruction-sources.json"),
    ]
    evidence = [(dest, pinned(BASE / source, digest)) for source, digest, dest in evidence_sources]
    nv = pinned(BASE / "nv_persistence_review/independent_review/hardware_nv_summary.json", "f797d759e331e7343f65c1c727c0b096eb04cbe19a891f546bca0ebde9372040")
    require(json.loads(nv.decode("utf-8-sig")), "NV evidence must parse")
    package = OUT / "package"
    archive = OUT / "W790-ACE-1904-AI-TWEAKER-C05-FLASHBACK-ONLY.zip"
    require(not package.exists() and not archive.exists(), "Existing delivery must not be overwritten")
    package.mkdir()
    for name, data in [(CANDIDATE_MEMBER, candidate), (RECOVERY_MEMBER, official), *evidence,
                       ("03-EVIDENCE/flashback-selection-review.json", selection)]:
        target = package / name
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open("xb") as stream:
            stream.write(data)
    (package / "README-USB-FlashBack.txt").write_text(README, encoding="utf-8", newline="\n")
    (package / "POSTFLASH-CHECKS.txt").write_text(POSTFLASH, encoding="utf-8", newline="\n")
    (package / "Verify-Package.ps1").write_text(VERIFY, encoding="ascii", newline="\n")
    write_json(package / "03-EVIDENCE/validation-summary.json", {
        "scope": "Candidate05 source/code and previously completed isolated hardware tests, not permanent-DXE acceptance",
        "candidate05_driver_sha256": DRIVER_SHA,
        "candidate_payload_sha256": PAYLOAD_SHA,
        "source_layout": "Independent UEFIExtract passed; 423 original inner DXE FFS offsets/bytes retained, new driver added",
        "entry_services_fix": "Synchronous retirement stops further initialization/provider use",
        "physical_password_core": "Enrollment, host Off/On persistence, wrong/cancel denial, correct unlock, session relock, password change and authenticated clearing passed with production objects under isolated console ownership",
        "hardware_nv_summary_sha256": sha(nv),
        "credential_cleanup": "Owned test record deleted; absence confirmed after another host Off/On",
        "native_password_UI_after_permanent_flash": "NOT_RUN",
        "USB_FlashBack_hardware_acceptance": "NOT_RUN",
        "BMC_and_EZFlash": "Distinct paths; previous BMC SPI Prepare failure and native OEM-root rejection do not establish FlashBack controller behavior",
        "boot_guard_and_full_recovery": "Not established by this package",
    })
    files = [{"path": p.relative_to(package).as_posix(), "bytes": p.stat().st_size, "sha256": sha(p.read_bytes())}
             for p in sorted(package.rglob("*")) if p.is_file()]
    manifest = {
        "schema": "ace1904_flashback_field_package_v1",
        "status": "PREPARED_FOR_PHYSICAL_USB_FLASHBACK_FIELD_VALIDATION",
        "board": "ASUS Pro WS W790-ACE", "base_bios": "1904", "candidate": "05",
        "delivery_route": "Physical USB BIOS FlashBack only",
        "user_schedule": "Package now; onsite USB/button operation later",
        "candidate_file": CANDIDATE_MEMBER, "official_recovery_file": RECOVERY_MEMBER,
        "candidate_CAP_sha256": CANDIDATE_SHA, "official_CAP_sha256": OFFICIAL_SHA,
        "candidate_payload_sha256": PAYLOAD_SHA, "driver_sha256": DRIVER_SHA,
        "full_CAP_bytes": CAP_BYTES, "header_bytes": HEADER_BYTES,
        "original_CAP_header_preserved": True, "modified_payload_OEM_signature_valid": False,
        "engineering_resigned_CAP_included": False,
        "hardware_flashback_acceptance_verified": False,
        "permanent_DXE_native_password_UI_verified": False,
        "firmware_flash_performed": False,
        "complete_current_SPI_backup_included": False,
        "files": files,
        "manifest_note": "files lists every packaged content file except this manifest and SHA256SUMS.txt to avoid self-reference. The ZIP hash is distributed separately.",
    }
    write_json(package / "manifest.json", manifest)
    sum_paths = sorted(p for p in package.rglob("*") if p.is_file())
    (package / "SHA256SUMS.txt").write_text("".join(f"{sha(p.read_bytes())}  {p.relative_to(package).as_posix()}\n" for p in sum_paths), encoding="ascii", newline="\n")
    with zipfile.ZipFile(archive, "x", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as output:
        for path in sorted(p for p in package.rglob("*") if p.is_file()):
            item = zipfile.ZipInfo(path.relative_to(package).as_posix(), date_time=(2026, 11, 8, 0, 0, 0))
            item.compress_type = zipfile.ZIP_DEFLATED
            item.external_attr = 0o100644 << 16
            output.writestr(item, path.read_bytes(), compresslevel=9)
    archive_record = {"path": str(archive), "bytes": archive.stat().st_size, "sha256": sha(archive.read_bytes()),
                      "files": sum(p.is_file() for p in package.rglob("*")),
                      "status": manifest["status"], "candidate_CAP_sha256": CANDIDATE_SHA,
                      "selection_report_sha256": args.selection_sha256,
                      "builder_sha256": sha(Path(__file__).read_bytes()),
                      "hardware_flash_performed": False}
    write_json(OUT / "build-receipt.json", archive_record)
    (OUT / (archive.name + ".sha256")).write_text(f"{archive_record['sha256']}  {archive.name}\n", encoding="ascii")
    print(json.dumps(archive_record, ensure_ascii=True))


if __name__ == "__main__":
    main()
