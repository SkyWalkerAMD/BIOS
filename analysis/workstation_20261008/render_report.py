"""Generate the Chinese analysis report and validate its source evidence."""
from pathlib import Path
from html import escape
from collections import Counter
import csv
import hashlib
import json

OUT = Path(__file__).resolve().parent
ROOT = OUT.parent.parent
ORDER = ["W790_SAGE_2003", "W790_ACE_2003", "W890_SAGE_0603"]
LABEL = {"W790_SAGE_2003": "W790E-SAGE SE 2003", "W790_ACE_2003": "W790-ACE 2003", "W890_SAGE_0603": "W890E-SAGE SE 0603"}
INV = {tag: json.loads((OUT / tag / "inventory.json").read_text(encoding="utf-8")) for tag in ORDER}
PACKAGES = json.loads((OUT / "packages.json").read_text(encoding="utf-8"))
DETAILS = json.loads((OUT / "details.json").read_text(encoding="utf-8"))
COMPARE = json.loads((OUT / "comparisons.json").read_text(encoding="utf-8"))
EXTENDED = json.loads((OUT / "extended_regions.json").read_text(encoding="utf-8"))
SOURCES = {
    "W790_SAGE_2003": {
        "url": "https://www.asus.com/motherboards-components/motherboards/workstation/pro-ws-w790e-sage-se/helpdesk_bios?model2Name=Pro-WS-W790E-SAGE-SE",
        "release_date": "2026-08-10", "build_date": "2026-07-09", "flashback_name": "PWW790SG.CAP",
        "release_summary": "更新 ME 及其更新库至 16.11.25.2028v3，并改进安全性。"},
    "W790_ACE_2003": {
        "url": "https://www.asus.com/motherboards-components/motherboards/workstation/pro-ws-w790-ace/helpdesk_bios?model2Name=Pro-WS-W790-ACE",
        "release_date": "2026-08-12", "build_date": "2026-07-09", "flashback_name": "PWW790A.CAP",
        "release_summary": "更新 ME 及其更新库至 16.11.25.2028v3，并改进安全性。"},
    "W890_SAGE_0603": {
        "url": "https://www.asus.com/us/supportonly/pro%20ws%20w890e-sage%20se/helpdesk_bios/",
        "release_date": "2026-08-21", "build_date": "2026-07-08", "flashback_name": "A5709.CAP",
        "release_summary": "改进性能与设备兼容性，更新 ME 至 19.10.6.1494，并更新 AMI CRB 代码基线。",
        "local_snapshot": "asus_w890_bios.html"},
}
REFERENCES = [
    ("ASUS W790E-SAGE SE 规格", "https://www.asus.com/motherboards-components/motherboards/workstation/pro-ws-w790e-sage-se/techspec/"),
    ("ASUS W790-ACE 规格", "https://www.asus.com/us/motherboards-components/motherboards/workstation/pro-ws-w790-ace/techspec/"),
    ("ASUS W890E-SAGE SE 规格", "https://www.asus.com/motherboards-components/motherboards/workstation/pro-ws-w890e-sage-se/techspec/"),
    ("ASUS W790 发布说明：板载 BMC 与 IPMI 扩展卡区别", "https://press.asus.com/news/press-releases/3384/"),
    ("UEFITool FFS / CPD 数据结构定义", "https://github.com/LongSoft/UEFITool/blob/new_engine/common/ffs.h"),
]


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def verify():
    result = {"analysis_date": "2026-10-08", "tool": "UEFIExtract NE alpha 75 (Jul 10 2026)",
              "tool_sha256": digest(ROOT / "tools/UEFIExtract_A75/UEFIExtract.exe"),
              "guid_database_sha256": digest(ROOT / "analysis/uefitool_guids.csv"), "images": {}}
    for tag in ORDER:
        p, inv, detail = PACKAGES[tag], INV[tag], DETAILS[tag]
        source_ok = digest(ROOT / p["source"]) == p["zip_sha256"] == p["official_zip_sha256"]
        cap_ok = digest(OUT / p["cap"]) == p["cap_sha256"]
        assert source_ok and cap_ok and p["zip_crc_ok"] and p["capsule_size_matches_header"]
        assert len(inv["modules"]) == inv["module_count"]
        assert all(n["dword_checksum_ok"] for n in inv["nodes"] if n["info"]["Type"] == "Intel microcode")
        assert all(v["matches_packed_schema"] for v in detail["variables"])
        variable_to_schema = {v["name"]: v["schema"] for v in detail["variables"]}
        assert len(detail["ifr_varstores"]) == 4
        assert all(v["size"] == detail["schemas"][variable_to_schema[v["name"]]]["packed_size"] for v in detail["ifr_varstores"])
        checksum_errors = [(m["guid"], k, v) for m in inv["modules"] for k,v in m["info"].items()
                           if "checksum" in k.lower() and "invalid" in v.lower()]
        assert not checksum_errors
        report = (OUT / p["cap"]).with_name(Path(p["cap"]).name + ".report.txt").read_text(errors="replace")
        report_files = sum(line.split("|", 1)[0].strip() == "File" for line in report.splitlines())
        assert report_files == inv["module_count"], (tag, report_files, inv["module_count"])
        result["images"][tag] = {"source_zip_unchanged": source_ok, "official_hash_match": source_ok,
                                 "cap_unchanged": cap_ok, "zip_crc_ok": p["zip_crc_ok"],
                                 "main_tree_file_count_matches_uefiextract_report": True,
                                 "main_tree_file_count": report_files,
                                 "microcode_checksums_valid": True,
                                 "four_schemas_match_ifr_and_nvram_default_sizes": True,
                                 "invalid_ffs_checksums_found": checksum_errors}
    for key, pair in COMPARE.items():
        left, right = key.split("__vs__")
        counts = pair["counts"]
        assert sum(counts.get(k,0) for k in ("identical", "changed", "left_only")) == INV[left]["module_count"]
        assert sum(counts.get(k,0) for k in ("identical", "changed", "right_only")) == INV[right]["module_count"]
    assert EXTENDED[ORDER[0]]["update_payload_sha256"] == EXTENDED[ORDER[1]]["update_payload_sha256"]
    result["w790_embedded_me_update_payloads_identical"] = True
    result["capsule_signature_cryptographically_verified"] = False
    result["hardware_execution_tested"] = False
    (OUT / "verification.json").write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    (OUT / "official_sources.json").write_text(json.dumps({"checked_date": "2026-10-08", "releases": SOURCES, "references": REFERENCES}, ensure_ascii=False, indent=2), encoding="utf-8")
    return result


plain, html = [], []


def heading(s):
    plain.extend(["", s, "=" * 48, ""])
    html.append("<h2>" + escape(s) + "</h2>")


def paragraph(s):
    plain.extend([s, ""])
    html.append("<p>" + escape(s) + "</p>")


def table(headers, rows):
    plain.append("\t".join(str(x) for x in headers))
    plain.extend("\t".join(str(x) for x in row) for row in rows)
    plain.append("")
    html.append("<div class='table'><table><thead><tr>" + "".join("<th>"+escape(str(x))+"</th>" for x in headers) + "</tr></thead><tbody>")
    for row in rows:
        html.append("<tr>" + "".join("<td>"+escape(str(x))+"</td>" for x in row) + "</tr>")
    html.append("</tbody></table></div>")


def link(title, url):
    plain.append(title + "：" + url)
    html.append("<p><a href='" + escape(url, quote=True) + "'>" + escape(title) + "</a></p>")


def render():
    verify()
    heading("三份 ASUS 工作站 BIOS 静态分析报告")
    paragraph("分析日期：2026-10-08。对象仅为用户提供的三份 ZIP。原始压缩包与提取出的 CAP 均经分析结束后的 SHA-256 复核，没有修改；没有执行 BIOSRenamer、刷写固件或访问主板硬件。")
    paragraph("结论：三份 ZIP 均与 ASUS 对应版本公布的 SHA-256 一致。两份 W790 同属一个平台世代，但板级初始化、IPMI 配置和硬件监控实现有差异。W890 改用不同 CPU/芯片组平台、ME 主版本、固件分区布局和配置结构；三者不能互刷，也不能把同名模块视作可直接替换。")

    heading("1. 文件身份与官方版本")
    rows = []
    for tag in ORDER:
        p, s = PACKAGES[tag], SOURCES[tag]
        rows.append([LABEL[tag], f"{p['zip_size']:,}", s["build_date"], s["release_date"], s["flashback_name"], "匹配"])
    table(["固件", "ZIP 字节数", "镜像内构建日期", "官方发布日期", "FlashBack 名称", "官方哈希"], rows)
    paragraph("三份 CAP 均为 67,112,960 字节 = 64 MiB 镜像 + 4 KiB 封装。Capsule GUID 均为 4A3CA68B-7723-48FB-803D-578CC1FEC44D，UEFIExtract 将其识别为 AMI Aptio signed capsule；签名结构识别与加密签名验证是两项不同检查，本次未独立验证证书链/签名。构建日期取自固件尾部明文日期，并与 ZIP 内 CAP 时间戳交叉核对；不等同于官网发布日期。")
    for tag in ORDER:
        paragraph(LABEL[tag] + " 官方更新摘要：" + SOURCES[tag]["release_summary"])
        link(LABEL[tag] + " 官方下载说明", SOURCES[tag]["url"])
        paragraph("ZIP SHA-256：" + PACKAGES[tag]["zip_sha256"] + "\nCAP SHA-256：" + PACKAGES[tag]["cap_sha256"])
    paragraph("W890 ZIP 额外带有 MeFwUpdate_19.10.6.1494_Coporate.bin，8,384,628 字节；两份 W790 ZIP 各包含 CAP 和 BIOSRenamer.exe。三包的 BIOSRenamer.exe 字节一致，已记录哈希但未执行。FlashBack 名称仅作为文件身份信息列出。")

    heading("2. 平台、分区与模块规模")
    table(["项目", *[LABEL[t] for t in ORDER]], [
        ["CPU 插槽 / 芯片组（官方规格）", "LGA4677 / W790", "LGA4677 / W790", "LGA4710-2 / W890"],
        ["主机镜像容量", "64 MiB", "64 MiB", "64 MiB"],
        ["Descriptor 分区大小", "4 KiB", "4 KiB", "16 KiB"],
        ["Descriptor 声明的 BIOS 分区", "16 MiB", "16 MiB", "48 MiB"],
        ["Intel ME（镜像及 manifest）", "16.11.25.2028", "16.11.25.2028", "19.10.6.1494"],
        ["主解析树 FFS 文件数", *[INV[t]["module_count"] for t in ORDER]],
        ["其中含 PE/TE 的文件数", *[DETAILS[t]["executable_ffs_count"] for t in ORDER]],
        ["主解析树固件卷数量", *[sum(n["info"]["Type"] == "Volume" for n in INV[t]["nodes"]) for t in ORDER]],
    ])
    paragraph("FFS 数量包含驱动、原始数据、填充文件和嵌套容器，不等于驱动数、功能数或代码质量。可执行文件数按含至少一个 PE32/TE section 的 FFS 文件计数，含恢复/重复实例。模块名优先使用固件 UI 字段，再使用本地 UEFITool GUID 数据库；无可靠名称的模块保留 GUID。")
    for tag in ORDER:
        paragraph(LABEL[tag] + " 分区范围（下列偏移相对于去掉 4 KiB CAP 封装后的 SPI 镜像；结束地址不包含在区间内）：")
        table(["分区", "起始", "结束", "字节数"], [[r["name"], r["spi_start"], r["spi_end_exclusive"], f"{r['size']:,}"] for r in INV[tag]["descriptor"]["regions"]])
    paragraph("额外发现：两份 W790 的 Device Expansion 2 区在 CAP 偏移 0x02C61000 各包含一个相同的 FFS 压缩容器，GUID 为 67D6083C-EF48-43B8-A6B7-A39570947CA1，压缩文件长 3,744,803 字节。解压并去除 raw section 头后得到 7,129,076 字节的 ME 更新载荷；FTPR/NFTP/RBEP manifest 均显示 16.11.25.2028。两份载荷 SHA-256 完全相同。该容器没有列入 UEFIExtract 主树的 FFS 计数和主树比较表；若加上它，两份 W790 分别识别到 625 和 632 个 FFS 文件。")
    paragraph("W890 的同名扩展区全部为 FF；独立 ME 更新文件的 NFTP/RBEP manifest 显示 19.10.6.1494。两份 W790 的 SPI ME 分区哈希彼此不同，但核心版本与额外更新载荷相同；这表明整区内容并不相同，不能仅按版本号把整区当作可互换数据。")

    heading("3. CPU 微码")
    micro_rows = []
    for tag in ORDER:
        for n in [x for x in INV[tag]["nodes"] if x["info"]["Type"] == "Intel microcode"]:
            i = n["info"]
            micro_rows.append([LABEL[tag], i["CPU signature"], i["CPU platform Id"], i["Revision"], i["Date"], n["full_bytes"], "有效"])
    table(["固件", "CPUID", "平台掩码", "修订号", "微码日期", "字节数", "校验和"], micro_rows)
    paragraph("两份 W790 的两条微码逐字节一致。806F8 微码的扩展签名表还覆盖 806F7、806F6、806F5、806F4，平台掩码均为 0x87。W890 的两条 A06D1 微码是相同载荷的两个副本，只有一个唯一版本，平台掩码为 0x02。本次独立重算了微码 32 位加和校验，并保留 FIT 定位日志。微码存在不代表任意同 CPUID CPU 均被主板支持；CPU 支持列表、初始化代码与平台掩码仍需对应。未将不同平台的微码修订号直接作新旧排名。")

    heading("4. IPMI、BMC、Redfish 与风扇监控")
    paragraph("三份 BIOS 均含 PEI/DXE/SMM 阶段的 IPMI 初始化代码、BMC 日志/ACPI、IPv4/IPv6 BMC 网络配置和 ServerMgmtSetup。SAGE SE 两块板的官方规格列出板载 AST2600；W790-ACE 官方说明使用选配的 ASUS IPMI 扩展卡。ACE 的 BIOS 带 IPMI 代码，不表示主板本体自带完整 BMC。")
    link("板载 BMC 与扩展卡的官方说明", REFERENCES[3][1])
    keys = ["PeiIpmiBmcInitialize", "DxeIpmiInitialize", "SmmIpmiInitialize", "ServerMgmtSetup", "RedfishHi", "AsusHwmSensorPortingDxe", "ECSmmFramework"]
    table(["模块", *[LABEL[t] + " / 字节" for t in ORDER]], [[name, *[next(m["size"] for m in INV[t]["modules"] if m["name"] == name) for t in ORDER]] for name in keys])
    paragraph("以上同名模块在三个镜像间的 FFS 哈希均不同。W790 两板的 AsusHwmSensorPortingDxe 虽然长度同为 8,610 字节，内容仍不同。三者另有 GUID 11CB55C3-089D-4FF1-8B86-4745AB2FB501 的 EFI 应用，正文明确包含 ASUSTeK. IPMI Hardware Monitor 字符串；文件大小分别为 17,898、12,170、16,426 字节。")
    paragraph("W890 相对于 W790E-SAGE SE 新出现的管理组件包括 BmcRfCertDxe、RedfishHostInterfaceDxe、RedfishCredentialDxe、RedfishPlatformConfigDxe、RedfishRestExDxe、RedfishDiscoverDxe、RedfishConfigHandlerDriver 和 RemoteFWConfiguration。由此可判断主机侧 Redfish 集成发生明显扩展；仅凭模块存在，不能确认每项功能在特定硬件和 BIOS 设置下均已启用。")
    paragraph("三者都能识别到 NCT6686DPeiInit、AsusHwmSensorPortingDxe、AsusHwmSetupItem、ECSmmFramework 和 SioDxeInit。名字相同只说明存在相应组件；传感器映射、风扇寄存器及 BMC 通信实现不能据此认定相同。三份 ZIP 内未附带独立的 AST2600 BMC 系统固件包；Intel ME 固件与 BMC 固件不是同一组件。")

    heading("5. 设置变量与结构：已用三种证据交叉核对")
    paragraph("从镜像内嵌 C 结构定义计算字段偏移，再与 Setup/ServerMgmtSetup 的 IFR VARSTORE 长度、NVAR 默认变量体长度进行核对。下列 12 项结构长度全部一致，不是单纯由字符串或菜单名称推测。")
    table(["变量 / 结构", *[LABEL[t] + " / 字节" for t in ORDER]], [[name, *[DETAILS[t]["schemas"][schema]["packed_size"] for t in ORDER]] for name, schema in [
        ("Setup / SETUP_DATA", "SETUP_DATA"), ("ServerSetup / SERVER_MGMT_CONFIGURATION_DATA", "SERVER_MGMT_CONFIGURATION_DATA"),
        ("AsusHwmSetupOneof", "ASUS_HWM_SETUP_ONEOF"), ("AsusQFanSetupData", "ASUS_QFAN_SETUP_DATA")]])
    paragraph("具体例子：Setup.OnboardBmcEnable 在 W790E-SAGE SE、W790-ACE、W890E-SAGE SE 中分别位于 0x22C、0x221、0x187。同名字段已经发生偏移变化。ACE 的 ServerSetup 还包含 BmcLanLed、BmcMsgLed、BmcFanSrc 字段；两块 SAGE 的结构更大，包含第二组 BMC LAN/IPV6 配置等差异。")
    paragraph("W790 两板的 Q-Fan 结构都是 196 字节；W890 为 528 字节，并含 CpuFanManualTempPwm[9]、CpuFanManualDutyPwm[9] 等数组。它证明存储结构变化，不直接证明菜单中一定有 9 个可编辑曲线点。不同板型的 BIOS 配置块、NVRAM 偏移以及风扇配置不能按同一布局复制。完整字段与偏移保存在 details.json 和各镜像目录的 embedded_*_structures.h。")

    heading("6. 模块级比较")
    rows = []
    for key, pair in COMPARE.items():
        a,b = key.split("__vs__")
        c = pair["counts"]
        rows.append([LABEL[a] + " → " + LABEL[b], c.get("identical",0), c.get("changed",0), c.get("left_only",0), c.get("right_only",0)])
    table(["比较顺序", "配对且字节相同", "配对但内容不同", "仅左侧实例", "仅右侧实例"], rows)
    paragraph("比较口径：仅 UEFIExtract 主解析树中的 FFS，按 GUID 匹配，重复 GUID 保留多个实例，并优先匹配完全一致的 SHA-256。相同内容指完整 FFS 头和体一致；内容不同不自动表示功能改变，可能含编译、链接、元数据差异。该表不代表整幅固件的相似百分比，且不包含第 2 节手工识别的扩展区 ME 更新容器。若额外计入该容器，W790 两板相同 FFS 数增加为 371，其余该对比较项不变。")
    paragraph("解释：两份 W790 共享大量字节一致的底层模块，差异集中于板级实现及多个管理模块；W890 与 W790 仅有少量 FFS 字节一致，同时 CPU/芯片组初始化、ME、固件卷组织和配置布局均改变。W890 出现 GnrWs、CXL、GPIO v2 等平台组件，不能作为 W790 的整体替代固件。")

    heading("7. 校验结果与分析边界")
    paragraph("已通过：三包官方 SHA-256 对照和 ZIP CRC；CAP 长度、源文件未变校验；主树文件数量与 UEFIExtract 报告一致；解析到的 FFS/固件卷未出现无效校验和；全部 6 个微码实例的加和校验；4 类配置结构在三个镜像中的 schema/IFR/NVAR 长度一致；两份 W790 扩展区 FFS 头校验、LZMA 解压长度及 ME 更新载荷一致性。")
    paragraph("解析日志仍有具体提示：每个镜像各有一个未知类型 00h 的 section；两份 W790 各有 38 条、W890 有 36 条 CPD 压缩分区缺少 metadata 的长度调整提示；W890 另有一个未知 CPD 扩展类型。日志保留供复核。这些提示与官方 ZIP 哈希匹配并存，不能单独当作损坏或恶意篡改的证据，也意味着本报告不声称解码了所有专有字段。")
    paragraph("三者包含 SecureBootDXE、Tcg/Tcg2、TPM 2.0 及存储安全相关模块。模块存在不证明当前机器已启用 Secure Boot、TPM 或 Boot Guard；这需要设备运行状态和配置。没有执行所有模块的完整反汇编、漏洞审计、加密签名信任验证或上机测试，因此不据此承诺没有漏洞或必然可启动。")
    paragraph("结论适用于固件分析与后续差异研究。直接互刷、直接覆盖 ME 整区或照搬设置偏移均不受这些结果支持。官方 SAGE 版本说明还提示：更新后 ME 不会因回刷旧 BIOS 自动回退。提取的 BIN/结构文件是分析产物，不是经过构建与上机验证的刷写方案。")

    heading("8. 交付文件与复核方法")
    for title, filename in [
        ("全部主树 FFS 清单（名称、GUID、类型、大小、哈希、路径）", "modules.tsv"),
        ("三组逐模块比较结果", "comparisons.json"), ("配置结构与 IFR/NVAR 证据", "details.json"),
        ("分区、微码与摘要", "summary.json"), ("ME 扩展载荷、独立更新文件与 manifest", "extended_regions.json"),
        ("源包、ZIP 内容和文件哈希", "packages.json"), ("最终复核记录", "verification.json"),
        ("官方来源和发布日期", "official_sources.json"), ("可重跑的本地分析脚本", "analyze_bios.py"),
    ]:
        link(title, filename)
    paragraph("每个镜像目录保留原样提取的 CAP、UEFIExtract 完整解包树、report.txt、uefiextract.log、inventory.json 和内嵌结构定义。分析脚本依次运行 extract、inventory、details、extended 四个阶段；render_report.py 会执行证据一致性校验并生成本报告。脚本使用 Python 标准库及现有 UEFIExtract，不执行待分析固件。")
    for title,url in REFERENCES:
        link(title,url)
    (OUT / "BIOS分析报告.txt").write_text("\n".join(plain) + "\n", encoding="utf-8-sig")
    style = """body{font-family:system-ui,'Microsoft YaHei',sans-serif;max-width:1200px;margin:36px auto;padding:0 24px;color:#182334;line-height:1.75;background:#fff}h2{margin-top:38px;font-size:1.35rem;border-bottom:2px solid #dce7ec;padding-bottom:8px}h2:first-child{font-size:1.8rem}p{white-space:pre-line;overflow-wrap:anywhere}.table{overflow-x:auto;margin:18px 0}table{border-collapse:collapse;width:100%;font-size:14px}th,td{border:1px solid #dbe2e8;padding:9px 12px;text-align:left;vertical-align:top}th{background:#eef4f7}tr:nth-child(even){background:#f8fafb}a{color:#155e93} @media print{body{margin:0;font-size:10pt}h2{break-after:avoid}tr{break-inside:avoid}.table{overflow:visible}}"""
    (OUT / "BIOS分析报告.html").write_text("<!doctype html><html lang='zh-CN'><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'><title>三份 ASUS BIOS 分析报告</title><style>" + style + "</style><body>" + "\n".join(html) + "</body></html>", encoding="utf-8")
    print("Verified original ZIPs, CAPs, FFS inventories, microcodes, schemas, and comparisons.")
    print("Reports:", OUT / "BIOS分析报告.html", OUT / "BIOS分析报告.txt")


if __name__ == "__main__":
    render()
