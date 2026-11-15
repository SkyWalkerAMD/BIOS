"""Verify the captured evidence and publish a bounded Chinese investigation report."""
from pathlib import Path
import hashlib
import html
import json
import struct
import sys

HERE = Path(__file__).resolve().parent
BASE = HERE.parent
ROOT = BASE.parent.parent
sys.path[:0] = [str(ROOT / 'tools/pydeps'), str(BASE / 'probe_p3_kvm')]
import pefile
from decode_captures import assemble

TITLE = 'W790-ACE-1904-二维码与REA解析报告'


def read(path):
    return json.loads(path.read_text(encoding='utf-8'))


def write(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')


def unwrap(path):
    obj = read(path)
    if 'content' not in obj:
        return None
    return obj.get('structuredContent') or json.loads(obj['content'][0]['text'])


def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def main():
    manifest = read(HERE / 'capture_manifest.json')
    log = (HERE / manifest['recovered_log']).read_bytes()
    assembled, frame_meta = assemble([(HERE / f'frame-{n:03d}.bin').read_bytes() for n in range(1, 7)])
    assert log == assembled
    assert frame_meta['sha256'] == manifest['sha256']
    for frame in manifest['frames']:
        assert sha(HERE / frame['stored']) == frame['image_sha256']
    module_meta = read(HERE / 'module_metadata.json')
    for name, meta in module_meta.items():
        assert sha(HERE / f'modules/{name}.efi') == meta['sha256']

    records = []
    evidence_by_label = {}
    for p in sorted((HERE / 'rea').glob('*.json')):
        if not p.name.startswith(('AMITSE-', 'Setup-Seeded-')):
            continue
        e = unwrap(p)
        if not isinstance(e, dict) or e.get('operation') != 'analyze_function':
            continue
        n = e['normalized_result']
        record = {'file': str(p.relative_to(HERE)), 'sha256': sha(p),
                  'evidence_id': e['evidence_id'], 'target_sha256': e['subject']['digest']['sha256'],
                  'provider': e['provider'], 'analysis_profile_digest': e['analysis_profile']['digest'],
                  'procedure': n['procedure'], 'relationship_coverage': e['relationship_coverage'],
                  'limitations': e['limitations'], 'facet_availability': n.get('facet_availability')}
        records.append(record)
        evidence_by_label[p.stem] = record
        code = n.get('pseudocode')
        if isinstance(code, str):
            (HERE / 'rea' / (p.stem + '.c')).write_text(code.replace('\r\n', '\n'), encoding='utf-8', newline='\n')
    assert len(records) == 19, len(records)
    assert all(r['provider']['id'] == 'ghidra' and r['provider']['version'] == '12.1.4' for r in records)

    checks = []
    for label, module in [('AMITSE-Seeded-SendForm-bytes', 'AMITSE'),
                          ('Setup-Seeded-ConfigAccess-bytes', 'Setup'),
                          ('AMITSE-hook-table-bytes', 'AMITSE')]:
        e = unwrap(HERE / f'rea/{label}.json')
        n = e['normalized_result']
        pe = pefile.PE(str(HERE / f'modules/{module}.efi'))
        observed = bytes.fromhex(n['bytes_hex'])
        assert n['complete'] and n['returned_bytes'] == n['requested_bytes'] == 32
        assert observed == pe.get_data(int(n['address'], 16), len(observed))
        checks.append({'module': module, 'rva': n['address'], 'bytes': len(observed),
                       'original_pe_bytes_equal_ghidra_memory': True, 'evidence_id': e['evidence_id']})

    pe = pefile.PE(str(HERE / 'modules/AMITSE.efi'))
    assert struct.unpack('<QQQQ', pe.get_data(0x7cb20, 32)) == (0xffff0029, 0x62bc, 0x1200c, 0xffff002a)
    assert pe.get_data(0x1200c, 3) == bytes.fromhex('33c0c3')
    navigation = {
        'target': 'W790-ACE 1904 AMITSE', 'sha256': module_meta['AMITSE']['sha256'],
        'coordinate_system': 'Module RVA; none of these is a physical flash address',
        'loop': '0xe208', 'application_input': '0x121b8', 'page_input': '0x16c70', 'page_render': '0x16ae0',
        'application_global_pointer_rva': '0x82748', 'current_page_index_offset': '0x28',
        'page_records_index_global_rva': '0x92270', 'page_records_base_global_rva': '0x92b08',
        'page_record_form_id_offset': '0xa', 'page_record_formset_index_offset': '0x8',
        'hook_table_rva': '0x7c5e0', 'transition_hook_id': '0xffff0029',
        'transition_dispatcher_rva': '0x62bc', 'static_callback_slot_rva': '0x7cb30',
        'static_default_callback_rva': '0x1200c', 'static_default_callback_behavior': 'xor eax,eax; ret (EFI_SUCCESS)',
        'arguments_inferred': ['old formset GUID pointer', 'old form ID pointer', 'new formset GUID pointer', 'new form ID pointer'],
        'observed_static_call_sites': [
            {'rva': '0x1701c', 'caller': '0x16c70', 'result_handling': 'EFI_ACCESS_DENIED (0x800000000000000F) restores old page index and returns'},
            {'rva': '0xe6f4', 'caller': '0xe208', 'result_handling': 'Return value is not checked before continuing into the browser loop'},
        ],
        'limitations': [
            'The physical log does not read this hook slot or application state; live values remain unobserved.',
            'Default callback source bytes are not proof the callback slot remains unchanged at runtime.',
            'One caller ignores the returned status; replacing this slot alone is not established as a complete lock.',
            'Keyboard top tabs, mouse, Favorites, search, initial page and alternate configuration writes require separate coverage.',
            'All function and structure labels are analyst interpretations, not recovered OEM symbols or a verified public ABI.',
        ],
    }
    write(HERE / 'navigation_candidate.json', navigation)
    write(HERE / 'rea_evidence_index.json', {'functions': records, 'analysis_memory_checks': checks,
                                           'execution_observed': False,
                                           'function_names_source': 'Analyst-supplied seed labels; original firmware symbols are absent'})

    releases = {
        'AiTweaker-实机采集工具包-USB与KVM.zip': '0e5da5393feab4162b20c1c6f9f4a7b9dd01d834279ac9abe5ad25bc1bf06a91',
        'AiTweaker-P2-免刷写诊断.zip': 'c06fafc804b6cedc74003459c49d18da53db7618d21edf72391dcfc2ac43ae64',
        'Pro-WS-W790E-SAGE-SE-ASUS-2003.zip': 'd093fb2a045633eb7285a45606ea1548d9250982e266f7480193296ed8231845',
        'Pro-WS-W790-ACE-ASUS-2003.zip': '4ca36875d8c37310fe4e6eaddfd59e2433d3c2dbaf1d9551d3ade59f4a1ee47d',
        'Pro-WS-W890E-SAGE-SE-ASUS-0603.zip': '5bad35967954afb2f10123828e3698c1f36b413b21ce127f15778ed424997df8',
    }
    preserved = {}
    for name, expected in releases.items():
        p = ROOT / name
        if not p.exists():
            p = BASE / name
        assert p.is_file(), p
        actual = sha(p)
        assert actual == expected, (name, actual, expected)
        preserved[name] = actual
    for name in ['rea-amitse-seeded-plan', 'rea-setup-seeded-plan', 'rea-navigation-plan', 'rea-input-plan', 'rea-hook-plan']:
        close = unwrap(HERE / f'rea/{name}.final-close.json')
        assert close is not None and 'error' not in close, (name, close)
    verification = {'capture_frames_assemble_exactly': True, 'all_six_original_image_hashes_match': True,
                    'firmware_module_hashes_unchanged': True, 'analysis_memory_checks': checks,
                    'rea_function_evidence_records': len(records), 'explicit_native_session_close_records': 5,
                    'preserved_original_files': preserved, 'modified_bios_created': False,
                    'password_lock_implemented': False, 'target_firmware_executed': False}
    write(HERE / 'verification.json', verification)

    def ev(label):
        return evidence_by_label[label]['evidence_id']

    findings = [
        {'id': 'F01', 'status': 'confirmed', 'type': 'physical_capture_and_static_match',
         'claim': '六页完整还原为 4582 字节；Setup 与 AMITSE 的代码段指纹、RVA、长度及入口均匹配官方 1904。',
         'sources': ['capture_manifest.json', 'reconciliation.json'],
         'boundary': '匹配的是采集到的两个模块字段；没有读取或验证实机整片 SPI。'},
        {'id': 'F02', 'status': 'confirmed', 'type': 'static_ifr',
         'claim': 'Ai Tweaker 为 Form 0x2714；入口 Question 0x0003、flags=0，25 个静态可达页面，没有独立密码控件。',
         'sources': ['forms_1904.json'], 'boundary': '包含条件隐藏页面；静态可达不等于当前界面全部可见。'},
        {'id': 'F03', 'status': 'confirmed', 'type': 'static_disassembly_and_rea',
         'claim': 'Setup Callback 按 QuestionId 遍历静态表及动态链表；945 项静态表中没有入口 Question 0x0003。',
         'sources': ['callback_dispatch_table.json', ev('Setup-Seeded-ConfigAccess')],
         'boundary': '动态链表内容尚未在实机采集，不能由静态表推断不存在其他回调。'},
        {'id': 'F04', 'status': 'partial', 'type': 'static_rea_inference',
         'claim': 'AMITSE 0xE208 包含页面索引变化检测、绘制及输入分派，是后续验证导航拦截的核心路径。',
         'sources': [ev('AMITSE-navigation-Candidate_BrowserLoop'), ev('AMITSE-input-Candidate_PageInputHandler')],
         'boundary': '尚未观察实机点击、键盘或鼠标导航时执行的路径。'},
        {'id': 'F05', 'status': 'partial', 'type': 'static_rea_and_byte_checks',
         'claim': '找到内部页面切换检查 0xFFFF0029：0x62BC 分派，表项 0x7CB30 默认指向返回成功的 0x1200C；一处调用可按 ACCESS_DENIED 恢复旧页面。',
         'sources': ['navigation_candidate.json', ev('AMITSE-hook-Candidate_PageTransitionHook'), ev('AMITSE-hook-Candidate_DefaultAllowHook'), ev('AMITSE-input-Candidate_PageInputHandler')],
         'boundary': '初始页面路径 0xE6F4 忽略返回值；单独替换此槽位不能证明完整加锁。'},
        {'id': 'F06', 'status': 'confirmed_static', 'type': 'static_rea_inference',
         'claim': '0x606D8 中的 0x2714 属于配置 XML 输出过滤；0x57858 的 ConfigurationData 处理也触发 SetupEnter GUID。',
         'sources': [ev('AMITSE-Seeded-FormListFilter'), ev('AMITSE-Seeded-SetupEntryPath'), ev('AMITSE-navigation-Candidate_ProtocolPulse')],
         'boundary': 'GUID 触发不能单独等同于用户每次进入 BIOS 的会话边界。'},
        {'id': 'F07', 'status': 'unresolved', 'type': 'string_observation',
         'claim': 'AMITSE 中有 Enter AiTweaker Password 文本，尚未证明存在可直接启用的独立密码实现。',
         'sources': ['modules/AMITSE_strings.json'], 'boundary': '字符串存在不能证明凭据存储、校验、会话状态及所有入口均实现。'},
    ]
    write(HERE / 'findings.json', {'findings': findings, 'checklist': {
        'QR恢复与版本核对': 'answered', '1904接口定位': 'answered',
        '可靠的AiTweaker进入拦截': 'partial', '独立密码设置与保存': 'unimplemented',
        '会话内首次解锁语义': 'unverified', '其余两块主板及2003/0603适配': 'unverified_on_hardware'}})

    text = f'''ASUS Pro WS W790-ACE / BIOS 1904 — 二维码与 REA 解析报告
2026-11-02

本轮结论
六页二维码已完整恢复并校验；实机的 Setup、AMITSE 代码指纹匹配官方 1904。
已使用 REA 6.8.0 + Ghidra 12.1.4 分析 {len(records)} 个函数，并找到具体的页面切换检查候选。
独立密码尚未实现。本轮没有修改 CAP、刷写主板或执行这些固件模块。

1. 实机证据
主板与版本：用户确认 ASUS W790-ACE / 1904。
日志：6 页，4582 字节，CRC32 E9B906DF。
日志 SHA256：{manifest['sha256']}
Setup：.text CRC32 9E141291，RVA 0x2C0，长度 0x2746F，入口 0x590。
AMITSE：.text CRC32 760C4005，RVA 0x2C0，长度 0x69ECF，入口 0x5A0。
下载的官方 1904 ZIP SHA256 与华硕公布值一致：
dcae6e446cfb475755b0a5118317e28e88fc9af7c917bf5cf29c6da1a5fd3e37
匹配范围为两个模块的采集字段，没有读取实机整片 SPI。

2. 为什么原日志仍显示 PARTIAL
原始记录保持不变。5 个警告中，2 个 UNKNOWN_BUILD 和 1 个 known_modules 汇总警告来自工具未收录 1904；
另外 2 个来自其他 HII 菜单：一个未返回驱动句柄，一个 ConfigAccess 返回 EFI_UNSUPPORTED。
PARTIAL 指接口清单的局限，不代表二维码漏页或传输损坏。
FormBrowser2、PostManager、HII Database 均已定位，Setup 的 83 个表单和 4 个密码控件已采集。

3. Ai Tweaker 结构
根页面 FormId=0x2714；入口 QuestionId=0x0003、flags=0，没有标准 CALLBACK 标志。
沿本地 IFR 引用可达 25 页、1983 条控件记录；包含条件隐藏和调试项，不等于界面可见数量。
这 25 页中没有 PASSWORD 控件。Setup 现有 4 项为管理员、用户、硬盘用户及硬盘主密码。
AMITSE 中存在 Enter AiTweaker Password 文本，但不能据此认定已有可启用的独立密码功能。

4. 实机锚定的接口位置（均为模块 RVA，仅适用于当前 1904 指纹）
Setup ExtractConfig：0x1524 -> 0x215C。
Setup RouteConfig：0x152C -> 0x2568。
Setup ConfigAccess.Callback：0x1534。
AMITSE FormBrowser2.SendForm：0x20F34。
AMITSE FormBrowser2.BrowserCallback：0x2168C。
Setup Callback 按控件编号分派；静态表 945 项、30 个目标函数，没有入口 Question 0x0003；另有动态链表。
BrowserCallback 用于浏览器配置数据访问，不是“进入 Ai Tweaker”的专用通知。
RouteConfig 包含配置解析和变量写入路径；后续需要研究写入保护覆盖，不能只控制画面。

5. 新找到的导航检查候选
浏览器循环 0xE208：读取当前页面索引、比较前后页面、调用页面绘制和输入处理。
应用输入 0x121B8；页面输入 0x16C70；页面绘制 0x16AE0。
页面切换内部编号 0xFFFF0029，由 0x62BC 分派。
静态表从 0x7C5E0 开始；该记录在 0x7CB20，回调槽位 0x7CB30 默认指向 0x1200C。
默认函数为 xor eax,eax; ret，即返回 EFI_SUCCESS。
页面输入路径在 0x1701C 调用此检查；收到 EFI_ACCESS_DENIED 时恢复旧页面索引。
但初始页面路径在 0xE6F4 调用后不检查返回值。因此仅让此回调返回拒绝访问，不足以覆盖初始页面。
这些是静态候选，尚未实测该槽位的运行时内容；本轮未写入或替换任何回调。

6. 已排除的误判
0x606D8 包含 0x2714，但它在生成配置 XML，不是菜单点击入口。
SetupEnter GUID 也被 0x57858 的 ConfigurationData 处理路径触发，不能单独作为 BIOS 会话重置依据。
反编译函数名来自分析者提供的起点标签；类型、函数边界和间接调用仍需结合汇编核对。
REA 的调用关系覆盖是 partial，未知间接调用仍保留为未知。

7. 距离可上机的密码锁还缺什么
核对实机导航回调槽位、页面与 Formset 对应关系；覆盖初始直接落在 Ai Tweaker 和普通切页。
检查鼠标/键盘、子页、收藏、搜索、EZ 模式及配置导入等入口和改写路径。
实现独立密码设置/修改/清除、验证器存储、错误及取消返回、每次实际 BIOS 会话的解锁状态重置。
为其余主板与版本重新定位并验证，1904 地址不能直接用于 2003 或 W890 0603。
再开展模拟和实机交互验证。本轮结果是分析证据，不是密码锁发布包。

8. 保存与复核
原始 6 张图片、6 个二维码分片、原始 TXT、官方固件模块指纹、IFR、完整 REA Evidence 与反编译文本均保存在本报告目录。
rea_evidence_index.json 逐项记录 Evidence ID、模块 SHA256、分析配置摘要与覆盖局限。
verification.json 记录分片重组、图片及固件哈希、3 处 Ghidra 内存字节与原文件一致性、会话关闭及旧发布包校验。
原 USB 文件日志方案和 KVM 二维码方案均保留；原双模式采集 ZIP 的 SHA256 未改变。

来源
华硕官方 BIOS：https://www.asus.com/motherboards-components/motherboards/workstation/pro-ws-w790-ace/helpdesk_bios?model2Name=Pro-WS-W790-ACE
REA：https://github.com/morluto/rea
UEFI FormBrowser2：https://uefi.org/specs/UEFI/2.11/35_HII_Configuration_Processing_and_Browser_Protocol.html
'''
    (HERE / '报告.txt').write_text(text, encoding='utf-8-sig')
    (ROOT / f'{TITLE}.txt').write_text(text, encoding='utf-8-sig')
    sections = text.split('\n\n')
    body = []
    for part in sections:
        lines = part.splitlines()
        if not lines:
            continue
        first, *rest = lines
        if first[:1].isdigit() and '. ' in first:
            body.append('<h2>' + html.escape(first) + '</h2><p>' + '<br>'.join(map(html.escape, rest)) + '</p>')
        else:
            body.append('<p>' + '<br>'.join(map(html.escape, lines)) + '</p>')
    table_rows = ''.join(f'<tr><td>{html.escape(r["subject"])}</td><td><code>{html.escape(r["rva"])}</code></td><td>{html.escape(r["role"])}</td></tr>' for r in [
        {'subject':'Setup','rva':'0x1534','role':'实机采集的 ConfigAccess.Callback'},
        {'subject':'AMITSE','rva':'0x20F34','role':'实机采集的 SendForm'},
        {'subject':'AMITSE','rva':'0xE208','role':'静态定位的浏览器循环'},
        {'subject':'AMITSE','rva':'0x62BC / 0xFFFF0029','role':'静态页面切换检查候选'},
        {'subject':'AMITSE','rva':'0x7CB30 -> 0x1200C','role':'静态回调槽位与默认成功处理'},
    ])
    document = f'''<!doctype html><html lang="zh-CN"><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>{TITLE}</title><style>body{{font:16px/1.75 system-ui,"Microsoft YaHei",sans-serif;color:#172033;background:#f3f5f8;margin:0}}main{{max-width:1000px;margin:32px auto;background:white;padding:36px 44px;border-radius:14px}}h1{{font-size:28px;margin-top:0}}h2{{font-size:20px;border-top:1px solid #ddd;padding-top:22px}}.status{{background:#eaf3ff;padding:14px 20px;border-radius:8px}}p{{overflow-wrap:anywhere}}table{{border-collapse:collapse;width:100%;font-size:15px}}td,th{{text-align:left;border-bottom:1px solid #ddd;padding:10px}}a{{color:#145cb2}}code{{font-family:Consolas,monospace}}@media(max-width:650px){{main{{margin:0;padding:22px}}}}@media print{{body{{background:white}}main{{margin:0;padding:10px}}}}</style>
<main><h1>W790-ACE / 1904 实机与 REA 解析</h1><div class="status">二维码完整 · 1904 指纹匹配 · 19 个函数已分析 · 独立密码尚未实现</div>
<p><a href="analysis/aitweaker_lock/{HERE.name}/{manifest['recovered_log']}">原始还原日志</a> · <a href="analysis/aitweaker_lock/{HERE.name}/findings.json">结论与证据索引</a></p>
<table><thead><tr><th>模块</th><th>RVA / 内部编号</th><th>用途与证据范围</th></tr></thead><tbody>{table_rows}</tbody></table>
{''.join(body)}<p>完整 Evidence：<a href="analysis/aitweaker_lock/{HERE.name}/rea_evidence_index.json">rea_evidence_index.json</a></p></main></html>'''
    (ROOT / f'{TITLE}.html').write_text(document, encoding='utf-8')
    local_document = document.replace(f'analysis/aitweaker_lock/{HERE.name}/', '')
    (HERE / '报告.html').write_text(local_document, encoding='utf-8')
    print(json.dumps({'report': str(ROOT / f'{TITLE}.html'), 'functions': len(records),
                      'capture': frame_meta, 'checks': 'PASS'}, ensure_ascii=False))


if __name__ == '__main__':
    main()
