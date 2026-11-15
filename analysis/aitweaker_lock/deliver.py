"""Package the analysis and tested diagnostic tool; contains no modified CAP."""
from pathlib import Path
from datetime import datetime,timezone
import hashlib
import html
import json
import zipfile
from inspect_setup import OUT,ROOT,PREVIOUS,TAGS,get_module


def main():
    forms=json.loads((OUT/'form_findings.json').read_text(encoding='utf8'))
    strings=json.loads((OUT/'string_findings.json').read_text(encoding='utf8'))
    packages=json.loads((PREVIOUS/'packages.json').read_text(encoding='utf8'))
    checks=json.loads((OUT/'probe/verification.json').read_text(encoding='utf8'))
    build=json.loads((OUT/'probe/build.json').read_text(encoding='utf8'))
    now=datetime.now(timezone.utc).isoformat()
    requirements={
        'targets':TAGS,
        'confirmed_by_user':{
            'all_three_boards':True,'prompt_on_first_ai_tweaker_open_each_bios_session':True,
            'unlock_remains_for_current_bios_session':True,'independent_password_set_in_bios':True},
        'proposed_details_not_yet_implemented':[
            'Add an independent Ai Tweaker Password item in BIOS Security.',
            'Require current Ai Tweaker password to change or clear it.',
            'Keep only salt and a password-derived verifier in a separate versioned variable.',
            'Keep the unlocked flag in RAM and clear it on actual Setup session exit and entry.',
            'Wrong input and Escape keep Ai Tweaker locked and return to the previous page.',
            'Inventory Favorites, search, EZ-mode OC controls and profile-import paths before claiming coverage.',
            'Preserve the independent credential when loading ordinary setup defaults.'],
        'implementation_status':'NOT_IMPLEMENTED_IN_FIRMWARE',
        'modified_cap_created':False,'hardware_validation_performed':False,
        'next_required_external_evidence':'P1 probe logs from available target boards; later UI behavior testing remains necessary.'}
    (OUT/'requirements.json').write_text(json.dumps(requirements,ensure_ascii=False,indent=2),encoding='utf8')
    mapping={}
    for tag in TAGS:
        p=packages[tag]
        assert hashlib.sha256((ROOT/p['source']).read_bytes()).hexdigest()==p['zip_sha256']
        assert hashlib.sha256((PREVIOUS/p['cap']).read_bytes()).hexdigest()==p['cap_sha256']
        f=forms[tag]
        pwd=next(x for x in strings[tag]['AMITSE']['strings'] if x['text']=='Enter AiTweaker Password')
        idx=json.loads((OUT/tag/'AMITSE_code_index.json').read_text())
        events=[]
        for g in idx['guids']:
            if g['name']=='AmiTseSetupEnterGuid':
                events.append({**g,'code_references':idx['refs'].get(str(g['rva']),[]),
                    'status':'static GUID and references only; session-reset semantics not verified on hardware'})
        mapping[tag]={
            'source_zip':p['source'],'source_zip_sha256':p['zip_sha256'],'source_cap_sha256':p['cap_sha256'],
            'modules':{name:{'guid':strings[tag][name]['guid'],'pe_sha256':strings[tag][name]['sha256'],
                             'section_path':strings[tag][name]['section_path']} for name in ('Setup','AMITSE')},
            'main_formset_guid':f['formset'],'ai_tweaker_root_form_id':f['form_id'],
            'root_ifr_offset_in_setup_pe':f['offset'],'root_ifr_end_in_setup_pe':f['end'],
            'ai_tweaker_title_token_in_setup':f['title_id'],
            'ai_tweaker_password_title_token_in_amitse':pwd['token'],
            'existing_ai_tweaker_password_feature_verified':False,
            'local_ref_reachable_forms_including_root':f['subforms'],
            'static_question_records_in_reachable_forms':f['questions_count'],
            'referenced_varstores':f['varstores'],
            'setup_enter_notifications':events,
            'patch_offsets_approved_for_use':False}
    (OUT/'integration_map.json').write_text(json.dumps(mapping,ensure_ascii=False,indent=2),encoding='utf8')
    abi_sources={name:'https://raw.githubusercontent.com/tianocore/edk2/edk2-stable202502/MdePkg/Include/Protocol/'+name+'.h'
                 for name in ('HiiDatabase','HiiConfigAccess','FormBrowser2','LoadedImage')}
    (OUT/'probe/reference/ABI_sources.json').write_text(json.dumps(abi_sources,indent=2),encoding='utf8')
    readme='''Ai Tweaker 固件接口诊断 P1 — 使用说明

这不是修改后的 BIOS，也尚未实现密码锁。不要把 BOOTX64.EFI 交给 EZ Flash 或 USB BIOS FlashBack。
用途：读取实机已加载的 Setup / AMITSE 模块标识、HII 菜单结构与回调所属模块，为后续适配提供依据。
固件只读；只在带有指定标记文件的启动 U 盘上新建 AITWK-000.TXT、AITWK-001.TXT 等日志。
不会调用 BIOS 密码校验、读取密码变量、写入 NVRAM、改写 SPI、替换菜单回调或自动修改设置。

使用步骤
1. 使用一个 FAT32 U 盘，保留原有数据。请选择没有现有 EFI/BOOT/BOOTX64.EFI 启动文件的空闲盘，避免覆盖其他启动程序。
2. 把本包 USB 文件夹里面的内容复制到 U 盘根目录。最终必须有：
   /EFI/BOOT/BOOTX64.EFI
   /AITWEAKER-PROBE.TAG
3. 在待测主板的启动菜单中选择该 U 盘的 UEFI 启动项。也可从已有的 x64 UEFI Shell 执行此 EFI 文件。
4. 程序自动读取接口并保存日志；显示 Saved 后约 3 秒返回固件。无需输入任何密码。
5. 将 U 盘根目录新生成的 AITWK-xxx.TXT 发回，同时注明主板型号和当前 BIOS 版本。不同主板的日志可自行重命名区分。

程序未签名。如果 Secure Boot 策略拒绝启动，请记录提示；本程序不会更改该策略。
如果显示 Could not save the log，请检查根目录标记文件以及 U 盘是否可写。
若模块标识为 UNKNOWN_BUILD，仅表示实际加载代码未匹配这次分析的版本，不能据此判断固件有问题。
没有主板可测试时，可先保留本包；仅凭 ZIP 和离线模拟无法确认最终菜单行为。

验证范围
118 项本机 C 解析断言，以及 14 项对实际 EFI 字节的 Unicorn 模拟运行已通过。
测试覆盖三款目标模块、接口缺失、损坏的 HII 数据、分配失败、未知代码版本、标记文件校验、已有日志保护、短写入和刷新失败。
模拟中的原始固件映像被设置为只读，并检查运行后内容未变化；所有 NVRAM、刷写及菜单修改接口均禁止调用。
这不能替代实机验证，也不证明密码锁已实现。

文件说明
USB/：可启动诊断程序及标记文件。
source/、build.py：完整诊断源码和构建脚本；脚本依赖本工作区的原始分析目录、inspect_setup.py、Python 与 Zig 0.14.1，不是脱离工作区的独立 SDK。
verify.py、verification.json：离线验证脚本和结果；脚本依赖原始分析目录与本机 Python / pefile / Unicorn。
profiles.json：六个目标模块的标识。CRC32 用于版本识别，不承担真实性认证。
example-MOCK-log.txt：明确标注的模拟样例，里面的回调地址是人工构造，不能作为补丁位置。
包内没有修改后的 CAP 文件。
'''
    (OUT/'probe/使用说明.txt').write_text(readme,encoding='utf-8-sig')
    table=[]
    for tag in TAGS:
        f=forms[tag];pwd=next(x for x in strings[tag]['AMITSE']['strings'] if x['text']=='Enter AiTweaker Password')
        table.append([tag,f"0x{f['form_id']:04X}",f"0x{f['offset']:X}",str(len(f['subforms'])),str(f['questions_count']),f"0x{pwd['token']:X}"])
    text='''Ai Tweaker 独立密码锁 — 分析与适配状态
日期：2026-10-08

当前结论
需求已明确，三份原始 BIOS 的菜单与资源定位已完成；固件密码锁尚未实现，没有生成修改后的 CAP。
已提供免刷写的 P1 诊断程序，以便核对实机的菜单回调和模块版本。

已确认的用户要求
三块板都修改：W790E-SAGE SE 2003、W790-ACE 2003、W890E-SAGE SE 0603。
使用独立的 Ai Tweaker 密码，由用户在 BIOS 内设置。
每次进入 BIOS 后，首次打开 Ai Tweaker 验证；同一 BIOS 会话后续访问免重复验证；下次进入重新锁定。

已确认的固件证据
Setup FFS GUID：899407D7-99FE-43D8-9A21-79EC328CAC21。
AMITSE FFS GUID：B1DA0ADF-4F77-4070-A88E-BFFE1C60529A。
三份 Setup 的主 FormSet GUID：7B59104A-C00D-4158-87FF-F04D6396A915。
三份 AMITSE 都含有 Enter AiTweaker Password 提示文字，但未验证存在可直接启用的完整密码功能。
三份主 Setup IFR 中各有 4 个 PASSWORD 问题：管理员、用户、硬盘用户、硬盘主密码；未发现 Ai Tweaker 独立密码设置项。
不能仅把管理员权限、Overclocking Lock 或一个菜单可见性字节当作本需求的实现。

主板 | 根 Form ID | Setup PE 内 IFR 偏移 | 可达页面数 | 静态问题数 | AMITSE 提示 Token
'''+ '\n'.join(' | '.join(row) for row in table)+'''

页面数包括根页面，按同一 FormSet 内静态 REF 边递归统计；包含隐藏、条件分支、调试和多核心条目，并非实机同时可见的页面或设置数量。
偏移是解压后的模块 PE 文件偏移，不是 CAP 或 SPI 地址，不能直接拿来对 CAP 打补丁。

存储和适配差异
W790 两份：VARSTORE_OCMR_SETTINGS_NAME = 26681 字节，VarStore ID 0x1D，普通 buffer varstore；SocketMemoryConfig = 1392 字节，ID 0x21。
W890：VARSTORE_OCMR_SETTINGS_NAME = 22955 字节，VarStore ID 0x23，EFI varstore；SocketMemoryConfig = 1219 字节，ID 0x28。
这说明改动不应只围绕 Setup 变量的一个固定偏移，W890 也不能直接套用 W790 的二进制补丁。

建议实现方式（尚未写入固件）
在 BIOS Security 中增加 Ai Tweaker Password，支持设置、修改、清除；修改与清除需要原独立密码。
密码凭据使用独立、带版本的存储记录，保存随机盐和经口令派生的校验值，不保存明文密码。
解锁标记仅存在当前 Setup 会话的 RAM 状态中，在真正退出和重新进入 Setup 时清除。
验证失败或按 ESC 时保持锁定并返回原页面；验证成功后才开放 Ai Tweaker 与其子页面。
核对 Favorites、搜索、EZ Mode 超频控件和 User Profile 导入，确认它们不能成为未验证的修改入口。
普通加载默认值应保留独立密码；不能把整块 OC 变量永久设为只读，否则可能破坏默认值和平台配置流程。
保护边界先限定为 BIOS 设置界面；外部固件或 NVRAM 改写的防篡改需另行设计。

尚未解决的实现与验证事项
1. 统一的菜单/问题访问拦截点及原生弹窗的调用约定尚未完成验证。
2. SetupEnter 通知 GUID 71202EEE-5F53-40D9-AB3D-9E0C26D96657 已定位到三份代码；是否足以划分本需求中的会话，需要实机跟踪。
3. 还需实现并接入独立凭据管理、密码设置页面、错误处理和失败时保持锁定的路径。
4. 还需确认替代入口与配置保存路径，测试错误密码、ESC、切换模式、退出后重进、重启、改密、清除、恢复默认值、配置导入。
5. 修改后映像的原厂更新签名检查、启动验证范围、可恢复性与板上启动均未验证。

为什么 P1 先只做诊断
读取原始 ZIP 能证明静态资源与代码位置；不能证明当前主板的运行接口、界面生命周期或最终修改后的启动行为。
P1 只核对接口，并不自动进入菜单、弹出测试密码窗口或修改回调。它的日志是下一阶段适配的依据，不能替代后续功能测试。

已完成验证
118 项原生解析断言、14 项 EFI 模拟测试通过；诊断程序 PE 校验和正确、x64 EFI application、无导入表、有重定位、未签名。
三份原始 ZIP 和提取 CAP 的 SHA-256 已重新核对，与原分析记录一致。

交付文件
AiTweaker-P1-免刷写诊断.zip：诊断程序、说明、源码、离线验证结果。
requirements.json：用户要求、拟定行为和明确的未实现状态。
integration_map.json：每块板的模块哈希、菜单 ID、偏移、变量以及静态通知引用。
form_findings.json / string_findings.json：详细解析证据。
各主板子目录的 Setup_IFR.txt 与 AMITSE_disassembly.txt：供复核的完整静态输出。

外部接口依据
UEFI HII Configuration Processing and Browser Protocol：
https://uefi.org/specs/UEFI/2.10/35_HII_Configuration_Processing_and_Browser_Protocol.html
EDK II edk2-stable202502 的 HiiDatabase、HiiConfigAccess、FormBrowser2、LoadedImage 声明，链接保存在 probe/reference/ABI_sources.json。
'''
    (OUT/'AiTweaker密码锁分析与状态.txt').write_text(text,encoding='utf-8-sig')
    esc=html.escape
    rows=''.join('<tr>'+''.join('<td>'+esc(c)+'</td>' for c in row)+'</tr>' for row in table)
    body=f'''<!doctype html><html lang="zh-CN"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Ai Tweaker 独立密码锁 · 适配状态</title><style>
body{{font-family:"Microsoft YaHei",system-ui,sans-serif;background:#f4f6f8;color:#182331;line-height:1.7;margin:0;padding:36px}}
main{{max-width:1160px;margin:auto;background:white;padding:36px;border-radius:12px}}h1{{margin-top:0;font-size:28px}}
.status{{padding:18px 22px;background:#fff4d8;border-left:5px solid #b97404;margin:24px 0}}table{{border-collapse:collapse;width:100%;font-size:14px}}th,td{{border:1px solid #dce1e6;padding:10px;text-align:left}}th{{background:#edf3f8}}pre{{font:inherit;white-space:pre-wrap;overflow-wrap:anywhere}}a{{color:#0967a4}}
@media(max-width:700px){{body{{padding:12px}}main{{padding:18px}}.scroll{{overflow:auto}}}}
</style><main><h1>Ai Tweaker 独立密码锁</h1><p>三款 ASUS 工作站主板 · 2026-10-08</p>
<div class="status"><strong>当前状态：完成静态定位与诊断工具，密码锁尚未接入固件。</strong><br>没有修改版 CAP；P1 是免刷写的固件接口诊断程序。</div>
<p>已确认：三款都改；独立密码在 BIOS 内设置；每次 BIOS 会话首次打开 Ai Tweaker 验证一次。</p>
<div class="scroll"><table><tr><th>目标</th><th>根 Form ID</th><th>Setup PE 偏移</th><th>可达页面</th><th>静态问题</th><th>提示 Token</th></tr>{rows}</table></div>
<p>数量含条件隐藏项目；偏移属于解压后的 PE 模块，不能作为 CAP 文件补丁偏移。</p>
<p><a href="AiTweaker-P1-免刷写诊断.zip">下载 P1 诊断包</a> · <a href="probe/使用说明.txt">运行说明</a> · <a href="integration_map.json">机器可读适配定位</a></p>
<pre>{esc(text)}</pre></main></html>'''
    (OUT/'AiTweaker密码锁分析与状态.html').write_text(body,encoding='utf8')
    assert checks['shipped_efi_sha256']==build['sha256']
    assert len(checks['efi_emulation_cases'])==14 and all(c['passed'] for c in checks['efi_emulation_cases'])
    selected=[OUT/'probe'/p for p in ('使用说明.txt','build.py','verify.py','build.json','verification.json','profiles.json','example-MOCK-log.txt','reference/ABI_sources.json')]
    selected+=list((OUT/'probe/source').glob('*'))+list((OUT/'probe/USB').rglob('*'))
    selected=[p for p in selected if p.is_file()]
    sums='\n'.join(hashlib.sha256(p.read_bytes()).hexdigest()+'  '+p.relative_to(OUT/'probe').as_posix() for p in sorted(selected))+'\n'
    (OUT/'probe/SHA256SUMS.txt').write_text(sums,encoding='utf8');selected.append(OUT/'probe/SHA256SUMS.txt')
    zip_path=OUT/'AiTweaker-P1-免刷写诊断.zip'
    with zipfile.ZipFile(zip_path,'w',zipfile.ZIP_DEFLATED,compresslevel=9) as archive:
        for p in selected:archive.write(p,p.relative_to(OUT/'probe'))
    with zipfile.ZipFile(zip_path) as archive:
        assert archive.testzip() is None
        assert not any(n.lower().endswith(('.cap','.rom','.bin')) for n in archive.namelist())
        assert archive.read('USB/EFI/BOOT/BOOTX64.EFI')==(OUT/'probe/USB/EFI/BOOT/BOOTX64.EFI').read_bytes()
    delivery={'created_utc':now,'status':'AWAITING_TARGET_DIAGNOSTIC_AND_IMPLEMENTATION',
              'modified_bios_created':False,'original_zip_and_cap_hashes_unchanged':True,
              'diagnostic_zip':zip_path.name,'diagnostic_zip_sha256':hashlib.sha256(zip_path.read_bytes()).hexdigest(),
              'diagnostic_efi_sha256':build['sha256'],'zip_integrity_ok':True,'no_caps_in_package':True}
    (OUT/'delivery.json').write_text(json.dumps(delivery,indent=2),encoding='utf8')
    (OUT/(zip_path.name+'.sha256')).write_text(delivery['diagnostic_zip_sha256']+'  '+zip_path.name+'\n',encoding='utf8')
    print(json.dumps(delivery,ensure_ascii=False,indent=2))


if __name__=='__main__':main()
