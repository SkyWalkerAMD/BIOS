"""Reconcile already captured hardware evidence. No BMC or device access."""
from pathlib import Path
import base64, datetime, hashlib, html, json, zlib

HERE = Path(__file__).resolve().parent
LOCK = HERE.parent
ROOT = LOCK.parents[2]

def read(path):
    return json.loads(path.read_text(encoding='utf8'))

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def save(path, data):
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2)+'\n', encoding='utf8')

final_dir = HERE/'hardware-p4-1793625532666'
manifest = read(final_dir/'manifest.json')
assert manifest['pages']==6 and manifest['bytes']==4208 and manifest['crc32']=='70BDDBAA'
assert zlib.crc32((final_dir/'hardware-log.txt').read_bytes())==0x70BDDBAA
for name,digest in manifest['files'].items():assert sha(final_dir/name)==digest
log = (final_dir/'hardware-log.txt').read_text(encoding='ascii')
assert sha(final_dir/'hardware-log.txt') == '16562095c27b7fba2e5ce5b9899d0dd0947edda96bbdcd37956e772069741080'
assert len((final_dir/'hardware-log.txt').read_bytes()) == 4208
assert log.count('PASS ') == 41 and 'FAIL ' not in log
assert 'Failures=0x0000000000000000' in log
assert log.count('SendForm.status=0x0000000000000000') == 5
assert log.count('Credential.active_after_return=0x0000000000000000') == 5
assert log.count('Credential.unlocked_after_return=0x0000000000000000') == 5
assert log.count('PASS variable metadata and SHA256 unchanged') == 21
assert log.endswith('PROBE_COMPLETE\n')

boot_files = ['system-1793625657191.json', 'system-1793625676254.json']
order = [f'Boot000{i}' for i in range(1,7)]
for name in boot_files:
    b = read(HERE/name)['Boot']
    assert b['BootSourceOverrideEnabled'] == 'Disabled'
    assert b['BootSourceOverrideTarget'] == 'None'
    assert b['BootOrder'] == order and b['BootNext'] is None

# These are human/agent observations from actual KVM screenshots, separately
# labelled from the automatic checks in the diagnostic log.
cases = [
 ('未配置时拒绝进入', 'Ai Tweaker 提示先在 Security 设置独立密码；返回 Main。', ['screen-89-current.png','screen-90-key-result.png']),
 ('Security 管理项和设置', '原 Administrator/User Password 仍为 Not Installed；新增独立设置项，设置完成显示 Done。', ['screen-92-key-result.png','screen-96-key-result.png']),
 ('正常标签切换需要密码', '从 Main 切换 Ai Tweaker 出现独立密码提示。', ['screen-99-key-result.png']),
 ('取消输入', '按 ESC 后留在 Main。', ['screen-100-key-result.png']),
 ('错误密码', '界面显示 Password was not accepted。', ['screen-102-key-result.png']),
 ('正确密码', '成功显示 Ai Tweaker 参数页；没有编辑参数。', ['screen-106-current.png']),
 ('同会话再次进入', '切回 Main 再进 Ai Tweaker，不再提示密码。', ['screen-109-current.png']),
 ('新会话重新锁定 / Ai 初始页', '退出 SendForm 后直接以 0x2714 为初始页，再次提示；取消重定向到 Main。', ['screen-113-current.png','screen-114-key-result.png']),
 ('收藏夹初始入口', '直接请求 Form 0x2712 时提示密码；取消重定向到 Main。没有验证全部收藏项。', ['screen-117-current.png','screen-118-key-result.png']),
 ('ASUS Profile 初始入口', '直接请求 Form 0x272C 时提示密码；取消重定向到 Main。没有执行配置导入。', ['screen-121-current.png','screen-122-key-result.png']),
 ('界面修改密码', '输入当前、新、确认密码后显示 Done。', ['screen-129-key-result.png']),
 ('修改后旧密码失效', '旧临时密码被拒绝。', ['screen-133-key-result.png']),
 ('修改后新密码有效', '新临时密码成功显示 Ai Tweaker。', ['screen-137-current.png']),
 ('界面清除密码', '输入当前密码并确认 Y，显示 Done。', ['screen-142-key-result.png','screen-143-key-result.png']),
 ('清除后新会话免提示', '退出浏览器，再直接打开 Ai Tweaker，未输入密码即显示参数页。', ['screen-148-current.png']),
]
for _,_,screens in cases:
    for name in screens:
        assert (HERE/name).is_file(), name

driver = LOCK/'baselines/P5-445585c3/AiTweakerLock1904.efi'
iso = HERE/'ram_test/AiTweaker-P5-RAM-Test.iso'
assert sha(driver)=='445585c388d437a12bf331a42a216a88c7ae5104f7e91a086dc3bc4d8238b97a'
assert sha(iso)=='21518f8f3b3004342d46e59c13770c26df86393add26fad999196452fe6583ed'
assert sha(HERE/'ram_test/BOOTX64.EFI')=='bffc1b9c34da05de51852c23406cddcc108793f8cbb9574920663426888f0550'

limits = [
 '本次运行链接生产模块的 P5 RAM 测试应用，通过原厂 AMITSE 的 FormBrowser2.SendForm 打开真实文本界面；不是从固件卷自动调度生产 DXE。实体板上的永久部署、直接 Del/F2 开机路径、ASUS 图形/EZ/搜索私有路径仍未完成验证。',
 '密码凭据仅在 RAM 中保存。真实 NVRAM 凭据的跨重启保持、Load Defaults、固件恢复和最终部署均未在实体板验证；跨冷启动存储检查目前来自 OVMF。',
 '测试禁止 RuntimeServices 表中的 SetVariable 写入，累计阻止 76 次调用；没有执行超频修改、配置导入、Save & Reset 或刷写。此设计不证明 OEM 缓存指针、SMM 或直接硬件写入均被拦截。',
 '摘要核对只覆盖 OCMR、SocketMemoryConfig、AiTweakerPassword1904 三个指定变量的状态、长度、属性和内容；不代表整片 NVRAM 或整片 SPI 的前后逐字节比对。',
 '已观察系统恢复到 Rocky Linux 8.10 登录界面；没有登录操作系统或验证后台业务。',
 '修改映像没有重新取得原厂签名。现有恢复条件只有 BMC 虚拟光驱和 KVM，仍未建立可恢复的固件部署方式，不能把本次免刷结果当作刷写放行。',
 '适配范围为 W790-ACE 1904，不能推广到另外两款主板或 W790-ACE 2003。',
]

evidence = [HERE/name for _,_,screens in cases for name in screens]
evidence += [HERE/'screen-152-key-result.png', HERE/'screen-156-current.png']
evidence += [HERE/name for name in boot_files]
for folder in ['hardware-p4-1793622153630','hardware-p4-1793623494926','hardware-p4-1793625532666']:
    evidence.extend(p for p in (HERE/folder).iterdir() if p.is_file())
evidence += [HERE/'ram_lock_test.c',HERE/'build_ram_test.py',HERE/'preflight_extra.c',HERE/'build_preflight.py',HERE/'verify_ram_boot.py',HERE/'verify_preflight_vm.py']
evidence += [p for folder in ['ram_test','preflight'] for p in (HERE/folder).glob('*.json')]
evidence = sorted(set(evidence))
assert all(p.is_file() for p in evidence)

summary = {
 'generated_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),
 'target':'ASUS Pro WS W790-ACE BIOS 1904',
 'status':'RAM_ONLY_HARDWARE_TEST_PASSED_HOST_RESTORED',
 'driver_sha256':sha(driver), 'ram_test_iso_sha256':sha(iso),
 'ram_test_efi_sha256':sha(HERE/'ram_test/BOOTX64.EFI'),
 'production_dxe_entry_executed_on_hardware':False,
 'production_modules_linked_into_ram_test':True,
 'native_browser_sendform_used':True,
 'persistent_password_lock_deployed':False,
 'firmware_flashing_performed':False,
 'credential_persistence_on_hardware':'RAM_ONLY',
 'preflight':{'pages':9,'bytes':6748,'crc32':'384C9D60','log':'hardware-p4-1793622153630/hardware-log.txt'},
 'final_log':{'pages':6,'bytes':4208,'crc32':'70BDDBAA','sha256':sha(final_dir/'hardware-log.txt'),'path':'hardware-p4-1793625532666/hardware-log.txt','checks':41,'failures':0,'browser_sessions':5,'variables_compared_per_snapshot':3,'snapshot_rounds':7,'blocked_setvariable_calls':76},
 'visual_observations':[{'name':n,'result':'PASS_OBSERVED','observation':d,'screenshots':s} for n,d,s in cases],
 'restoration':{'cold_reset_requested_from_ram_app':True,'virtual_media_detached':True,'boot_order':order,'boot_override_active':'Disabled','boot_override_pending':'Disabled','normal_os_login_observed':True,'os':'Rocky Linux 8.10','hostname':'K6C-087','screenshot':'screen-156-current.png','bmc_logout_http':200,'controller_exit_code':0,'business_health_checked':False,
   'cleanup_note':'The optional client-disposal helper addressed its wrapper incorrectly and failed after stopping keepalive. Built-in BMC logout then returned HTTP 200; browser/context closed and controller exited 0, releasing in-memory credentials. Helper source corrected afterward; no reconnect needed.'},
 'limits':limits,
 'evidence_files':{p.relative_to(HERE).as_posix():{'bytes':p.stat().st_size,'sha256':sha(p)} for p in evidence},
}
save(HERE/'hardware_summary.json',summary)

title='W790-ACE 1904 独立密码锁：免刷实机验证'
intro='免刷实机测试通过，主机已恢复到 Rocky Linux 8.10 登录界面。独立密码的设置、错误拒绝、取消、会话重锁、入口拦截、修改和清除已在原厂 AMITSE 浏览器验证。永久开机生效尚未部署。'
adaptation='实机预检发现没有 EFI_RNG_PROTOCOL。驱动新增经 CPUID 检测的 RDSEED 取盐路径，并检查每次指令的成功标志、限制重试次数、失败擦除输出。已有 RNG 服务返回错误时不会被 CPU 路径掩盖。10 个编译后机器码故障注入用例通过；新版驱动在 OVMF 的 6 次冷启动中完成 350 项检查。实体 CPU 的取熵、PBKDF2、单调时钟和错误重试限制也通过 P5 自检。'
scope='通过 BMC 挂载只读 ISO 启动 P4/P5；P5 只在 RAM 挂接导航和 HII 管理项，凭据存储回调也指向 RAM。5 次原厂浏览器调用均正常返回，每次返回后 active/unlocked 均为 0。最终 41 项检查包括重复变量核对，不代表 41 种独立攻击路径。15 项界面观察单独列出，避免与自动断言混合计数。'
result='最终日志共 6 页、4,208 字节，CRC32 70BDDBAA，逐页校验和整包校验通过。7 轮核对中，3 个指定变量的状态、长度、属性和 SHA-256 均与初始值一致。测试期间 76 次 RuntimeServices 表写变量请求被阻止。冷重启后临时挂钩和凭据随 RAM 测试环境退出；虚拟光盘已卸载，当前及待应用一次性引导均 Disabled，原 6 项启动顺序保持不变。'
txt = f'{title}\n\n{intro}\n\n本次适配\n{adaptation}\n\n测试边界\n{scope}\n\n实机界面观察\n'
txt += '\n'.join(f'{i}. {n}：{d}（证据：{", ".join(s)}）' for i,(n,d,s) in enumerate(cases,1))
txt += f'\n\n日志与恢复\n{result}\n\n尚未完成\n'+'\n'.join(f'{i}. {v}' for i,v in enumerate(limits,1))
txt += f'\n\n日志 SHA-256：{summary["final_log"]["sha256"]}\n驱动 SHA-256：{sha(driver)}\nP5 ISO SHA-256：{sha(iso)}\n\n证据目录：{HERE}\n'
report_txt=ROOT/'W790-ACE-1904-独立密码锁-实机验证报告.txt'
report_txt.write_text(txt,encoding='utf8')
esc=html.escape
rows=''.join(f'<tr><td>{i}</td><td>{esc(n)}</td><td>{esc(d)}</td></tr>' for i,(n,d,_) in enumerate(cases,1))
def picture(name,caption):
    encoded=base64.b64encode((HERE/name).read_bytes()).decode('ascii')
    return f'<figure><img alt="{esc(caption)}" src="data:image/png;base64,{encoded}"><figcaption>{esc(caption)} · {esc(name)}</figcaption></figure>'
body=f'<h1>{title}</h1><p>2026-11-02 · ASUS Pro WS W790-ACE / 1904</p><aside>{intro}</aside><h2>实机发现与修正</h2><p>{adaptation}</p><h2>实际执行范围</h2><p>{scope}</p><table><thead><tr><th>#</th><th>检查</th><th>观察结果</th></tr></thead><tbody>{rows}</tbody></table><h2>日志与恢复</h2><p>{result}</p>'
body+=picture('screen-92-key-result.png','Security 内新增独立密码管理项')
body+=picture('screen-113-current.png','新的浏览器会话直接请求 Ai Tweaker，密码提示再次出现')
body+=picture('screen-156-current.png','冷重启后恢复 Rocky Linux 登录界面，虚拟介质为 Start Media / 0 KB')
body+='<h2>仍未证明的事项</h2><ul>'+''.join(f'<li>{esc(v)}</li>' for v in limits)+'</ul>'
body+=f'<h2>证据校验</h2><p>最终日志 SHA-256：<code>{summary["final_log"]["sha256"]}</code></p><p>驱动 SHA-256：<code>{sha(driver)}</code></p><p>二维码原帧、原图、构建记录、逐项截图索引保存在 <code>{esc(str(HERE))}</code>。hardware_summary.json 含逐文件摘要。</p>'
report_html=report_txt.with_suffix('.html')
report_html.write_text('<!doctype html><html lang="zh-CN"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>'+title+'</title><style>body{max-width:1050px;margin:32px auto;padding:0 22px 60px;font:16px/1.75 "Microsoft YaHei",sans-serif;color:#172b40;background:#f6f8fa}aside{background:#e5f2e9;border-left:5px solid #247144;padding:18px}h1{font-size:29px}h2{margin-top:32px}table{width:100%;border-collapse:collapse;background:white}td,th{padding:10px;border:1px solid #ced8e1;text-align:left}th{background:#eaf0f6}td:first-child{width:28px}figure{margin:22px 0}img{display:block;width:100%;height:auto;border:1px solid #ced8e1}figcaption{color:#526578;font-size:14px}code{overflow-wrap:anywhere;font-size:13px}li{margin:9px 0}</style><body>'+body+'</body></html>',encoding='utf8')
print(json.dumps({'status':summary['status'],'checks':41,'visual_observations':len(cases),'report':str(report_html),'evidence_files':len(evidence)},ensure_ascii=True))
