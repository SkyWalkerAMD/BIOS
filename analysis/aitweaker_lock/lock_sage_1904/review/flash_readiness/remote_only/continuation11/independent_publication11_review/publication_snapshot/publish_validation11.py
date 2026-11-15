"""Publish the bounded C11 physical run, preserving the completed C10 snapshot."""
from pathlib import Path
from datetime import datetime, timezone
import hashlib
import html
import json

HERE = Path(__file__).resolve().parent
READY = HERE.parents[1]
CASE = READY.parents[1]
HW = CASE / 'remote_172_20_2_162'
D04 = READY / 'native13_split_candidate/installer_design04'
REVIEW = D04 / 'ram_transaction08_independent_review/hardware_review01'
SNAP = HERE / 'publication11_snapshot'


def read(p):
    return json.loads(p.read_text(encoding='utf-8-sig'))


def sha(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()


def bind(p):
    return dict(path=str(p), bytes=p.stat().st_size, sha256=sha(p))


def save(p, obj):
    p.write_text(json.dumps(obj, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')


def exact(p, data):
    if p.exists():
        assert p.read_bytes() == data, p
    else:
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)


def main():
    prior = HERE.parent / 'continuation10/publication10_snapshot/acceptance_status.json'
    assert sha(prior) == 'e88ce3192fb97eb287797daed44a46c035a56b0b85a7a333b61450ad3c1ce32c'
    status = read(prior)
    state = read(HERE / 'work_status.json')
    assert not state['controller_open'] and state['closure']['controller_exit_code'] == 0
    assert state['password_input_events'] == state['firmware_uploads'] == state['firmware_flashes'] == 0
    assert state['first_M']['UI_acceptance'] is False
    reviews = {}
    expected = {
        'initial_hardware-native13-ram-test08-1793715405937-cb989a98_review.json': '5118f813300fbe027f71fc2e84d11e4f6e7b4d288ae2e5fcecd74c775f436c6b',
        'mode1_hardware-native13-ram-test08-1793715526855-aea3521f_review.json': 'ce5678e05470cf0307f37f023866ebaa7010366d3e62bdefc8cc3015d860752b',
        'mode2_hardware-native13-ram-test08-1793715646283-8c2b8643_review.json': 'cbd31152d17adb7af58cee9ae7decce111811cf76bfe74c1a3112864cc8e2feb',
        'management_first_attempt_incident_review.json': '2b8d01e396853ce39c45e40301ca7e0ee5303e79e89a16bf221fb0aca91a152b',
        'recovery_hardware-native13-ram-test08-1793716547807-ef828dd1_review.json': '970471670a403cfde363cb8544bd2bf16c27c76336218858b2e856ee106b1536',
    }
    for name, digest in expected.items():
        p = REVIEW / name
        assert sha(p) == digest, name
        reviews[name] = bind(p)
    captures = {}
    for key in ['initial_snapshot', 'mode1', 'mode2', 'recovery_snapshot']:
        entry = state[key]
        folder = HW / entry['folder']
        m = read(folder / 'manifest.json')
        assert all(m[k] == entry[k] for k in ['pages', 'bytes', 'crc32', 'sha256'])
        assert sha(folder / 'hardware-log.txt') == entry['sha256']
        assert (folder / 'hardware-log.txt').stat().st_size == entry['bytes']
        for rel, digest in m['files'].items():
            assert sha(folder / rel) == digest, rel
        captures[key] = bind(folder / 'manifest.json')
    off = HW / state['closure']['off']
    media = HW / state['closure']['media']
    logout = HW / state['closure']['logout']
    r = read(off)
    assert r['system']['PowerState'] == 'Off' and r['power']['data']['power_status'] == 0
    for view in ['system', 'settings']:
        boot = r[view]['Boot']
        assert boot['BootNext'] is None
        assert [boot[k] for k in ['BootSourceOverrideEnabled', 'BootSourceOverrideMode', 'BootSourceOverrideTarget']] == ['Disabled', 'Legacy', 'None']
    assert all(read(media)['verified'].values()) and read(logout)['status'] == 200
    image = READY / 'native12_safety_review/implementation/build/integration_native12_review/W790E-SAGE-SE-1904-NATIVE12-INTERNAL-UNSIGNED-NOT-RELEASE-READY.review.bin'
    assert sha(image) == 'b1223ca05cf9630382e5fc014457d3c6343aaf7d970b58e5769950200f65ac02'
    artifacts = {
        'app': (D04/'ram_transaction08/app_build/SageNative13RamTest08.efi', state['candidate_efi_sha256']),
        'provider': (D04/'provider14_chrome07/build/AiTweakerSplitProvider14.UNSIGNED.local.efi', state['provider14_sha256']),
        'iso': (D04/'ram_test08_delivery/packages/e0793175f78b6488/SAGE-N13-RAMTEST08-NOFLASH.iso', state['candidate_iso_sha256']),
    }
    for p, digest in artifacts.values():
        assert sha(p) == digest, p
    for name in ['screen-376-current.png', 'screen-377-current.png', 'screen-378-current.png']:
        assert sha(HW/name) == '503b195245166a3eba8673aa6bd83b530583bfe7d65db16ceb1cfe287c447e72'
    exact(SNAP/'prior_acceptance_status10.json', prior.read_bytes())
    exact(SNAP/'continuation11_work_status.json', (HERE/'work_status.json').read_bytes())
    gaps = [
        '真实密码管理页尚未通过：C11首次M显示未设置密码提示，单次Esc后仍是同一画面；设密、改密、错密拒绝和各入口均未完成实机验收。',
        '永久Del/F2装载和拦截仍未实测。修改映像尚未取得已验证的更新链信任，原厂签名不再有效；没有上传或刷写固件。',
        '仍缺机器专属完整SPI备份，以及仅有BMC/KVM时可用的无POST恢复证据。',
    ]
    result = {
        'status': 'C11_TX08_INSTALL_ROLLBACK_ATTACH_PASS_MANAGEMENT_UI_FAILED_RECOVERY_OBSERVED',
        'generated_utc': datetime.now(timezone.utc).isoformat(),
        'round': 11, 'diagnostic_session_complete': True, 'task_complete': False, 'release_ready': False,
        'firmware_uploads': 0, 'firmware_flashes': 0, 'password_input_events': 0,
        'mode1': 'Exact twelve-site installation and rollback passed before provider start.',
        'mode2': 'One provider attach passed; original protected-store values and attributes unchanged at this pre-M check.',
        'management': 'One M displayed UNCONFIGURED provider request rather than the expected three-action form. One Esc and later observation show identical PNGs; no post-M return log.',
        'management_limits': 'No proof of key consumption, repeated loop, CPU hold or exact failed page/control. No password fixture was created or typed, no action Enter or B was sent.',
        'recovery': 'ForceOff ended RAM execution. Separate boot observed original BIOS1904, current original identity/twelve sites, private variable absent and fresh protected-store reads. Only Q, no new transaction or M.',
        'recovery_limits': 'Not an in-place rollback of the interrupted run. Initial logs contain no store contents/digests; no cross-boot store equality or absence of all OEM writes is claimed.',
        'next_work': 'Isolated nonsecret request/classification diagnostics; investigate native kind4 menu without relaxing unknown policy. No next diagnostic executable has physical acceptance.',
        'three_major_gaps_zh': gaps, 'reviews': reviews, 'captures': captures,
        'artifacts': {k: bind(p) for k, (p, _) in artifacts.items()},
        'screens': {name: bind(HW/name) for name in ['screen-376-current.png','screen-377-current.png','screen-378-current.png','screen-383-current.png','screen-386-current.png']},
        'closure': {**state['closure'], 'evidence': {'off': bind(off), 'media': bind(media), 'logout': bind(logout)}},
        'internal_image': bind(image), 'prior_publication': bind(prior),
    }
    save(HERE/'validation11_result.json', result)
    status['prior_remote_validation10'] = status['latest_remote_validation']
    status.update(generated_utc=result['generated_utc'], latest_remote_validation=result,
                  latest_completed_validation_round=11, active_continuation='continuation11',
                  current_work='isolated_request_diagnostics09', task_complete=False, release_ready=False,
                  machine_state_scope='2026-11-03T14:37:31.566Z closing observation only', three_major_gaps_zh=gaps)
    updates = {
        '免刷诊断上机测试': ('第11轮安装回滚和加载通过；管理页失败', gaps[0]),
        '首次 Del/F2 自动拦截': ('尚未通过永久启动实测', gaps[1]),
        '免刷原生拦截安装': ('新TX08的12处安装与精确回滚通过', '模式2模块成功附着；首次M未返回，随后关机结束RAM执行。恢复启动是另一次启动，不是应用原地撤销。'),
        '密码持久化及界面恢复': ('虚拟机有证据，实机密码动作尚未执行', 'C11提示页可见，但设置/修改/验证三动作管理页未出现；单次Esc后同屏，尚无返回日志。'),
        '完整备份与恢复': ('原版启动和当前私有变量缺失已复核；完整恢复能力仍缺', gaps[2]),
        '第8轮结束与启动字段': ('最新第11轮会话已关闭', '14:37:31.566 UTC注销200、控制进程退出0。Off、CD/HD空闲；Self与SD均Disabled/Legacy/None，BootNext为空。'),
        '原厂静态标题控件兼容': ('局部07已接入P14/TX08并实测；管理页仍未通过', '本轮显示未配置密码提示。原厂kind4菜单是进一步分析线索，尚未获得实机结构快照，不能宣称唯一根因或直接放行。'),
    }
    for gate in status['gates']:
        if gate['item'] in updates:
            gate['status'], gate['detail'] = updates[gate['item']]
    save(READY/'acceptance_status.json', status)
    rows = [
        ('12处RAM挂钩安装与撤销', '通过本次实测', '模式1精确恢复12处原字节；未启动密码模块。'),
        ('密码模块加载', '通过本次加载检查', '模式2单次附着通过；进入管理页之前参数内容与属性复核通过。'),
        ('独立密码管理页', '未通过', '首次M出现“请先在Security设置密码”；单次Esc后仍是同一提示，未收回返回日志。'),
        ('设置、修改、验证密码', '实机尚未执行', '未创建或输入测试密码，未选择密码动作，也未进行其他入口测试。'),
        ('恢复启动', '通过本次恢复观察', '原版1904 BIOS显示正常；新启动当前密码变量不存在，原始身份及12处代码检查通过。'),
        ('可刷写正式版', '尚未完成', '永久锁实测、更新链信任、完整SPI备份及无POST恢复均有未完成项。'),
    ]
    tr = ''.join('<tr>'+''.join('<td>'+html.escape(v)+'</td>' for v in row)+'</tr>' for row in rows)
    links = [(name, REVIEW/name) for name in expected]
    links.extend([('第11轮汇总及绑定', HERE/'validation11_result.json'), ('完整准入状态和历史', READY/'acceptance_status.json'), ('第10轮冻结状态', prior)])
    link_html = ''.join('<li><a href="'+html.escape(p.relative_to(READY).as_posix(), quote=True)+'">'+html.escape(name)+'</a></li>' for name,p in links)
    page = '''<!doctype html><html lang="zh-CN"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>W790E-SAGE SE 1904 验证进度</title><style>body{max-width:1050px;margin:32px auto;padding:0 24px;font:16px/1.7 system-ui,sans-serif;color:#172638}table{border-collapse:collapse;width:100%}td,th{border:1px solid #cad4de;padding:12px;text-align:left;vertical-align:top}td:first-child{width:25%}td:nth-child(2){width:20%}a,code{overflow-wrap:anywhere}.note{background:#fff2d5;padding:14px;border-left:4px solid #c87500}</style><body>
<h1>W790E-SAGE SE 1904：第11轮实机验证</h1>
<p class="note"><strong>尚未达到可刷写正式版条件。</strong>TX08安装撤销和模块加载通过；独立密码管理页未通过。没有上传或刷写固件，没有输入或设置实机独立密码。</p>
<table><thead><tr><th>项目</th><th>结果</th><th>范围</th></tr></thead><tbody>'''+tr+'''</tbody></table>
<h2>本轮发现</h2><p>模块加载后，首次M显示“Set an independent password under Security first.”，未显示预期的三个管理动作。按一次Esc及之后观察仍为相同画面；不能仅凭截图判定按键是否被读取、是否反复触发或CPU是否停顿。本轮没有密码输入、动作Enter或B，没有管理页返回后的日志。</p>
<p>下一步在隔离诊断版提示页显示触发入口及首个分类失败的控件。原厂kind4菜单是本地原码分析中的线索，尚无实机结构证据；不会将未知菜单直接放行。该诊断工作尚不构成新版本实机验收。</p>
<h2>恢复及结束状态</h2><p>关机结束了失败运行中的RAM挂钩执行。新启动重新看到原版1904 BIOS；只读取初始日志，未再次执行安装、模块加载或M。恢复日志2页、1,168字节，CRC32 <code>397A6A63</code>，当前私有密码变量不存在，原始模块身份和12处代码检查通过。</p>
<p>这不是失败运行中由应用完成的原地撤销，也不证明跨启动的所有参数字节相等或所有OEM变量均未写入。恢复日志仅两处加载地址不同，不含参数内容或摘要。</p>
<p>截至2026-11-03 14:37:31.566 UTC（23:37:31 JST），主机Off，CD/HD虚拟介质空闲，BMC注销返回200，控制进程退出0。Self和SD的启动覆盖均为Disabled/Legacy/None，BootNext为空；未发送启动顺序写入请求。此处为该次结束时的读回状态。</p>
<h2>正式发布仍需完成</h2><ul>'''+''.join('<li>'+html.escape(x)+'</li>' for x in gaps)+'''</ul>
<p>NATIVE12内部映像保持不变，仍为UNSIGNED / NOT RELEASE READY；本次RAM测试和永久固件属于不同构建，不能相互继承验收。SHA256：<code>b1223ca05cf9630382e5fc014457d3c6343aaf7d970b58e5769950200f65ac02</code>。</p>
<h2>证据文件</h2><ul>'''+link_html+'''</ul></body></html>'''
    (READY/'检查报告.html').write_text(page, encoding='utf-8')
    for p in [CASE/'requirements.json', CASE.parent/'requirements.json']:
        req = read(p)
        old = req.get('production_release_work', {})
        exact(SNAP/(p.parent.name+'_prior_production_release_work.json'), (json.dumps(old,ensure_ascii=False,indent=2)+'\n').encode('utf-8'))
        req['production_release_work'].update(latest_completed_validation_round=11, active_continuation='continuation11',
            current_work=status['current_work'], task_complete=False, release_ready=False, flashing_performed=False)
        save(p, req)
    for name in ['acceptance_status.json','检查报告.html']:
        exact(SNAP/name, (READY/name).read_bytes())
    save(HERE/'publication11_check.json', {'status':'PASS_BOUND_EVIDENCE_AND_PUBLISHED_SCOPE',
        'files':{str(p.relative_to(READY)).replace('\\','/'):sha(p) for p in [READY/'acceptance_status.json',READY/'检查报告.html',HERE/'validation11_result.json',Path(__file__)]},
        'release_ready':False,'session_closed':True})
    print(json.dumps({'published_round':11,'release_ready':False,'result':str(HERE/'validation11_result.json')},ensure_ascii=False))


if __name__ == '__main__':
    main()
