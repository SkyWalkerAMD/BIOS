"""Publish completed C09/C10 hardware evidence, retaining the previous publication."""
from pathlib import Path
from datetime import datetime, timezone
import hashlib, html, json

HERE = Path(__file__).resolve().parent
READY = HERE.parents[1]
CASE = READY.parents[1]
HW = CASE / 'remote_172_20_2_162'
D04 = READY / 'native13_split_candidate/installer_design04'

def read(p):
    return json.loads(p.read_text(encoding='utf-8-sig'))

def sha(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()

def bind(p):
    return dict(path=str(p), bytes=p.stat().st_size, sha256=sha(p))

def save(p, value):
    p.write_text(json.dumps(value, ensure_ascii=False, indent=2)+'\n', encoding='utf-8')

def exact(p, data):
    if p.exists():
        assert p.read_bytes() == data, str(p)
    else:
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)

def check_capture(name, length, crc, digest):
    p = HW / name
    m = read(p/'manifest.json')
    assert (m['bytes'], m['crc32'], m['sha256']) == (length, crc, digest)
    assert len((p/'hardware-log.txt').read_bytes()) == length and sha(p/'hardware-log.txt') == digest
    for rel, expected in m['files'].items():
        assert sha(p/rel) == expected, rel
    return bind(p/'manifest.json')

def main():
    snapshot = HERE/'publication10_snapshot'
    old = READY/'remote_only/continuation08/publication08_inputs/report_snapshot/acceptance_status.json'
    assert sha(old) == 'd663d75482aa3d4f8c0bca25718bbe1266408627cddeb81c5143852c18875f5c'
    record = read(old)
    exact(snapshot/'prior_acceptance_status08.json', old.read_bytes())
    reviews = {
        'ram_mode1': D04/'ram_transaction05_independent_review/hardware_review01/mode1_0000000000000002_review.json',
        'ram_mode2_black_screen': D04/'ram_transaction05_independent_review/hardware_review01/mode2_snapshot3_black_screen_review.json',
        'ram_recovery': D04/'ram_transaction05_independent_review/hardware_review01/second_boot_recovery_review.json',
        'baseline_initial': D04/'readonly_browser_baseline06_independent_review/hardware_review01/initial_hardware-native13-browser-baseline06-1793713331040-a1540dce_review.json',
        'chrome07_local': D04/'static_chrome_candidate07_independent_review/independent_review.json',
    }
    final = sorted((D04/'readonly_browser_baseline06_independent_review/hardware_review01').glob('returned_*_review.json'))
    assert len(final) == 1, 'Final independent baseline review required'
    reviews['baseline_return'] = final[0]
    expected = {
        'ram_mode1': '36ec962bc732af9d2b54002621162d48e3dd85f97945de72d87d2c7004864325',
        'ram_mode2_black_screen': 'ff668f8cf8a13aa907b34ad169ee7c0f07e9384944bbac9d56774600d863034b',
        'ram_recovery': '1d4a0f5e7b0dd51ab96aadbe0273f325ea66cdbc9a8bbb37765de6bdfb2d570c',
        'baseline_initial': '9bc8ea591b58d383cd2a713a9dc7e1249f1eeae8de43daef3fa87ca87e3c485b',
        'baseline_return': 'dd669c3995ac34d9a37b5a1b654758ad975f2a03bd09e90d0898fd226f22b2ad',
        'chrome07_local': 'ef952cdf10709506724f7f7dd92f5c17ed1acbfc6dd18e1a310593ec3a96ee63',
    }
    for name, digest in expected.items():
        assert sha(reviews[name]) == digest, name
    captures = {
        'ram_mode1': check_capture('hardware-native13-ram-test05-1793710122082-b4174444', 1506, '4A4F399F', '07bd3c779114777b5b5ef50f8ed4030fc3712e6d8c8e3dda7fde1fb2dc88c6aa'),
        'ram_mode2': check_capture('hardware-native13-ram-test05-1793710255493-6348c6d6', 1901, '5086171C', '9777421d6aa15eb86fd9ba67a0fb76afb7796fa342a0309f6f13424e999d6fa9'),
        'ram_recovery': check_capture('hardware-native13-ram-test05-1793710733660-6383ec06', 1168, '7DC729FE', '517ba5e82cf7ebed211cdbc47f222cb14a289ece6e28db964dabaa27d5afd2a4'),
        'baseline_initial': check_capture('hardware-native13-browser-baseline06-1793713331040-a1540dce', 1518, '3A8A6A8B', '483a3a0cb5d0e029d560dde14eec9e048b15b06f2a5165a05eac47c3b0a36337'),
        'baseline_return': check_capture('hardware-native13-browser-baseline06-1793713512938-ce806332', 4911, 'CCF8A98C', '520ea66fc0965f1268df8b0a7ca8f9d4a4d1bc6119676814092e79643e962cee'),
    }
    log = (HW/'hardware-native13-browser-baseline06-1793713512938-ce806332/hardware-log.txt').read_text()
    for line in ['BROWSER_ATTEMPTED=0000000000000001', 'BASELINE_RETURN_ACCEPTED=0000000000000001',
                 'NativeSendFormStatus=0000000000000000', 'NativeActionRequest=0000000000000000',
                 'ConfigAccessCallCount=0000000000000009', 'Warnings=0000000000000000',
                 'PASS original text header snapshots and twelve sites unchanged',
                 'PASS private credential still absent; no content read']:
        assert line in log, line
    cleanup_path = HW/'media-cleanup-1793713759331.json'
    cleanup = read(cleanup_path)
    assert all(cleanup['verified'].values())
    off_path = HW/'manager-restart08-capability-1793713728874.json'
    off = read(off_path)
    assert off['system']['PowerState'] == 'Off' and off['power']['data']['power_status'] == 0
    for name in ['system', 'settings']:
        boot = off[name]['Boot']
        assert [boot[k] for k in ['BootSourceOverrideEnabled', 'BootSourceOverrideMode', 'BootSourceOverrideTarget']] == ['Disabled', 'Legacy', 'None']
        assert boot['BootNext'] is None
    logout_path = HW/'inventory-session-logout-1793713772482.json'
    assert read(logout_path)['status'] == 200
    state = read(HERE/'work_status.json')
    assert not state['controller_open'] and state['closure']['controller_exit_code'] == 0
    image_path = READY/'native12_safety_review/implementation/build/integration_native12_review/W790E-SAGE-SE-1904-NATIVE12-INTERNAL-UNSIGNED-NOT-RELEASE-READY.review.bin'
    assert sha(image_path) == 'b1223ca05cf9630382e5fc014457d3c6343aaf7d970b58e5769950200f65ac02'
    for folder in [HERE.parent/'continuation09', HERE]:
        exact(snapshot/(folder.name+'_work_status.json'), (folder/'work_status.json').read_bytes())
    gaps = [
        '真实独立密码设置、解锁、各入口及永久 Del/F2 拦截尚未验收；无安全页面时的退出仍有缺口。',
        '修改映像没有取得已验证的更新链信任；原厂内容签名不再有效，尚未向 BMC 上传或刷写。',
        '仍缺机器专属完整 SPI 备份及在仅有 BMC/KVM 条件下可用的无 POST 恢复证据。',
    ]
    result = {
        'status': 'C09_RAM_TRANSACTION_AND_C10_ORIGINAL_BROWSER_BASELINE_COMPLETED_NOT_PASSWORD_ACCEPTANCE',
        'generated_utc': datetime.now(timezone.utc).isoformat(), 'rounds': [9, 10],
        'diagnostic_sessions_complete': True, 'task_complete': False, 'release_ready': False,
        'firmware_uploads': 0, 'firmware_flashes': 0, 'password_input_events': 0,
        'ram_mode1': '12 sites installed and exact rollback passed before provider execution',
        'ram_mode2': 'Provider attached; first M displayed black screen, one Esc did not restore a usable page; power off ended resident execution',
        'ram_recovery': 'Original BIOS observed; second boot currently reported private variable absent and original identities; no cross-boot whole-store equality claim',
        'baseline': 'One original ASUS SendForm invocation without guard/provider, same P13 formset displayed, Esc returned status0/request0; readonly postchecks passed',
        'baseline_scope': 'All9 lifecycle callbacks rejected. No password action was invoked. Display labels do not establish password functionality. Original OEM internal variable writes not globally excluded.',
        'display_limit': 'Return menu retained portions of prior QR background; full clear-screen restoration not accepted',
        'new_classifier_scope': 'Only local isolated07 classifier accepted by independent review; no new complete app/provider/ISO hardware acceptance at this publication',
        'three_major_gaps_zh': gaps, 'reviews': {n:bind(p) for n,p in reviews.items()}, 'captures': captures,
        'screens': {n:bind(HW/n) for n in ['screen-310-current.png','screen-314-current.png','screen-337-current.png','screen-342-current.png','screen-343-current.png']},
        'closure': {'off':bind(off_path), 'media':bind(cleanup_path), 'logout':bind(logout_path),
                    'controller_exit_code_reported_by_operator':0, 'host_off_at_readback':True, 'CD_HD_idle_at_readback':True,
                    'BootNext_null_both_views':True, 'SD_and_Self_fields':'Disabled/Legacy/None',
                    'override_patches_in_C09_C10':0, 'BootOrder_write_requests':0,
                    'time_scope':'2026-11-03T13:49:32.482Z closing observation only'},
        'internal_image':bind(image_path), 'prior_publication':bind(old),
    }
    save(HERE/'validation10_result.json', result)
    record['prior_remote_validation08'] = record['latest_remote_validation']
    record.update(generated_utc=result['generated_utc'], latest_remote_validation=result,
                  latest_completed_validation_round=10, active_continuation='continuation10',
                  current_work='local_chrome07_provider14_transaction08_integration', task_complete=False,
                  machine_state_scope=result['closure']['time_scope'], three_major_gaps_zh=gaps)
    updates = {
        '免刷诊断上机测试': ('第9轮安装回滚通过；第10轮原厂浏览器基线通过', '原生管理表单在guard/provider加载后黑屏；无guard/provider对照显示正常并Esc返回。基线7页4911字节CRC CCF8A98C，不能视作密码验收。'),
        '首次 Del/F2 自动拦截': ('尚未通过永久启动实测', '12处RAM安装和回滚已验证，永久固件装载及首次Del/F2密码拦截仍未验证。'),
        '免刷原生拦截安装': ('12处安装与精确回滚通过', '第一模式通过；第二模式provider成功附着，随后M黑屏。该次由关机结束RAM执行，没有声称应用完成回滚。'),
        '密码持久化及界面恢复': ('虚拟机有证据，实机密码动作尚未执行', 'C10只有拒绝全部动作的同形表单显示/Esc返回通过；主菜单仍有QR背景残留。设密、改密、错密拒绝和会话撤销尚需新候选上机。'),
        '完整备份与恢复': ('原版BIOS恢复已观察；完整备份及无POST恢复仍缺', 'C09失败后可重新进入原版1904 BIOS，并在新启动读取到当前私有密码变量缺失；这不等于可恢复损坏的SPI固件。'),
        '第8轮结束与启动字段': ('最新第10轮会话已关闭', '2026-11-03 13:49:32 UTC注销HTTP200，控制进程退出0。Off、CD/HD空闲，Self和SD均Disabled/Legacy/None且BootNext为空；未发启动顺序写入。'),
    }
    for gate in record['gates']:
        if gate['item'] in updates:
            gate['status'], gate['detail'] = updates[gate['item']]
    record['gates'].append({'item':'原厂静态标题控件兼容', 'status':'局部07修正通过独审，整包接入进行中',
        'detail':'严格识别原厂HII=-1 SUBTITLE初始化结构，同时核对方法表、代码、条件与来源。保留未知结构拒绝；无安全页退出未修复，尚非上机包。'})
    save(READY/'acceptance_status.json', record)
    rows = [
        ('12处RAM拦截安装与回滚', '通过有限实测', '模式1安装后精确恢复全部12处原字节。'),
        ('加载密码模块后的原厂菜单', '未通过', '模块附着成功，首次M黑屏；没有输入密码，已恢复原版启动。'),
        ('无拦截的原厂表单对照', '通过有限实测', '同一表单正常显示，Esc返回0/request0；超频与内存参数、原代码复核通过。'),
        ('设置、修改、验证独立密码', '实机尚未执行', '虚拟机结果保留；本轮屏幕上的动作标签由拒绝回调的基线提供。'),
        ('静态控件兼容修正', '局部代码独审通过', '新的完整免刷候选接入中；未知页面退出及永久启动仍需完成。'),
        ('可刷写正式版', '尚未完成', '更新链信任、完整SPI备份、无POST恢复和永久密码锁实测仍未通过。'),
    ]
    tr = ''.join('<tr>'+''.join('<td>'+html.escape(v)+'</td>' for v in row)+'</tr>' for row in rows)
    links = ''.join('<li><a href="'+html.escape(str(p.relative_to(READY)).replace('\\','/'), quote=True)+'">'+html.escape(name)+'</a></li>' for name,p in reviews.items())
    page = '''<!doctype html><html lang="zh-CN"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>W790E-SAGE SE 1904 验证进度</title><style>body{max-width:1050px;margin:32px auto;padding:0 24px;font:16px/1.7 system-ui,sans-serif;color:#172638}table{border-collapse:collapse;width:100%}td,th{border:1px solid #cad4de;padding:12px;text-align:left;vertical-align:top}td:first-child{width:25%}td:nth-child(2){width:20%}a,code{overflow-wrap:anywhere}.note{background:#fff2d5;padding:14px;border-left:4px solid #c87500}</style><body>
<h1>W790E-SAGE SE 1904：验证进度</h1>
<p class="note"><strong>尚未达到可刷写正式版条件。</strong>本次完成了第9轮RAM安装/恢复及第10轮原厂浏览器对照。没有上传或刷写固件，没有输入或设置实机独立密码。</p>
<table><thead><tr><th>项目</th><th>结果</th><th>范围</th></tr></thead><tbody>'''+tr+'''</tbody></table>
<h2>本轮实机证据</h2><p>加载原拦截与密码模块后的菜单出现黑屏。移除两者的独立基线能够显示同形表单并用Esc返回，因此新候选优先修正原厂静态标题控件的兼容性；尚未证明它就是实机黑屏的唯一原因。</p>
<p>基线返回日志共7页、4,911字节，CRC32 <code>CCF8A98C</code>，SHA256 <code>520ea66fc0965f1268df8b0a7ca8f9d4a4d1bc6119676814092e79643e962cee</code>。全9次回调均拒绝，超频及内存参数内容与属性、原模块代码/头部/12处位置复核通过，当前私有密码变量缺失。不能由此推断所有OEM内部变量都没有写入。</p>
<p>返回主菜单有旧二维码背景残留；完整清屏恢复尚未通过。二维码刷新中的失败和旧页截图均保留，最终接收页经过独立重解及完整CRC校验。</p>
<h2>结束状态</h2><p>截至2026-11-03 13:49:32 UTC（22:49:32 JST），主机已关机，CD/HD虚拟介质空闲，BMC注销返回200，控制进程退出0。Self和SD读取均为Disabled/Legacy/None，BootNext为空。此处只描述该次结束读回。</p>
<h2>正式发布仍需完成</h2><ul>'''+''.join('<li>'+html.escape(x)+'</li>' for x in gaps)+'''</ul>
<p>NATIVE12内部映像保持不变，SHA256 <code>b1223ca05cf9630382e5fc014457d3c6343aaf7d970b58e5769950200f65ac02</code>，仍为UNSIGNED / NOT RELEASE READY。局部07、后续免刷候选与该映像是不同构建，不能相互继承验收。</p>
<h2>证据文件</h2><ul>'''+links+'''<li><a href="remote_only/continuation10/validation10_result.json">本轮汇总及绑定</a></li><li><a href="acceptance_status.json">完整准入状态及历史证据</a></li><li><a href="remote_only/continuation08/publication08_inputs/report_snapshot/检查报告.html">第8轮历史快照（相对链接仅在原位置有效）</a></li></ul></body></html>'''
    (READY/'检查报告.html').write_text(page, encoding='utf-8')
    for p in [CASE/'requirements.json', CASE.parent/'requirements.json']:
        req=read(p)
        previous=req.get('production_release_work',{})
        exact(snapshot/(p.parent.name+'_prior_production_release_work.json'), (json.dumps(previous,ensure_ascii=False,indent=2)+'\n').encode())
        req['production_release_work'].update(latest_completed_validation_round=10, active_continuation='continuation10',
            current_work=record['current_work'], task_complete=False, release_ready=False, flashing_performed=False)
        save(p,req)
    for name in ['acceptance_status.json','检查报告.html']:
        exact(snapshot/name,(READY/name).read_bytes())
    save(HERE/'publication10_check.json', {'status':'PASS_BOUND_EVIDENCE_AND_PUBLISHED_SCOPE',
        'files':{str(p.relative_to(READY)).replace('\\','/'):sha(p) for p in [READY/'acceptance_status.json',READY/'检查报告.html',HERE/'validation10_result.json',Path(__file__)]},
        'release_ready':False,'sessions_closed':True})
    print(json.dumps({'published_round':10,'release_ready':False,'result':str(HERE/'validation10_result.json')},ensure_ascii=False))

if __name__=='__main__':
    main()
