"""Assemble a field handoff without modifying either firmware image."""
from pathlib import Path, PurePosixPath
import hashlib, json, zipfile

P=Path(__file__).resolve().parent
A=P.parent
OLD=A/'HERO-3107-IPMI-P5-RC2-REA-REVIEWED-FLASHBACK.zip'
OUT=A/'HERO-3107-IPMI-RC2-FIELD-VALIDATION-20261104.zip'
STAGE=P/'field-package'
items={}
def sha(b): return hashlib.sha256(b).hexdigest()
def add(name,data):
    assert name not in items,name
    assert not PurePosixPath(name).is_absolute() and '..' not in PurePosixPath(name).parts
    items[name]=data
def text(name,s): add(name,s.replace('\r\n','\n').replace('\n','\r\n').encode('utf-8-sig'))
def load(name): return json.loads((P/name).read_text(encoding='utf-8'))

live=load('live-image-check.json')
auth=load('capsule/hero_capsule_authentication.json')
openssl=load('capsule/hero_openssl_authentication.json')
rea=load('capsule/hero_capsule_rea_review.json')
boot=load('bootguard/bootguard-review.json')
manual=load('manual-build.json')
assert manual.get('visual_render_review_pending') is False
assert manual.get('all_pages_visually_reviewed')==list(range(1,8))
assert not live['candidate']['accepted'] and not live['changes']['bios_written']
assert not live['flashback']['candidate_performed']
assert auth['status']=='ORIGINAL_BOTH_SIGNATURES_VALID_RC2_FIRMWARE_SIGNATURE_INVALID'
assert openssl['status']=='OPENSSL_AGREES_ORIGINAL_VALID_RC2_FIRMWARE_INVALID'
assert all(x['signature_valid']==x['expected_valid'] for x in openssl['checks'])
assert rea['status']=='BOUNDED_STATIC_REVIEW_COMPLETE_RC2_CAP_SIGNATURE_INVALID'
assert rea['signature_result']=={'official_firmware':True,'official_certificate':True,'rc2_firmware':False,'rc2_certificate':True}
for evidence in rea['evidence'].values():
    assert sha(Path(evidence['raw_response']).read_bytes())==evidence['raw_response_sha256']
for folder,close in [('rea-smm','021-close.json'),('rea-key-peim','007-close.json'),('rea-crypto','012-close.json')]:
    response=load('capsule/'+folder+'/responses/'+close)
    assert 'error' not in response and not response['result'].get('isError',False)

with zipfile.ZipFile(OLD) as z:
    old_manifest=json.loads(z.read('SHA256-MANIFEST.json'))
    assert set(z.namelist())==set(old_manifest)|{'SHA256-MANIFEST.json'}
    assert z.testzip() is None
    for name,entry in old_manifest.items():
        data=z.read(name)
        assert len(data)==entry['bytes'] and sha(data)==entry['sha256'],name
        if name=='01-TEST-USB/MZ790H.CAP': add('02-RC2-EXPERIMENTAL/MZ790H.CAP',data)
        elif name=='02-RECOVERY-USB/MZ790H.CAP': add('01-OFFICIAL-3107/MZ790H.CAP',data)
        elif name=='02-RECOVERY-USB/source.json': add('01-OFFICIAL-3107/source.json',data)
        elif name.startswith('03-DIAGNOSTIC/'): add(name,data)
        elif name.startswith('04-SOURCE/'): add(name.replace('04-SOURCE/','06-SOURCE/',1),data)
        elif name.startswith('05-REVIEW/'): add(name.replace('05-REVIEW/','05-PRIOR-REVIEW/20261103-REA/',1),data)
        elif name.startswith('06-PRIOR-EVIDENCE/'): add(name.replace('06-PRIOR-EVIDENCE/','05-PRIOR-REVIEW/earlier-evidence/',1),data)

official_sha=sha(items['01-OFFICIAL-3107/MZ790H.CAP'])
rc2_sha=sha(items['02-RC2-EXPERIMENTAL/MZ790H.CAP'])
assert official_sha==live['official_control']['sha256']==auth['files']['original']['sha256']
assert rc2_sha==live['candidate']['sha256']==auth['files']['rc2']['sha256']
pdf=P/'output/pdf/现场指导手册-HERO-IPMI-RC2.pdf'
assert sha(pdf.read_bytes())==manual['sha256']
add('00-START/现场指导手册-HERO-IPMI-RC2.pdf',pdf.read_bytes())
add('00-START/现场指导手册-HERO-IPMI-RC2.txt',(P/'现场指导手册-HERO-IPMI-RC2.txt').read_text(encoding='utf-8').encode('utf-8-sig'))

text('00-START/快速执行顺序.txt',f'''Z790 HERO IPMI / 现场验证包 F1 / 2026-11-04

先阅读同目录七页 PDF 手册。现场只需手册、CAP 与诊断工具，无需运行源码或安装 REA。
此包内仍是同字节 P5 RC2，不是新的已签名固件或已验收正式版。
本轮实机 EZ Flash 已拒绝 RC2；官方3107通过文件检查后已取消，没有刷写。
FlashBack 尚未执行。是否接受RC2、刷后启动和刷回恢复都必须现场验证。
现场无编程器及本板完整SPI备份；官方对照成功不能保证所有失败都能恢复。

准备两只 FAT32 / MBR / 单分区 U 盘，分别标记“官方3107”和“IPMI RC2”。
对应目录中 MZ790H.CAP 复制到各自 U 盘根目录。不要将同名文件混放。
官方: 01-OFFICIAL-3107/MZ790H.CAP
SHA-256: {official_sha}
RC2: 02-RC2-EXPERIMENTAL/MZ790H.CAP
SHA-256: {rc2_sha}
两份均为33,558,528字节，不能靠文件大小区分。

A：官方3107 FlashBack 对照；完成后开机核对型号、版本、页面和OS。
B：仅A通过后，按手册试RC2 FlashBack；控制器接受后会实际写入，不是只读检查。
C：先拍Advanced → IPMI五页自动状态；再做冷/热启动、OS和必要诊断。
D：若RC2确实写入，用官方盘刷回并核对启动，才能记录“恢复通过”。

按住FlashBack约3秒到开始闪烁后松开，等待灯熄灭。处理中不拔盘、不断电、不开机。
官方A失败就停；RC2很快常亮/无正常流程就记录并停，不删CAP头、不用强刷参数。
灯结束和显示3107均不能单独证明原生IPMI功能已生效。
RC2不能由EZ Flash更新，现场无须重复已完成的拒绝测试。

本版仅五页只读BMC状态；并无Creator完整可修改配置，也未合入R2传感器初始化。
ISO日志通过C二维码或R文字分页保存；可写U盘按L保存P5LOGxxx.TXT。
先留自动状态，再按诊断T；T后有数据不能替代自动初始化通过。
填写验证回报表，附灯态/耗时、Q-Code、首次页面和完整日志。
本轮远程结束状态：主机关机、虚拟介质已卸载、BMC已退出；以现场最新状态为准。
''')
text('00-START/验证回报表.txt','''Z790 HERO IPMI RC2 现场回报表
未知写“未知”，未做写“未测”，每个实际刷写过程独立记录。

操作者 / 日期时间（注明时区）：
主板完整型号：
开始前 BIOS / BMC 版本：
开始前能否进入 BIOS / OS：
已拍摄原有启动、存储、内存、风扇设置：
官方盘复制后 SHA-256：
RC2盘复制后 SHA-256：

A 官方 FlashBack 对照
是否实际执行：
按键开始时间 / 开始闪烁 / 熄灭时间：
灯态全过程与耗时：
首次启动等待时间 / Q-Code / 是否循环重启：
BIOS型号与版本 / 原有页面 / OS启动：
结果（通过 / 失败 / 未测）：
截图或录像文件名：

B RC2 FlashBack
是否实际执行（A失败不得继续）：
按键开始时间 / 开始闪烁 / 熄灭时间：
灯态全过程与耗时：
是快速拒绝，还是处理完成：
首次启动等待时间 / Q-Code / POST / BIOS / 循环重启：
结果（接受性和启动分别填写）：
截图或录像文件名：

C 原生 IPMI 功能（先自动，再诊断）
自动测试前是否已经启动诊断工具、按D/T或跑R2：
Advanced → IPMI 入口有无：
五页首次状态截图：
BMC自检 / 设备信息 / 固件版本：
Watchdog状态 / LAN地址 / SEL数量与首批记录：
与带外页面是否一致、差异：
各页能否返回：
热重启后结果 / 冷启动后结果 / OS启动：
如做诊断，启动方式（ISO / 可写USB）和按键先后：
D返回状态 / T返回状态 / T前后差异：
全部QR或TEXT页数 / P5LOG文件名：

D 从已写入的候选刷回官方
RC2此前是否确实写入：
是否实际执行官方刷回：
开始 / 结束时间 / 灯态 / 耗时：
刷回后型号 / 版本 / 新IPMI入口是否消失：
原有BIOS页面 / OS启动 / Q-Code：
恢复结果（通过 / 失败 / 未测 / 不适用）：
最终保留固件（官方3107 / RC2 / 未知）：
完整附件列表：
''')
text('00-START/SOURCE-LINKS.txt','''Primary references, consulted 2026-11-04

ASUS USB BIOS FlashBack: https://www.asus.com/support/faq/1038568/
ASUS EZ Flash: https://www.asus.com/support/faq/1012815/
HERO manual E21512 V3, section 2.2:
https://dlcdnets.asus.com/pub/ASUS/mb/LGA1700/ROG_MAXIMUS_Z790_HERO/E21512_ROG_MAXIMUS_Z790_HERO_UM_V3_WEB.pdf
HERO official BIOS support:
https://rog.asus.com/motherboards/rog-maximus/rog-maximus-z790-hero-model/helpdesk_bios/
REA repository: https://github.com/morluto/rea

Official operating instructions do not establish acceptance of unsigned/custom firmware.
Cryptographic, FIT and REA details: 04-CURRENT-EVIDENCE.
REA SKILL and retained earlier references: 05-PRIOR-REVIEW/20261103-REA/REA-SKILL.
The original firmware source metadata is in 01-OFFICIAL-3107/source.json.
''')
text('01-OFFICIAL-3107/用途.txt',f'官方对照 / 恢复固件，先执行手册阶段A。\n文件名 MZ790H.CAP\nSHA-256 {official_sha}\n官方CAP不是这块板的完整SPI备份。\n')
text('02-RC2-EXPERIMENTAL/先读说明.txt',f'实验固件P5 RC2，同上一包，未重新签名。\nSHA-256 {rc2_sha}\nEZ Flash已经实机拒绝。FlashBack是否接受和刷后启动均未验证。\n只有手册A通过后才进行B；控制器接受即实际写入。\n此包不是已验收正式版。五页只读状态，不含完整Creator写配置功能。\n')
text('03-DIAGNOSTIC/使用说明.txt','''此工具与上一轮实机预检的P5工具字节相同，标题P5 RC1属于正常。
虚拟光驱挂载HERO-IPMI-P5-PREFLIGHT.iso并从UEFI启动，或将USB目录内容复制到可写FAT32盘根目录。
先记录固件自动状态，诊断工具不安装或替换表单。
D读BMC；T只刷新精确匹配的P5原生字符串；L保存到可写启动USB。
C二维码；R文字；分页N/Enter下一页、P上一页、Esc返回；主菜单Q/Esc退出。
ISO只读，不能保存TXT。用KVM截取所有QR/文字页，退出前保留。
二维码可交回项目解析，decode_captures.py提供离线解码；现场无需安装Python。
官方未修改BIOS执行T返回NOT_FOUND属于预期；D成功只说明通信成功。
''')
add('03-DIAGNOSTIC/decode_captures.py',items['06-SOURCE/hero_ipmi_p5/decode_captures.py'])

# Current evidence is a bounded whitelist, never a browser-profile or network-session archive.
for name in ['live-image-check.json','manual-build.json','review-media.json']:
    add('04-CURRENT-EVIDENCE/'+name,(P/name).read_bytes())
for s in live['screenshots']:
    data=(A/'hero_ipmi_flash_live_20261104'/s['file']).read_bytes()
    assert len(data)==s['bytes'] and sha(data)==s['sha256']
    add('04-CURRENT-EVIDENCE/'+s['file'],data)
for sub in ['bootguard','capsule']:
    for f in sorted((P/sub).rglob('*')):
        if not f.is_file():continue
        rel=f.relative_to(P)
        if '__pycache__' in rel.parts:continue
        if f.name in {'tool-catalog.json','process.json','rea-stderr.log','stop-session','initialize.json'}:continue
        if f.suffix not in {'.json','.py','.efi','.pem','.bin','.txt','.c','.md','.log'}:continue
        add('04-CURRENT-EVIDENCE/'+rel.as_posix(),f.read_bytes())
for name in ['write_live_record.py','build_manual.py','build_field_package.py']:
    add('06-SOURCE/current-handoff/'+name,(P/name).read_bytes())

text('04-CURRENT-EVIDENCE/验证记录与剩余项.txt','''Z790 HERO / 3107 / IPMI P5 RC2 验证记录 - 2026-11-04

交付结论
本轮离线分析和EZ Flash对照已完成；新包F1仅整理证据和现场流程，CAP仍为同一RC2。
不能标记为“已验证可刷 / 正式版”。现场FlashBack接受性、原生自动加载、刷回恢复尚待执行。

1. 实机文件检查
目标HERO实际BIOS3107，14900KS，64GiB，ME16.1.38.2676，BMC1.3.13。
同一虚拟光驱ISO包含两份CAP；RC2报“Selected file is not a proper BIOS!”。
官方3107到达更新确认，选No取消，返回原BIOS。没有BIOS设置或固件写入。
主机已关闭，介质卸载、登录退出。见live-image-check.json及13张选定截图。
这个通用错误不等于已捕获运行中的精确失败分支；独立签名分析是另一条证据。

2. CAP签名和HERO自身验证链
AMI Aptio封装：0x1000头+32MiBROM；两层RSA2048/PSS/SHA256，MGF1-SHA256、salt8。
按ROM表中attrs & 0x200收集区域，保留表顺序，追加含终止项的ROM表。
原版证书层和固件层均通过。RC2保留同一头和证书，证书层通过、固件层摘要不匹配。
独立数学脚本与OpenSSL交叉核验一致。没有ASUS私钥、没有重新签名。
REA进一步确认HERO自身的密钥发布、CryptoSmm和SMM capsule验证代码；这些模块在原版与RC2中未改动。
该固件内链条不能代表板载独立FlashBack控制器；具体函数、偏移、证据与不确定项见capsule/hero_capsule_rea_review.json。

3. 启动认证边界
FIT地址0xFF090100，FIT及六个微码区域原版/候选相同。变更均在DXE容器范围。
对原版2123、候选2126个解压叶节点做了有界静态搜索，未找到ACM/KM/BPM及相应哈希文件。
未读取实机Boot Guard寄存器/熔丝或完整SPI；不能证明Boot Guard关闭、不能证明DXE不属于IBB。
缺少BPM时也不能验证实际IBB覆盖和摘要。未把静态阴性结果写成开机保证。

4. 保留的此前证据
上轮REA检查了DXE内层容器、Setup/SPF、AMITSE消费路径及驱动；具体记录在05-PRIOR-REVIEW。
同字节P5驱动RAM加载完成28条BMC只读查询，PCI位0→2→0恢复，能够返回原BIOS。
这些结果不等于RC2已经刷入；固件自动加载和五页原生UI尚未实机验收。
驱动本轮未改字节，因此沿用已有编译/协议策略/字符串发布检查，没有将重复测试冒作新实机结果。

5. 仍需现场完成
A 官方3107 FlashBack完整写入后正常开机，只验证健康板的官方通道。
B RC2是否接受及写后启动；拒绝即停止，不尝试强刷。
C Advanced→IPMI五页自动显示、冷/热启动及OS；先自动后D/T诊断。
D RC2确实写入后再刷官方并核对恢复；尚未写入时不把A成功当D通过。
以上步骤详见00-START手册和回报表，当前全部标为未测。

范围
现有RC2只包含五页只读BMC信息、watchdog状态、LAN和SEL快照；SEL最多16条原始记录。
LAN修改、watchdog写配置、SEL清除、LED同步、In-Band切换和R2传感器初始化均不在本版。
两份CAP使用3107基线，不能替其他型号使用。包内无BMC登录凭据、无自动刷写脚本。
''')
text('05-PRIOR-REVIEW/阅读顺序.txt','''此目录为保留的此前证据，不是2026-11-04现场FlashBack结果。
20261103-REA：容器/菜单/驱动REA分析、SKILL、源模块和响应。
earlier-evidence：RAM只读预检、旧RC1 EZ Flash对照及编译检查。
当前RC2 EZ Flash拒绝和签名分析位于04-CURRENT-EVIDENCE。
本包操作只按00-START新手册，不沿用旧包的刷写说明。
''')
index={
    'package_revision':'FIELD-VALIDATION-F1','date':'2026-11-04','firmware_revision':'P5 RC2 unchanged',
    'official_sha256':official_sha,'candidate_sha256':rc2_sha,
    'verified_prior_package_sha256':sha(OLD.read_bytes()),'prior_manifest_entries_verified':len(old_manifest),
    'current_results':{'ez_flash_rc2':'rejected','ez_flash_official':'accepted_to_confirmation_then_cancelled',
        'official_crypto':'both_valid','rc2_crypto':'firmware_signature_invalid',
        'rea_capsule_review':'capsule/hero_capsule_rea_review.json',
        'boot_guard_hardware_and_ibb':'unresolved','bios_written_this_session':False},
    'onsite_pending':['official_flashback_and_boot','candidate_flashback_and_boot','native_pages_automatic','cold_and_warm_boot','restore_from_candidate'],
    'final_remote_state':{'host':'off','media':'unmounted','bmc_session':'logged_out','browser':'closed'},
    'official_is_not_board_specific_spi_backup':True,'programmer_available':False,
    'manual_visual_qa':manual,
}
add('04-CURRENT-EVIDENCE/VERIFICATION-INDEX.json',(json.dumps(index,ensure_ascii=False,indent=2)+'\n').encode('utf-8'))
manifest={n:{'bytes':len(b),'sha256':sha(b)} for n,b in sorted(items.items())}
add('SHA256-MANIFEST.json',(json.dumps(manifest,ensure_ascii=False,indent=2)+'\n').encode('utf-8'))
STAGE.mkdir(exist_ok=True)
for name,data in items.items():
    target=STAGE/name
    target.parent.mkdir(parents=True,exist_ok=True)
    target.write_bytes(data)
with zipfile.ZipFile(OUT,'w',zipfile.ZIP_DEFLATED,compresslevel=8) as z:
    for name,data in sorted(items.items()):z.writestr(name,data)
with zipfile.ZipFile(OUT) as z:
    assert z.testzip() is None
    assert set(z.namelist())==set(items) and len(z.namelist())==len(set(z.namelist()))
    for name,expected in manifest.items():
        data=z.read(name)
        assert len(data)==expected['bytes'] and sha(data)==expected['sha256'],name
    assert sorted(n for n in z.namelist() if n.lower().endswith('.cap'))==['01-OFFICIAL-3107/MZ790H.CAP','02-RC2-EXPERIMENTAL/MZ790H.CAP']
result={'zip':str(OUT),'bytes':OUT.stat().st_size,'sha256':sha(OUT.read_bytes()),
        'manifest_entries_verified':len(manifest),'zip_crc_passed':True,'firmware_images_changed':False,
        'manual_pages':7,'live_flashback':'pending','prior_package_manifest_verified':len(old_manifest)}
(P/'field-package-result.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
OUT.with_suffix('.zip.sha256').write_text(result['sha256']+'  '+OUT.name+'\n',encoding='ascii')
print(json.dumps(result,ensure_ascii=False,indent=2))
