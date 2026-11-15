"""Create the printable field guide and matching plain-text operator handoff."""
from pathlib import Path
from xml.sax.saxutils import escape
import json,hashlib
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.lib.styles import ParagraphStyle
from reportlab.platypus import Paragraph,Table,TableStyle
from pypdf import PdfReader

P=Path(__file__).resolve().parent
ANALYSIS=P.parent
OFFICIAL_SHA=hashlib.sha256((ANALYSIS/'hero_3107_official/ROG-MAXIMUS-Z790-HERO-ASUS-3107.CAP').read_bytes()).hexdigest()
CANDIDATE_SHA=hashlib.sha256((ANALYSIS/'hero_ipmi_p5_rea_review_20261103/rc2/HERO-3107-IPMI-P5-RC2-UNSIGNED.CAP').read_bytes()).hexdigest()
LIVE=json.loads((P/'live-image-check.json').read_text(encoding='utf-8'))
assert OFFICIAL_SHA==LIVE['official_control']['sha256']
assert CANDIDATE_SHA==LIVE['candidate']['sha256']
OUT=P/'output/pdf'
OUT.mkdir(parents=True,exist_ok=True)
PDF=OUT/'现场指导手册-HERO-IPMI-RC2.pdf'
FONT='C:/Windows/Fonts/simhei.ttf'
pdfmetrics.registerFont(TTFont('GuideCJK',FONT))
pdfmetrics.registerFont(TTFont('GuideMono','C:/Windows/Fonts/consola.ttf'))
W,H=A4;LEFT=45;RIGHT=W-45;WIDTH=RIGHT-LEFT
INK=colors.HexColor('#202c39');BLUE=colors.HexColor('#244e72');GRAY=colors.HexColor('#64748b')
ORANGE=colors.HexColor('#a3471e');PALE=colors.HexColor('#edf3f8')
styles={
 'body':ParagraphStyle('body',fontName='GuideCJK',fontSize=10.5,leading=16.3,textColor=INK,wordWrap='CJK'),
 'small':ParagraphStyle('small',fontName='GuideCJK',fontSize=8.7,leading=13.3,textColor=GRAY,wordWrap='CJK'),
 'note':ParagraphStyle('note',fontName='GuideCJK',fontSize=10.3,leading=16,textColor=ORANGE,wordWrap='CJK'),
 'mono':ParagraphStyle('mono',fontName='GuideMono',fontSize=8.8,leading=13,textColor=INK),
}
c=canvas.Canvas(str(PDF),pagesize=A4,pageCompression=1)
c.setTitle('Z790 HERO IPMI RC2 现场验证指导手册')
c.setAuthor('HERO IPMI 项目')
page=0;y=0
plain=[]

def page_start(title,subtitle):
 global page,y
 if page:c.showPage()
 page+=1
 c.setFillColor(BLUE);c.rect(0,H-14,W,14,fill=1,stroke=0)
 c.setFont('GuideCJK',9);c.setFillColor(GRAY);c.drawString(LEFT,H-39,'HERO IPMI / 现场验证包 F1 / 2026-11-04')
 c.setFont('GuideCJK',20);c.setFillColor(INK);c.drawString(LEFT,H-73,title)
 c.setFont('GuideCJK',10);c.setFillColor(GRAY);c.drawString(LEFT,H-95,subtitle)
 c.setStrokeColor(colors.HexColor('#ccd6df'));c.line(LEFT,42,RIGHT,42)
 c.setFont('GuideCJK',8);c.setFillColor(GRAY);c.drawString(LEFT,28,'镜像仍为 P5 RC2；未完成 FlashBack / 刷后启动验证')
 c.drawRightString(RIGHT,28,f'{page} / 7')
 y=H-118
 plain.append('\n'+title+'\n'+subtitle+'\n')

def p(text,style='body',gap=9):
 global y
 para=Paragraph(escape(text).replace('\n','<br/>'),styles[style])
 _,height=para.wrap(WIDTH,1000)
 if y-height<58:raise RuntimeError(f'Page {page} overflow: {text[:70]}')
 para.drawOn(c,LEFT,y-height);y-=height+gap
 plain.append(text+'\n')

def h(text):
 global y
 y-=5
 c.setFont('GuideCJK',12.5);c.setFillColor(BLUE);c.drawString(LEFT,y-12,text);y-=24
 plain.append('\n'+text+'\n')

def table(rows,widths):
 global y
 cells=[[Paragraph(escape(str(x)).replace('\n','<br/>'),styles['small']) for x in row] for row in rows]
 t=Table(cells,colWidths=widths,hAlign='LEFT')
 t.setStyle(TableStyle([('BACKGROUND',(0,0),(-1,0),PALE),('VALIGN',(0,0),(-1,-1),'TOP'),
  ('GRID',(0,0),(-1,-1),.45,colors.HexColor('#cbd5e1')),('LEFTPADDING',(0,0),(-1,-1),8),
  ('RIGHTPADDING',(0,0),(-1,-1),8),('TOPPADDING',(0,0),(-1,-1),8),('BOTTOMPADDING',(0,0),(-1,-1),8)]))
 _,height=t.wrap(WIDTH,1000)
 if y-height<58:raise RuntimeError(f'Page {page} table overflow')
 t.drawOn(c,LEFT,y-height);y-=height+12
 for row in rows:plain.append(' | '.join(str(x) for x in row)+'\n')

page_start('开始前先读这一页','适用：ROG MAXIMUS Z790 HERO / 官方 BIOS 3107 / 扩展卡 BMC 1.3.13')
p('本包用于现场验证。RC2 已被 EZ Flash 实机拒绝；FlashBack 是否接受、刷入后能否启动及能否恢复仍未验证。不要把本包当作已通过实机验收的正式版。','note')
table([['项目','已经确认','尚未确认'],
 ['固件结构','独立 FV/FFS、资源、重定位检查通过','修改镜像的实际启动'],
 ['CAP 签名','原版通过；RC2 固件签名失败','FlashBack 控制器接受策略'],
 ['EZ Flash','RC2 拒绝；同一 ISO 的官方 3107 通过文件检查','没有执行更新写入'],
 ['读取驱动','相同驱动此前 RAM 加载完成28条只读查询','固件自动加载和原生菜单显示'],
 ['恢复','官方恢复 CAP 已核对来源和散列','本板 FlashBack 完整写入及刷回验证']],
 [91,207,WIDTH-298])
h('按顺序执行')
p('A. 官方 3107 FlashBack 对照并开机核对 → B. RC2 FlashBack 试刷 → C. 原生页面与启动验收 → D. 刷回官方 3107 并核对恢复。')
p('A 没通过，不做 B。B 被拒绝，不尝试强刷。进入写入过程后不要拔盘、断电、开机或按清 CMOS。')
p('现场没有 SPI 编程器，也没有本板完整 SPI 备份。官方 CAP 和 FlashBack 不能保证覆盖所有故障恢复；此风险在试刷前仍然存在。','note')
p('本轮远程结束状态：主机关机、虚拟光驱已卸载、BMC 已退出登录；本轮未写 BIOS。现场实际状态若已变化，以现场观察为准。','small')

page_start('准备两只 U 盘','先核对主板型号，再按用途分别复制同名 CAP')
h('01-OFFICIAL-3107：官方对照 / 恢复盘')
p('把此目录的 MZ790H.CAP 放到第一只 U 盘根目录，标签写“官方 3107”。文件大小 33,558,528 字节。')
p(OFFICIAL_SHA[:32]+'\n'+OFFICIAL_SHA[32:],'mono')
h('02-RC2-EXPERIMENTAL：RC2 试验盘')
p('把此目录的 MZ790H.CAP 放到第二只 U 盘根目录，标签写“IPMI RC2”。文件大小同样为 33,558,528 字节。')
p(CANDIDATE_SHA[:32]+'\n'+CANDIDATE_SHA[32:],'mono')
p('上面的散列为同一行 SHA-256 的分行显示。两份文件不能靠名称或大小区分；绝对不要放进同一只盘。两份均已按 HERO 的 FlashBack 文件名命名。','note')
h('介质与设置')
p('使用 FAT32、MBR、单分区 U 盘；格式化会清空原有内容。只将对应 CAP 复制到根目录，不要把 ZIP 文件直接放入后开始刷写。')
p('刷写可能重置 BIOS 设置。先用照片记录需要保留的启动、存储、风扇和内存设置；不要依赖跨版本导入设置文件来证明恢复成功。')
p('复制后检查 U 盘文件散列。以下 E: 只是示例，必须换成实际 U 盘盘符：','small')
p("Get-FileHash -Algorithm SHA256 -LiteralPath 'E:\\MZ790H.CAP'",'mono')
p('03-DIAGNOSTIC 是启动诊断工具，与上述两个 FlashBack 盘不同。现场无需执行源码、分析脚本或安装 REA。','small')

page_start('阶段 A：验证官方 FlashBack 通道','使用第一只“官方 3107”盘；此步骤会实际重写官方固件')
p('1. 确认当前是目标 HERO 主板，保存必要设置。正常关闭主机，保留电源供电；不要让操作系统正在运行时开始。')
p('2. 将官方盘插入背板明确标有 BIOS FlashBack 的专用 USB 接口。不要把 Clear CMOS 按钮当作 FlashBack 按钮。')
p('3. 按住 BIOS FlashBack 按钮约 3 秒，直到指示灯开始闪烁，然后松开。记录开始时间。')
p('4. 等待指示灯结束并熄灭。通常需要数分钟，不能用固定倒计时作为断电依据。处理中不拔盘、不断电、不开机、不按清 CMOS。','note')
p('5. 记录结束时间、闪烁时长与最终灯态。若几秒后常亮或始终不闪，记录为“未正常开始 / 未接受”，检查文件散列、文件名、介质和专用接口；不要进入阶段 B。')
p('6. 灯已熄灭后再启动，重复按 Del 或 F2 进入 BIOS。首次启动可能有内存训练，不连续强制重启。核对型号为 ROG MAXIMUS Z790 HERO，版本为 3107。')
p('7. 保存 Main 页面照片或 KVM 截图；确认原有 BIOS 页面可正常切换，操作系统能正常启动。再正常关机，记录 A 的结果。')
h('A 通过的条件')
p('官方盘完成正常灯态流程，且随后可进入正确型号 / 版本 BIOS、原有页面和操作系统。只看到灯熄灭，不够判定开机通过。')
p('A 验证的是当前健康主板的官方 FlashBack 通道，不等于已经验证从损坏固件恢复。若 A 失败，停在这里并提交记录。','note')
p('操作依据：ASUS USB BIOS FlashBack FAQ 和 HERO 用户手册。见第7页链接。','small')

page_start('阶段 B：RC2 的实际接受与启动','仅在 A 通过后进行；当前 RC2 的固件签名已确认无效')
p('RC2 和上一交付包的 CAP 字节完全相同。本次新增的是验证记录和操作手册，没有通过改版本号或改文件名让签名变有效。')
p('1. 确认官方恢复盘已备好，主机已关机并保留电源供电。核对第二只“IPMI RC2”盘的完整 SHA-256。')
p('2. 换用 RC2 盘插入同一专用接口，按 FlashBack 约3秒。此操作不是只读检查：如果控制器接受文件，会进入实际写入。','note')
p('3. 记录灯态与时长。仍在闪烁时不要中断。很快常亮 / 无闪烁按拒绝或流程失败记录；停止，不尝试删 CAP 头、换其他板型文件或使用强刷参数。')
p('4. 若灯正常熄灭，再启动并进入 BIOS。记录是否出现 POST / BIOS、Q-Code 和是否循环重启；先保存第一轮画面。')
p('5. Main 仍显示 3107 是预期现象，不能据此判断 RC2 已加载。需要下一页所述的 Advanced → IPMI 入口和实际数值作为功能证据。')
p('6. 若无法进入 BIOS，先确保 FlashBack 写入已结束，再按第6页恢复。首次内存训练未结束时不要连续重启；无法判断时先记录 Q-Code 和等待过程。')
h('结果要分开记录')
table([['观察','能说明什么'],['灯态正常结束','控制器结束了本次处理；仍要核对启动'],
 ['可进入 BIOS','候选在这台机器上至少完成了本次启动'],
 ['出现 IPMI 页面并自动有数值','才是原生集成功能的运行证据'],
 ['被 FlashBack 拒绝','本条路径未跑通；不据此宣称固件已刷入']], [145,WIDTH-145])

page_start('阶段 C：页面、启动与日志验收','先记录自动显示结果，再运行诊断；避免把手动刷新算成自动通过')
p('进入 BIOS 后先等待约60秒，再打开 Advanced → IPMI。依次保存总页、OS Watchdog Timer、System Event Log、BMC network configuration、View System Event Log。')
p('核对 BMC 自检、版本、网络地址、看门狗状态与带外页面一致；SEL 数量可能因本次启动新增事件。查看所有子页能否返回，再测试热重启、冷启动与操作系统启动。')
p('本版只有五页只读状态，读取为一次快照，SEL 最多显示前16条原始记录。没有网络修改、看门狗配置、SEL清除、LED同步或In-Band类型切换；也未合入 R2 传感器 OEM 初始化。无需为这些只读页面按 F10 保存。','note')
h('出现 Not queried、无入口或显示异常时')
p('先保存自动状态截图。能回到 Boot 时，挂载 03-DIAGNOSTIC/HERO-IPMI-P5-PREFLIGHT.iso 从 UEFI 启动，或把 USB 子目录的内容复制到可写 FAT32 启动盘。')
table([['按键','作用'],['D','读取 BMC，输出摘要和日志'],['T','刷新精确匹配的 P5 菜单字符串；T后有数值不算自动初始化通过'],
 ['C / R','C为二维码日志，R为文字日志；N下一页、P上一页、Esc返回'],['L','保存到可写启动 U 盘的 P5LOG000.TXT 等文件'],['Q / Esc','退出；退出或重启前先保存所有日志截图']], [65,WIDTH-65])
p('虚拟光驱只读，不能保存 TXT，使用 C/R 经 KVM 收集完整页码。工具标题仍写 P5 RC1：这是经上一轮实机验证的同字节工具，RC2 只调整 CAP 内驱动位置。原版 BIOS 执行 T 返回 NOT_FOUND 属于预期。','small')

page_start('阶段 D：恢复官方与回报结果','完整的恢复验收，需要实际刷回并再次检查启动')
p('如果 RC2 已写入，要完成恢复路径验证，需要再次使用“官方 3107”盘，按阶段 A 的关机、专用接口、约3秒按键及等待灯熄灭步骤刷回。')
p('刷回后核对正确型号 / 3107、原生 IPMI 新入口已消失、原有 BIOS 页面和操作系统启动正常。只有这一步实际完成，才把“从候选刷回原版”记为通过。')
p('如果 RC2 被拒绝且从未写入，不能把此前 A 的成功当作“从候选恢复成功”。若官方盘也无法完成或无法启动，停止反复试刷，转现场维修 / SPI 编程器处理。','note')
p('若 RC2 功能和刷回测试都通过，并希望最终保留 RC2，可再执行 B/C，同时保留官方恢复盘。包中没有自动刷写脚本。')
h('回报时至少包含')
table([['项目','填写内容'],['身份','操作者、时间、主板型号、原BIOS版本、复制后两份CAP散列'],
 ['官方对照 A','是否实际执行；灯态和耗时；是否进入正确BIOS及操作系统'],
 ['候选 B','是否实际执行；拒绝或完成；Q-Code、POST、BIOS和循环重启情况'],
 ['功能 C','五页首次自动状态截图；冷启动、热重启、OS结果；是否运行过D/T'],
 ['恢复 D','是否实际刷回；灯态和耗时；恢复后的BIOS及OS结果'],
 ['附件','完整KVM截图 / 录像、全部二维码或文字页、P5LOGxxx.TXT']], [90,WIDTH-90])
p('可直接填写 00-START/验证回报表.txt。不知道的项目写“未测 / 未知”，不要因为灯熄灭或版本仍为3107就代填全部通过。','small')

page_start('本轮证据与包内文件','现场验证包 F1；固件镜像仍为 P5 RC2，未冒充新签名版本')
table([['目录','用途'],['00-START','本手册、快速顺序、验证回报表'],['01-OFFICIAL-3107','官方3107对照 / 恢复 CAP'],
 ['02-RC2-EXPERIMENTAL','RC2试验 CAP，签名无效及实机接受性记录'],['03-DIAGNOSTIC','ISO、可写U盘工具、日志解码脚本'],
 ['04-CURRENT-EVIDENCE','本轮EZ Flash截图、CAP/OpenSSL及Boot Guard报告、REA补充分析'],
 ['05-PRIOR-REVIEW / 06-SOURCE','上轮REA证据、同字节驱动预检和源码留档'],['SHA256-MANIFEST.json','包内文件大小及散列']], [155,WIDTH-155])
p('2026-11-04 实机：同一 ISO 中，RC2 被 EZ Flash 拒绝，官方3107到达更新确认；已选择 No 取消。未写 BIOS，已退出登录和卸载介质，主机关机。')
p('密码学：HERO CAP 的原版两层 RSA-PSS 签名通过；RC2 证书层通过、固件层摘要不匹配。独立 OpenSSL 复核一致。EZ Flash 的通用错误未给出内部细分原因。')
p('启动认证：原版与 RC2 的 FIT 和六个微码区域相同，未找到 ACM/KM/BPM 清单。此有限静态搜索不能证明实机 Boot Guard 关闭，也不能证明刷后一定能启动。')
p('完整记录以 04-CURRENT-EVIDENCE 为准。上轮28条BMC读取通过，只覆盖RAM加载的相同驱动，不能替代刷后自动加载和菜单验收。','small')
h('官方参考')
p('ASUS FlashBack 操作说明：\nhttps://www.asus.com/support/faq/1038568/','small')
p('ASUS EZ Flash 操作说明：\nhttps://www.asus.com/support/faq/1012815/','small')
p('HERO 用户手册：ASUS E21512，V3，章节2.2。官方说明针对原版固件，不承诺接受或恢复自定义镜像。完整链接保存在 SOURCE-LINKS.txt。','small')
assert page==7
c.save()
reader=PdfReader(str(PDF))
assert len(reader.pages)==7
texts=[x.extract_text() or '' for x in reader.pages]
for i,text in enumerate(texts,1):assert len(text)>120,(i,len(text))
assert '阶段 D' in texts[5] and 'RC2' in texts[0]
(P/'现场指导手册-HERO-IPMI-RC2.txt').write_text('\n'.join(plain),encoding='utf-8')
result=dict(file=str(PDF),pages=7,bytes=PDF.stat().st_size,sha256=hashlib.sha256(PDF.read_bytes()).hexdigest(),
            text_extract_passed=True,visual_render_review_pending=True)
(P/'manual-build.json').write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8')
print(json.dumps(result,indent=2))
