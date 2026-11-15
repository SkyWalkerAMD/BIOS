"""Package the independently frozen field candidate; no device or network access."""
from pathlib import Path
import hashlib
import json
import zipfile

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
LIVE = ROOT / 'analysis/hero_ipmi_complete_live_20261108'
COLLECTOR = ROOT / 'analysis/hero_ipmi_p6_20261104/collector'
LABEL = 'HERO-3107-IPMI-RC5-C03-FLASHBACK-20261108'
BUILD_ID = 'RC5-IPMI-ONLY-R4-S21S-CANDIDATE03'
CAP_SHA = '7a21f28c5a805ea29d651524b2ec2e05925252ff0799b71251583d99e1d53624'
OFFICIAL_SHA = 'e900f164cbabec0088ea8f1dd3c0ad932f32a5e14412be814d06cce3a4210f6a'
FREEZE_SHA = '42d2d27c7a99f3c8d8555bc6c39ea9dc7fd09d6cfb6df55a5d13defda61f1761'
ISO_SHA = '8c4c3cbd0df0d5ca56042aa643b9bc4d090358de764b5d7ac10fe18b17617c94'
HARDWARE_SHA = '7133485ca073e689322ca48b2af887e4fc0ed7b7f8353212e224dcf0f1f1c591'
AUDIT_SHA = '144d0fec2c2760b1d20d6f5941388e489ad4f9aedeB4f5c88b44ba7cefee408f'.lower()
FINAL_REVIEW_SHA = 'a79ff878194b87f5272517b3c3262f4d8a41efa968a6ad4dcaada1bd5f932e4c'

def sha(data):
    return hashlib.sha256(data).hexdigest()

def read_checked(path, expected=None, size=None):
    path = path.resolve()
    if not path.is_relative_to(ROOT):
        raise ValueError('Source outside workspace')
    data = path.read_bytes()
    if expected is not None and sha(data) != expected:
        raise ValueError('Changed source: ' + str(path))
    if size is not None and len(data) != size:
        raise ValueError('Changed size: ' + str(path))
    return data

frozen = json.loads(read_checked(HERE/'FROZEN-CANDIDATE03.json', FREEZE_SHA))
for item in frozen['own_files'] + frozen['external_evidence']:
    read_checked(ROOT/item['path'], item['sha256'], item['bytes'])
if frozen['candidate']['sha256'] != CAP_SHA or not frozen['no_i3_i5_inventory_publisher']:
    raise ValueError('Wrong frozen candidate or scope')
if frozen['final_CAP_flashback_acceptance_verified'] or frozen['native_first_setupenter_timer_verified']:
    raise ValueError('Unexpected evidence scope; revise handbook rather than reusing it')
audit_path = ROOT/'analysis/hero_rc5_r4_s21s_independent_review_20261108/independent-byte-audit.json'
audit = json.loads(read_checked(audit_path, AUDIT_SHA))
if not audit['passed'] or audit['candidate_sha256'] != CAP_SHA or audit['unchanged_ffs_count'] != 543:
    raise ValueError('Missing exact CAP independent validation')
final_review_path = audit_path.parent/'final-review.json'
final_review = json.loads(read_checked(final_review_path, FINAL_REVIEW_SHA))
if not final_review['passed'] or not final_review['field_candidate_packaging_allowed']:
    raise ValueError('Final review does not allow field packaging')
hardware_path = ROOT/'analysis/hero_p6_s21s_independent_review_20261108/hardware-verification.json'
hardware = json.loads(read_checked(hardware_path, HARDWARE_SHA))
if not all(hardware[k] for k in ('passed_first_real_afterboot_cycle','passed_repeated_real_afterboot_no_replay','can_prepare_field_candidate')):
    raise ValueError('Missing real hardware-stage evidence')

delivery = HERE/'delivery'
out = delivery/LABEL
zip_path = delivery/(LABEL+'.zip')
if out.exists() or zip_path.exists():
    raise ValueError('Preserve an existing delivery; select a new version instead of overwriting it')
out.mkdir(parents=True)
sources = []

def write(relative, data, source=None):
    target = out/relative
    if target.exists() or not target.resolve().is_relative_to(out.resolve()):
        raise ValueError('Duplicate or unsafe package member: ' + str(relative))
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(data)
    if source is not None:
        sources.append({'package_path':target.relative_to(out).as_posix(),
                        'workspace_source':str(source.relative_to(ROOT)).replace('\\','/'),
                        'bytes':len(data),'sha256':sha(data)})

def copy(source, relative, expected=None, size=None):
    write(relative, read_checked(source, expected, size), source)

copy(ROOT/frozen['candidate']['path'], '01-IPMI-RC5-C03/MZ790H.CAP', CAP_SHA, 33558528)
copy(ROOT/'analysis/hero_3107_official/ROG-MAXIMUS-Z790-HERO-ASUS-3107.CAP',
     '90-ASUS-3107-RECOVERY/MZ790H.CAP', OFFICIAL_SHA, 33558528)
copy(COLLECTOR/'HERO-P6-RC4-READONLY-LOG.iso', '02-LOG-CAPTURE/HERO-P6-RC4-READONLY-LOG.iso', ISO_SHA, 8493056)
for name in ('decode_captures.py','USB/HERO_P6.TAG','USB/EFI/BOOT/BOOTX64.EFI'):
    copy(COLLECTOR/name, '02-LOG-CAPTURE/'+name)

manual = (HERE/'现场手册模板.txt').read_text(encoding='utf-8')
manual = manual.replace('{CAP_SHA256}', CAP_SHA).replace('{BUILD_ID}', BUILD_ID)
if '{CAP_' in manual or '{BUILD_' in manual or CAP_SHA not in manual:
    raise ValueError('Unresolved handbook placeholder')
write('现场刷写与验证手册.txt', manual.encode('utf-8'))
write('先读我.txt', (
    '本包为Z790 HERO 3107 IPMI RC5-C03现场验证候选。\n'
    '先读“现场刷写与验证手册.txt”。刷写候选位于01-IPMI-RC5-C03，官方恢复位于90-ASUS-3107-RECOVERY。\n'
    '两个目录均有MZ790H.CAP，但内容不同；一次只复制一个到U盘根目录并核对SHA-256。\n'
    'R4传感器与S21S返回后的自动读取已分别通过实机内存加载测试。\n'
    '最终CAP尚未实刷：首次冷启动菜单、F10配置写入、FlashBack接受与官方恢复仍待现场验收。\n'
    '本包不含早期失败候选、RAM驱动加载器或独立库存发布器。\n'
).encode('utf-8'))

copies = [
    (HERE/'FROZEN-CANDIDATE03.json','frozen-candidate.json',FREEZE_SHA),
    (HERE/'本轮核心验证摘要-供现场手册引用.txt','核心验证摘要.txt',None),
    (HERE/'inventory-exclusion.json','inventory-exclusion.json',None),
    (HERE/'builder-guard-tests-ipmi-only-s21s.json','builder-guard-tests.json',None),
    (HERE/BUILD_ID/'build-report.json','build-report.json',None),
    (HERE/BUILD_ID/'independent-container-verification.json','container-verification.json',None),
    (audit_path,'independent-byte-audit.json',AUDIT_SHA),
    (final_review_path,'final-review.json',FINAL_REVIEW_SHA),
    (audit_path.parent/'verification-regressions.json','verification-regressions.json','a2f85d105e0fb55f6202be4f01ef00f04ae5f9542016c0f1e5e578e3d1c5f431'),
    (audit_path.parent/'independent-inventory-exclusion.json','independent-inventory-exclusion.json','8518012ec993cf45490e722cd703d04b70a1cedb68b5bda32adc16ea1206a220'),
    (hardware_path,'s21s-hardware-verification.json',HARDWARE_SHA),
    (LIVE/'r4-fresh-hardware-verification.json','r4-fresh-hardware-verification.json','d0f967170dd055300647d6813d4e7004890176da85aa9e06dd77cf4e7c708600'),
    (LIVE/'r4-warm-hardware-verification.json','r4-warm-hardware-verification.json',None),
]
for source, name, expected in copies:
    copy(source,'03-VERIFICATION/'+name,expected)
for item in hardware['captures']:
    source = ROOT/item['path']
    copy(source,'03-VERIFICATION/logs/'+source.name,item['sha256'],item['bytes'])
    capture = LIVE/'captures'/source.stem
    for path in sorted(capture.iterdir()):
        if path.suffix.lower() in ('.png','.bin','.json'):
            copy(path,'03-VERIFICATION/qr/'+source.stem+'/'+path.name)
for name in ('hero71-r4-fresh-first.TXT','hero71-r4-fresh-second.TXT','hero71-r4-warm-second.TXT'):
    copy(LIVE/name,'03-VERIFICATION/logs/'+name)
for item in hardware['photos']:
    source = ROOT/item['path']
    copy(source,'03-VERIFICATION/screens/'+source.name,item['sha256'],item['bytes'])

write('03-VERIFICATION/source-map.json',(json.dumps(sources,ensure_ascii=False,indent=2)+'\n').encode('utf-8'))
write('03-VERIFICATION/证据阅读说明.txt', (
    '本目录保留本次候选的结构复核、R4传感器测试、S21S自动刷新测试、原生日志与画面。\n'
    'source-map.json将包内文件对应到项目中的原始路径；报告中的analysis路径是原工作区引用。\n'
    '完整构建器、模拟测试工具链及所有历史材料未放入现场包；可在原项目相应目录重现。\n'
    'S21S的35张二维码原图及帧数据均已包含；三份完整TXT和CRC对应各自采集。\n'
    '实机运行的是与CAP内逐字节相同的独立PE驱动，以内存方式加载；不是最终CAP实刷结果。\n'
    '不能将只读GET成功、页面正常显示或默认保持，解释为全部配置写入已经验证。\n'
).encode('utf-8'))
rows=[]
for path in sorted(p for p in out.rglob('*') if p.is_file()):
    data=path.read_bytes();rows.append({'path':path.relative_to(out).as_posix(),'bytes':len(data),'sha256':sha(data)})
manifest={
    'package':LABEL,'build_id':BUILD_ID,'status':'FIELD_VALIDATION_CANDIDATE',
    'board':'ROG MAXIMUS Z790 HERO','base_bios':'3107','cap_sha256':CAP_SHA,
    'official_recovery_sha256':OFFICIAL_SHA,'flashing_method_for_field_trial':'USB BIOS FlashBack',
    'hardware_verified':['R4 exact PE fresh/warm real BDS sensor initialization','S21S exact PE real AfterBoot native display and repeated-return no replay','Same-boot continuation to CentOS7 login'],
    'not_yet_verified':['Exact CAP FlashBack acceptance','Native early DXE/first SetupEnter timer','Full F10 save/reboot/BMC configuration writes','Official rollback from this CAP'],
    'inventory_publisher_included':False,'runtime_test_loader_included':False,
    'files':rows,
}
write('manifest.json',(json.dumps(manifest,ensure_ascii=False,indent=2)+'\n').encode('utf-8'))
all_before_sums=sorted(p for p in out.rglob('*') if p.is_file())
write('SHA256SUMS.txt',''.join(sha(p.read_bytes())+'  '+p.relative_to(out).as_posix()+'\n' for p in all_before_sums).encode('utf-8'))
members=sorted(p for p in out.rglob('*') if p.is_file())
if len({p.relative_to(out).as_posix().lower() for p in members}) != len(members):
    raise ValueError('Case-colliding filenames')
with zipfile.ZipFile(zip_path,'x',compression=zipfile.ZIP_DEFLATED,compresslevel=9) as z:
    for p in members:
        name=LABEL+'/'+p.relative_to(out).as_posix()
        info=zipfile.ZipInfo(name,date_time=(2026,11,8,0,0,0))
        info.compress_type=zipfile.ZIP_DEFLATED;info.external_attr=0o100644<<16
        z.writestr(info,p.read_bytes(),compress_type=zipfile.ZIP_DEFLATED,compresslevel=9)
with zipfile.ZipFile(zip_path) as z:
    if z.testzip() is not None or len(z.namelist()) != len(members):
        raise ValueError('ZIP integrity failure')
    for p in members:
        if z.read(LABEL+'/'+p.relative_to(out).as_posix()) != p.read_bytes():
            raise ValueError('ZIP member changed')
    if sha(z.read(LABEL+'/01-IPMI-RC5-C03/MZ790H.CAP')) != CAP_SHA:
        raise ValueError('Packaged candidate mismatch')
    if sha(z.read(LABEL+'/90-ASUS-3107-RECOVERY/MZ790H.CAP')) != OFFICIAL_SHA:
        raise ValueError('Packaged recovery mismatch')
result={'package':str(zip_path),'bytes':zip_path.stat().st_size,'sha256':sha(zip_path.read_bytes()),
        'files':len(members),'all_zip_members_read_back_equal':True,'cap_sha256':CAP_SHA,
        'manual':str(out/'现场刷写与验证手册.txt'),'native_flash_performed':False}
(delivery/'DELIVERY.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
print(json.dumps(result,ensure_ascii=False,indent=2))
