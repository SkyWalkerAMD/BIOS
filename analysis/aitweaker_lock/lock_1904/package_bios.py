"""Publish the validated EXP01 BIOS bytes as a labelled experimental CAP.

No network, device access, flash command, authentication bypass or signing.
The original Aptio capsule header is retained; its signature is not valid for
the modified payload. All validation reports must identify this exact driver.
"""
from pathlib import Path
import datetime, hashlib, json, shutil, zipfile

HERE=Path(__file__).resolve().parent
BASE=HERE.parent
ROOT=BASE.parents[1]
VERSION='EXP01'
DRIVER_SHA='eb4d9b43bc3fd88eef9b7b8570f636ea1c1c56cc36ae0693ebd1dfa7bdd71fb3'
CAP_SHA='fd5c6ffca92e66335c5da1839940435fa1abdb5eb81246c6293380a6ac9c6478'
SOURCE_SHA='03e4330430b2510d5e9e5c9868ca64c730844992b82c6a272b815aef3d20bf29'
NAME=f'Pro-WS-W790-ACE-1904-AiTweakerLock-{VERSION}-UNSIGNED.CAP'
OUT=ROOT/f'W790-ACE-1904-AiTweaker密码BIOS-{VERSION}'

def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def read(path):return json.loads(path.read_text(encoding='utf8'))
def save(path,data):path.write_text(json.dumps(data,ensure_ascii=False,indent=2)+'\n',encoding='utf8')

source=BASE/'official_W790_ACE_1904/W790_ACE_1904/Pro-WS-W790-ACE-ASUS-1904.CAP'
candidate=HERE/'lab/asus_review/W790-ACE-1904-lock.review.bin'
driver=HERE/'driver/build/AiTweakerLock1904.efi'
assert sha(source)==SOURCE_SHA and sha(candidate)==CAP_SHA and sha(driver)==DRIVER_SHA
assert source.stat().st_size==candidate.stat().st_size==0x4001000
assert source.read_bytes()[:4096]==candidate.read_bytes()[:4096]
assert source.read_bytes()!=candidate.read_bytes()
build=read(HERE/'driver/build/build.json')
for name,digest in build['sources'].items():assert sha(HERE/name)==digest
for name,digest in build.get('external_sources',{}).items():assert sha(ROOT/name)==digest

reports={
 'firmware_structure':HERE/'lab/asus_review/verification.json',
 'policy':HERE/'driver/build/policy_test.json',
 'adapter':HERE/'driver/build/adapter_emulation.json',
 'entropy':HERE/'driver/build/entropy_test.json',
 'hii_abi':HERE/'driver/build/hii_abi_test.json',
 'uefi_integration':HERE/'driver/build/vm_integration.json',
}
evidence={name:read(path) for name,path in reports.items()}
for name,r in evidence.items():
    assert r.get('driver_sha256',r.get('driver_efi_sha256'))==DRIVER_SHA,name
    assert r.get('status')=='PASS' or r.get('passed') is True or r.get('all_passed') is True,name
assert evidence['firmware_structure']['candidate_sha256']==CAP_SHA
vm=evidence['uefi_integration'];boots=[b for g in vm['groups'] for b in g['boots']]
assert len(boots)==6 and all(b['passed'] for b in boots)
assert sum(b['checks'] for b in boots)==368
revision=read(HERE/'review/driver_revision.json')
assert revision['driver_sha256']==DRIVER_SHA and revision['production_sources_changed']==['driver/efi.h','driver/hii.c']
review=read(HERE/'review/review_summary.json')
assert review['driver_sha256']==DRIVER_SHA and review['candidate_sha256']==CAP_SHA

OUT.mkdir(exist_ok=True)
cap=OUT/NAME
if cap.exists():assert sha(cap)==CAP_SHA,'Never reuse EXP01 for different BIOS bytes'
else:shutil.copyfile(candidate,cap)
assert sha(cap)==CAP_SHA
verify_dir=OUT/'验证';verify_dir.mkdir(exist_ok=True)
for name,path in reports.items():shutil.copyfile(path,verify_dir/(name+'.json'))
shutil.copyfile(HERE/'review/driver_revision.json',verify_dir/'driver_revision.json')
shutil.copyfile(HERE/'remote_172_20_2_209/hardware_summary.json',verify_dir/'P5基线实机结果.json')
shutil.copyfile(ROOT/'W790-ACE-1904-独立密码锁-离线验证报告.html',OUT/'完整验证报告.html')

readme=f'''ASUS Pro WS W790-ACE / 1904 — Ai Tweaker 独立密码 BIOS {VERSION}

文件：{NAME}
这是完整的修改版 BIOS Capsule，已将密码驱动加入固件卷。
基础版本仍为官方 1904；{VERSION} 是本修改包版本号，不改写原厂版本字段。
仅适配 Pro WS W790-ACE 1904；不适用于 W790E SAGE SE、W890E SAGE SE 或 ACE 2003。

包含的功能
1. Security 新增 Ai Tweaker Password（设置/修改）与 Clear Ai Tweaker Password（清除）。
   先前实测的原厂文本界面入口为 Main → Security。
2. 独立密码由用户自行设置，不预置密码。长度为 8–128 个可打印 ASCII 字符。
3. 每个 BIOS 会话首次进入 Ai Tweaker 等受保护入口时要求密码；正确解锁后该会话内不重复询问。
4. 修改和清除要求当前密码；清除后关闭保护。首次未设置时保持锁定，需先设置密码。
5. 正式驱动使用独立非易失 UEFI 变量保存加盐验证记录，不保存明文密码。
   本 CAP 不包含 P5 的 RAM-only 测试存储回调，也不依赖从虚拟光驱运行工具。

验证结果
本版通过 6 次 OVMF 冷启动、368 项集成检查；30 个入口适配用例、
6,355 项策略断言、10 个取熵用例和 8 个 HII 回调 ABI 用例通过。
独立 UEFIExtract 检查确认插入模块与最终 EFI 完全一致；除重压缩容器外，
631 个原有 FFS 文件逐字节保留，原版 CAP 未改变。
P5 基线曾在 W790-ACE 1904 实机通过密码管理、会话和初始入口的免刷测试。
本版额外修正了 HII 回调输出类型（UINT32 → UINTN）；本版二进制尚未再次实机运行。

发布状态
这是实验版修改映像，没有重新取得华硕有效签名；扩展名 CAP 不表示 EZ Flash、
FlashBack 或 BMC 更新器会接受它。原 Capsule 头仍在，但原签名不再认证修改后的负载。
尚未完成整包刷写启动、真实 ASUS 自动调度、直接 Del/F2、完整图形/EZ/搜索入口，
以及实体 NVRAM 跨重启/恢复默认值的验证。当前不能标为可直接刷写的正式发行版。
本轮只在本地生成文件，没有连接主机、刷写固件或修改机器上的密码。
当前仅有 BMC 虚拟光驱和 KVM 的恢复条件未改变；本包没有刷写程序或自动刷写脚本。

文件校验
CAP 字节数：{cap.stat().st_size:,}
CAP SHA-256：{CAP_SHA}
密码驱动 SHA-256：{DRIVER_SHA}
官方原版 CAP SHA-256：{SOURCE_SHA}
同目录 SHA256SUMS.txt 和 manifest.json 可核对包内所有文件。

阅读顺序：本说明 → 完整验证报告.html → 验证目录。
详细源码、REA 定位和完整日志另保存在工作区的“W790-ACE-1904-独立密码锁-离线审查包.zip”。
'''
(OUT/'说明-先读.txt').write_text(readme,encoding='utf8')
files=sorted(p for p in OUT.rglob('*') if p.is_file() and p.name not in {'manifest.json','SHA256SUMS.txt'})
manifest={
 'format_version':1,'release':VERSION,'generated_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),
 'target':'ASUS Pro WS W790-ACE BIOS 1904','status':'EXPERIMENTAL_MODIFIED_BIOS_NOT_FLASH_VALIDATED',
 'bios_file':NAME,'capsule_bytes':cap.stat().st_size,'capsule_sha256':CAP_SHA,
 'driver_sha256':DRIVER_SHA,'source_capsule_sha256':SOURCE_SHA,
 'driver_embedded_in_dxe_firmware_volume':True,'runtime_load_from_usb_required':False,
 'persistent_credential_implementation':'NV + BootServices UEFI variable; salted PBKDF2-HMAC-SHA256 verifier; no preset password',
 'signature_status':'ORIGINAL_SIGNATURE_NOT_VALID_FOR_MODIFIED_PAYLOAD',
 'vendor_signing_performed':False,'flashing_performed':False,'current_binary_hardware_tested':False,
 'automatic_asus_dispatch_verified':False,'persistent_hardware_deployment_complete':False,
 'baseline_hardware_driver_sha256':revision['baseline_driver_sha256'],
 'validation':{'uefi_cold_boots':6,'uefi_checks':368,'adapter_cases':30,'policy_assertions':6355,'entropy_cases':10,'hii_abi_cases':8,'independent_firmware_structure':'PASS'},
 'files':{p.relative_to(OUT).as_posix():{'bytes':p.stat().st_size,'sha256':sha(p)} for p in files},
}
save(OUT/'manifest.json',manifest)
files.append(OUT/'manifest.json')
(OUT/'SHA256SUMS.txt').write_text(''.join(f'{sha(p)}  {p.relative_to(OUT).as_posix()}\n' for p in sorted(files)),encoding='utf8')
files.append(OUT/'SHA256SUMS.txt')
archive=OUT.with_suffix('.zip')
with zipfile.ZipFile(archive,'w',zipfile.ZIP_DEFLATED,compresslevel=6) as z:
    for p in files:z.write(p,p.relative_to(OUT).as_posix())
with zipfile.ZipFile(archive) as z:
    assert z.testzip() is None
    for p in files:assert hashlib.sha256(z.read(p.relative_to(OUT).as_posix())).hexdigest()==sha(p)
    assert hashlib.sha256(z.read(NAME)).hexdigest()==CAP_SHA
assert sha(source)==SOURCE_SHA
delivery={'status':manifest['status'],'directory':str(OUT),'capsule':str(cap),'capsule_sha256':CAP_SHA,'zip':str(archive),'zip_sha256':sha(archive),'zip_bytes':archive.stat().st_size,'files_verified':len(files),'original_capsule_unchanged':True,'flashing_performed':False}
save(HERE/'bios_delivery.json',delivery)
for path in [BASE/'requirements.json',BASE/'delivery.json']:
    data=read(path);data['experimental_bios_release']=delivery
    data['password_lock_fully_delivered']=False
    save(path,data)
print(json.dumps(delivery,ensure_ascii=True,indent=2))
