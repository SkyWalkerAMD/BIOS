"""Index the completed internal structural review; never publish a release."""
from pathlib import Path
import hashlib,json,zipfile
HERE=Path(__file__).resolve().parent;CASE=HERE.parents[3];ROOT=CASE.parents[2]
OUT=HERE/'build/integration_native11_review';PROV=CASE/'review/flash_readiness/native_provider_candidate';sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
m=json.loads((OUT/'integration_manifest.json').read_text());v=json.loads((OUT/'verification.json').read_text());provider=json.loads((PROV/'provider_review.json').read_text())
assert v['input_manifest_sha256']==sha(OUT/'integration_manifest.json')and v['candidate_sha256']==m['candidate_sha256']==sha(Path(m['candidate_path']))
assert provider['efi']['sha256']==m['provider_sha256']and sha(PROV/'provider_review.json')==m['provider_review_sha256']
assert v['status']=='PASS_INTERNAL_UNSIGNED_STRUCTURE_ONLY_NOT_RELEASE_READY'
inputs=[]
def add(path,name):
 path=Path(path);assert path.is_file();inputs.append((path,name))
for path in sorted((HERE/'source').glob('*')):
 if path.is_file():add(path,'guard/source/'+path.name)
for name in ['build_guard.py','verify_guard.py','verify_structure.py','verify_memory.py','verify_exit_counterexample.py','verify_native_save.py','verify_native_commit.py','verify_hotkeys.py','verify_defaults.py','verify_native_history.py','verify_defaults_entries.py','freeze_review.py','inspect_defaults_protocol.py','size_container.py','verify_sizing_extract.py','build_internal_native11.py','verify_internal_native11.py','finalize_internal_native11.py']:
 add(HERE/name,'guard/'+name)
for name in ['build.json','native11_review.json','guard_regression.json','structure_verification.json','memory_verification.json','exit_counterexample.json','native_save_verification.json','native_commit_verification.json','hotkey_verification.json','defaults_verification.json','native_history_verification.json','defaults_entries_verification.json','defaults_protocol_inventory.json','OriginalAMITSESetupData.json']:
 add(HERE/'build'/name,'guard/evidence/'+name)
for name in ['sizing_report.json','extract_verification.json','inner-ffs-inventory.json']:add(HERE/'build/sizing_only'/name,'guard/sizing-only/'+name)
for path in sorted((PROV/'source').glob('*')):
 if path.is_file():add(path,'provider/source/'+path.name)
for name in ['provider_review.json','candidate_manifest.json','guard_binding.json','ovmf_load_result.json']:add(PROV/name,'provider/'+name)
for row in provider['tests']:
 path=Path(row['path']);assert sha(path)==row['sha256'];add(path,'provider/evidence/'+path.name)
for name in ['bind_guard.py','build_driver.py','build_state.py','finalize_review.py']:add(PROV/name,'provider/'+name)
for name in ['inject_ovmf.py','build_asus_review.py','verify_asus_review.py']:add(CASE/'lab'/name,'shared-tools/'+name)
add(CASE/'review/flash_readiness/verify_capsule_static.py','shared-tools/verify_capsule_static.py')
for name in ['integration_manifest.json','verification.json','uefiextract.stdout.txt','uefiextract.stderr.txt']:add(OUT/name,'integration/'+name)
# Exact explicit files only: no BMC source tree, credentials, HTTP sessions,
# device dumps, whole-workspace glob, or previous delivery-state JSON.
assert len({n for p,n in inputs})==len(inputs)
inventory=[{'archive_path':n,'bytes':p.stat().st_size,'sha256':sha(p)}for p,n in inputs]
archive=OUT/'INTERNAL-source-and-evidence.zip'
assert not archive.exists(),'Immutable source archive already exists'
with zipfile.ZipFile(archive,'w',compression=zipfile.ZIP_DEFLATED,compresslevel=9)as z:
 for path,name in inputs:z.writestr(name,path.read_bytes())
 z.writestr('archive-inventory.json',json.dumps(inventory,indent=2)+'\n')
with zipfile.ZipFile(archive)as z:
 for row in inventory:assert hashlib.sha256(z.read(row['archive_path'])).hexdigest()==row['sha256']
readme='''内部集成审查映像：ASUS Pro WS W790E-SAGE SE，原版 BIOS 1904。

INTERNAL / UNSIGNED / NOT_RELEASE_READY。此文件不得当作正式版或直接刷写包。

本次把 11 处静态门禁集成到原生 Setup / AMITSE，并加入单独的密码 provider。
没有 provider 或未解锁时，正常已验证的 Ai Tweaker 入口会关闭；Exit 的普通保存和放弃动作保留。独立密码的设置、修改和清除代码已实现。

完整镜像的字节范围、22 个 ROM 区、FFS/FV 校验和及独立 UEFIExtract 提取均已核验。两份目标模块和 provider 重新提取后与对应测试二进制完全一致。其余 620 个原始提取 FFS 保持不变；其他外层文件的偏移未移动。

仍未验收：ASUS 实机冷启动及直接 Del 完整图形 BIOS；缺失变量/CMOS 恢复时的正常初始化与保存；直接协议 defaults 方法的正常 UI 可达性；OEM 忽略拒绝状态时的保存提示；缺少安全 Main 或损坏历史状态的安全退出；真实主板 NVRAM 持久保存；运行时页面权限；厂商更新接受与可恢复刷写。

OVMF 只执行了两份 OEM 映像的标准 LoadImage，没有启动 OEM 入口；执行了 provider 入口和退出启动服务测试。不能把这些结果当成 ASUS 整机启动通过。实际 OVMF 页面仍显示 RWX，PE 标志不等于运行时 W^X。

保留的原厂 capsule 证书签名仍有效，但修改后固件内容的原厂 RSA-PSS 签名失效。没有重新签名，没有改变验签或保护机制，没有上传或刷写，没有修改旧 EXP02 / EXP03 或根目录工具包。

阅读 integration_review.json、verification.json 和 INTERNAL-source-and-evidence.zip 可复核结论及其限制。源归档只供审查；重建还需要原版 CAP、原始提取数据和本地工具。
'''
(OUT/'README-INTERNAL-NOT-RELEASE.txt').write_text(readme,encoding='utf8')
r={'status':'INTERNAL_NATIVE11_INTEGRATION_REVIEW_COMPLETE_NOT_RELEASE_READY','target':{'board':'ASUS Pro WS W790E-SAGE SE','original_BIOS':'1904'},'candidate':{'path':m['candidate_path'],'bytes':m['candidate_bytes'],'sha256':m['candidate_sha256']},'modules':m['guard_module_sha256'],'provider_sha256':m['provider_sha256'],'build_manifest':{'path':str(OUT/'integration_manifest.json'),'sha256':sha(OUT/'integration_manifest.json')},'independent_verification':{'path':str(OUT/'verification.json'),'sha256':sha(OUT/'verification.json'),'status':v['status']},'native_guard_review':{'path':str(HERE/'build/native11_review.json'),'sha256':sha(HERE/'build/native11_review.json')},'supplemental_defaults_entry_evidence':{'path':str(HERE/'build/defaults_entries_verification.json'),'sha256':sha(HERE/'build/defaults_entries_verification.json')},'source_archive':{'path':str(archive),'sha256':sha(archive),'files':len(inventory),'whole_workspace_or_BMC_capture_included':False},'readme_sha256':sha(OUT/'README-INTERNAL-NOT-RELEASE.txt'),'capsule_firmware_signature_valid':False,'capsule_certificate_signature_valid':True,'full_image_structure_verified':True,'ASUS_boot_verified':False,'flash_release_ready':False,'not_accepted':m['not_accepted'],'no_previous_hardware_pass_inherited':True,'no_upload_or_flash':True,'no_production_or_EXP02_EXP03_mutation':True,'finalizer_sha256':sha(Path(__file__))}
(OUT/'integration_review.json').write_text(json.dumps(r,indent=2)+'\n',encoding='utf8');print(json.dumps({'status':r['status'],'candidate_sha256':m['candidate_sha256'],'review_sha256':sha(OUT/'integration_review.json'),'archive_files':len(inventory)},indent=2))
