"""Index internal native12 integration without publishing a firmware release."""
from pathlib import Path
import hashlib,json,zipfile
HERE=Path(__file__).resolve().parent;N12=HERE.parent;CASE=HERE.parents[3];ROOT=CASE.parents[2]
OUT=HERE/'build/integration_native12_review';PROV=CASE/'review/flash_readiness/native_provider12_candidate'
FEEDBACK=CASE/'review/flash_readiness/save_feedback_review'
UI=CASE/'review/flash_readiness/native_provider12_ui_simulation'
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
read=lambda p:json.loads(p.read_text(encoding='utf8'))
m=read(OUT/'integration_manifest.json');v=read(OUT/'verification.json');pr=read(PROV/'provider_review.json');g=read(N12/'native12_review.json')
assert v['input_manifest_sha256']==sha(OUT/'integration_manifest.json')and v['candidate_sha256']==m['candidate_sha256']==sha(Path(m['candidate_path']))
assert v['status']=='PASS_INTERNAL_UNSIGNED_STRUCTURE_ONLY_NOT_RELEASE_READY'
assert pr['efi']['sha256']==m['provider_sha256']and sha(PROV/'provider_review.json')==m['provider_review_sha256']
assert sha(N12/'native12_review.json')==m['native12_review_sha256']
assert sha(FEEDBACK/'native12_feedback_verification.json')==m['independent_native12_save_feedback_sha256']
pm=read(PROV/'candidate_manifest.json');ui=read(UI/'latest_result.json');correction=read(UI/'visual_observation_correction.json')
assert len(pm['artifacts'])==107 and sha(PROV/'candidate_manifest.json')==m['provider_manifest_sha256']
assert ui['provider_sha256']==m['provider_sha256']and ui['bound_modules']==m['guard_module_sha256']and sum(x['checks']for x in ui['boot_reports'])==169
inputs=[]
def add(p,name):
 p=Path(p);assert p.is_file();inputs.append((p,name))
for p in sorted((HERE/'source').glob('*')):
 if p.is_file():add(p,'guard/source/'+p.name)
for n in ['build_guard.py','verify_guard.py','verify_structure.py','verify_memory.py','verify_native_save.py','verify_native_commit.py','verify_hotkeys.py','verify_defaults.py','verify_native_history.py','verify_defaults_entries.py','size_container.py','verify_sizing_extract.py','build_internal_native12.py','verify_internal_native12.py','finalize_internal_native12.py']:
 add(HERE/n,'guard/'+n)
for n in ['build.json','guard_regression.json','structure_verification.json','memory_verification.json','native_save_verification.json','native_commit_verification.json','hotkey_verification.json','defaults_verification.json','native_history_verification.json','defaults_entries_verification.json','OriginalAMITSESetupData.json','OriginalHiiDatabase.json']:
 add(HERE/'build'/n,'guard/evidence/'+n)
for n in ['sizing_report.json','extract_verification.json','inner-ffs-inventory.json']:add(HERE/'build/sizing_only'/n,'guard/sizing-only/'+n)
for n in ['native12_review.json','implementation_baseline.json','save_scope_verification.json','verify_save_scope.py','native_harness.py','counterexamples.json','verify_counterexamples.py','reset_call_chain.json','freeze_reset_evidence.py','initializer_callers.json','inspect_init_callers.py','original_paths.json','inspect_paths.py','freeze_native12.py']:
 add(N12/n,'native12/'+n)
for n in ['native12_feedback_verification.json','replay_native12_feedback.py','replay_ui_feedback.py','input-native-harness.py','native_save_callers.json','inspect_native.py']:
 add(FEEDBACK/n,'independent-save-feedback/'+n)
for p in sorted((PROV/'source').glob('*')):
 if p.is_file():add(p,'provider/source/'+p.name)
for n in ['provider_review.json','candidate_manifest.json','guard_binding.json','ovmf_load_result.json','source_origins.json']:
 add(PROV/n,'provider/'+n)
for row in pr['tests']:
 p=Path(row['path']);assert sha(p)==row['sha256'];add(p,'provider/evidence/'+p.name)
for n in ['bind_guard.py','build_driver.py','build_state.py','verify_state.py','verify_native_owner.py','verify_native_hii.py','verify_native_entry.py','verify_native_joint.py','verify_ebs_boundaries.py','verify_active_hii.py','run_ovmf_load.py','ovmf_load.c','finalize_review.py']:
 add(PROV/n,'provider/'+n)
manifest_by_path={str(Path(x['path']).resolve()):x for x in pm['artifacts']}
ui_files=[UI/n for n in ['persist_ui.c','run_persist_ui.py','freeze_run.py','verify_raw_screens.py','raw_screenshot_verification.json','visual_observation_correction.json']]
for boot in ui['boot_reports']:
 ui_files.append(Path(boot['debug_log']))
 ui_files.extend(Path(s['path'])for s in boot['screenshots'])
for p in ui_files:
 assert p.resolve().is_relative_to(UI.resolve())and sha(p)==manifest_by_path[str(p.resolve())]['sha256']
 add(p,'provider-ui/'+p.relative_to(UI).as_posix())
for n in ['inject_ovmf.py','build_asus_review.py','verify_asus_review.py']:add(CASE/'lab'/n,'shared-tools/'+n)
add(CASE/'review/flash_readiness/verify_capsule_static.py','shared-tools/verify_capsule_static.py')
add(CASE/'driver/verify_adapter.py','shared-tools/verify_adapter.py')
for n in ['integration_manifest.json','verification.json','uefiextract.stdout.txt','uefiextract.stderr.txt']:add(OUT/n,'integration/'+n)
assert len({n for p,n in inputs})==len(inputs)
inventory=[{'archive_path':n,'bytes':p.stat().st_size,'sha256':sha(p)}for p,n in inputs]
archive=OUT/'INTERNAL-source-and-evidence.zip';assert not archive.exists(),'Immutable archive already exists'
with zipfile.ZipFile(archive,'w',zipfile.ZIP_DEFLATED,compresslevel=9)as z:
 for p,n in inputs:z.writestr(n,p.read_bytes())
 z.writestr('archive-inventory.json',json.dumps(inventory,indent=2)+'\n')
with zipfile.ZipFile(archive)as z:
 for row in inventory:assert hashlib.sha256(z.read(row['archive_path'])).hexdigest()==row['sha256']
readme='''ASUS Pro WS W790E-SAGE SE BIOS 1904：NATIVE12 内部集成审查映像。

INTERNAL / UNSIGNED / NOT_RELEASE_READY。不是正式版，也不是可直接刷写包。

本次保留已有独立密码与静态门禁策略，在 AMITSE 增加第12处保存守卫。被保护值的本地提交返回 ACCESS_DENIED 时，原厂保存函数完成原有流程后返回失败。真实原厂机器码的六个已识别保存入口均已离线验证拒绝后不新设退出/重启标志；同值保存及不受保护的内存字段仍可保存。并未增加初始化或缺失变量创建放行例外。

已纠正前期“初始化保存”用语：5F688 已建立的外部调用来自原厂 Redfish ResetBios=true 链。没有证据将其等同清 CMOS 或正常冷启动初始化。直接 defaults 协议6286C会改变被保护RAM缓存，但已测后续通用提交仍被门禁拒绝。

整片镜像按原版1904复核所有字节范围、22个ROM区、FFS/FV校验和、长度和顺序。独立UEFIExtract重提取两个目标模块和密码provider，均与本次实际测试二进制精确相等。其他620个原提取FFS保持不变。只在原压缩容器分配范围和原有外层空白尾部写入新内容，没有静默移动其他外层文件。

仍未验收：ASUS完整图形BIOS、直接Del真实冷启动调度、真实主板NVRAM、缺安全页时恢复、运行时权限、厂商更新接受和可恢复刷写。Save-Stay仍会清除原状态字节83578，原保存流程还清835C9并执行OEM辅助函数；其完整视觉/缓存语义尚未证明，不能称图形反馈全部修复。非保护变量可在拒绝保护变量的同次保存中提交，不承诺事务回滚。

OVMF的标准LoadImage/provider及虚拟存储测试不等于启动完整ASUS主板；OEM入口未作为完整固件启动。PE节标志也不证明实际W^X。原厂固件内容签名对修改后的映像失效，保留的证书签名仍有效。未重新签名、未更改验签机制、未连接设备、未上传刷写，旧NATIVE11/EXP02/EXP03及根目录包均保持原样。

本次精确provider已通过两个独立OVMF进程的169项真实虚拟变量存储、标准键盘密码操作和屏幕/光标恢复检查；全部107项源码/对象/运行记录绑定已核验。先前“密码提示标题缺字”的观察已被原始PNG/PPM像素证伪，没有因此加入额外刷新代码。两项更正均已独立留存证据。

请结合integration_review.json、verification.json及显式源码/证据归档审查。归档不包含BMC凭据、原始HTTP会话或旧交付状态；重建仍需原始CAP、提取数据和本地工具。
'''
(OUT/'README-INTERNAL-NOT-RELEASE.txt').write_text(readme,encoding='utf8')
r={'status':'INTERNAL_NATIVE12_INTEGRATION_REVIEW_COMPLETE_NOT_RELEASE_READY','target':{'board':'ASUS Pro WS W790E-SAGE SE','original_BIOS':'1904'},
 'candidate':{'path':m['candidate_path'],'bytes':m['candidate_bytes'],'sha256':m['candidate_sha256']},'guard_module_sha256':m['guard_module_sha256'],'provider_sha256':m['provider_sha256'],
 'build_manifest':{'path':str(OUT/'integration_manifest.json'),'sha256':sha(OUT/'integration_manifest.json')},'independent_verification':{'path':str(OUT/'verification.json'),'sha256':sha(OUT/'verification.json'),'status':v['status']},
 'native_guard_review':{'path':str(N12/'native12_review.json'),'sha256':sha(N12/'native12_review.json')},'independent_six_save_callers':{'path':str(FEEDBACK/'native12_feedback_verification.json'),'sha256':sha(FEEDBACK/'native12_feedback_verification.json'),'cases':24,'return_or_exit_interventions':0},
 'OEM_reset_source_evidence':{'path':str(N12/'reset_call_chain.json'),'sha256':sha(N12/'reset_call_chain.json'),'physical_CMOS_trigger_established':False},
 'compiled_save_scope':{'path':str(N12/'save_scope_verification.json'),'sha256':sha(N12/'save_scope_verification.json'),'checks':47,'initialization_authorization_added':False},
 'provider_manifest':{'path':str(PROV/'candidate_manifest.json'),'sha256':sha(PROV/'candidate_manifest.json'),'artifacts_verified':107},
 'two_process_OVMF_password_persistence':{'path':str(UI/'latest_result.json'),'sha256':sha(UI/'latest_result.json'),'checks':169,'processes':2,'actual_ASUS_GUI':False},
 'prior_visual_inference_correction':{'path':str(UI/'visual_observation_correction.json'),'sha256':sha(UI/'visual_observation_correction.json'),'status':correction['status'],'extra_console_refresh_patch_included':False},
 'source_archive':{'path':str(archive),'sha256':sha(archive),'files':len(inventory),'whole_workspace_BMC_credentials_or_HTTP_capture_included':False},
 'readme_sha256':sha(OUT/'README-INTERNAL-NOT-RELEASE.txt'),'capsule_firmware_signature_valid':False,'capsule_certificate_signature_valid':True,'full_image_structure_verified':True,
 'ASUS_boot_verified':False,'flash_release_ready':False,'not_accepted':m['not_accepted'],'no_previous_hardware_pass_inherited':True,'no_upload_or_flash':True,'no_frozen_native11_or_EXP02_EXP03_mutation':True,'finalizer_sha256':sha(Path(__file__))}
(OUT/'integration_review.json').write_text(json.dumps(r,indent=2)+'\n')
print(json.dumps({'status':r['status'],'candidate_sha256':m['candidate_sha256'],'review_sha256':sha(OUT/'integration_review.json'),'archive_files':len(inventory)},indent=2))
