"""Freeze this independent analysis, or verify it without changing anything."""
from pathlib import Path
import hashlib,json,sys
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent;D04=HERE.parent
ROOT=next(p for p in HERE.parents if (p/'tools/pydeps').is_dir())
HW=ROOT/'analysis/aitweaker_lock/lock_sage_1904/remote_172_20_2_162'
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
def row(p):return {'path':p.relative_to(ROOT).as_posix(),'bytes':p.stat().st_size,'sha256':sha(p)}
def write(p,obj):p.write_text(json.dumps(obj,ensure_ascii=False,indent=2)+'\n',encoding='utf8')
manifest_path=HERE/'independent_manifest.json'
if '--verify-only'in sys.argv:
 m=json.loads(manifest_path.read_text(encoding='utf8'))
 for r in m['artifacts']:
  p=ROOT/r['path'];assert p.stat().st_size==r['bytes']and sha(p)==r['sha256'],r['path']
 print(json.dumps({'status':'PASS_VERIFY_ONLY','bindings':len(m['artifacts']),'manifest_sha256':sha(manifest_path)}));raise SystemExit
assert not manifest_path.exists(),'Frozen output exists; use --verify-only or new sibling review.'
proposal=D04/'diagnostic_design09';snapshot=HERE/'proposal_snapshot';snapshot.mkdir(exist_ok=True)
for name in ['diagnostic09.h','schema_contract.json','diagnostic_plan.json','repeat_request_counterexample.json','verify_repeat_request.py','write_design.py']:
 (snapshot/name).write_bytes((proposal/name).read_bytes())
assert sha(snapshot/'diagnostic09.h')=='3cf976a0e3d90bdd813f24bfe1702fb67286e66b9f06150ff4c5e6ee72c05cdc'
assert sha(snapshot/'schema_contract.json')=='f46c724d8fa3cf61034e493f2834ba584a3f31a0d464df7a70b4317084a7c3c9'
schema={
 'status':'DESIGN_DIRECTION_ACCEPTABLE_SUBJECT_TO_IMPLEMENTATION_CHECKS_NOT_EXECUTABLE_APPROVAL',
 'inputs':[row(snapshot/x)for x in ['diagnostic09.h','schema_contract.json','diagnostic_plan.json']],
 'layout':{'owned_state_bytes':4096,'public_prefix_unchanged':32,'diagnostic_start':64,'diagnostic_bytes':576,'diagnostic_end_exclusive':640,'header_bytes':64,'record_bytes':256,'first_state_offset':128,'request_state_offset':384},
 'accepted_contract':['Owned RAM only; unchanged classification, return values, firmware-call count/order and unknown refusal.','Caller-local trace scratch; primary failing field retained, redirect sink absent, first denial separate from the exact current Request.','Direct FFE2 has its own explicit origin; pending requests cannot be overwritten by reentry.','Only existing UNCONFIGURED prompt gains six bounded lines; no new keys, forced exit, native flag mutation, credential collection or setter.'],
 'implementation_requirements_sent_to_author':['Commit/counter/flags publication and reader access need atomic acquire/release or explicit equivalent compiler/CPU ordering. Nonblocking writer CAS alone does not make plain double reads reliable.','owner_reason/status must identify whether page/control ownership supplied the primary failure; incidental canonical enumeration errors must not overwrite it.','At kind4 control-owner failure, IFR has not been validated/read: opcode/question/store fields must be unavailable, not populated by following a new pointer. Only already validated fixed control header scalars may be recorded.','A newly increased Request sequence after a key can establish a later request; identical sequence/screen cannot prove that key was consumed.','Contention, stale pending, overflow and torn snapshots must make current diagnostics unavailable without changing the guard decision.'],
 'scope':'Proposal/header review only. The later diagnostic_guard09/provider15 implementation and root displayed100B decoder are not reviewed or accepted by this report.'
}
write(HERE/'schema_design_review.json',schema)
external=[];manifest_checks=[]
for rel,expected,base in [
 ('static_chrome_candidate07/candidate_manifest.json','bb3227b7dd77d259d8a5eeaadf3c69e5b997d0fd8c741d4746bdc455a69169a8',ROOT),
 ('provider14_chrome07/local_candidate_manifest.json','150ae9aaba738a2c70f3075d741f4875f0c9f26ce8006ca83eafd71c5e9e7019',D04),
 ('ram_transaction08/ram_candidate_manifest.json','7f08d975710179f88f953636b1da72db34ebd0c41ef04447bdf40b296a599e96',D04),
]:
 p=D04/rel;assert sha(p)==expected;doc=json.loads(p.read_text(encoding='utf8'))
 for r in doc['artifacts']:
  target=base/r['path'];assert target.stat().st_size==r['bytes']and sha(target)==r['sha256'],str(target)
  external.append(target)
 external.append(p);manifest_checks.append({'manifest':row(p),'verified_bindings':len(doc['artifacts'])})
for name in ['screen-376-current.png','screen-377-current.png','screen-378-current.png']:
 assert sha(HW/name)=='503b195245166a3eba8673aa6bd83b530583bfe7d65db16ceb1cfe287c447e72'
 external.append(HW/name)
external.extend([HW/'hardware-native13-ram-test08-1793715646283-8c2b8643/hardware-log.txt',
 HW/'native-test11-key-1793715715877-68d82412-intent.json',HW/'native-test11-key-1793715715877-68d82412-result.json',
 D04.parent/'boot_context/AMITSE.original.efi',D04/'provider14_chrome07/source/ui.c',D04/'provider14_chrome07/source/hii.c',
 D04/'native_unwind_review08/independent_review.json',D04/'native_unwind_review08/independent_manifest.json'])
tests=[]
for report,script,count in [('request_classification.json','verify_request_classification.py',13),('kind4_source_transition.json','verify_native_kind4_transition.py',3),('kind4_navigation_tail.json','verify_kind4_navigation_tail.py',8)]:
 doc=json.loads((HERE/report).read_text(encoding='utf8'));assert doc['cases']==count and doc['source_sha256']==sha(HERE/script)
 tests.append({'report':row(HERE/report),'cases':count,'script':row(HERE/script)})
report={
 'status':'FROZEN_INDEPENDENT_REQUEST_CLASSIFICATION_AND_MENU_PATH_REVIEW_NOT_HARDWARE_CAUSE',
 'release_ready':False,'device_actions':False,
 'physical_claim':'376/377/378 are identical captured UNCONFIGURED provider-message screens. No actual failed page/control record was captured. A single ESC and unchanged image do not distinguish no key, acknowledged repeat, hold or exception.',
 'frozen_identities':{'guard':'2aef4bfca4ecb31631c60f9ee01cc2480a5782169524620a502ae0cf2e295efa','provider':'495fe43ffa8ebb685c1346501a08c2d2932bc94d62809ab01b3f019d33029630','app':'e0793175f78b6488c8222b65f0d5321d97e881bd06dca033a314d3fa8d307486'},
 'conclusions_zh':[
  '提示对应P14未配置的Request分支，不能证明当前页就是Ai Tweaker；保护页和未知分类均可请求。',
  '真实kind4构造提供AMITSE字符串HII、type14、vtable6D6F0；冻结07 generic owner缺少ConfigAccess时拒绝。显式foreign page模型仍被此frame判unknown，两次poll均Request。这是强诊断线索，尚非实机定因。',
  'kind4是带15C44回调的菜单，不可套用静态字幕例外。171D4晚期更新HII会影响分类时序。',
  '真实Page.Input后续导航分派可拒绝已知Setup保护form并恢复旧index，但不会回滚15C44已清空的history。',
  '未知/不一致目标或pending更新存在比下一poll更早的工作边界：FORM_OPEN action3与29AE4。实际callback正文仍为模型，未证明OC写或绕过。',
  '诊断09设计可继续实现，必须满足原子发布、当前Request首因和unavailable字段规则；此报告不接受尚未独审的后续编译产物。'],
 'tests':tests,'verified_frozen_manifests':manifest_checks,
 'verified_binding_sum_not_unique_files':sum(x['verified_bindings']for x in manifest_checks),
 'harness_corrections':['Inherited ChromeVM page5 was Setup-owned despite a foreign label. First observation and failure are preserved; final tests explicitly assert foreign owner0. Frozen old reports were not edited.','Initial tail harness registered its Request hook twice, causing a double model return and emulator fault. Removed the duplicate hook; final actual instruction cases pass. This was a harness defect, not a firmware defect.'],
 'limits':['Actual native selected constructors/helpers/input/selection/Page.Input tail and frozen guard instructions execute in Unicorn. HII/allocator/provider, memory predicates, key decode, history/lifecycle/queue bodies are explicitly modeled as recorded in each test.','No complete ASUS browser boot/render, new diagnostic executable, original callback side effect, native password validation, direct-Del startup integration, SPI backup, flash trust or recovery acceptance.','Known no-safe-page exit gap remains; no unknown allowance, native field or RuntimeServices mutation, new installer, variable write or hardware operation was performed.']
}
write(HERE/'independent_review.json',report)
paths=set(p.resolve()for p in external)
paths.update(p.resolve()for p in HERE.rglob('*')if p.is_file()and '__pycache__'not in p.parts and p.name!='independent_manifest.json')
artifacts=[row(p)for p in sorted(paths,key=lambda x:str(x).lower())]
write(manifest_path,{'status':'FROZEN_INDEPENDENT_REVIEW_INPUT_AND_OUTPUT_BINDINGS','path_base':'workspace','artifacts':artifacts})
for r in artifacts:
 p=ROOT/r['path'];assert p.stat().st_size==r['bytes']and sha(p)==r['sha256']
print(json.dumps({'status':'FROZEN','bindings':len(artifacts),'review_sha256':sha(HERE/'independent_review.json'),'manifest_sha256':sha(manifest_path),'prior_binding_sum':sum(x['verified_bindings']for x in manifest_checks)}))
