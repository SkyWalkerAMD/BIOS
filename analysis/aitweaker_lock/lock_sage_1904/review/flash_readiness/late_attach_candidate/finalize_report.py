"""Bind local evidence to the exact isolated candidate, without publishing it."""
from pathlib import Path
import hashlib,json
HERE=Path(__file__).resolve().parent;CASE=HERE.parents[2];ROOT=CASE.parents[2]
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
read=lambda p:json.loads(p.read_text(encoding='utf8'))
build=read(HERE/'build/build.json');source=read(HERE/'source_manifest.json')
for name,digest in source['candidate_sources'].items():assert sha(HERE/name)==digest
for name,digest in source['baseline_sources'].items():assert sha(CASE/name)==digest
assert sha(CASE/'driver/build/AiTweakerLock1904.efi')==build['baseline_driver_sha256']
assert sha(HERE.parent/'ebs_candidate/build/AiTweakerLock1904.efi')==build['ebs_candidate_driver_sha256']
assert sha(HERE/'build/AiTweakerLock1904.efi')==build['candidate_driver_sha256']
assert all(sha(CASE/name)==digest for name,digest in build['object_sha256'].items())
marker='static int update_runtime_set(SETVAR fn) {'
new=(HERE/'services.c').read_text(encoding='utf8');old=(HERE.parent/'ebs_candidate/services.c').read_text(encoding='utf8')
assert new[new.index(marker):]==old[old.index(marker):]
late=read(HERE/'late_attach_regression.json');ebs=read(HERE/'ebs_regression.json');full=read(HERE/'full_regression/summary.json')
assert late['status']=='PASS_ISOLATED_LATE_ATTACH_OWNER_CANDIDATE' and late['checks']==269
assert late['test_sha256']==sha(HERE/'verify_late_attach.py')
assert ebs['status']=='PASS_LOCAL_CANDIDATE' and ebs['checks']==83
assert full['status']=='PASS_SIX_EXISTING_COMPILED_REGRESSION_SUITES_ON_ISOLATED_CANDIDATE'
assert all(x['candidate_driver_sha256']==build['candidate_driver_sha256'] for x in [late,ebs,full])
files=['source_manifest.json','build/build.json','build/AiTweakerLock1904.efi','build/driver.map','late_attach_regression.json','ebs_regression.json','full_regression/summary.json','full_regression/build_context.json','prepare_candidate.py','build_candidate.py','prepare_tests.py','run_full_regression.py','verify_late_attach.py','verify_ebs.py']+list(source['candidate_sources'])+[n+'.patch' for n in source['candidate_sources']]
result={'status':'PASS_LOCAL_SESSION_OWNER_CANDIDATE_NOT_DEPLOYED','candidate_driver_sha256':build['candidate_driver_sha256'],
 'baseline_driver_sha256':build['baseline_driver_sha256'],'ebs_candidate_preserved_sha256':build['ebs_candidate_driver_sha256'],
 'hardware_acceptance_inherited':False,'source_sha256':source['candidate_sources'],'files':{name:sha(HERE/name) for name in files},
 'checks':{'new_late_attach_owner':late['checks'],'retargeted_ebs':ebs['checks'],'retargeted_existing_suites':[{k:t[k] for k in ['test','checks_or_cases','status']} for t in full['tests']]},
 'behavior':['All installed render/page/app/frame/navigation/poll hooks enforce protection without relying on loop_depth to decide whether to check.',
 'Only an owned wrapper session may prompt/authenticate or manage/persist a password; stale AP_CORE active/unlocked is insufficient.',
 'HII callbacks, protected RouteConfig and protected variable changes share owner-aware authorization. Explicit disabled mode retains normal outside-browser OC UI/write behavior.',
 'Unknown/malformed protected context is consumed or safely redirected; native HISTORY01 reset/ESC behavior remains intact.',
 'Normal wrapped/nested sessions still prompt once and reuse authorization until outer return; prompt/input ownership is rechecked.',
 'EBS restore/final-safety-check implementation is unchanged from isolated EBS fix, and all 83 cases pass on this complete EFI.'],
 'fixture_notes':['HII ABI suite adds only owned-session precondition to its normal-path fixture; original eight ABI assertions remain unchanged.',
 'New negative UI entry and input ownership tests run compiled ensure/manage; accepted navigation-password outcomes and firmware services are explicit stubs.',
 'Original native navigation/history/ESC routines execute in Unicorn. No original EFI or privileged code executes on the Windows CPU.'],
 'unresolved':['First discovery at native stage5 still leaves that invocation unhooked; initial attachment scheduling was not expanded.',
 'A transient first attachment failure is still not retried.',
 'OEM Save commit timing relative to outer browser return and ordinary-boot protected variable writes still need separate acceptance.',
 'No new physical test, UEFI flash write, full SPI backup, CAP/ISO deployment or signed-update/recovery acceptance.'],
 'ebs_cleanup_source_unchanged':True}
(HERE/'candidate_summary.json').write_text(json.dumps(result,indent=2)+'\n',encoding='utf8')
(HERE/'review.txt').write_text('隔离候选：迟挂钩 UI 拒绝 + 会话归属一致校验\n\n完整 EFI SHA256: '+build['candidate_driver_sha256']+'\n\n新增269项、EBS83项、原6套回归通过。所有测试绑定该EFI；没有继承实机通过。\n\n变化：已安装的UI hook不再因loop_depth=0跳过检查；未经过wrapper的active/unlocked残留不能放行、弹密码或写受保护变量；密码设置/清除/持久化仍要求owned session。明确disabled保持原普通UI和写入行为。原生历史根重置和Esc路径保持，EBS清理主体源码未变。\n\n仍未解决：首次发现即stage5的未挂钩窗口、首次挂钩失败不重试、原厂Save实际提交时序、普通开机变量写入兼容性。未访问BMC、未刷写、未生成新的CAP/ISO；原EXP02和EBS候选保持原hash。\n\n详见candidate_summary.json及绑定报告。\n',encoding='utf8')
print(json.dumps({'status':result['status'],'candidate_driver_sha256':result['candidate_driver_sha256'],'summary_sha256':sha(HERE/'candidate_summary.json')},indent=2))
