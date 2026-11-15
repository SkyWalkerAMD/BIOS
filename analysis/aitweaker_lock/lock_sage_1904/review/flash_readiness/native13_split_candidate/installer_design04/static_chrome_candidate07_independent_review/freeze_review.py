"""Freeze independent local classifier review without changing author inputs."""
from pathlib import Path
import argparse,hashlib,json
HERE=Path(__file__).resolve().parent;D04=HERE.parent
ROOT=next(p for p in HERE.parents if(p/'tools/pydeps').is_dir())
CANDIDATE=D04/'static_chrome_candidate07'
MANIFEST=HERE/'independent_manifest.json';REPORT=HERE/'independent_review.json'
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
def load(p):return json.loads(p.read_text(encoding='utf8'))
def row(p):return {'path':p.relative_to(ROOT).as_posix(),'bytes':p.stat().st_size,'sha256':sha(p)}
def verify_rows(rows):
 for r in rows:
  p=ROOT/r['path'];assert p.stat().st_size==r['bytes']and sha(p)==r['sha256'],str(p)
def verify():
 m=load(MANIFEST);verify_rows(m['artifacts'])
 print(json.dumps({'status':'PASS_FROZEN_INDEPENDENT_CLASSIFIER07_REVIEW','bindings':len(m['artifacts']),
                   'manifest_sha256':sha(MANIFEST),'review_sha256':sha(REPORT)}))
def freeze():
 assert not MANIFEST.exists()
 if REPORT.exists():assert load(REPORT)['status']=='FROZEN_INDEPENDENT_REVIEW_LOCAL_CLASSIFIER_ONLY_NO_REMAINING_LOCAL_BLOCKER'
 author=load(CANDIDATE/'candidate_manifest.json')
 assert len(author['artifacts'])==102 and sha(CANDIDATE/'candidate_manifest.json')=='bb3227b7dd77d259d8a5eeaadf3c69e5b997d0fd8c741d4746bdc455a69169a8'
 assert sha(CANDIDATE/'candidate_review.json')=='c70d0a0e91b0bb2a1f81b9772f30c00e405ae6c9b8f60c682115c8a277e06a9f'
 verify_rows(author['artifacts'])
 final=load(HERE/'independent_final_cases.json');initial=load(HERE/'independent_initial_cases.json');prior=load(HERE/'prior_fallback_comparison.json')
 assert final['checks']==53 and len(final['cases'])==53 and all(x['status']=='PASS'for x in final['cases'])
 assert final['template_sha256']=='2aef4bfca4ecb31631c60f9ee01cc2480a5782169524620a502ae0cf2e295efa'
 assert initial['template_sha256']=='251219b67d0eeb2b72e405c47b30b8a876d3a92c8aa1ef06bacbb51269e82e4a'
 assert len(initial['cases'])==19 and len(prior['cases'])==9
 for folder in ['input_candidate','input_2aef4bfc']:
  for r in load(HERE/folder/'snapshot.json')['files']:
   p=HERE/folder/r['path'];assert p.stat().st_size==r['bytes']and sha(p)==r['sha256']
 for r in load(HERE/'input_2aef4bfc/snapshot.json')['files']:
  assert sha(CANDIDATE/r['path'])==r['sha256'],r['path']
 regression=load(CANDIDATE/'build/split_guard_regression.json')
 chrome=load(CANDIDATE/'build/chrome_verification.json')
 assert regression['checks']==198 and regression['reused_policy_checks']==139 and chrome['checks']==106
 report={
  'status':'FROZEN_INDEPENDENT_REVIEW_LOCAL_CLASSIFIER_ONLY_NO_REMAINING_LOCAL_BLOCKER',
  'target':'ASUS Pro WS W790E-SAGE SE BIOS 1904',
  'template_sha256':final['template_sha256'],'template_bytes':16932,
  'author_manifest_verified_bindings':102,'author_manifest_sha256':sha(CANDIDATE/'candidate_manifest.json'),
  'author_review_sha256':sha(CANDIDATE/'candidate_review.json'),
  'scope':{'target_actions':False,'author_source_edits':False,'provider_bound':False,'application_or_iso_acceptance':False,'hardware_acceptance':False,'password_acceptance':False,'release_ready':False},
  'review_findings_closed':[
   {'id':'FRAME_METHOD_TABLE','initial':'实际251219分类器仍接受frame方法槽0/3/4/6/9改变后的HII=-1原生静态对象。',
    'final':'2aef固定全部10个frame槽和12个control槽，独立回归对10个frame槽逐个变异均拒绝；实际Frame.Render、Frame.Input余部、当前E9目标和NOP填充也校验。'},
   {'id':'POST_HII_FALLBACK','initial':'严格例外失败后可回落通用分类器，已赋有效Setup/foreign HII的对象可带异常callback/expression/vtable而仍判不受保护；旧657f1350的9例对照也有此行为。',
    'final':'2aef区分普通对象、已验证静态对象、声明静态但不合法对象。后者直接UNKNOWN。独立16例覆盖四种source下callback、expression、vtable及question变异；全部拒绝。未称旧行为是已证OC绕过。'},
   {'id':'WRITABLE_NATIVE_OBJECTS','initial':'原构造/晚赋值/滚动代码会写frame、control和IFR；只验证可读不足。',
    'final':'作者改为写权限检查；独立kind5 frame/control/7B IFR各一例只读对象均拒绝。权限检查端点是显式模型，不是实机页表执行。'}
  ],
  'original_code_review':{
   'constructors':'复核148E4/14A00/16354/33634：固定frame/control类，初始HII=-1；descriptor无Question、callback和条件指针。',
   'kind5':'33634分支3379E申请7字节，337AE设SUBTITLE02，337B1设token3，337B6存control+48。此为原构造证据；7B内容与可写检查不等于任意敌意RAM下的allocation ownership证明。',
   'render':'16A90在16B1B/16B43/16B5D调用171D4，为kind1/4/3填HII/字符串；随后经全局6B8D0调用Frame.Render。不能把171D4对受控四类的直接测试说成每类都由实际16A90调用。',
   'input':'实际1C2CC只有限定本地计数/滚动路径，滚动可经6BB38重新调用1BE5C；render会调用31DA4条件解析，故条件指针必须为空。静态例外不允许Question或任意回调。',
   'source_93970':'独立执行原5A0→1034至1136前缀：原入口ImageHandle被传给NewPackageList第三参，输出指向93970。早期库helper、OpenProtocol/LocateProtocol/NewPackageList为模型；HiiDatabase官方头定义GetPackageListHandle返回同一DriverHandle。未捕获实机post-render HII拓扑。',
   'identity_scope':'两张vtable逐项RVA及声明的CRC区间均独立从固定原始PE重算一致。CRC区间不覆盖所有传递调用，未来provider仍需完整原.text和12处patch身份约束。'},
  'validation':{
   'independent_final':{'checks':53,'expected_regression_checks':51,'known_unwind_gap_observations':2,'result':row(HERE/'independent_final_cases.json')},
   'initial_snapshot':{'rows':19,'result':row(HERE/'independent_initial_cases.json'),'includes':'首版方法槽反例、post-HII变异和原NewPackageList前缀。'},
   'prior_policy_comparison':{'cases':9,'result':row(HERE/'prior_fallback_comparison.json')},
   'author_records_verified':{'new':106,'old':198,'inherited_old_policy_subset':139,'scope':'复核已冻结记录和102个输入文件，不将其称为本agent重跑或原生GUI验收。'},
   'models':'实际候选机器码和选定原生构造函数执行；HII归属/UEFI服务/可访问性及完整render/input/poll端点为显式模型。'},
  'remaining_blockers_for_deployment':[
   '无安全页的原生退出/清理仍未完成。独立测试明确保留压制render/input/poll且不设置native exit的行为，不把这些期望观察算作退出成功。',
   '冻结P13仍绑定旧模板，不能直接使用2aef。需要新provider、RAM事务app和ISO的精确绑定及完整回归。',
   '真实ASUS页面/密码UI、永久Security入口和直接Del/F2启动自动安装尚不能由本局部分类器测试证明。',
   '本次原厂黑屏原因没有现场对象轨迹，不以静态构造反例替代物理定因。'],
  'conclusion':'未发现要求继续修改2aef局部分类器的剩余阻断；仅允许作为下一离线集成输入，不构成新07硬件执行或最终密码锁准入。'}
 REPORT.write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n',encoding='utf8')
 (HERE/'README.md').write_text(
  '07 局部分类器独立审查完成，固定模板为2aef4bfc…（16932 B）。作者102项文件绑定已重新核对，独立实际机器码53项期望检查通过，其中两项专门记录仍未解决的无安全页退出缺口。\n\n'
  '首版方法表未校验及HII赋值后退回通用分类的两个问题均已修正。新版本固定frame/control方法表，对声明为原厂静态控件但检查失败的对象直接拒绝；不会用有效HII掩盖异常callback、条件表达式或Question。kind5原厂7B动态IFR的构造路径及93970的ImageHandle关联已有独立原始指令证据。\n\n'
  '本报告没有上机、没有改作者源文件，也没有新provider/app/ISO。模型中的HII/权限/完整界面端点仍有明确范围；P13绑定和无安全页退出需继续完成。当前局部结果不等于原生GUI、密码锁或永久刷写验收。\n',encoding='utf8')
 paths=[ROOT/r['path']for r in author['artifacts']]
 paths += [CANDIDATE/'candidate_manifest.json',CANDIDATE/'candidate_review.json',
  D04/'guard_blackout_review01/static_populator_input_review.json',
  D04/'guard_blackout_review01/verify_native_static_controls.py',
  D04/'split_core/build/split_build.json',D04/'split_core/verify_split.py',
  D04.parent.parent/'remote_only/continuation08/edk2_hii_reference/HiiDatabase.h',
  D04.parent.parent/'remote_only/continuation08/edk2_hii_reference/provenance.json']
 paths += [p for p in HERE.rglob('*')if p.is_file()and p!=MANIFEST and '__pycache__'not in p.parts]
 unique={str(p.resolve()):row(p.resolve())for p in paths}
 MANIFEST.write_text(json.dumps({'path_base':'workspace_root','status':report['status'],
  'artifacts':sorted(unique.values(),key=lambda x:x['path'])},ensure_ascii=False,indent=2)+'\n',encoding='utf8')
 verify()
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--verify-only',action='store_true');a=p.parse_args();verify()if a.verify_only else freeze()
