"""Prepare and seal an explicitly reviewed CANDIDATE05 engineering archive.

Local files only. Does not rebuild firmware, sign a new image, execute other
scripts, access a BMC, enter update mode or flash anything. --prepare produces
an inventory/control template; --package requires the final NV evidence and
root's closed collection. Canonical inputs and frozen04 are never modified.
"""
from pathlib import Path, PurePosixPath
import argparse, datetime, hashlib, json, re, sys, zipfile
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent
ROOT=next(p for p in HERE.parents if (p/'tools/pydeps').is_dir())
BASE=HERE.parent;CASE=HERE/'lock_1904_candidate05';OUT=HERE/'delivery_review'
DRIVER='71b05ebe21fd0b4de496fc9684f57e4acc79431e38a403dec9017501605eca98'
CAP='e330039ecd2c334c4f9d502589e7f9503000b34462a7e21f6b97b1b581794d08'
REVIEW='9b038c4eae111a985c5c5fef460f0874338d16764b0ead6f89a3e55c775f5455'
OFFICIAL='03e4330430b2510d5e9e5c9868ca64c730844992b82c6a272b815aef3d20bf29'
CAP_PATH=HERE/'engineering_signature/W790-ACE-1904-CANDIDATE05-ENGINEERING-NONOEM-NOT-FLASH-READY.CAP'
CAP_ALIAS='ENGINEERING/W790-ACE-1904-AI-TWEAKER-ENGINEERING-CANDIDATE05.CAP'
HEX=re.compile(r'^[0-9a-f]{64}$')
BAD_PARTS={'__pycache__','.git','node_modules','runtime-temp','operations','sessions','credentials','.zig-global','.zig-local'}
BAD_NAME=re.compile(r'(?i)(?:^|[._-])(?:cookies?|credential|session|login|secret|private|config|process|pid|endpoint)(?:[._-]|$)')
SECRET=re.compile(rb'(?i)(?:-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----|\bBearer\s+[A-Za-z0-9._~+/-]{24,}|\bBasic\s+[A-Za-z0-9+/]{16,}={0,2})')
TEXT_EXT={'.json','.txt','.md','.py','.c','.h','.diff','.tsv','.map','.pem','.log'}

def require(ok,message):
    if not ok:raise ValueError(message)
def digest(path):
    with Path(path).open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()
def rel(path):return Path(path).resolve().relative_to(ROOT.resolve()).as_posix()
def resolve(value):
    p=Path(value);p=(p if p.is_absolute() else ROOT/p).resolve()
    require(p.is_relative_to(ROOT.resolve()) and p.is_file(),'Missing/outside-workspace input: '+str(value));return p
def read(path):return json.loads(Path(path).read_text(encoding='utf8'))
def write_json(path,data):Path(path).write_text(json.dumps(data,ensure_ascii=False,indent=2)+'\n',encoding='utf8')
def safe_name(name):
    p=PurePosixPath(name);require(not p.is_absolute() and '..' not in p.parts and not any(c in name for c in '\\\0\r\n:'),'Unsafe archive path')
def scan(path,raw,extra=()):
    require(not any(s and s in raw for s in extra),'Private input pattern found in selected artifact: '+Path(path).name)
    if Path(path).suffix.lower() not in TEXT_EXT:return
    require(not SECRET.search(raw),'Credential/private-key content in selected artifact: '+Path(path).name)
    if Path(path).suffix.lower()=='.json':
        def walk(x):
            if isinstance(x,dict):
                for k,v in x.items():
                    key=re.sub(r'[-_]','',k.lower())
                    if key in {'authorization','xauthtoken','cookie','setcookie','password','sessionid','accesstoken','refreshtoken','csrftoken'}:
                        require(not isinstance(v,str) or v.lower() in {'','redacted','[redacted]','none'},'Secret/session field in selected JSON: '+Path(path).name)
                    walk(v)
            elif isinstance(x,list):
                for v in x:walk(v)
        walk(json.loads(raw))

class Selection:
    def __init__(self):self.files={};self.inputs={}
    def bind(self,path,expected=None,include=True,role='evidence',version='candidate05',alias=None):
        path=resolve(path);h=digest(path)
        require(expected is None or h==expected,'Hash mismatch: '+rel(path))
        require(path not in self.inputs or self.inputs[path]==h,'Input changed while collecting: '+rel(path));self.inputs[path]=h
        if include:
            parts={p.lower() for p in path.parts}
            require(not (parts&BAD_PARTS) and not any(p.lower().startswith('ghidra-') for p in path.parts),'Excluded cache/runtime directory')
            require(not BAD_NAME.search(path.name),'Excluded auth/config/process file: '+rel(path))
            require(path.suffix.lower() not in {'.mjs','.js','.fd','.img','.gpr','.rep','.pyc','.zip'},'Excluded runtime/bulk type: '+rel(path))
            require(path.stat().st_size<=72*1024*1024,'Individual file exceeds bound')
            if path.suffix.lower()=='.pem':require(path.name.endswith('.public.pem'),'Only explicit public-key PEM can be selected')
            name=alias or 'workspace/'+rel(path);safe_name(name);scan(path,path.read_bytes())
            entry={'source_path':rel(path),'archive_path':name,'sha256':h,'bytes':path.stat().st_size,'role':role,'version_binding':version}
            require(name not in self.files or self.files[name]['sha256']==h,'Archive path conflict');self.files[name]=entry
        return path
    def json(self,path,expected=None,include=True,role='evidence',version='candidate05'):
        return read(self.bind(path,expected,include,role,version))
    def generated(self,name,data,role):
        path=OUT/name;write_json(path,data);self.bind(path,role=role,alias='REVIEW/'+name);return path
    def unchanged(self):
        for p,h in self.inputs.items():require(digest(p)==h,'Input changed after collection: '+rel(p))

REPORTS={
 'current_driver':[
  'lock_1904_candidate05/driver/build/discovery_regression.json',
  'lock_1904_candidate05/ebs_review/integrated_ebs_regression.json',
  'lock_1904_candidate05/entry_review/integrated_retirement_regression.json',
  'lock_1904_candidate05/lab/asus_review/verification.json',
  'lock_1904_candidate05/lab/asus_review/W790-ACE-1904-lock.review.json',
  'lock_1904_candidate05/source-seed.json','lock_1904_candidate05/regression-source-binding.json'],
 'coldpath':[
  'rea_cold_entry/cold_entry_review_summary.json','rea_cold_entry/native_cold_sequence.json',
  'rea_cold_entry/entry_lifetime_71b05e.json','rea_cold_entry/entry_lifetime_463b.json',
  'rea_cold_entry/close_retirement_edge_summary.json','rea_cold_entry/close_retirement_edge_71b05e.json',
  'rea_cold_entry/close_retirement_edge_463b.json','rea_cold_entry/core_dispatch_sequence.json','rea_cold_entry/readiness_options.json'],
 'signature':[
  'engineering_signature/creation_manifest.json','engineering_signature/verification.json','engineering_signature/delivery_manifest.json',
  'update_path_reference/ace_capsule_signature_review05.json','update_path_reference/bmc1313_engineering_signature_replay.json',
  'update_path_reference/api_auth_review/live_staging_review.json',
  'bmc_signature_api05/official_positive.json','bmc_signature_api05/old_signature_negative.json','bmc_signature_api05/engineering_positive.json'],
 'layout_historical04':[
  'layout_recovery/layout_recovery_summary.json','layout_recovery/layout_identity.json',
  'layout_recovery/fit_boot_guard_reference.json','layout_recovery/preservation_ranges.json','layout_recovery/backup_gap_assessment.json'],
 'recovery_and_preservation':[
  'update_path_reference/update_preservation/update_preservation_review.json',
  'update_path_reference/update_preservation/native_pdk_evidence.json','update_path_reference/update_preservation/ace1904_nonprogram_table.json',
  'update_path_reference/update_preservation/README-preservation.txt','update_path_reference/backup_recovery_review.json',
  'update_path_reference/recovery_extension/recovery_extension_summary.json','update_path_reference/recovery_extension/prepare_exit_review.json',
  'update_path_reference/recovery_extension/normal_flash_export_review.json','update_path_reference/recovery_extension/fmp_getimage_review.json'],
 'spi_inventory':[
  'layout_recovery/probe/media_manifest.json','layout_recovery/probe/build/build.json',
  'spi_register_probe06/media_manifest.json','spi_register_probe06/build/build.json',
  'spi_register_probe06/build/local_verification.json','spi_register_probe06/build/ovmf_verification.json',
  'spi_register_probe06/hardware_review/hardware06_interpretation.json','update_path_reference/spi_probe06_independent_review.json',
  'bmc_inventory01/inventory-results/manifest.json','bmc_inventory01/inventory-results/hardware-log.txt',
  'bmc_spi06/inventory-results/manifest.json','bmc_spi06/inventory-results/hardware-log.txt'],
 'nv_local':[
  'nv_persistence_review/README-NV-PERSISTENCE.txt','nv_persistence_review/delivery_summary-at-media-build.json',
  'nv_persistence_review/stage1/build/build.json','nv_persistence_review/stage1/build/guard_validation.json',
  'nv_persistence_review/stage1/build/boot_validation.json','nv_persistence_review/stage1/build/stage2_binding_validation.json',
  'nv_persistence_review/password_chain_fixture/password_chain_validation.json',
  'nv_persistence_review/independent_review/nv_independent_review.json','nv_persistence_review/independent_review/residency_validation.json',
  'nv_persistence_review/independent_review/stage2_binding_review.json','nv_persistence_review/stage2/README-STAGE2.txt',
  'nv_persistence_review/stage2/review_delta.json','nv_persistence_review/stage2/generated_source_diff.txt',
  'nv_persistence_review/stage2/build/build.json','nv_persistence_review/stage2/build/boot_validation.json',
  'nv_persistence_review/stage2/delivery_summary-at-media-build.json',
  'bmc_nv05/stage1-receipt/manifest.json','bmc_nv05/stage1-receipt/hardware-log.txt']}

def baseline_component_binding(s,production):
    old=BASE/'lock_1904_integrated04';baseline=s.json(old/'driver/build/build.json',role='historical_baseline',version='integrated04')
    identical=[];changed=[]
    for name,h in production['sources'].items():
        old_h=baseline['sources'].get(name);s.bind(old/name,old_h,False)
        (identical if h==old_h else changed).append(name)
    require(set(changed)=={'driver\\entry.c','driver\\services.c'},'Unexpected 04-to-05 source change set')
    idx=s.json(old/'final_validation_index.json',role='historical_baseline',version='integrated04')
    reports=[]
    for row in idx['reports']:
        if row['role'] in {'entry','ebs','discovery'}:continue
        p=s.bind(row['path'],row['sha256'],role='historical_component_regression',version='integrated04_not_full_candidate05_run')
        reports.append({'role':row['role'],'path':rel(p),'sha256':row['sha256'],'claim':'Historical component/regression evidence; no new full-driver or hardware run inferred.'})
    return s.generated('component_source_reuse.json',{'status':'IDENTICAL_COMPONENT_SOURCES_WITH_EXPLICIT_ENTRY_SERVICE_CHANGES',
        'baseline_driver_sha256':baseline['efi_sha256'],'candidate_driver_sha256':DRIVER,
        'identical_source_files':identical,'changed_source_files':changed,'historical_reports':reports,
        'fresh_candidate_checks':['81 EBS','53 retirement +24 discovery','REA native cold-path/lifetime review','real core/services isolated-console NVRAM test'],
        'limit':'Source identity does not turn integrated04 whole-driver OVMF/physical results into candidate05 whole-driver or flash acceptance.'},'source_reuse')

def collect():
    OUT.mkdir(exist_ok=True);s=Selection()
    s.bind(CAP_PATH,CAP,alias=CAP_ALIAS,role='engineering_capsule')
    review=s.bind(CASE/'lab/asus_review/W790-ACE-1904-lock.review.bin',REVIEW,False)
    cap=CAP_PATH.read_bytes();raw=review.read_bytes()
    require(len(cap)==len(raw)==67112960 and cap[4096:]==raw[4096:],'Engineering CAP payload mismatch')
    allowed=set(range(0x48,0x248))|set(range(0x258,0x458))
    changed=[i for i,(x,y) in enumerate(zip(cap[:4096],raw[:4096])) if x!=y]
    require(set(changed)<=allowed and changed,'Unexpected capsule header changes')
    s.generated('candidate_identity.json',{'engineering_cap_sha256':CAP,'unsigned_review_sha256':REVIEW,
       'payload_sha256':hashlib.sha256(cap[4096:]).hexdigest(),'payload_bytes':67108864,
       'payload_byte_identical':True,'changed_header_byte_count':len(changed),
       'allowed_header_changes':'Only engineering firmware/certificate RSA public moduli and signatures; original flags/maps/payload unchanged.',
       'ASUS_signature':False,'flash_ready':False},'image_identity')
    production=s.json(CASE/'driver/build/build.json',role='production_build')
    require(production['efi_sha256']==DRIVER and production['revision']=='ACE1904_CANDIDATE05','Wrong production build')
    s.bind(CASE/'driver/build/AiTweakerLock1904.efi',DRIVER,role='production_driver')
    s.bind(CASE/'driver/build/driver.map',role='production_link_map')
    for name,h in production['sources'].items():s.bind(CASE/name,h,role='production_source')
    for name,h in production['external_sources'].items():s.bind(ROOT/name,h,role='production_external_source')
    for name in ['core','driver','lab','ebs_review','entry_review']:
        for p in sorted((CASE/name).glob('*')):
            if p.is_file() and p.suffix.lower() in {'.py','.c','.h','.txt'}:s.bind(p,role='build_or_validation_source')
    for p in sorted((CASE/'driver/build').glob('*.obj')):s.bind(p,role='production_coff')
    s.bind(CASE/'driver/policy.json',role='policy_input')
    for role,names in REPORTS.items():
        for name in names:s.bind(HERE/name,role=role,version='integrated04_reference' if role=='layout_historical04' else 'candidate05_related')
    for folder in [HERE/'rea_cold_entry',HERE/'engineering_signature',HERE/'nv_persistence_review',HERE/'nv_persistence_review/stage2',HERE/'spi_register_probe06',HERE/'layout_recovery/probe']:
        for p in sorted(folder.glob('*')):
            if p.is_file() and p.suffix.lower() in {'.c','.h','.py'}:s.bind(p,role='reproduction_source')
    for p in sorted((HERE/'engineering_signature/public_evidence').glob('*')):
        if p.is_file() and (p.name.endswith('.public.pem') or p.suffix.lower()=='.bin'):s.bind(p,role='public_signature_evidence')
    for stage in [1,2]:
        folder=HERE/('nv_persistence_review/stage'+str(stage)+'/build');b=read(folder/'build.json')
        s.bind(folder/'BOOTX64.EFI',b['efi_sha256'],role='nv_test_efi',version='isolated_console_stage'+str(stage))
        s.bind(b['iso_path'],b['iso_sha256'],False)
        for n,h in b['external_sources'].items():s.bind(ROOT/n,h,role='nv_test_external_source')
    for folder in ['bmc_inventory01','bmc_spi06']:
        m=read(HERE/folder/'inventory-results/manifest.json')
        s.bind(HERE/folder/'inventory-results/hardware-log.txt',m['transport']['sha256'],role='physical_spi_qr_log')
        for row in m['screenshots']:s.bind(HERE/folder/row['file'],row['sha256'],role='physical_spi_qr_image')
    structural=read(CASE/'lab/asus_review/verification.json')
    require(structural['status']=='PASS' and structural['candidate_sha256']==REVIEW and structural['driver_sha256']==DRIVER,'Structural result identity mismatch')
    for name in ['driver/build/discovery_regression.json','ebs_review/integrated_ebs_regression.json','entry_review/integrated_retirement_regression.json']:
        r=read(CASE/name);require(r['driver_sha256']==DRIVER and r['status'].startswith('PASS'),'Current regression mismatch')
    crypt=read(HERE/'engineering_signature/verification.json')
    require(crypt['engineering_artifact']['sha256']==CAP and crypt['engineering_valid_signatures']==2 and crypt['check_count']==17 and crypt['negative_controls_rejected_by_both_verifiers']==11,'Signature regression mismatch')
    for name,h,status in [('official_positive',OFFICIAL,200),('old_signature_negative',REVIEW,500),('engineering_positive',CAP,200)]:
        r=read(HERE/'bmc_signature_api05'/(name+'.json'))
        require(r['sha256']==h and r['expected_outcome_observed'] is True and r['upload']=={'status':200,'body':{'cc':0}} and r['verification']['status']==status,'Live signature case mismatch')
    independent=read(HERE/'update_path_reference/api_auth_review/live_staging_review.json')
    require(independent['check_count']==85 and independent['failure_count']==0 and all(r['pass'] for r in independent['checks']),'Independent live signature review incomplete')
    source=s.bind(HERE/'bmc_signature_api05/summary.json',include=False)
    raw_summary=read(source)
    require(not raw_summary['flash_performed'] and not raw_summary['update_mode_entered'],'Unexpected full-update activity')
    public={k:raw_summary[k] for k in ['status','scope','cases','flash_performed','update_mode_entered','spi_driver_or_gpio_action_invoked','atomic_exclusion_proven','boot_unchanged','cleanup_complete','staging_file_deletion','resident_root_tail_signature_tested','spi_electrical_connection_tested','recovery_proven']}
    public['source']={'path':rel(source),'sha256':digest(source)}
    public['omitted']='Login/cookie/legacy service/session observations and network-process sources are not included.'
    s.generated('live_signature_public_excerpt.json',public,'sanitized_live_signature_record')
    baseline_component_binding(s,production)
    s.bind(Path(__file__),role='archive_builder')
    s.unchanged()
    inventory={'schema':1,'created_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),
      'engineering_cap_sha256':CAP,'driver_sha256':DRIVER,'flash_ready':False,'status':'REVIEW_INVENTORY_WAITING_FOR_FINAL_NV_AND_ROOT_CLOSURE',
      'entries':sorted(s.files.values(),key=lambda x:x['archive_path']),
      'checked_inputs_not_packaged':[{'path':rel(p),'sha256':h,'reason':'Reference or duplicate bulk/auth-bearing record; hash retained without publishing its bytes.'} for p,h in s.inputs.items() if rel(p) not in {x['source_path'] for x in s.files.values()}],
      'excluded':'BMC login/session/cookies/credentials/config/runners, private keys, Ghidra projects/caches, QEMU disks, duplicate full official/review images and full test ISOs.',
      'historical_evidence_rule':'Every file retains its original version binding; no earlier hardware PASS is promoted to a different driver.'}
    write_json(OUT/'review_inventory.json',inventory)
    control=OUT/'archive_control.json'
    if not control.exists():write_json(control,{'schema':1,'root_collection_closed':False,'engineering_cap_sha256':CAP,'driver_sha256':DRIVER,
      'nv':{'stage2_load_log':None,'final_log':None,'hardware_summary':None,'cold_power_evidence':[]},'cleanup_report':None,'additional_public_evidence':[],
      'reference_format':{'path':'workspace-relative file path','sha256':'exact lowercase SHA256'},
      'note':'Root fills references after physical phase2/cleanup. Closing this collection authorizes only this local archive, not flashing.'})
    return inventory

def ref(selection,value,role,include=True):
    require(isinstance(value,dict) and set(value)>={'path','sha256'} and HEX.fullmatch(value['sha256']),'Required final path/SHA reference missing: '+role)
    return selection.bind(value['path'],value['sha256'],include,role)
def log_fields(path):
    rows={}
    for line in Path(path).read_text(encoding='ascii').splitlines():
        if '=' in line:
            k,v=line.split('=',1);rows.setdefault(k,[]).append(v)
    return rows
def exact(rows,key,value):require(rows.get(key)==[value],'Final NV log field not unique/exact: '+key)

def validate_final(s,control):
    require(control.get('root_collection_closed') is True,'Root collection is not closed; final NV evidence is still pending')
    require(control.get('engineering_cap_sha256')==CAP and control.get('driver_sha256')==DRIVER,'Final control identity mismatch')
    nv=control['nv'];load=ref(s,nv['stage2_load_log'],'physical_nv_cold_reload_log');final=ref(s,nv['final_log'],'physical_nv_final_cleanup_log')
    ref(s,nv['hardware_summary'],'physical_nv_observations');require(nv['cold_power_evidence'],'Physical cold-power evidence references missing')
    for row in nv['cold_power_evidence']:ref(s,row,'physical_cold_power_evidence')
    ref(s,control['cleanup_report'],'physical_test_cleanup_report')
    initial=log_fields(load);last=log_fields(final);build=read(HERE/'nv_persistence_review/stage2/build/build.json')
    for rows in [initial,last]:
        exact(rows,'DriverSHA256',DRIVER);exact(rows,'RequestedStage','0x0000000000000002');exact(rows,'Stage','0x0000000000000002')
        exact(rows,'Phase1ReceiptLogSHA256',build['stage1_receipt_binding']['log_sha256']);exact(rows,'Fault','0x0000000000000000');exact(rows,'Failures','0x0000000000000000')
    exact(initial,'CredentialSHA256',build['stage1_receipt_binding']['record_sha256']);exact(initial,'CredentialMode','0x0000000000000001');exact(initial,'CoreUnlocked','0x0000000000000000')
    for k,v in {'CredentialAttributes':3,'CredentialBytes':128,'CredentialGeneration':1,'AcceptedWrites':0,'NativeSetAttempts':0}.items():exact(initial,k,'0x'+format(v,'016x'))
    for k,v in {'CleanupRestoredAbsence':1,'CleanupDeleteAttempts':1,'CredentialBytes':0,'CredentialAttributes':0,'CoreActive':0,'CoreUnlocked':0,'ConsoleOwnerActive':0,'CredentialMode':2,'CredentialGeneration':3,'AcceptedWrites':2,'NativeSetAttempts':2}.items():exact(last,k,'0x'+format(v,'016x'))
    exact(last,'CredentialSHA256','0'*64)
    require({'0x0000000000000000','0x0000000000000001'}<=set(last.get('UnlockResult',[])),'Final log lacks both denied and accepted authentication results')
    require('PASS explicit new console session relocks' in Path(final).read_text(encoding='ascii'),'Final log lacks explicit session relock check')
    require('PASS OC/memory variable metadata and SHA256 unchanged' in Path(final).read_text(encoding='ascii'),'Final monitored-variable evidence missing')
    for row in control.get('additional_public_evidence',[]):ref(s,row,'additional_reviewed_public_evidence')
    return {'status':'PHYSICAL_ISOLATED_CONSOLE_NV_COMPLETED_WITH_EXACT_ABSENCE_LOG',
            'stage2_load_log':{'path':rel(load),'sha256':digest(load)},'final_log':{'path':rel(final),'sha256':digest(final)},
            'native_setup_ui_proven':False,'complete_firmware_flash_or_recovery_proven':False}

def chinese_note(nv_complete):
    return ('W790 ACE 1904 AI Tweaker 独立密码 — 候选05工程审阅包\n\n'
      '主文件是官方1904基础的完整64MiB payload工程CAP，不是188当前SHUANG整片固件的局部补丁。工程签名不是ASUS签名。CAP SHA256：'+CAP+'；生产驱动 SHA256：'+DRIVER+'。\n\n'
      '188已实际完成三份CAP独立验签：原厂200、修改payload沿用旧签名500、新工程签名200；另有85项独立复核。此证据不等于Prepare/全流程刷写、驻留根后续尾签、电气排线或死BIOS恢复已验证。没有当前机器整片SPI备份。\n\n'
      +('两阶段隔离控制台NVRAM实测最终证据已纳入，核对冷掉电后记录、认证/会话边界以及精确自有disabled tombstone删除恢复缺失。该应用复用真实生产core/services/UI对象，但用控制台owner适配，不替代native SendForm/完整Setup集成测试。\n\n' if nv_complete else '真实NVRAM第二阶段最终结果仍待收集；当前仅生成审阅清单，不能封包。\n\n')+
      '正常BMC更新按完整raw镜像逐块比较后更新差异块；签名ROM map不是刷写白名单。NonProgramBlock表只覆盖部分范围，保留依赖实现及读取成功。NVRAM不在该保留范围，可能重置Setup、Boot、密码等变量；定制Logo和其他未保护模块可能被官方内容替换，不能承诺保留全部机器数据。\n\n'
      '仅entry/services相对冻结04变化，05已另做入口/EBS/REA冷路径检查。其余历史报告保留原版本标记，源码一致性单独核对，不把04完整启动或RAM结果套到05整机。包内报告中的旧“尚未实机/未上传”描述是当时制作状态，最终新证据由本包总清单明确列出。\n\n'
      '包中不含登录资料、会话、运行进程、私钥、配置或Ghidra缓存；只保留公共密钥/签名和必要哈希。原厂CAP、重复review镜像、测试ISO及工具链大文件以外部输入哈希标识，避免重复bulk。封包动作不进行刷写；本包不标生产flash_ready。\n')

def main():
    p=argparse.ArgumentParser(description=__doc__);m=p.add_mutually_exclusive_group(required=True)
    m.add_argument('--prepare',action='store_true');m.add_argument('--check-pending',action='store_true');m.add_argument('--package',action='store_true')
    p.add_argument('--private-patterns-stdin',action='store_true',help='Optional JSON list of temporary secret strings from an in-memory runner; never retained or printed')
    args=p.parse_args();extra=[]
    if args.private_patterns_stdin:
        values=json.load(sys.stdin);require(isinstance(values,list) and all(isinstance(x,str) and len(x)>=8 for x in values),'Private scan input must be strings of length >=8')
        for value in values:extra.extend([value.encode('utf8'),value.encode('utf-16-le')])
    if args.prepare:
        inventory=collect();(OUT/'README-待封包.txt').write_text(chinese_note(False),encoding='utf8')
        print(json.dumps({'status':'PREPARED_REVIEW_INVENTORY_NO_ARCHIVE','files':len(inventory['entries']),'bytes':sum(x['bytes'] for x in inventory['entries']),'control':rel(OUT/'archive_control.json')},ensure_ascii=False));return
    inventory=read(OUT/'review_inventory.json');control=read(OUT/'archive_control.json');s=Selection()
    require(inventory['engineering_cap_sha256']==CAP and inventory['driver_sha256']==DRIVER,'Inventory identity mismatch')
    for row in inventory['entries']:s.bind(row['source_path'],row['sha256'],role=row['role'],version=row['version_binding'],alias=row['archive_path'])
    for row in inventory['checked_inputs_not_packaged']:s.bind(row['path'],row['sha256'],False)
    if args.check_pending:
        s.unchanged();print(json.dumps({'status':'PINNED_LOCAL_INPUTS_VALID_FINAL_NV_COLLECTION_PENDING' if not control['root_collection_closed'] else 'PINNED_LOCAL_INPUTS_VALID_ROOT_COLLECTION_CLOSED','files':len(s.files),'archive_created':False}));return
    nv=validate_final(s,control);s.bind(OUT/'review_inventory.json',role='review_inventory',alias='REVIEW/review_inventory.json');s.bind(OUT/'archive_control.json',role='root_closed_control',alias='REVIEW/archive_control.json')
    entries=sorted(s.files.values(),key=lambda x:x['archive_path']);require(len({x['archive_path'].casefold() for x in entries})==len(entries),'Case-insensitive archive name collision')
    require(sum(x['bytes'] for x in entries)<256*1024*1024,'Selected archive exceeds 256MiB uncompressed bound')
    s.unchanged();folder=OUT/'archives';folder.mkdir(exist_ok=True)
    target=folder/'W790-ACE-1904-AI-TWEAKER-CANDIDATE05-ENGINEERING.zip';temp=target.with_suffix('.zip.pending')
    require(not target.exists() and not temp.exists(),'Refusing to overwrite an existing archive or pending archive')
    note=chinese_note(True).encode('utf8');scan('README.txt',note,extra)
    public={'status':'ENGINEERING_REVIEW_ARTIFACT_NOT_PRODUCTION_FLASH_READY','engineering_cap_sha256':CAP,'driver_sha256':DRIVER,
       'flash_ready':False,'ASUS_signature':False,'physical_nv':nv,'files':entries,
       'private_pattern_scan_requested':args.private_patterns_stdin,'notes':'Archive creation did not access BMC or flash firmware.'}
    with zipfile.ZipFile(temp,'x',compression=zipfile.ZIP_DEFLATED,compresslevel=6) as z:
        for row in entries:
            raw=resolve(row['source_path']).read_bytes();require(hashlib.sha256(raw).hexdigest()==row['sha256'],'Input changed before ZIP write: '+row['source_path']);scan(row['source_path'],raw,extra);z.writestr(row['archive_path'],raw)
        z.writestr('README-工程交付.txt',note)
        manifest=(json.dumps(public,ensure_ascii=False,indent=2)+'\n').encode('utf8');scan('manifest.json',manifest,extra);z.writestr('PUBLIC-ARTIFACT-MANIFEST.json',manifest)
        sums='\n'.join(x['sha256']+'  '+x['archive_path'] for x in entries)+'\n'+hashlib.sha256(note).hexdigest()+'  README-工程交付.txt\n'+hashlib.sha256(manifest).hexdigest()+'  PUBLIC-ARTIFACT-MANIFEST.json\n';z.writestr('SHA256SUMS.txt',sums)
    with zipfile.ZipFile(temp) as z:
        require(z.testzip() is None,'ZIP CRC verification failed')
        for row in entries:require(hashlib.sha256(z.read(row['archive_path'])).hexdigest()==row['sha256'],'ZIP bytes mismatch')
        require(hashlib.sha256(z.read(CAP_ALIAS)).hexdigest()==CAP,'CAP alias changed bytes')
    s.unchanged();temp.rename(target)
    result={'status':'ENGINEERING_ARCHIVE_CREATED_NOT_FLASHED','path':rel(target),'sha256':digest(target),'bytes':target.stat().st_size,'files':len(entries)+3,'engineering_cap_sha256':CAP,'flash_ready':False}
    write_json(OUT/'archive_result.json',result);print(json.dumps(result,ensure_ascii=False,indent=2))

if __name__=='__main__':
    try:main()
    except (ValueError,KeyError,OSError) as e:
        print('DELIVERY REFUSED: '+str(e),file=sys.stderr);raise SystemExit(2)
