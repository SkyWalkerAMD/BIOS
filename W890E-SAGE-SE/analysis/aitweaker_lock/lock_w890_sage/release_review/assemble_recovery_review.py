"""Summarize captured W890 BMC backup/recovery syntax without device actions."""
from pathlib import Path
import hashlib,json
HERE=Path(__file__).resolve().parent
def read(p):return json.loads(p.read_text(encoding='utf-8'))
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def binding(p):return dict(path=str(p.resolve()),size=p.stat().st_size,sha256=sha(p))
derivation=read(HERE/'bmc_recovery_source_derivation.json')
ast=read(HERE/'bmc_recovery_ast_functions.json')
source=Path(derivation['original']['path']).read_bytes()
assert hashlib.sha256(source).hexdigest()==derivation['original']['sha256']
for item in derivation['modules']:
    p=Path(item['file']);assert sha(p)==item['sha256']
    assert source[item['utf8_start']:item['utf8_end']]==p.read_bytes()
methods={}
for module in ast['modules']:
    code=Path(module['file']).read_text(encoding='utf-8')
    for f in module['functions']:
        assert code[f['start']:f['end']]==f['source']
        methods[(module['module'],f['name'])]=f
def method(module,name,needles):
    f=methods[('views/maintenance/'+module,name)]
    assert all(n in f['source'] for n in needles)
    return dict(module=module,function=name,utf16_start=f['start'],utf16_end=f['end'],
                function_sha256=hashlib.sha256(f['source'].encode()).hexdigest())

rea=read(HERE/'bmc_recovery_rea_summary.json')['summary']['normalized_result']
assert rea['summary']['statistics']['parsed_javascript_files']==31 and rea['summary']['statistics']['parse_failures']==0
report=dict(status='NO_COMPLETE_HOST_SPI_BACKUP_OR_NO_POST_RECOVERY_PROVED',release_ready=False,
 target='W890E-SAGE SE 0603 / BMC 2.01.11',
 current_user_constraints=dict(confirmed_date='2026-11-08',scope='Current W890 target, conveyed by root from user clarification',
    available=['BMC','remote KVM'],onsite_operator_today=False,
    physical_FlashBack_available_today=False,not_inherited_from_old_W790=True),
 sources=[binding(HERE/x) for x in ['bmc_recovery_source_derivation.json','bmc_recovery_ast_functions.json',
          'bmc_recovery_rea_summary.json','bmc_recovery_rea_evidence.json']],
 actual_rea=dict(evidence_id=rea['parent_evidence_id'],parsed_files=31,parse_failures=0,
     total_text_bytes=132001,semantic_status=rea['summary']['coverage']['semantic']['status'],
     limit='Named-module subset; opaque outer aliases and backend service semantics remain unresolved.'),
 features=[
  dict(name='Backup Configuration',observed='Exports bmc-config.bak after model.save; selected items are BMC network, IPMI, KVM, authentication, SNMP, NTP, syslog and fan settings.',
       evidence=method('backup_config','save',['model.save','/api/maintenance/download_config','bmc-config.bak']),
       classification='BMC_CONFIGURATION_EXPORT_NOT_HOST_FIRMWARE_BACKUP',
       effect='UI first saves configuration selection. Do not label the entire flow read-only or call it a complete BIOS/SPI backup.'),
  dict(name='BIOS User Profile',observed='Downloads OOB.CMOS or individual .CMO setting profiles; individual profile path invokes edituserprofile and download uses POST.',
       evidence=method('BIOSUserProfileView','Download_UserProfile',['OOB.CMOS','.CMO','/api/maintenance/edituserprofile','type:"POST"']),
       classification='SETTINGS_PROFILE_NOT_HOST_SPI_BACKUP',
       effect='Other controls set profile flags/password or stage settings. These are not required for read-only diagnostics and cannot recover missing executable firmware.'),
  dict(name='BIOS OOB Update',observed='Start calls POST start-lmedia; then upload_oob, modifyoob and setoobflag. Supported UI file types depend on Feature3.',
       evidence=[method('BIOSOOBUpdateView','Start_OOB',['/api/oob/start-lmedia','type:"POST"','Upload_OOB.call']),
                 method('BIOSOOBUpdateView','ModifyOOBImage',['/api/oob/modifyoob','type:"POST"','SetOOBFlag.call'])],
       classification='STAGED_VIRTUAL_MEDIA_UPDATE_NOT_VERIFIED_RECOVERY',
       effect='Staging and flag writes are real operations. Host update dependency, modified-image trust and recovery when host cannot POST are unproved.'),
  dict(name='BMC Recovery',observed='Model /api/maintenance/bmc_recovery stores forceRecovery, retry counts, serverAddress and imageName.',
       evidence=method('bmc_recovery','save',['model.save','forceRecovery','recoveryRetryCount','serverAddress','imageName']),
       classification='BMC_RECOVERY_CONFIGURATION_NOT_HOST_BIOS_PROOF',
       effect='UI name and model do not demonstrate host SPI backup or host no-POST recovery. No setting changed.'),
  dict(name='BIOS Clear CMOS',observed='After confirmation and host-off check, perform sends GET /api/ClearCmos and reports ClearCmosStatus.',
       evidence=method('BIOSClearCmosView','perform',['/api/ClearCmos','type:"GET"','ClearCmosStatus']),
       classification='MUTATING_ACTION_DESPITE_GET_METHOD',
       effect='Do not include this endpoint in generic read-only GET discovery. Clearing settings is not executable firmware restoration.'),
 ],
 conclusions=[
    'The examined UI contains useful settings exports but no established complete current-machine SPI dump operation.',
    'This is a scoped negative finding, not proof no backend backup API exists anywhere.',
    'With no onsite operator today, physical FlashBack is not a presently reachable fallback.',
    'BMC/KVM availability and ordinary update UI do not by themselves establish recovery from a non-POST modified BIOS.',
    'Continue adaptation, disabled container tests, real EFI simulation and bounded read-only hardware evidence; do not upgrade artifact labels to flash-ready based on these UI paths.'
 ],
 operations_performed=dict(local_static_analysis=True,device_access=False,settings_export=False,
    backup_prepare=False,oob_upload=False,clear_cmos=False,firmware_write=False))
(HERE/'bmc_recovery_path_review.json').write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
print(json.dumps(dict(status=report['status'],sha256=sha(HERE/'bmc_recovery_path_review.json'))))
