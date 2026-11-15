"""Create the FlashBack-only package selection review; no device actions."""
from pathlib import Path
import hashlib,json

BASE=Path(__file__).resolve().parent
CASE=BASE.parent
ROOT=next(p for p in BASE.parents if (p/'tools/pydeps').is_dir())


def ref(p):
    b=p.read_bytes();return {'path':p.relative_to(ROOT).as_posix(),'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest()}


def load(p):return json.loads(p.read_text(encoding='utf8'))
def write(p,d):p.write_text(json.dumps(d,ensure_ascii=False,indent=2)+'\n',encoding='utf8')


def main():
    formats=load(BASE/'materials_validation.json')
    assert formats['status']=='PASS_FLASHBACK_MATERIAL_FORMAT_AND_IDENTITY_ONLY'
    sigpath=CASE/'engineering_signature/verification.json';sig=load(sigpath)
    peer=CASE/'flashback_packaging_review/source_review.json'
    assert peer.exists()
    evidence=[];sessions=[]
    for name in ['ec01','ec02','ec03']:
        s=BASE/name;closes=[];failures=[]
        for p in sorted((s/'responses').glob('*.json')):
            result=load(p).get('result',{});e=result.get('structuredContent',{})
            if e.get('operation')=='analyze_function':
                evidence.append({'response':ref(p),'evidence_id':e['evidence_id'],'provider':e['provider'],
                                 'subject':e['subject'],'parameters':e['parameters']})
            if result.get('isError'):failures.append(ref(p))
            if 'close' in p.name:
                assert e=={'result':None};closes.append(ref(p))
        assert closes and (s/'close-finally.json').exists()
        sessions.append({'name':name,'explicit_close':closes,'final_close':ref(s/'close-finally.json'),
                         'runner_exit_code_observed':0,'evidence_bundle':ref(s/'evidence.json'),
                         'commands':[ref(p) for p in sorted((s/'commands').glob('*.json'))],
                         'responses':[ref(p) for p in sorted((s/'responses').glob('*.json'))],
                         'failed_requests_retained':failures,'seed_file':ref(s/'seeds.tsv') if (s/'seeds.tsv').exists() else None})
    sources=[
      {'url':'https://www.asus.com/us/supportonly/pro%20ws%20w790-ace/helpdesk_bios/',
       'accessed_date':'2026-11-08','scope':'Exact ACE1904 release entry','observed':'Version1904 support entry explicitly gives PWW790A.CAP for USB BIOS FlashBack. It does not describe acceptance of a modified payload or engineering key.'},
      {'url':'https://dlcdnets.asus.com/pub/ASUS/mb/LGA4677/Pro_WS_W790-ACE/E22143_Pro_WS_W790-ACE_UM_V3_WEB.pdf?model=Pro+WS+W790-ACE',
       'accessed_date':'2026-11-08','scope':'Exact W790-ACE manual E22143 V3, printed2-19/PDF54 and specifications page10',
       'observed':'Use PWW790A.CAP and dedicated FlashBack port/button with standby power. Hold button3 seconds; blinking starts, completion indicated by LED going out. It works without entering the existing BIOS/OS. Manual gives failure indications but no cryptographic trust policy.'},
      {'url':'https://www.asus.com/support/faq/1038568/','accessed_date':'2026-11-08','scope':'ASUS general FlashBack operation, subordinate to model-specific manual',
       'observed':'FAT16/FAT32 MBR USB storage, named CAP at root, system shut down while power remains connected. Do not interrupt active updating. This is operation guidance, not modified-image acceptance evidence.'}]
    write(BASE/'official_sources.json',{'sources':sources})
    chosen=formats['variants']['candidate_original_header']['file']
    official=formats['variants']['official']['file']
    report={
      'schema':'ace1904_flashback_package_review_v1',
      'status':'READY_FOR_FLASHBACK_ONLY_PACKAGE_FIELD_ACCEPTANCE_PENDING',
      'scope':'Prepare the requested package now, with physical USB BIOS FlashBack operation deferred to the user. No BMC/target contact, firmware execution, hardware writes, trust modification or force method.',
      'selected_candidate':{**chosen,'usb_root_filename':'PWW790A.CAP','role':'Candidate05 modified payload with the complete original official4096-byte capsule header retained.'},
      'official_recovery_file':{**official,'usb_root_filename_when_deliberately_prepared_for_recovery':'PWW790A.CAP',
          'role':'Separate original ASUS1904 recovery material; not a backup of the SHUANG-customized machine and does not contain the adaptation.'},
      'engineering_variant':{'sha256':'e330039ecd2c334c4f9d502589e7f9503000b34462a7e21f6b97b1b581794d08',
          'include_in_default_usb_contents':False,'reason':'Its payload is identical to the selected candidate, but it replaces both public-key/signature pairs. No ACE FlashBack evidence shows those changes are required or improve acceptance. BMC standalone validation is a different route.'},
      'selection_basis':[
          'Exact official ACE filename PWW790A.CAP is documented and matches the embedded BIOSRenamer field.',
          'Selected9b038 retains every byte of the official4KiB container header and both original trust-material fields; only the already-tested candidate05 payload is changed.',
          'Selected9b038 and engineeringe330 carry exactly the same64MiB payload SHA2dd240c1ddb8890500ce028bb7de25d2db8f687117f4c0d2a57ba400ffbe9809.',
          'All three CAPs contain the same ASUS_USBFLASHBACK FFS and62-byte model metadata; original EC framework/firmware are also preserved in candidate05.',
          'This is a minimal-change format choice for the authorized field candidate. It is not a measured acceptance advantage or proof of successful FlashBack.'
      ],
      'signature_distinction':{
          'evidence':ref(sigpath),
          'official03e':sig['ASUS_original_valid_signatures'],
          'original_header9b':sig['stale_candidate05_valid_signatures'],
          'engineeringe330':sig['engineering_valid_signatures'],
          'interpretation':'The chosen modified payload is not authenticated by the preserved original firmware signature. Engineering self-contained signature correctness does not establish ASUS FlashBack trust. No claim that either altered variant has OEM-valid signing is made.'},
      'format_and_metadata_evidence':ref(BASE/'materials_validation.json'),
      'metadata_detail':ref(BASE/'usbflashback_metadata_comparison.json'),
      'independent_packaging_review':ref(peer),
      'rea_findings':[
          {'module':'ECUpdateFramework','sha256':'0fc43393d7cdd6da0c8eca4a81e60ccb681d4c7d667b397f2f13f0897e219aa7',
           'observation':'Entry0x4d4 registers an event. Callback0xaa4 walks a controller-update table with one row at0x2e90: firmware GUID38715e0a-ecd3-4776-8ac4-7d93510a7468, detect0xcdc and update0xf60.'},
          {'observation':'Detect0xcdc compares controller state/version against MBEC-W790-0120 through0xb74. Update0xf60 calls0xd6c;0x988 retrieves a Raw section through firmware-volume protocol. The extracted blob is131072 bytes, SHA bdb7cf6460c9c14fa884a80248da57f04bdaa4f3c548b47bf60c65882d80e818.'},
          {'observation':'Update0xd6c performs host-time controller operations and eventually writes reset portCF9. This is original DXE EC maintenance code. It has not been identified as the standalone powered-off FlashBack USB receiver or its CAP signature checker.'},
          {'observation':'The FFS named ASUS_USBFLASHBACK by the GUID database is only106 bytes total, containing62 bytes of model data: $USBFLASH$, Pro-WS-W790-ACE and A5336. It is not executable validator code.'}
      ],
      'unresolved_controller_boundary':{
          'physical_flashback_controller_implementation_identified':False,
          'physical_flashback_signature_policy_proved':False,
          'actual_ACE_modified_CAP_accepted':False,
          'acceptance_status':'NOT_YET_TESTED_ON_HARDWARE',
          'EC_blob_architecture':'The reset bytes020100 and code pattern suggest an8051-family/banked image; exact controller/model/bank mapping was not established. No guessed-architecture analysis is labeled verified.',
          'REA_capability':'Installed REA raw-binary architecture contract lists x86,x86_64,arm,arm64,6502,m68k;8051 is absent. This is a tool limitation, not evidence that the motherboard or FlashBack lacks support.',
          'capability_source':ref(ROOT/'tools/rea-runtime/node_modules/rea-agents/dist/domain/rawBinary.js'),
          'inference_not_made':'EZFlash/SMM rejection is not used to infer FlashBack rejection; BMC acceptance is not used to infer FlashBack acceptance; HERO/W890 outcomes are not substituted for ACE.'},
      'package_contract':{
          'default_usb_files':['PWW790A.CAP'],
          'default_file_sha256':chosen['sha256'],
          'retain_CAP_header':True,'strip_to_raw_SPI':False,'modify_keys_or_signatures':False,
          'official_recovery_separate_from_candidate_usb_directory':True,
          'do_not_mix_engineering_variant_in_default_usb_directory':True,
          'field_acceptance_remains_to_be_recorded':['Correct physical port/button and complete LED sequence','First native boot and permanent-DXE adaptation behavior','Password persistence and protected-settings behavior using the installed BIOS'],
          'claims_to_avoid':['Already accepted/flashed on ACE','Full board backup or guaranteed recovery','Native FlashBack checks/no-checks RSA proven','RAM console or another board proves permanent ACE boot']},
      'official_sources':ref(BASE/'official_sources.json'),
      'analysis_hygiene':{
          'REA':'6.8, Ghidra12.1.4, actual local stdio sessions with full returned Evidence',
          'skill':ref(ROOT/'analysis/hero_ipmi_flash_validation_20261104/field-package/05-PRIOR-REVIEW/20261103-REA/REA-SKILL/SKILL.md'),
          'sessions_closed':3,'analyzed_function_records':len(evidence),'unique_analyzed_functions':len({e['parameters']['procedure'] for e in evidence}),
          'indirect_entry_recovery':'Initial unseeded procedure list omitted the callback and table targets; the failed callback request is retained. A fresh callback seed resolved it and also enabled the two table targets. A subsequent explicit table-target seed repeated two dossiers and added three helpers. Nine records cover seven unique functions; repeated records are not additional independent cases.',
          'old_reports_and_candidates_unchanged':True,'no_firmware_run':True,'no_hardware_access':True,
          'decoder_note':'Independent material check uses the existing documented known-length+EOS RAW decode for05 after host ALONE rejection, requiring exact declared length and EOS. No firmware rejection inferred.'},
      'evidence':evidence,'sessions':sessions,
      'additional_inputs':[ref(BASE/n) for n in ['input_inventory.json','bounded_flashback_string_inventory.json','ec_notify_guid_references.json','verify_flashback_materials.py','rea_session.py']]}
    write(BASE/'flashback_selection_review.json',report)
    text='''W790 ACE1904 Candidate05：USB BIOS FlashBack专用包选型复核

主候选选择保留原厂完整4KiB头的9b038c4e…，复制时仅命名PWW790A.CAP，文件总大小67,112,960字节，不去头、不再改签名。原厂03e43304…单独存放作为恢复材料；e330工程重签变体不放入默认USB目录。

理由：主候选保留原厂容器字段和公钥/签名字节，与e330具有完全相同的Candidate05负载（2dd240c1…）。三份文件的FlashBack板型识别块完全相同；ECUpdateFramework和MBEC-W790-0120控制器固件在候选中原样保留。34项材料格式/身份断言通过。

必须区分：保留原签名字节并不意味着修改后的负载获得原厂有效签名。这个选型是为稍后现场验证准备的最小变更候选，不是已经证明FlashBack接受。

真实REA已检查主机DXE的EC更新入口、事件回调、控制器版本检查、固件加载和更新路径。命名为ASUS_USBFLASHBACK的文件只是62B模型数据，并非验签代码。已找到128KiB MBEC控制器固件，但没有定位并证明独立FlashBack接收器的签名策略；8051分析能力/映射缺口仅是工具与证据边界，不是硬件不支持。

官方ACE文档要求PWW790A.CAP、专用USB端口、待机供电和物理FlashBack按钮；普通ASUS指南要求FAT16/FAT32 MBR媒体及根目录文件。具体操作以本板手册为准。不得用EZFlash拒绝、BMC验签或其它主板结果代替ACE FlashBack接受性。

3个本轮REA会话均已关闭。无带外连接、无实机操作、无候选修改。现场LED完整流程、首次原生启动和永久安装后的密码适配效果仍须实际记录。原厂恢复CAP也不是当前SHUANG机器的完整备份。
'''
    (BASE/'README-FlashBack选型.txt').write_text(text,encoding='utf8')
    write(BASE/'review_index.json',{'status':report['status'],'files':[ref(BASE/n) for n in ['flashback_selection_review.json','README-FlashBack选型.txt','materials_validation.json','usbflashback_metadata_comparison.json','official_sources.json','finalize_flashback_review.py']]})
    print(json.dumps({'report':ref(BASE/'flashback_selection_review.json'),'index':ref(BASE/'review_index.json'),'REA_sessions_closed':3,'REA_function_records':len(evidence)},ensure_ascii=False))


if __name__=='__main__':main()
