"""Pin local BMC UI/REA evidence and classify the normal update sequence.

This parses saved text only. It has no HTTP client, credentials or device actions.
The browser UI is not the native BMC verifier and does not establish its policy.
"""
from pathlib import Path
import hashlib,json

HERE=Path(__file__).resolve().parent
REMOTE=HERE.parent/'remote_172_20_2_245/update-capabilities-1794099031025'
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def binding(p):return dict(path=str(p.resolve()),size=p.stat().st_size,sha256=sha(p))
def read(p):return json.loads(p.read_text(encoding='utf-8'))
def save(name,obj):(HERE/name).write_text(json.dumps(obj,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')

source=HERE/'bmc_update_source/BIOSUpdateView.js'
assert sha(REMOTE/'source.min.js')=='4edc19419e3478f362999b020d4381be2cdcef55431168e0235856adf46af296'
assert sha(source)=='12e3d136cd5975c7567fa870a297b622b1c9e9d67f59f0c07592c8aab867c874'
derivation=read(HERE/'bmc_update_source_derivation.json')['modules'][0]
assert (REMOTE/'source.min.js').read_bytes()[derivation['utf8_start']:derivation['utf8_end']]==source.read_bytes()
ast=read(HERE/'bmc_update_ast_functions.json')
methods={f['name']:f for f in ast['selected']}
text=source.read_text(encoding='utf-8')
for f in methods.values():assert text[f['start']:f['end']]==f['source']
rea=read(HERE/'bmc_update_rea_summary02.json')['summary']
assert rea['normalized_result']['parent_evidence_id']=='ev_50f55fc940dfcf0c44d4a4872a585c31397b2702a7f2dcdde21f69418d100ba9'
stats=rea['normalized_result']['summary']['statistics']
assert stats['parsed_javascript_files']==1 and stats['parse_failures']==0

def step(name,method,path,classification,next_name=None,payload=None):
    f=methods[name]
    assert f'type:"{method}"' in f['source']
    assert path in f['source'] or path.split('/')[-1] in f['source']
    if next_name:assert next_name+'.call(' in f['source']
    return dict(function=name,method=method,path=path,classification=classification,
                function_utf16_start=f['start'],function_utf16_end=f['end'],
                function_source_sha256=hashlib.sha256(f['source'].encode()).hexdigest(),
                success_next=next_name,payload=payload)

steps=[
 step('EntryUpdateMode','PUT','/api/maintenance/bios/updatemode','MUTATES_UPDATE_SESSION','PrepareComponents','Empty JSON, response unique_id retained'),
 step('PrepareComponents','PUT','/api/maintenance/bios/preparecomponents','PREPARES_COMPONENT; NOT_PROVED_READ_ONLY','UploadSignature','FWUPDATEID, COMPONENT_ID=2, IS_MMC=0, COMPONENT_DATA_LEN=CAP size minus size modulo 16 MiB'),
 step('UploadSignature','POST','/api/maintenance/bios/uploadSignature','STAGES_COMPLETE_CAP','VerifySignature','FormData biossignature receives the whole selected CAP'),
 step('VerifySignature','PUT','/api/maintenance/bios/verifySignature','VERIFICATION_ACTION_AFTER_PREPARE','UploadBIOS','Empty JSON; backend policy and side effects not in UI source'),
 step('UploadBIOS','POST','/api/maintenance/bios/biosfw','STAGES_FIRMWARE_BODY','GetBIOSInfo','FormData hpmbios receives CAP slice(size modulo 16 MiB, size)'),
 step('GetBIOSInfo','GET','/api/maintenance/biosversion','GET_AFTER_STAGING; NOT_A_PREUPLOAD_READONLY_FLOW',None,'FWUPDATEID and component ID'),
 step('FlashBIOS','PUT','/api/maintenance/bios/flash','FLASH_ACTION','FlashProgress','Normal SECTION_FLASH=0, FlashOffset=0, component ID 2 and component data length'),
 step('VerifyBIOS','PUT','/api/maintenance/bios/verifyimage','POST_FLASH_VERIFICATION','VerifyFlashStatus','Component data length and offset 0'),
 step('ActivateComp','PUT','/api/maintenance/bios/activatecomponents','ACTIVATION_ACTION','ExitUpdateMode','Component ID 2'),
 step('ExitUpdateMode','PUT','/api/maintenance/bios/exitupdatemode','UPDATE_SESSION_EXIT',None,'FWUPDATEID and component ID'),
]
assert 'a.size-a.size%16777216' in methods['PrepareComponents']['source']
assert 'a.size%16777216' in methods['UploadBIOS']['source']
assert 'l.append(r,n)' in methods['UploadSignature']['source']
assert 't.ExitUpdateMode.call(t),t.cleanInfoBar()' in methods['VerifySignature']['source']
cap=read(HERE/'original_static_review.json')
cap_bytes=67112960
action=read(REMOTE/'02-metadata.json')
assert action['method']=='GET' and action['status']==200

report=dict(target='ASUS Pro WS W890E-SAGE SE 0603 / ASMB12-iKVM 2.01.11',
    status='STATIC_UI_SEQUENCE_VERIFIED_BACKEND_ACCEPTANCE_UNKNOWN',release_ready=False,
    analysis_method='Exact UTF-8 source slice and Babel AST + actual REA JavaScript analysis, inert text only',
    sources=[binding(REMOTE/'source.min.js'),binding(source),binding(HERE/'bmc_update_source_derivation.json'),
             binding(HERE/'bmc_update_ast_functions.json'),binding(HERE/'bmc_update_rea_evidence02.json'),binding(REMOTE/'02-metadata.json')],
    rea=dict(evidence_id=rea['normalized_result']['parent_evidence_id'],parsed_files=1,parse_failures=0,
             scope='Only exact BIOSUpdateView module, not whole BMC backend',
             semantic_status=rea['normalized_result']['summary']['coverage']['semantic']['status'],
             limitations='REA does not resolve all jQuery AJAX/call-flow semantics. Exact AST function bodies and manual trace support this sequence; no application code executed.'),
    normal_cap_path=steps,
    initial_ui_conditions=['Host reports powered off in ordinary mode; chassis-off settling delay must expire.',
                           'Selected file nonempty, extension .cap in ordinary mode.'],
    after_staging_before_flash_checks=['CAP versus current baseboard ID equality',
        'Configured minimum major/minor BIOS version',
        'CAP hardware version not older than current hardware version',
        'CAP versus current project path equality','Explicit UI continue confirmation'],
    ui_payload_for_supplied_original=dict(cap_size=cap_bytes,header_removed_by_modulo=cap_bytes%0x1000000,
        body_uploaded=cap_bytes-cap_bytes%0x1000000,prepare_component_data_len=cap_bytes-cap_bytes%0x1000000,
        descriptor_bios_region_length=0x3000000,
        interpretation='UI passes 64 MiB body and length; descriptor BIOS area is 48 MiB. Backend may select regions; actual written SPI ranges cannot be derived from these UI values.'),
    redfish_action_info=dict(resource=action['resource'],parameters=action['data']['Parameters'],
        limitation='Advertisement of action and parameters only; no validation-only flag or safe dry-run semantics established here.'),
    conclusions=['Normal CAP signature verification is preceded by update-mode entry and component Prepare.',
        'Opening a Start/verification flow cannot be described as a proved read-only compatibility check.',
        'Original signed DXE mutation fails offline firmware signature verification; UI promises no exception.',
        'ForceMode-related branches exist in source but do not prove unsigned acceptance, preservation of machine-specific data or recovery. They are not a validated deployment path.'],
    unknowns=['BMC native verifier/trust store and exact signature coverage',
        'Actual SPI region selection and preservation of descriptor/ME/NVRAM/unit identity data',
        'Prepare/verification cancellation side effects and crash/power-loss behavior',
        'Rollback or remotely reachable recovery if host cannot POST',
        'Actual platform boot-integrity enforcement for altered DXE',
        'Supported acceptance/signing path for a future complete modified candidate'],
    actions_performed=dict(network=False,upload=False,prepare=False,flash=False,activation=False,application_source_execution=False))
save('bmc_update_path_review.json',report)
print(json.dumps(dict(status=report['status'],sha256=sha(HERE/'bmc_update_path_review.json'),steps=len(steps))))
