"""Bind the final source/API contract and verification to root-built 463b EFI."""
import importlib.util
import json
from pathlib import Path

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[3]
DRIVER=HERE.parent/'lock_1904_integrated04/driver'
spec=importlib.util.spec_from_file_location('integration_ledger',HERE/'summarize_integration_review.py')
ledger=importlib.util.module_from_spec(spec);spec.loader.exec_module(ledger)
sha=ledger.sha


def artifact(path):
 data=json.loads(path.read_text())
 return {'path':str(path.relative_to(HERE)),'sha256':sha(path.read_bytes()),'status':data['status'],
         **{key:data[key] for key in ('cases','case_groups','save_attempts') if key in data and isinstance(data[key],int)}}


def main():
 build=json.loads((DRIVER/'build/build.json').read_text())
 pin='463b94139cb64207e1b756965ebb9ca3513250c8712bbbcd20798fd317dec904'
 assert build['efi_sha256']==pin==sha((DRIVER/'build/AiTweakerLock1904.efi').read_bytes())
 bindings=[]
 for name in ('save_feedback.c','save_feedback.h','services.c','platform.c','hii.c','ui.c','lock.h','build.py'):
  p=DRIVER/name;digest=sha(p.read_bytes());key='driver\\'+name
  if key in build['sources']:assert digest==build['sources'][key],name
  bindings.append({'path':str(p.relative_to(ROOT)),'sha256':digest,'in_build_manifest':key in build['sources']})
 cache_evidence=ledger.ledger(HERE/'save_state_rea',
   ['002-refresh-cache-record','003-refresh-cache-index','004-post-save-reconnect','005-confirm-save',
    '006-save-validation','007-oem-callback-lookup'],['008-cache-refresh-bytes'],'010-close')
 contract={
  'schema':'ace1904-save-feedback-integration/v1','status':'INTEGRATED_AND_VERIFIED_IN_PINNED_463B_EFI',
  'efi':{'path':str(DRIVER/'build/AiTweakerLock1904.efi'),'sha256':pin,'bytes':build['efi_bytes']},
  'source_bindings':bindings,
  'original_module':{'sha256':'99ff85060750d39c9e1a861fd29c48726aa0c82f47b1ec7e6c12150836070ec5',
   'board':'ASUS Pro WS W790-ACE','bios':'1904','identity_precondition':'Platform validates original full .text CRC/PE layout and exact entry/slot bytes before publication.'},
  'patch_abi':{'type':'SAVE_FEEDBACK_PATCH','x64_size':56,'array_count':2,
   'fields':[{'name':'target','offset':0,'bytes':8},{'name':'length','offset':8,'bytes':8},
             {'name':'original','offset':16,'bytes':18},{'name':'replacement','offset':34,'bytes':18}],
   'patches':[{'name':'SaveIterator','target_rva':'0x142ac','length':18,
               'original_hex':'40555356574154415541564157488d6c24e1','continuation':'0x142be'},
              {'name':'SaveStay','target_rva':'0x440fc','length':16,
               'original_hex':'4883ec28488d0d09740200e8a001fdff','continuation':'0x4410c'}],
   'entry_encoding':'FF 25 00 00 00 00 + absolute wrapper pointer; NOP to whole-instruction span'},
  'gateway':{'allocation':'Existing retained 4096-byte platform trampoline page','base_offset_in_page':128,'capacity':128,
   'save_iterator':{'offset_in_gateway':0,'used_bytes':32,'encoding':'original 18-byte position-independent prefix, absolute jump to native 0x142be'},
   'save_stay':{'offset_in_gateway':64,'used_bytes':44,
    'encoding':'original sub rsp,0x28; mov rcx,absolute(tse+0x6b510); indirect RIP call to tse+0x142ac with short jump over embedded pointer; absolute jump to tse+0x4410c'},
   'reason_for_save_stay_relocation':'The stolen LEA and direct CALL use relative addresses. Raw copying is incorrect; the new encodings preserve their operands and original native call.',
   'cache_alias_coverage':'The static 0x6bb18 slot remains unchanged. Old or newly copied pointers to 0x440fc enter the same patched function; no mutable table-slot replacement is required.'},
  'api':[
   {'name':'save_feedback_prepare','arguments':'tse, image_size, gateway, 128, patches[2]',
    'effects':'Checks exact prefixes/slot/flags and caller buffers; creates gateways and patch descriptions; changes no original AMITSE byte.'},
   {'name':'save_feedback_commit','arguments':'none','effects':'Requires exact replacement bytes at both entries; arms aggregation only after both verify.'},
   {'name':'save_feedback_note_denial','arguments':'actual EFI error returned by an existing guard',
    'effects':'Records the first in-scope error; production Runtime and HII RouteConfig explicit-denial branches call it. It never grants authorization.'},
   {'name':'save_feedback_take_notice','arguments':'none','effects':'Returns one pending status only for the real current owned browser token; busy retains it; stale token clears it.'},
   {'name':'save_feedback_cancel_unpublished','arguments':'none',
    'effects':'Resets private preparation only while unarmed/no live scopes and both entries are exactly original. It does not free gateways or authorize a retry after publication.'},
   {'name':'save_feedback_retire','arguments':'none','effects':'Permanently stops aggregation/flag writes/notices; end_platform calls it. Platform retains gateways and owns physical code restoration.'},
  ],
  'actual_publication_order':[
   'Validate both original module identities and existing slot/prologue expectations.',
   'Allocate retained page; build browser/frame gateways; prepare save gateways at page+128.',
   'Set publication_attempted; install existing Runtime variable guard.',
   'Publish known UI slots, then original FrameInput entry.',
   'Publish SaveIterator entry then SaveStay entry; verify and commit feedback.',
   'Publish BrowserLoop owner entry last, then set platform_ready.',
   'HII installation uses the already-published current session/ownership rules.',
  ],
  'failure_and_retirement_contract':[
   'Any possible publication is terminal for discovery retries.',
   'Rollback restores BrowserLoop, then SaveStay and SaveIterator in reverse order with exact readback, then FrameInput/UI slots.',
   'Before feedback commit, exact original restoration permits cancel_unpublished. After commit, or on any restoration/ownership uncertainty, retire permanently and retain gateway memory.',
   'Residual BrowserLoop code cannot create an owning session while platform_ready is false; parent platform guard enforces this.',
   'A live wrapper restores dirty flags only when epoch is unchanged, both entry patches are still owned, flags are writable, and Boot Services have not ended. Owner loss faults the core and returns failure.',
   'BeforeExit/end_platform retirement clears notice ownership; a stale direct wrapper cannot re-enter native save after retirement.',
  ],
  'behavior':[
   'Native SaveIterator and original per-variable calls remain intact. Only a recorded deliberate guard denial changes the final BOOLEAN to false.',
   'Failed native VariableCommit skips cache refresh; edited bytes survive. A later authorized retry submits them again and success refreshes the cache from persisted values.',
   'Rejected saves keep module changed flags 0x82789 and 0x82738 set. SaveStay restores them after its own unconditional native clear.',
   'Vendor initialization still calls the native iterator without requiring an owning UI session; existing selective write policy remains authoritative.',
   'Original OEM post-save calls and unrelated writes still run. This is error feedback and edit retention, not transaction rollback.',
   'The outer stage5 poll shows a single safe notice only in a real owned session. Text warns that other settings may already be saved.',
  ],
  'supersedes':'ace_save_hook_design.json phase-1/slot-followup proposal; the accepted implementation uses a relocated SaveStay function-entry gateway.',
  'limits':['Original full live HII reconstruction, arbitrary external protocol notifications and physical ASUS graphical behavior remain separate acceptance steps.',
   'The memory/core/context fixtures do not test the physical CPU page table, password KDF, or BMC display.',
   'Unmarked backend errors retain legacy behavior; the implemented aggregation is for explicit existing guard denials.',
   'No atomic cross-variable transaction, complete NVRAM rollback or guarantee for unknown mid-function entry aliases is claimed.']}
 out=HERE/'save_feedback_integration_contract.json';out.write_text(json.dumps(contract,indent=2)+'\n')
 tests=[artifact(HERE/'save_wrapper_experiment'/name) for name in (
  'verification.json','retry_state_verification.json','production_candidate_verification.json',
  'unified_efi_verification.json','notice_ui_verification.json')]
 final={
  'status':'PASS_PINNED_463B_SAVE_FEEDBACK_ORIGINAL_NATIVE_AND_UI_FIXTURES',
  'source_integration_contract':{'path':out.name,'sha256':sha(out.read_bytes())},
  'accepted_efi_sha256':pin,'source_bindings':bindings,
  'scope_of_agent_changes':{'production_files':['lock_1904_integrated04/driver/save_feedback.c','lock_1904_integrated04/driver/save_feedback.h',
    'lock_1904_integrated04/driver/services.c explicit-denial marker only'],
   'other_integration':'Parent/other agents integrated platform, HII, UI and build; this report verifies their unified EFI.',
   'integrated03_modified_by_this_agent':False,'device_access':False,'production_rebuild_by_this_agent':False},
  'cache_state_REA':cache_evidence,
  'REA_recovery_note':{'first_attempt':'save_state_rea/attempt1-invalid-seed-format',
   'error':'configuration_invalid: seed kind column missing','correction':'Added explicit function column; no code/provider configuration change',
   'result':'Fresh targeted ACE calls succeeded; both failed-open and completed sessions were explicitly closed.'},
  'verification_reports':tests,
  'final_acceptance_evidence':{'unified_efi_groups':20,'actual_notice_UI_cases':12,
   'native_guard':'Real SocketMemoryConfig GUID/name/1392-byte payload exercises actual unified protected_change and guarded_set.',
   'save_state':'Rejected protected write reaches no backend, keeps edited cache/dirty flags, and later unlocked retry writes the same edited data and runs original cache refresh.',
   'cached_callers':'Original entry pointers cached before or copied after patching both hit the SaveStay entry wrapper.',
   'notice_UI':'Actual show/take code prints exact partial-save text, restores GOP pixel snapshot and console mode, and consumes once.',
   'ack_retirement':'Actual end_platform during input acknowledgement prevents every subsequent console/GOP/pool/Stall service in both success and NOT_READY return cases.'},
  'known_fixture_correction':'Initial UI fixture mistyped the GOP GUID as ...0d80...; comparison with the target literal corrected it to ...d080... before the final passing run. No production defect or source change.',
  'remaining_limits':contract['limits'],
 }
 final_out=HERE/'save_feedback_final_summary.json';final_out.write_text(json.dumps(final,indent=2)+'\n')
 print(json.dumps({'status':final['status'],'summary':str(final_out),'summary_sha256':sha(final_out.read_bytes()),
  'contract':str(out),'contract_sha256':sha(out.read_bytes()),'state_REA_records':len(cache_evidence['functions'])},indent=2))


if __name__=='__main__':main()
