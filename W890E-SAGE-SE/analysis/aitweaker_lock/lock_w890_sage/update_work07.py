"""Record completed physical collection and the user's FlashBack-only route."""
from pathlib import Path
import datetime,json
H=Path(__file__).resolve().parent
p=H/'work_status.json';s=json.loads(p.read_text(encoding='utf-8'))
s.update(current_stage='round07_flashback_route_native_entry_and_exit_adaptation',release_ready=False,flashing_performed=False)
s['remaining_required_work']=[
 'Finish focused Ai Tweaker entry interception while preserving original ordinary HII updates, lifecycle callbacks and BIOS exit paths.',
 'Compose and validate the independent-password menu, first entry and per-visit reset against the final aggregate; current components are not a complete boot test.',
 'Keep dynamic native identity checks valid across HII changes; the two non-FV executable producers remain unexported.',
 'Resolve whether the parser model boundary change is needed in real cold initialization before accepting any change to original parsing code.',
 'Run complete startup, GUI and credential-persistence validation plus reviewed no-flash hardware validation.',
 'Prepare and qualify the complete FlashBack candidate including modified-image acceptance, board boot policy and original-image recovery. BMC updater acceptance is no longer required.'
]
s['current_remote_session'].update(active=False,virtual_cd_attached=False,
 last_observed_stage='Original BIOS Main0603; reviewed Delta07 exited, optical media detached, original boot order/Disabled override verified, owned BMC session logged out HTTP200 at 06:16:32 UTC.',
 host_password_write_count=0)
s['active_work07']={
 'updated_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),
 'state':'IN_PROGRESS_NOT_FLASHABLE',
 'hardware_delta':'hardware_delta07/component_manifest.json',
 'hardware_log_sha256':'6e7a57f9729b082ce15931a063d94a32a56f51d78c9dc8097a80984e9487aa00',
 'hardware_pages':17,'hardware_bytes':12989,'hardware_crc32':'ABFB51BC',
 'restored_objects':5,'omitted_objects':0,'refused_objects':0,'hardware_spf_observations_complete_and_equal':True,
 'dynamic_forms_original_code_replay':'dynamic_forms06/physical_appendix07/result.json',
 'physical_independent_review':'hardware_delta07_review/physical_review.json',
 'composite_parser':'hardware_parser07/component_manifest.json',
 'composite_parser_native_pages':396,'composite_parser_original_control_count':13827,'composite_parser_changed_control_count':13830,
 'composite_parser_emulator_only_branch_experiments':True,
 'source_spf_sample_limit':'Post-Setup only. No allocator ownership or original first-parser state established.',
 'unknown_producers':'Two independent NON_FV instances each expose NicCfgData/4 forms/40 questions; static structure decoded, callback effects and executable provenance not qualified.',
 'callback_shape_review':'callback_shapes07/component_manifest.json',
 'callback_shape_candidates':1187,'callback_shapes_not_runtime_authority':True,
 'original_exit_tail':'exit_control07/component_manifest.json',
 'early_exit_guard':'navigation07_exit/component_manifest.json (28 cases; cancellation only, not normal exit)',
 'native_lifecycle_adaptation':'navigation08 (separating UI entry protection from unchanged native lifecycle)',
 'pending_hii_adaptation':'pending_hii08 (original-code analysis under way)',
 'native_callback_consumers':'native_callbacks08 (under analysis)',
 'original_boot_policy':'boot_policy07/component_manifest.json',
 'flashback_route':'flashback07/component_manifest.json',
 'flashback_original_filename':'A5709.CAP',
 'password_operations':0,'firmware_flash_requests':0,
 'no_modified_cap_rom_or_private_test_keys_persisted':True,
 'release_limit':'No complete hardware lock qualification or FlashBack acceptance has occurred; no flashable release claimed.'}
s['deployment_preference']={'route':'USB BIOS FlashBack','user_statement':'我可以接受只用flashback更新BIOS的',
 'bmc_updater_acceptance_required':False,'modified_cap_flashback_acceptance_proven':False,
 'onsite_usb_availability_confirmed':False,'hardware_flash_performed':False}
p.write_text(json.dumps(s,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
progress=H/'hardware_delta07/session_progress.json';v=json.loads(progress.read_text())
v.update(status='COLLECTION_COMPLETE_ORIGINAL_MAIN_SESSION_CLOSED',owned_controller_pty=None,
 virtual_media_attached=False,collector_executed_on_hardware_proven=True)
v['events'] += ['Original Main0603 observed in screen-90. Boot tab selected; screen-93 confirms the optical Boot Override item before Enter.',
 'Delta07 executed and showed17 QR pages. All12989B recovered with CRCABFB51BC; strict reconstruction restored all5 objects with no omissions or refusals.',
 'Escape returned to original Exit; Right returned to Main, media detached. screen-96 and state07-1794118563252 confirm Main0603/PowerOn/unchanged order/Disabled override.',
 'Owned keepalive stopped, isolated Redfish client disposed, BMC browser session logout HTTP200 at06:16:32 UTC; controller exited0.']
v['events']=list(dict.fromkeys(v['events']))
progress.write_text(json.dumps(v,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
print(json.dumps({'file':str(p),'stage':s['current_stage'],'remote_active':False,'release_ready':False}))
