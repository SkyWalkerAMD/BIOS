"""Write a bounded TX09 derivation plan only; do not copy/change/build sources."""
from pathlib import Path
from datetime import datetime,timezone
import hashlib,json
HERE=Path(__file__).resolve().parent;D04=HERE.parent;OLD=D04/'ram_transaction08'
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
def item(p):return {'path':str(p.relative_to(D04)),'bytes':p.stat().st_size,'sha256':sha(p)}
def main():
 assert not (HERE/'source').exists() and not (HERE/'app_build').exists()
 manifest=OLD/'ram_candidate_manifest.json';assert sha(manifest)=='7f08d975710179f88f953636b1da72db34ebd0c41ef04447bdf40b296a599e96'
 frozen=json.loads(manifest.read_text())
 for row in frozen['artifacts']:
  p=D04/row['path'];assert p.stat().st_size==row['bytes'] and sha(p)==row['sha256'],p
 assert sha(OLD/'app_build/SageNative13RamTest08.efi')=='e0793175f78b6488c8222b65f0d5321d97e881bd06dca033a314d3fa8d307486'
 header=D04/'diagnostic_design09/diagnostic09.h';contract=D04/'diagnostic_design09/schema_contract.json'
 assert sha(header)=='3cf976a0e3d90bdd813f24bfe1702fb67286e66b9f06150ff4c5e6ee72c05cdc'
 schema=json.loads(contract.read_text());assert schema['header_sha256']==sha(header)
 assert(schema['offset_in_owned_state'],schema['region_bytes'],schema['end_exclusive_in_owned_state'],schema['unchanged_prefix_bytes'])==(64,576,640,32)
 build=json.loads((OLD/'app_build/app_build.json').read_text())
 for row in build['sources']:assert sha(OLD/row['path'])==row['sha256']
 result={'status':'PLAN_ONLY_AWAITING_FROZEN_DIAGNOSTIC_GUARD09_AND_PROVIDER15_NO_NEW_EXECUTABLE',
  'utc':datetime.now(timezone.utc).isoformat(),'device_actions':0,'source_mutations':0,'builds':0,
  'outputs_reserved':{'app_directory':'ram_transaction09','efi':'ram_transaction09/app_build/SageNative13RamTest09.efi',
   'log_prefix':'AITWK-P3-KVM\\r\\nSAGE_NATIVE13_RAM_TEST09\\r\\n','log_end':'SAGE_NATIVE13_RAM_TEST09_END',
   'root_delivery_directory':'ram_test09_delivery','root_round':'continuation12','root_decoder':'read_native13_ram_test09_qr.py'},
  'frozen_predecessor':{'app_sha256':build['efi_sha256'],'manifest':item(manifest),'manifest_items_verified':len(frozen['artifacts']),
   'build':item(OLD/'app_build/app_build.json'),'compiled_source_count':len(build['sources'])},
  'diagnostic_contract':{'header':item(header),'schema':item(contract),'state_total_bytes':4096,'original_public_prefix':[0,32],
   'untouched_prefix_gap':[32,64],'owned_trace_extent':[64,640],'trace_bytes':576,'trace_header_bytes':64,'first_record':[128,384],'request_record':[384,640],
   'trace_magic':'0x3930474149444753','revision':1,'header_bytes_value':576,'public_abi_changed':False,
   'unchanged_abi_bytes':{'provider':56,'frame':48,'context':96,'immutable_binding':160,'public_state':32}},
  'planned_source_changes':[
   {'file':'source/app.c','change':'Only RAM_TEST08 -> RAM_TEST09 title and snapshot prefix/end markers. No action/menu/schema additions, automatic keys, retry or alternate exit.'},
   {'file':'source/transport/kvm.c','change':'Only diagnostic family/title markers; retain per-service ending checks. Root owns package/optical media/control tools.'},
   {'file':'source/diagnostic09.h','change':'Copy exact final approved schema header; static bounds/layout assertions. No extra live pointer or API is introduced.'},
   {'file':'source/platform.c','change':'Include the exact schema. Immediately after the existing whole-state4096B zeroing and unchanged public magic/phase initialization, initialize only trace magic, revision and bytes at state+0x40. This occurs while the exclusively owned state page is validated RW/NX, before provider LoadImage and before tx_prepare/publishing any original hook.'},
   {'file':'source/split_profile.h','change':'Regenerate from finalized diagnostic_guard09/provider15 exact immutable template, original identity,12 target RVAs,trampolines and begin/end callsite binding; never hand-adjust accepted CRCs or weak identity predicates.'},
   {'file':'source/provider_asset.h','change':'Embed exact final provider15 PE, declared header/VirtualSize/BSS range hashes, all DIR64 RVAs, preferred ImageBase, exact native_provider object and five method RVAs.'},
   {'file':'source/transaction_plan.h','change':'Regenerate from final diagnostic guard build. Require original module identity/site RVA/kind/length/original bytes unchanged versus TX08; only guard target offsets/guard byte sizes may change.'},
   {'file':'source/session_ui.c','change':'If needed, only exact P14 -> P15 diagnostic label. Existing post-globals recheck, ActionRequest NONE0, ownership/TPL/ending gates, private exact cleanup and OC/MEM observations remain byte-identical in logic.'},
   {'file':'build and verification scripts','change':'Derive new names/directories/frozen manifest identities only. Regenerate all assets rather than reuse old P14 mapped sizes. Re-run actual complete TX09 code tests; no old hash result transfer.'}
  ],
  'allocation_and_lifecycle':[
   'No additional pages or allocation are needed for the trace. It lies inside the existing4096B state payload with both existing neighboring allocation pages unchanged.',
   'Guard code may grow beyond the old five payload pages. Use actual new guard_size rounded upward plus existing two neighbor pages; preserve below2GiB/rel32/exclusion bounds. Do not fix the old page count or silently truncate.',
   'The state prefix remains32B; trace begins at0x40. No mutation of module PE size/header, foreign page permissions, RuntimeServices, original native app/reset flags, file, flash or protected-variable contents.',
   'State, guards, provider context, LoadedImage cached span and application remain resident through partial start, normal rollback and shutdown. No new FreePages/UnloadImage/reinitialize/reuse path.',
   'tx_end retains its existing state.phase=ENDED behavior. tx_remove changes only its existing public phase and original12 sites; no trace clearing on remove or new validation dependency.',
   'Trace validity/counters/CRC never enter grant, owner, tx_validate or rollback predicates. Malformed trace is unavailable diagnostics; underlying allow/deny behavior stays unchanged.',
   'Guard/provider own bounded nonblocking writer, stable-even-commit reader and prompt display. App adds no trace reader/exporter or service call; Q remains the existing schema.'
  ],
  'required_frozen_inputs_before_source_derivation':[
   'Exact diagnostic_guard09 template/build/patch list plus actual differential policy, native-constructor and recording-boundary results.',
   'Exact provider15 EFI/map/build/generated split profile and immutable source manifest, including reviewed schema header SHA.',
   'Independent diagnosis/presentation review of no-secret field allowlist, EBS/TPL prints, nested request/overflow/torn record and acknowledgement sequencing.',
   'Explicit confirmation of state extent, original public ABI and unchanged12 native windows; any change requires renewed plan review rather than automatic adaptation.'
  ],
  'verification_plan':[
   'Verify frozen TX08 source/build81 and unchanged artifact hashes before and after one-shot copies into new TX09 only. Snapshot all source provenance and reject conflicting existing outputs.',
   'Actual platform_prepare writes the correct trace header only after exclusive state ownership; initial gap [0x20,0x40) and tail [0x280,0x1000) remain zero. Validate before any installed site/provider start.',
   'Exercise both mode allocations. Trace initialization/content does not weaken invalid identity, mapping, permission, original-site, context or provider-loader refusal paths.',
   'Corrupt trace magic/revision/bytes/counters/record during an installed fixture and require identical transaction removal/restoration behavior; diagnostic availability is not a new rollback gate.',
   'Re-run exact full-app75 transaction,43 platform,37 publication/TPL/partial-StartImage,23 globals and independent20 entry/ending suites; update only target assets and documented assertions for new private state bytes.',
   'Verify runtime constructed guard blobs equal final provider-bound expected bytes and actual provider accepts the original owner/frame callsites. Full new provider size and all declared sections/BSS/relocations get actual OVMF validator coverage.',
   'Re-run full-app UI boundary matrix on TX09: first M still optional only after initial/mode1/mode2 snapshots; no policy relaxation or additional UI action is inferred from diagnostics.',
   'Independent review must bind final EFI/ISO/physical controls and all dependencies before parent considers a new diagnostic session. Root optical/QR smoke remains unsupported-platform refusal, not positive ASUS GUI.',
   'Physical diagnostic prompt fields need a new screenshot; local kind4 constructor evidence is a hypothesis and must not be synthesized as an actual captured result.'
  ],
  'explicit_nonclaims':[
   'No source copied, changed, compiled, packaged or booted by this plan.',
   'No kind4 allowance, automatic browser escape or password authentication policy change.',
   'Not a fix or acceptance of C11 management UI; not permanent direct-Del protection or flash readiness.'
  ],
  'bindings':[item(OLD/'source/platform.c'),item(OLD/'source/transaction.c'),item(OLD/'source/transaction.h'),item(OLD/'source/split_owner.h'),item(OLD/'source/session_ui.c'),
   item(OLD/'build_transaction.py'),item(OLD/'generate_platform_assets.py'),item(OLD/'build_app.py'),item(D04/'diagnostic_design09/diagnostic_plan.json'),
   item(D04/'management_request_review09/diagnostic_review_requirements.json'),item(Path(__file__))]}
 out=HERE/'integration_plan.json';assert not out.exists();out.write_text(json.dumps(result,indent=2,ensure_ascii=False)+'\n',encoding='utf-8')
 print(json.dumps({'status':result['status'],'plan_sha256':sha(out),'schema_sha256':sha(contract)}))
if __name__=='__main__':main()
