"""Bind offline findings to exact source hashes and native instruction bytes."""
import sys
sys.dont_write_bytecode=True
from pathlib import Path
import hashlib,json,struct,datetime
HERE=Path(__file__).resolve().parent
BASE=HERE.parents[2]
ROOT=HERE.parents[5]
sys.path.insert(0,str(ROOT/'tools/pydeps'))
import pefile,capstone
CS=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64)
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
paths={
 'AMITSE':BASE/'analysis/modules/AMITSE.efi',
 'Setup':BASE/'analysis/modules/Setup.efi',
 'OriginalBds':HERE/'OriginalBds.efi',
 'OriginalDxeCore':HERE.parent/'runtime_navigation/OriginalDxeCore.efi',
}
identities={k:{'path':str(p),'sha256':sha(p),'size':p.stat().st_size} for k,p in paths.items()}
images={k:pefile.PE(str(p)).get_memory_mapped_image() for k,p in paths.items()}
def block(module,start,size,label):
 data=images[module][start:start+size]
 ops=list(CS.disasm(data,start))
 return {'module':module,'rva':hex(start),'length':size,'label':label,'bytes_hex':data.hex(),
         'decoded_length':sum(o.size for o in ops),
         'instructions':[{'rva':hex(o.address),'bytes':o.bytes.hex(),'mnemonic':o.mnemonic,'operands':o.op_str} for o in ops]}
blocks=[
 block('AMITSE',0x1191,0x17,'AMITSE stage reset, protocol installer, then additional initialization'),
 block('AMITSE',0x2624,0x107,'AMITSE installs BootManager then FormBrowser2 then other interfaces'),
 block('AMITSE',0x77e4,0x66,'Post-FormBrowser2 protocol notify registration and proactive SignalEvent'),
 block('AMITSE',0x2b21,0x4c,'BootManager conditional Setup entry to browser loop'),
 block('AMITSE',0xe1e2,0x0b,'Browser begins stage4'),
 block('AMITSE',0xe1fe,0x2f,'Stage4 initialization calls InstallMultipleProtocolInterfaces before stage5; pending notifications can run on its RestoreTPL'),
 block('AMITSE',0xe655,0x0b,'Browser enters stage5'),
 block('AMITSE',0xe8d0,0x22,'Outer browser calls AppInput slot synchronously'),
 block('AMITSE',0x1208c,0x52,'Hotkey object creation and callback binding from 24-byte records'),
 block('AMITSE',0x12168,0x50,'AppInput iterates hotkey objects'),
 block('AMITSE',0x18c40,0x64,'Hotkey compares key and calls registered callback'),
 block('AMITSE',0x330a8,0x17,'F10 callback saves first then sets app exit flag'),
 block('AMITSE',0x1422c,0x2d,'Save-and-exit wrapper synchronously calls save routine'),
 block('AMITSE',0x1483a,0x55,'Generic save loop calls variable commit before returning'),
 block('AMITSE',0x11164,0xa4,'Generic variable commit chooses runtime SetVariable or ConfigRouting'),
 block('AMITSE',0x974,0x1d,'HiiConfigRouting LocateProtocol stores interface at 0x83408'),
 block('AMITSE',0x1dbea,0x21,'Synchronous HiiConfigRouting RouteConfig invocation'),
 block('Setup',0x5f6,0x1d,'SystemTable RuntimeServices pointer initialization'),
 block('Setup',0x152c,0x5,'Setup RouteConfig trampoline'),
 block('Setup',0x27cc,0x37,'Successful Setup RouteConfig ends in RuntimeServices.SetVariable'),
 block('AMITSE',0x34b2c,0x5f,'Poll pointer is filled only when NULL; installed non-NULL proxy prevents lazy overwrite'),
 block('OriginalBds',0xb38,0x2c,'BDS architectural protocol interface registration'),
 block('OriginalBds',0x2817,0x28,'BDS sequential function-pointer dispatch'),
 block('OriginalBds',0x1987,0x59,'EndOfDxe event creation, signal and close'),
 block('OriginalBds',0x269c,0x2d,'BDS locates AMITSE BootManager and calls first member'),
 block('OriginalDxeCore',0x24d4,0x5b,'DXE dispatcher runs before BDS architecture Entry'),
 block('OriginalDxeCore',0x9bb5,0x4b,'Dispatcher rechecks eligible DEPEX entries until no new scheduled drivers'),
 block('OriginalDxeCore',0x9c85,0x42,'Dispatcher starts each scheduled image synchronously'),
 block('OriginalDxeCore',0x84a6,0x81,'LoadedImage initially installed without notification, then image loader and reinstallation'),
 block('OriginalDxeCore',0x91ca,0x32,'LoadedImage reinstallation signals registered notify events'),
 block('OriginalDxeCore',0x4af8,0x21,'InstallMultipleProtocolInterfaces saves current TPL and raises to16'),
 block('OriginalDxeCore',0x4a51,0x32,'Protocol installer signals registered events'),
 block('OriginalDxeCore',0x4be7,0x1a,'InstallMultiple restores original TPL before returning'),
 block('OriginalDxeCore',0xccac,0xa3,'RestoreTPL selects pending event level and calls callback synchronously'),
 block('OriginalDxeCore',0xcd8b,0x39,'RestoreTPL restores caller level after pending higher-level callbacks'),
]
sources={}
for rel in ['driver/entry.c','driver/platform.c','driver/services.c','driver/build/AiTweakerLock1904.efi','lab/inject_ovmf.py','lab/build_asus_review.py','lab/asus_review_exp02/verification.json']:
 p=BASE/rel;sources[rel]={'path':str(p),'sha256':sha(p)}
recipe=json.loads((BASE/'lab/asus_review_exp02/W790E-SAGE-SE-1904-lock-EXP02.review.json').read_text())
inventory=json.loads((HERE/'dxe_order_inventory.json').read_text())
bds_table=[]
for i in range(200):
 a=0x15ff0+i*8;v=struct.unpack_from('<Q',images['OriginalBds'],a)[0]
 bds_table.append({'index':i,'rva':hex(a),'function':hex(v)})
 if not v:break
hotkey=images['AMITSE'][0x6ccb8:0x6ccd0]
pointer_slots=[]
for module,slot,want in [('AMITSE',0x6b4f0,0x2780),('AMITSE',0x6b840,0x12168),('AMITSE',0x6b9f0,0x18c2c),('AMITSE',0x6ccc0,0x330a8),('OriginalBds',0x15108,0x26cc),('OriginalDxeCore',0x15e90+0x148,0x4ac0),('OriginalDxeCore',0x15e90+0x20,0xcc98)]:
 value=struct.unpack_from('<Q',images[module],slot)[0];assert value==want
 pointer_slots.append({'module':module,'rva':hex(slot),'value':hex(value),'bytes':images[module][slot:slot+8].hex()})
for module,site,want in [('AMITSE',0x2b65,0xe1b8),('AMITSE',0x330b1,0x1422c),('AMITSE',0x14237,0x1425c),('AMITSE',0x1484a,0x11164),('AMITSE',0x111c7,0x1d8d8),('OriginalDxeCore',0x24d4,0x9a74)]:
 data=images[module][site:site+5];assert data[0]==0xe8 and site+5+struct.unpack_from('<i',data,1)[0]==want
assert images['Setup'][0x27ec:0x27ef]==bytes.fromhex('ff5058')
assert all(b['length']==b['decoded_length'] for b in blocks)
assert bds_table[7]['function']=='0x194c' and bds_table[61]['function']=='0x25ec'
report={
 'schema':'sage1904-offline-entry-save-timing/v1',
 'created_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),
 'scope':{'device_access':False,'firmware_writes':False,'production_source_changes':False,'new_capsule':False,'evidence_kind':'shipped-artifact static bytes and local source; no new native or hardware replay'},
 'artifacts':identities,'source_hashes':sources,
 'question_status':{'F10_save_before_outer_return':'answered for identified native F10 chain','normal_BDS_EndOfDxe_before_first_Setup':'answered for unmodified sequential BDS table path','all_discovery_prerequisites_ready_at_EndOfDxe':'not dynamically observed; conditional static support only','all_OEM_Save_UI_paths':'not exhaustively established','one_shot_attach_recovery':'observed source limitation, unchanged','late_first_attach_at_stage4':'conditional integration gap established from source/native control flow; trigger frequency unmeasured'},
 'confirmed_static_findings':[
  {'id':'SAVE01','claim':'The native F10 hotkey callback commits variables synchronously before setting browser exit flag. Therefore, if production browser_loop was installed before entry, the identified commit calls run while its session remains active.',
   'chain':['0xe1b8 outer browser -> indirect AppInput at 0xe8ec, slot 0x6b840=0x12168','0x12168 -> hotkey slot 0x6b9f0=0x18c2c','0x18c9f -> callback from key record 0x6ccb8, scan 0x14, callback0x330a8','0x330b1 ->0x1422c -> call0x14237 ->0x1425c','save loop0x1484a ->0x11164','0x111e8 RT.SetVariable OR0x111c7 ->0x1d8d8 ->0x1dc08 HiiConfigRouting.RouteConfig','Setup ConfigAccess RouteConfig0x152c ->0x2568 ->0x27ec RT.SetVariable','only after save returns:0x330b6 stores app+0x5a'],
   'qualification':'F10 binding is also corroborated by native AMITSE HII strings26 and165. ConfigRouting dispatch to a given variable owner depends on runtime HII registrations; Setup is the reviewed owner implementation, not a replayed routing engine.'},
  {'id':'BDS01','claim':'On the original sequential BDS table path, EndOfDxe is signaled before the BootManager call that can open the first Setup browser.',
   'chain':['BDS architectural interface at0x15108 points to0x26cc','0x2817 selects table0x15ff0;0x2828 calls entries in index order','index7,table0x16028 points to0x194c;0x19b7 CreateEventEx(EndOfDxe,TPL8),0x19ce SignalEvent','index61,table0x161d8 points to0x25ec;0x26b1 locates8a91b1e1-56c7-4adc-abeb-1c2ca1729eff;0x26c1 calls interface[0]','AMITSE0x2624 publishes that interface at0x6b4f0 with interface[0]=0x2780','AMITSE0x2b65 calls0xe1b8 only later;0xe655 sets stage5'],
   'qualification':'Does not prove every possible OEM earlier SendForm callback is absent, nor that all runtime prerequisites/allocations succeed.'},
  {'id':'TPL01','claim':'Notify dispatch is synchronous while RestoreTPL lowers below a pending notification level. A driver TPL8 FormBrowser2 notify can run inside AMITSE InstallMultipleProtocolInterfaces before that install API returns when original caller TPL is4.',
   'chain':['DXE Core BS table0x15e90+0x148=0x4ac0','0x4af8 saves current TPL;0x4b0e sets TPL16','internal installer0x4a5e signals registered protocol notifications','0x4bea RestoreTPL0xcc98 drains eligible pending callbacks;0xcd4c calls event.NotifyFunction','AMITSE publishes FormBrowser2 at0x268e; it continues more interface installs and then0x77a0 after0x2624 returns'],
   'qualification':'The instruction behavior is observed statically. Actual current TPL and exact delivery order on a physical cold boot have not been measured.'},
  {'id':'LOAD01','claim':'Original DXE Core installs LoadedImage with notify=false before its image loader, then calls image loading and reinstallation, which signals notifications. Discover must not equate LoadedImage publication with image entry point completion.',
   'chain':['0x84be sets install notify=false;0x84c3 installs LoadedImage','0x84db calls image loader0x7ae0','0x8522 reinstalls LoadedImage via0x90bc;notify loop0x91d7 SignalEvent','DXE dispatcher LoadImage0x9b31 precedes StartImage0x9ca8'],
   'qualification':'AMITSE FormBrowser2 publication guards AMITSE progress beyond loader completion; Setup can still be loaded before its entry has published HII. Current attach permits pending HII then retries HII at outer browser entry, so absent HII alone is not the one-shot attach blocker.'},
  {'id':'DISCOVERY01','claim':'Normal DXE dispatch is run before BDS entry. EXP02 appends the production driver in the same main inner FV with VariableArch AND VariableWriteArch dependency; it does not explicitly order before AMITSE. Successful eligible driver dispatch gives it opportunities to attach before the BDS Setup call.',
   'chain':['DXE Core0x24d4 calls dispatcher0x9a74 before0x252d BDS.Entry','dispatcher checks/schedules dependent entries0x9bdf and loops0x9bfe until no newly eligible entries','Original Setup FFS offset0x3d2758 has10 protocol dependencies; original AMITSE FFS offset0xfbb688 has no DXE dependency section in extracted section tree','driver depex contains only VariableArch AND VariableWriteArch; neither Setup/AMITSE nor lock driver appears in original20-entry apriori list'],
   'qualification':'A completed dispatch pass is not proof every dependency was satisfied or every image entry succeeded. SMBIOS configuration table publication and exact driver snapshot at EndOfDxe remain unmeasured.'},
  {'id':'SLOTS01','claim':'The bounded linear .text scan found only indirect reads/calls for static render/page/app slots and only a NULL-conditional LocateProtocol fill for poll slot0x837d8. It did not establish a normal post-FormBrowser2 overwrite of the installed non-NULL poll proxy.',
   'qualification':'RIP-relative scan is not an exhaustive indirect-write alias analysis. Navigation slot can be reached via table base, so absence of direct RIP writes is not proof of complete absence.'},
  {'id':'SAVE02','claim':'The generic save loop does not check the per-variable commit return at0x1484a before advancing to the next record;0x1488c returns true. A visible successful Save/Exit alone therefore cannot demonstrate every guarded write persisted.',
   'qualification':'This is behavior of the original OEM save loop, not a newly introduced lock defect. Acceptance must compare saved settings/readback after reboot, especially after any guard-denied write.'},
 ],
 'source_observations':[
  {'id':'SOURCE01','claim':'entry.c discover skips stage5 without setting attempted, allowing later retry; failed attach sets attempted before call and cancels discovery timer, so it is one-shot even when later readiness changes.',
   'classification':'late-first-entry coverage and fault recovery limitation; stage5 fixture is not evidence normal integrated DXE starts late'},
  {'id':'SOURCE02','claim':'platform.c starts session at outer0xe1b8 wrapper entry and ends only after original_loop returns. It does not intentionally retain authentication for writes after browser return.',
   'classification':'matches identified synchronous F10 save chain; no evidence-based reason to widen authorization lifetime'},
  {'id':'SOURCE03','claim':'Failed attach after guard installation can leave a guarded SetVariable chain and faulted core; rollback does not verify all restore calls. Blindly clearing attempted could double-hook or retry over partial patches.',
   'classification':'fault recovery restriction; current fail-closed state is intentional protection, not by itself a normal-path feature defect'},
  {'id':'SOURCE04','claim':'discover rejects only stage5, but stage4 occurs inside original_loop after its entry prologue has already executed (AMITSE0xe1e2), not only before browser entry. If first successful attach occurs after0xe1e2 and before0xe655, the current original call does not retroactively pass through the newly patched entry wrapper. loop_depth remains0, so render/page_input/app_input/frame_input/poll gating conditioned on loop_depth is skipped for that current invocation.',
   'reproducible_condition':['Driver loaded but has not successfully attached.','First native0xe1b8 call begins unwrapped, executes0xe1e2 stage=4.','A discovery event runs in this stage4 initialization window with all discovery checks now true.','attach succeeds and patches0xe1b8 and UI slots.','Execution resumes within the already-running original loop; its frame never called browser_loop, so the UI slots see loop_depth=0.'],
   'effect':'The initial protected page can be drawn/handled without the normal wrapper-gated password prompt under this timing premise. Variable guard still exists and denies changed protected writes while unauthorized. Unconditionally hooked navigation may still gate later protected transitions. This is not a claim of a complete NVRAM-write bypass.',
   'classification':'conditional timing defect rather than resource failure; exact code path follows from premise, but no evidence yet that normal successful cold-boot DXE/BDS scheduling reaches this premise',
   'caution':'BootManager also sets stage4 before calling0xe1b8, so rejecting every stage4 observation would discard legitimate safe pre-entry opportunities. Stage value alone cannot distinguish these two call-stack states.'},
 ],
 'inferences':[
  'Under successful ordinary DXE dispatch and ready SMBIOS/Setup/AMITSE state, persistent driver registration and EndOfDxe happen before the identified first BDS Setup stage5. The late-loading runtime fixture is a useful counterexample, but does not prove the integrated driver will miss first Del/F2.',
  'Finding FormBrowser2 is a useful progress marker, but entry.c comment that all AMITSE protocol initialization is complete is stronger than the binary proves.',
  'The stage5 refusal alone is not a complete guard against late patching an already-active browser invocation. A proven pre-entry boundary must also exclude the stage4-initialization window; repeated retries alone would not solve that distinction.',
  'The identified F10 commit path should not be denied solely by ap_session_end timing once wrapper attachment and authentication succeed. Other OEM commit paths and cached RuntimeServices pointers remain outside this proof.',
 ],
 'unverified':[
  'Cold-boot snapshot showing driver entry, SMBIOS board/version, both LoadedImage bases/sizes, each discovery event, current TPL/stage, successful attach and first browser entry in order.',
  'Runtime satisfaction of all Setup DEPEX predicates and its entry success at EndOfDxe.',
  'Physical direct Del/F2, early OEM SendForm, EZ/search/Favorites, Save without exit, Save and reset, nested SendForm and resume/boot-mode variations.',
  'Real NVRAM save/readback and a second boot proving the password persists, first entry is locked, and authorized settings persist; existing RAM deny shim did not establish these writes.',
  'Successful policy-preserving recovery from partial patch/attribute/allocator failure.',
 ],
 'minimal_fix_design':[
  {'priority':1,'design':'First add bounded diagnostic snapshots in an isolated candidate: event origin, TPL, stage, prerequisite bitmask, attempted/ready, attach failure phase, outer begin/end, protected SetVariable result and reset. Never include plaintext password or password record bytes. This tests the missing ordering premise without widening authorization.'},
  {'priority':2,'design':'Require an attachment boundary known to precede the protected browser invocation. For the proven normal BDS path, EndOfDxe is such a candidate checkpoint; include a verified pre-entry handshake for each BootManager/SendForm entry before permitting UI access. Never initialize a session retroactively from a timer inside a possibly active stage4 frame, and do not treat stage4 alone as safe. Preserve fail-closed handling when no safe boundary can be established.'},
  {'priority':2,'design':'For already-installed render/page_input/app_input/frame_input hooks, always classify protected/unknown content rather than skipping gates whenever loop_depth==0. Separately permit interactive authentication only while a valid wrapper-owned active session exists. Without that session, reject protected display/input and redirect to a verified safe page or terminate the current browser; never call ensure_unlocked or ap_session_begin to invent a session. Audit poll/navigation too: a late stage5 poll can apply no-prompt rejection, and protected navigation outside a valid wrapper must not open an unlock prompt.'},
  {'priority':2,'design':'Replace boolean attach result with explicit WAITING_PREREQUISITE, UNSUPPORTED_IDENTITY, READY, MUTATION_FAULT states. Retry WAITING only if no mutation has started. MUTATION_FAULT remains fail-closed until full rollback and hook ownership are verified. Keep stage5 live patching prohibited.'},
  {'priority':3,'design':'Use the existing EndOfDxe checkpoint as a final pre-BDS attachment/verification opportunity on the proven normal BDS path. If prerequisites remain missing, report a distinct not-protected state and design a verified pre-entry gate; do not declare protection just because driver loaded. Adding BEFORE/AFTER or apriori alone does not prove all prerequisites ready and may introduce new order dependencies.'},
  {'priority':4,'design':'Keep authorization bounded to the active outer browser for now. The proven F10 path saves before return. If a different OEM path dynamically commits after return, design a tightly scoped authenticated commit transaction for that proven path instead of extending unlock globally.'},
 ],
 'fail_closed_design_assessment':{
  'status':'suitable minimal isolated-candidate direction; not implemented or executed in this task',
  'why':'With the stage4 timing premise, newly patched UI dispatch slots are used by the current original browser even though its entry wrapper was missed. Eliminating loop_depth as the condition for deciding whether to enforce protection closes that specific UI gate omission while retaining loop_depth/active as a requirement for authentication.',
  'requirements':[
   'Keep three decisions distinct: content classification, authorization from an established session, and whether a prompt may run. A missing wrapper must never grant or start authorization.',
   'Use both wrapper ownership/depth and active core state when permitting prompts; a stale authorized bit by itself must not qualify an unowned browser invocation.',
   'Reuse the verified redirect/history reset validation; if no safe redirect is possible or metadata is malformed, terminate/consume the operation without calling the original protected renderer or handler.',
   'Retain consumed-input return conventions so a denied page/frame input does not fall through into AppInput.',
   'Preserve the existing behavior of legitimate wrapped sessions and explicitly define/test disabled-policy semantics; do not accidentally re-enable a lock the authenticated management flow intentionally disabled.',
   'Do not clear attempted or automatically retry a MUTATION_FAULT as part of this UI change.',
  ],
  'isolated_validation_needed':[
   'Simulate first attach after native0xe1e2 and before0xe655; invoke each newly hooked UI route with a protected page/frame. Assert original protected dispatch count0, no credential prompt, core.active remains0, and safe history redirect or termination.',
   'Repeat for unknown/malformed page/frame/history and for unprotected pages; verify fail-closed errors and ordinary allowed navigation respectively.',
   'Exercise navigation and poll with no wrapper, including stage5 reached by the current unwrapped invocation; neither may create or unlock a session.',
   'Re-run already-covered wrapped correct/wrong password, nesting and HISTORY01 behavior to confirm unchanged semantics.',
   'First discovery atstage5 before any hook exists must still be flagged as an uncovered initial-entry condition; only a separate verified pre-entry boundary can resolve it.',
  ],
  'not_solved':['A first stage5 discovery where no hooks were installed at all.','Other entry routes that bypass every installed UI hook.','Actual prerequisite readiness and cold-boot event order.','NVRAM persistence or physical flashed boot acceptance.'],
 },
 'existing_REA_evidence':[
  str(BASE/'navigation/rea/FOCUS-loop-e1b8.c'),str(BASE/'navigation/rea/STATE-app12168.c'),
 ],
 'REA_new_attempt':{'plan':str(HERE/'plan-initial.json'),'open_succeeded':True,'list_procedures_client_timeout_ms':180000,'new_decompile_claims':False,'cleanup':'close_binary reported success; stderr and final-close JSON retained','unchanged_retry':False},
 'invalid_prior_label_caution':'runtime_navigation/rea/SAVE-29ae4 and29934 mainly manage HII notification queues;22cd0 releases caches. Those labels do not establish actual save sequencing. The new proof is bound to F10 table and commit callsites.',
 'candidate_recipe_excerpt':{k:recipe[k] for k in ['source_capsule_sha256','candidate_sha256','driver_sha256','driver_ffs_guid','outer_container_offset','original_inner_ffs_offsets_preserved','original_inner_ffs_bytes_preserved','depex']},
 'original_depex_and_apriori':{'depex':inventory['depex'],'apriori':inventory['apriori']},
 'hotkey_record':{'module':'AMITSE','rva':'0x6ccb8','bytes':hotkey.hex(),'scan_code':struct.unpack_from('<H',hotkey)[0],'callback':hex(struct.unpack_from('<Q',hotkey,8)[0])},
 'pointer_slots':pointer_slots,
 'evidence_checks':'All selected byte ranges decode completely. Asserted7 native pointer slots,6 direct E8 call targets,Setup SetVariable opcode,and BDS EndOfDxe/Setup table indices. No native target execution.',
 'bds_dispatch_table':bds_table,
 'native_blocks':blocks,
}
out=HERE/'entry_save_timing_review.json';out.write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
print(str(out));print('sha256',sha(out),'bytes',out.stat().st_size)
print('source unchanged check:',{k:v['sha256'] for k,v in sources.items() if k.startswith('driver/')})
if __name__=='__main__': pass
