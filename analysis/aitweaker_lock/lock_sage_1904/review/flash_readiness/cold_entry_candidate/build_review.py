"""Create read-only evidence/design reports. Never changes a PE or firmware."""
from pathlib import Path
from datetime import datetime, timezone
import hashlib, json, sys
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent;CASE=HERE.parents[2];ROOT=HERE.parents[5]
sys.path.insert(0,str(ROOT/'tools/pydeps'))
import pefile,capstone
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
def binding(p):return {'path':str(p.relative_to(CASE)),'sha256':sha(p),'bytes':p.stat().st_size}
def save(name, data):
 p=HERE/name;p.write_text(json.dumps(data,ensure_ascii=False,indent=2)+'\n',encoding='utf8');return binding(p)

modules={'AMITSE':CASE/'analysis/modules/AMITSE.efi','Setup':CASE/'analysis/modules/Setup.efi',
 'Core':HERE.parent/'runtime_navigation/OriginalDxeCore.efi',
 'BDS':HERE.parent/'entry_save_timing/OriginalBds.efi'}
expected={'AMITSE':'531ed4993b27252df7bc9c2104e0b752857868e3e40691707e4e490b362de3b1',
 'Setup':'719bad779e9ae60340187c7aae6c12ab9dff3ee398c58a9fca2a4e027a33f21d',
 'Core':'d8684ae913fe44bfcb950c0635299465d7813b1f60407a733f7cce34e50f584d',
 'BDS':'84bece9e2afa7206de68d138b19935b3b73f9f9ee59b341b2c50ce890ad0b41a'}
for name,p in modules.items():assert sha(p)==expected[name],name
pes={n:pefile.PE(str(p)) for n,p in modules.items()}; images={n:p.get_memory_mapped_image() for n,p in pes.items()}
cs=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64)
ranges=[]
for name,start,end,label in [
 ('Core',0x988c,0x9954,'Read DXE DEPEX; BEFORE/AFTER flags and GUID'),
 ('Core',0x9ccc,0x9dc0,'Recursive BEFORE/AFTER scheduling'),
 ('Core',0x9a74,0x9ccc,'Dispatch queue; continues after preceding load or start failure'),
 ('Core',0xf004,0xf067,'Empty DEPEX requires all architectural protocols'),
 ('Core',0x84a6,0x8527,'LoadedImage no-notify install, loader, notified reinstall'),
 ('Core',0xcc98,0xcdc4,'RestoreTPL native notification dispatch'),
 ('AMITSE',0x1191,0x11a8,'Stage zero then protocol publication then more initialization'),
 ('AMITSE',0x2624,0x272b,'BootManager published before FormBrowser2'),
 ('AMITSE',0xe1b8,0xe1ed,'Original browser prologue and stage4'),
 ('AMITSE',0xe655,0xe660,'Original stage5 qword store'),
 ('AMITSE',0xe6b0,0xe6c2,'Initial exit check and poll call'),
 ('AMITSE',0xe91e,0xe940,'Browser exit flag redirects to cleanup'),
 ('AMITSE',0xe52d,0xe632,'Cleanup can reset conditionally; not an unconditional harmless return'),
 ('AMITSE',0x2b65,0x2b9c,'BootManager browser call and continuation'),
 ('AMITSE',0x2125c,0x2129f,'SendForm browser call and continuation'),
 ('Setup',0x152c,0x1549,'Original RouteConfig jump and Callback prologue'),
]:
 raw=images[name][start:end];ops=list(cs.disasm(raw,start))
 assert b''.join(bytes(x.bytes) for x in ops)==raw,(name,hex(start),hex(end))
 ranges.append({'module':name,'start_rva':hex(start),'end_exclusive_rva':hex(end),'label':label,'bytes_hex':raw.hex(),
                'instructions':[{'rva':hex(x.address),'bytes':x.bytes.hex(),'mnemonic':x.mnemonic,'operands':x.op_str} for x in ops]})

pe_layout={}
for name in ['AMITSE','Setup']:
 p=pes[name];rel={e.rva:e.type for b in p.DIRECTORY_ENTRY_BASERELOC for e in b.entries}
 targets=[0x6b928,0x6b930,0x6b840,0x7d4f8,0x837d8] if name=='AMITSE' else [0x2bdd8,0x2bde0]
 pe_layout[name]={'module':binding(modules[name]),'image_base':hex(p.OPTIONAL_HEADER.ImageBase),
  'size_of_image':hex(p.OPTIONAL_HEADER.SizeOfImage),'file_alignment':hex(p.OPTIONAL_HEADER.FileAlignment),
  'section_alignment':hex(p.OPTIONAL_HEADER.SectionAlignment),'section_table_end':hex(p.sections[-1].get_file_offset()+40),
  'size_of_headers':hex(p.OPTIONAL_HEADER.SizeOfHeaders),
  'no_spare_section_header_bytes':p.sections[-1].get_file_offset()+40==p.OPTIONAL_HEADER.SizeOfHeaders,
  'sections':[{'name':s.Name.rstrip(b'\0').decode(),'rva':hex(s.VirtualAddress),'virtual_size':hex(s.Misc_VirtualSize),
               'raw_offset':hex(s.PointerToRawData),'raw_size':hex(s.SizeOfRawData),'characteristics':hex(s.Characteristics)} for s in p.sections],
  'selected_pointer_slots':[{'rva':hex(r),'initial_value':hex(int.from_bytes(images[name][r:r+8],'little')),'base_relocation_type':rel.get(r)} for r in targets]}
stub_refs=[hex(e.rva) for b in pes['AMITSE'].DIRECTORY_ENTRY_BASERELOC for e in b.entries
           if e.type==10 and int.from_bytes(images['AMITSE'][e.rva:e.rva+8],'little')==0x11fbc]
assert len(stub_refs)==16
native=save('native_ranges.json',{'module_bindings':{n:binding(p) for n,p in modules.items()},'ranges':ranges,
 'pe_layout':pe_layout,'AMITSE_11fbc_shared_stub_DIR64_slots':stub_refs,
 'limits':'Direct bytes, parsed base relocations and selected instruction ranges. Not exhaustive alias/caller analysis.'})

counter=HERE/'native_counterexamples.json';notify=HERE/'notification_replay.json'
c=json.loads(counter.read_text());n=json.loads(notify.read_text())
assert c['checks']==46 and n['checks']==15
for rel,digest in c['input_sha256'].items():assert sha(CASE/rel)==digest
for rel,digest in c['fixture_sources_sha256'].items():assert sha(CASE/rel)==digest
assert n['original_core_sha256']==sha(modules['Core'])
assert n['verification_source_sha256']==sha(HERE/'verify_notifications.py')
assert n['fixture_helper_sha256']==sha(HERE/'verify_cold_entry.py')
prior=HERE.parent/'entry_save_timing/entry_save_timing_review.json'
prior_data=json.loads(prior.read_text())
# Independently bind every selected prior byte range to its original module.
prior_names={'AMITSE':'AMITSE','Setup':'Setup','OriginalBds':'BDS','OriginalDxeCore':'Core'}
for row in prior_data['native_blocks']:
 a=int(row['rva'],16);raw=bytes.fromhex(row['bytes_hex'])
 assert images[prior_names[row['module']]][a:a+len(raw)]==raw

rea_close=HERE/'rea/plan-core.final-close.json';rea_open=HERE/'rea/CORE-open.json'
assert rea_open.exists() and rea_close.exists()
rea={'tool':'pinned local REA MCP/ghidra provider','module':binding(modules['Core']),
 'open_report':binding(rea_open),'open_succeeded':not json.loads(rea_open.read_text()).get('isError',False),
 'requested_function':'0x9ccc','analyze_function_client_timeout_ms':180000,
 'new_pseudocode_obtained':False,'close_report':binding(rea_close),
 'close_succeeded':not json.loads(rea_close.read_text()).get('isError',False),
 'fallback':'Original PE bytes independently decoded and run in Unicorn; no decompilation result is claimed.'}
rea_binding=save('REA_attempt.json',rea)

entry=CASE/'driver/entry.c';platform=HERE.parent/'late_attach_candidate/platform.c'
def line(p,text):
 rows=p.read_text(encoding='utf8').splitlines();hits=[i+1 for i,x in enumerate(rows) if text in x]
 assert hits,(p,text);return hits
source={'entry':binding(entry),'candidate_platform':binding(platform),
 'source_lines':{'entry_discover':line(entry,'static void EA discover'),
 'stage5_refusal':line(entry,'if(stage==5)'), 'attempted_before_attach':line(entry,'attempted=1;'),
 'timer_cancel':line(entry,'attempted || platform_ready'), 'entry_registration':line(entry,'create_event('),
 'platform_attach':line(platform,'int attach_platform('),'install_variable_guard':line(platform,'if(!install_variable_guard())'),
 'unverified_rollback_results':line(platform,'rollback:')}}
standards=[
 {'url':'https://uefi.org/specs/PI/1.8/V2_DXE_Dispatcher.html','sections':['10.7.1','10.9','10.11'],
  'supports':'BEFORE ordering, empty-DEPEX architectural dependencies, dispatcher state machine; actual ASUS behavior separately verified.',
  'retrieval':'Search result rendered full relevant specification text; subsequent direct open returned 403.'},
 {'url':'https://uefi.org/specs/UEFI/2.10_A/07_Services_Boot_Services.html','sections':['7.1','7.3 RegisterProtocolNotify','7.4 Image Services'],
  'supports':'Notifications wait until TPL drops below their level; image load and entry execution are separate; SendForm runs at TPL_APPLICATION.'},
 {'url':'https://uefi.org/specs/UEFI/2.10_A/34_HII_Protocols.html','sections':['34.8.1','34.8.12'],
  'supports':'GetPackageListHandle returns the EFI handle registered for a package; x64 interface method slot10 at0x50.'},
]
review={'schema':'sage1904-first-entry-offline-review/v1','created_utc':datetime.now(timezone.utc).isoformat(),
 'reviewer':'/root/sage_original','status':'BLOCKED_FOR_GUARANTEED_FIRST_ENTRY_WITH_CURRENT_OPTIONAL_DXE_ARCHITECTURE',
 'review_builder':binding(Path(__file__)),
 'scope':{'device_access':False,'firmware_write':False,'new_driver_or_capsule':False,'production_or_e41_or_EXP03_modified':False},
 'candidate_driver':binding(HERE.parent/'late_attach_candidate/build/AiTweakerLock1904.efi'),
 'source':source,'native_ranges':native,'counterexamples':binding(counter),'notification_execution':binding(notify),
 'prior_static_chain':binding(prior),'prior_byte_ranges_independently_matched':len(prior_data['native_blocks']),
 'REA':rea_binding,'standards':standards,
 'finding_summary':[
  {'id':'COLD-ORDER','evidence':'Original Core 988c/9ccc executed with valid BEFORE bytes','finding':'BEFORE can order lock before AMITSE, including when the file is physically appended. It cannot require success of lock loading/entry.'},
  {'id':'COLD-FAIL-OPEN','evidence':'Original Core 9a74 dispatcher executed in four fixtures','finding':'AMITSE starts after preceding lock LoadImage returns SecurityViolation or OutOfResources, and after lock StartImage returns DeviceError. Native dispatch returns success once AMITSE executes. No universal first-entry guard follows from ordering alone.'},
  {'id':'COLD-NOTIFY','evidence':'Original Core 84a6..8527 and cc98..cdc4 executed','finding':'Initial LoadedImage install suppresses notifications; notified reinstall follows the loader. This is before image entry completion. A TPL8 event executes when RestoreTPL lowers below8, not merely because a protocol exists.'},
  {'id':'COLD-PUBLISH','evidence':'AMITSE1191/119e/11a3 and2624..272a','finding':'AMITSE publishes BootManager before FormBrowser2 and continues initialization after FormBrowser2 publication. Current discover waits for FormBrowser2 plus Setup image and SMBIOS identity. No event marker by itself proves all predicates ready or excludes an earlier private entry.'},
  {'id':'COLD-NORMAL-PATH','evidence':'Original BDS table index7 EndOfDxe vs index61 BootManager, independently rebound existing native evidence','finding':'Successful normal sequential BDS dispatch provides pre-Setup attachment opportunities. This is positive conditional static support, not proof a normal physical cold boot was observed to fail.'},
  {'id':'COLD-STAGE5','evidence':'Native stage5 store atE655 then exact e41 discover','finding':'First discovery at stage5 leaves all UI hooks and RuntimeServices.SetVariable unchanged. Protected-page dispatch reaches the original renderer entry. Later stage7 attachment does not protect that first invocation.'},
  {'id':'COLD-ATTEMPTED','evidence':'Exact e41 discover/attach with pre-mutation AllocatePages and post-guard UI-patch failures','finding':'Both failures permanently latch attempted. Even allocation failure with zero patch calls is not retried. After a partial attach, unchanged code does not prove rollback ownership; blindly clearing attempted is unsound.'},
 ],
 'decision':{'earlier_opportunity_exists':True,'BEFORE_or_apriori_alone_sufficient':False,'current_e41_guarantees_initial_entry':False,
  'safe_to_claim_physical_cold_entry_pass':False,'implemented_fix':False,
  'reason':'An optional driver cannot enforce a default-deny UI boundary while it is absent or has not attached. The original UI needs an independent selective gate if protection must survive that condition.'},
 'not_inferred':['No assertion that this conditional first-stage5 premise occurred during a physical normal cold boot.',
  'No assertion that an unprotected UI dispatch always commits protected NVRAM: a partial attach can retain the separate variable guard.',
  'No assertion of full browser emulation, signature validity, recovery readiness, or flashing permission.'],
 'preservation':c['preserved_files']}
review_binding=save('cold_entry_review.json',review)

policy=CASE/'driver/policy.json';policy_data=json.loads(policy.read_text())
design={'schema':'sage1904-selective-native-gate-design/v1','status':'OFFLINE_DESIGN_WITH_BOUND_NATIVE_FEASIBILITY_NOT_IMPLEMENTED',
 'parent_review':review_binding,'native_ranges':native,'target':'Default-close only Ai Tweaker and reviewed OC entry routes if optional password DXE is absent, late or faulted; keep valid unrelated UI and ordinary BDS usable.',
 'principle':'Put permanent selective guards in the original AMITSE/Setup files. The independent DXE becomes an optional credential/session provider; it never removes or overwrites those guards to unlock.',
 'normal_missing_DXE_behavior':{'protected_navigation':'deny without invoking protected native handler; navigate to verified Main with coherent history when present',
  'unprotected_Main_Security_and_other_columns':'classify through verified Setup/HII ownership and chain original handlers',
  'password_management':'unavailable until provider initializes successfully; protected UI stays closed',
  'normal_boot':'no blanket BDS refusal, ResetSystem, cli/hlt, or unbounded wait is introduced'},
 'mandatory_guard_points':[
  {'module':'AMITSE','rva':'0x6b928','kind':'DIR64 pointer slot','original_target':'0x16a90','role':'Page renderer; reject protected/unknown page before drawing.'},
  {'module':'AMITSE','rva':'0x6b930','kind':'DIR64 pointer slot','original_target':'0x16c20','role':'Page input; consume protected input with zero without falling through.'},
  {'module':'AMITSE','rva':'0x6b840','kind':'DIR64 pointer slot','original_target':'0x12168','role':'Application input; prevent hotkeys acting on a denied page; preserve safe-page dispatch.'},
  {'module':'AMITSE','rva':'0x7d4f8','kind':'DIR64 pointer slot','original_target':'0x11fbc','role':'Only the verified four-pointer form navigation callback. Do not globally patch shared11fbc.'},
  {'module':'AMITSE','rva':'0x15320','kind':'15-byte verified prologue/trampoline','continuation':'0x1532f','role':'Modal frame input even when current visible page is Main.'},
  {'module':'AMITSE','rva':'0xe1b8','kind':'18-byte verified prologue/trampoline','continuation':'0xe1ca','role':'Optional provider Begin/End around the real outer browser, preserving nesting and registers. No provider still runs original safe UI under static guards.'},
  {'module':'AMITSE','rva':'0xe6bd','kind':'5-byte rel32 CALL','original_target':'0x34b2c','role':'Before first/repeated loop input, guard initial protected selection then call original poll. This avoids assigning the lazily initialized837d8 pointer.'},
  {'module':'Setup','rva':'0x2bdd8','kind':'DIR64 pointer slot','original_target':'0x152c ->0x2568','role':'Default-deny protected RouteConfig ranges; chain unrelated configuration. Do not replace global RT.SetVariable in the fallback.'},
  {'module':'Setup','rva':'0x2bde0','kind':'DIR64 pointer slot','original_target':'0x1534','role':'Default-deny reviewed protected question callbacks; chain unrelated question/actions with correct UINTN request ABI.'},
 ],
 'minimality_qualification':'These nine selected patch sites are the proposed minimal defensible set for known initial, navigation, dynamic, modal and HII routes; they are not a proof that no indirect alias or private entry exists. Native pointer/data writes after initialization must still be audited.',
 'provider_contract':{
  'ABI':'New versioned private protocol, separate from old status protocol; checked signature, structure size, revision and required method pointers.',
  'methods':['BeginBrowser','EndBrowser','RequestProtectedAccess','QueryAccess','ManageCredential'],
  'default':'Missing, wrong revision, invalid pointer, initialization fault, no owner, stale token, busy or EBS => protected access denied.',
  'grant':'Only validated disabled-policy state or authenticated current wrapper-owned outer session. QueryAccess never prompts or starts a session.',
  'prompt':'RequestProtectedAccess may prompt atTPL_APPLICATION only after BeginBrowser established ownership; render/input rechecks grant and never invents a session.',
  'late_arrival':'If first BeginBrowser had no provider, late provider appearance must not create ownership inside the active OEM invocation; keep that invocation locked, acquire ownership at next verified outer BeginBrowser.',
  'nesting':'One outer owner/epoch, bounded nested depth; inner returns retain grant, outer return and EBS revoke it.',
  'HII_management':'The provider may add the existing0xffe0/0xffe1 questions and strings, but must not replace the permanent Setup callback/route guards. Those guards dispatch management only to a valid owner-bound provider. Missing provider management requests return denied.',
  'handshake_failure':'Keep native guards active. No double-hook or attempted-bit reset is needed for UI safety. HII update/persistence transaction failures remain faulted until independently restored.'},
 'allocation_free_identity_direction':{
  'public_path':'For a page HII handle use HiiDatabase.GetPackageListHandle (x64 method10/offset0x50), then HandleProtocol for ConfigAccess. The two static Setup guard method addresses provide a paired known-RVA anchor for the modified Setup module.',
  'verification':'Validate pointer ranges, subtraction/overflow, PE bounds, exact expected text/guard-region fingerprint and both route/callback targets before treating it as Setup. A matching form number alone cannot identify Setup.',
  'reason':'Does not require allocating and exporting every package during a missing-DXE fault. Exact implementation and original provider behavior still need a bounded replay.',
  'unknown':'Do not label an unresolved handle as foreign/unprotected. Do not claim preservation of arbitrary malformed HII state.'},
 'selective_save_semantics':{
  'unrelated_configuration':'Preserve original RouteConfig return and Progress behavior for unrelated GUID/name/ranges.',
  'protected_noop':'A save of unrelated settings can also submit unchanged OC bytes. A blanket rejection of every OC RouteConfig is not sufficient: parse bounded offsets/widths and compare the affected protected bytes with the current variable; identical protected bytes may pass, actual changes require current provider authorization.',
  'memory_store':'Compare only the reviewed protected SocketMemoryConfig byte offsets; keep unrelated bytes writable according to the existing policy.',
  'read_or_parse_failure':'Reject the affected protected request, never substitute an assumed old value, disable all RuntimeServices, halt, or reset.',
  'required_test':'Provider absent: non-OC F10 save still commits its unrelated values, unchanged OC submission is a no-op pass, changed OC submission is denied. Exercise original synchronous save loop because it does not inspect every per-variable error.'},
 'policy':{'binding':binding(policy),'protected_forms':policy_data['forms'],'form_count':policy_data['form_count'],'question_count':policy_data['question_count'],
  'dynamic_controls':'Retain Setup varstore29 and selected varstore33 offset checks, source-HII identity, inert Exit descriptors and unknown/malformed rejection. Retain reviewed HISTORY01 root reset validation.'},
 'availability_boundary':{
  'normal_verified_Main':'Redirect only after full page/history/index/ownership/bounds validation. Main->Security->Esc must still return Main.',
  'no_verified_safe_page':'Cannot just set app+0x5a and call it harmless: nativeE91e/E52d cleanup can reset when byte83580 is set and qword93028 iszero. A new bounded return path must preserve/unwind only owned resources and must be proven through both BootManager and SendForm callers.',
  'no_fatal_stop':'Do not solve malformed UI or missing password provider by halting/resetting the whole machine. If safe non-reset unwind cannot be established, stop candidate development at that case and report the gap.',
  'scope':'Module-load failure of AMITSE itself is distinct from missing optional password DXE. Availability of an entire corrupted/rejected original UI module cannot be promised.'},
 'PE_integration_constraints':{
  'no_header_slack':True,'original_headers':'Both modules have section-table end == SizeOfHeaders ==0x2c0; cannot add a seventh section header in-place over original.text.',
  'possible_preserve_RVA_layout':'Evaluate extending the existing final.reloc section after its relocation payload for position-independent guard code, retaining relocation-directory original span, updating size/code flags and making added code non-discardable executable/read-only. Existing six static pointer slots already haveDIR64 entries. This is a proposed layout, not yet constructed or loader-tested.',
  'alternatives':'A correctly rebuilt PE with rewritten metadata is possible; moving sections or using an assumed code cave without complete relocation/resource/offset validation is not acceptable.',
  'guard_state':'Prefer position-independent code/constant policy and provider-owned state; do not require writable-executable storage or repurpose unproven original globals.',
  'compatibility':'The current e41 attach expects original AMITSE slot/prologue bytes and must not be used unchanged. Build a separate provider-only DXE and new module manifest.',
  'container_space':'EXP03 exact container allocation is nearly full; no claim added guards fit. Recompress and fully verify sizes/FFS/regions after a real candidate exists.',
  'signatures':'Any actual changed modules/capsule invalidate original covered signatures; static design is not update-tool acceptance.'},
 'required_validation_sequence':[
  'Compile only isolated guard/provider objects. Assert no flash/PCI/MMIO write, ResetSystem or cli/hlt references in UI fallback paths; preserve old artifacts.',
  'Run native AMITSE/Setup methods with provider absent, wrong ABI, initialization failure, late stage4/stage5 appearance and pre/post mutation faults. All known protected render/input/navigation/config actions must remain denied.',
  'With provider absent verify Main, Security, non-OC Advanced/Boot/Tool and foreign HII source-ID collisions call original handlers unchanged; test Main->Security->Esc and preserved history.',
  'With provider absent execute the identified native F10 route: unrelated saved values remain writable, identical OC submission passes, changed protected bytes are denied, and callback Progress/request canaries remain intact.',
  'Test initial Ai/Favorites/Profile/OC Presets/Memory Presets, search/dynamic controls and modal frame. Correct/wrong/cancel password, one prompt per outer session, nested calls, new-session relock and management ABI.',
  'Execute original E6bd/E86b/E881/E8a3/E8ec dispatch instructions against STATICALLY relocated guard slots, not only call guard functions directly.',
  'Validate no-safe-page return through native BootManager2b65 and SendForm2125c, including both83580 pending-reset states and93028 conditions. No new unintended reset or whole-boot stop allowed.',
  'Run original Core LoadImage/StartImage failure fixtures while static guard bytes remain present; driver failure must no longer imply protected original dispatch.',
  'Verify native modules load/relocate and respect executable/read-only section attributes under a standard UEFI loader; whole-ASUS hardware remains separate.',
  'Only after the above, integrate into a new internal UNSIGNED review image and independently re-extract/hash-check all changed modules and unchanged FFS/regions. No automatic flash approval.'
 ],
 'reused_feasibility_evidence':{'existing_late_attach_suite':binding(HERE.parent/'late_attach_candidate/late_attach_regression.json'),
  'limit':'The existing269 checks establish current guard semantics with valid fixture ownership and native route/history instructions; they do not validate a future statically patched PE or new protocol.'},
 'standards':standards,'not_implemented':True,'new_patched_PE_or_CAP':False}
design_binding=save('selective_native_gate_design.json',design)

md='''当前 e41 / EXP03 仍不能证明“每次直接 Del 首次进入 Setup 都已经有锁”。本轮没有修改驱动或固件，也没有连接设备。

原厂 DXE Core 的 BEFORE 排序确实可以把密码驱动排在 AMITSE 前，但前一个驱动加载或入口失败后，Core 仍继续启动 AMITSE。本地执行原厂指令已复现这点。首次发现 stage5 时，e41 的 UI 和变量钩子均未安装；初次 AllocatePages 失败即使尚无任何目标写入，也会锁存 attempted，后续条件恢复仍不重试。46 项边界/反例断言通过，含这些失败路径的复现；另有 15 项原厂通知/加载顺序断言通过。这些不是 61 项冷启动通过率。

正常原厂 BDS 顺序中，EndOfDxe 早于 BootManager→Setup，因而成功初始化时存在提前安装机会。但它不强制所有前提已就绪，更不提供“密码驱动失败则只关闭超频入口”的屏障。[PI DXE Dispatcher](https://uefi.org/specs/PI/1.8/V2_DXE_Dispatcher.html)；通知还受 TPL 约束。[UEFI Boot Services](https://uefi.org/specs/UEFI/2.10_A/07_Services_Boot_Services.html)

可继续落地的方向是把默认拒绝的选择性守卫静态置于 AMITSE / Setup 文件中，再让独立 DXE 提供当前会话的密码授权。DXE 缺失时，守卫仍拒绝 Ai Tweaker 和已识别的 OC 入口；有效的 Main、Security 和其他非 OC 页面继续调用原厂处理函数。不能用整机停机、重启或无限等待替代用户要求的栏目锁。

设计已列出九个具体修补点和验证顺序，但尚未实现。两个关键限制是：AMITSE 的11fbc空桩被16个指针共用，必须仅改导航专用槽7d4f8；原厂 app+5a 退出清理在特定既有状态下会调用 ResetSystem，不能未经验证就把“结束当前页面”当成无副作用返回。原 PE 也没有新节头空间，添加守卫代码需要完整验证布局、重定位、执行权限和压缩容器余量。

REA 已成功打开原版 Core，但 analyze_function 在180秒超时，close_binary 成功。本轮未声称取得新的反编译结果；主要证据来自绑定原始 SHA 的机器码、Capstone 解码与 Unicorn 有界执行。
'''
(HERE/'cold_entry_review.md').write_text(md,encoding='utf8')
print(json.dumps({'review':review_binding,'design':design_binding,'readme':binding(HERE/'cold_entry_review.md')},ensure_ascii=False))
