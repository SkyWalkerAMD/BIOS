"""Freeze the bounded offline BMC update-chain review; no device capability."""
from pathlib import Path
from datetime import datetime,timezone
import hashlib,json,re,sys
sys.dont_write_bytecode=True
from inspect_chain import HERE,BASE,ROOT,Elf32,FILES,sha
def art(p):
    p=Path(p);return {'path':str(p),'bytes':p.stat().st_size,'sha256':sha(p.read_bytes())}
def read(p):return json.loads(Path(p).read_text())
def main():
    native=read(HERE/'native_replay.json');pre=read(HERE/'preflight_npb_replay.json');api=read(HERE/'api_and_ranges.json')
    assert native['status']=='PASS' and native['checks']==64 and native['cases']==23
    assert pre['status']=='PASS_COUNTEREXAMPLE_CONFIRMED' and pre['checks']==37 and pre['cases']==12
    assert native['source']['sha256']==sha((HERE/'replay_chain.py').read_bytes())
    assert pre['inputs']['script_sha256']==sha((HERE/'replay_preflight_npb.py').read_bytes())
    assert pre['inputs']['harness_sha256']==sha((HERE/'replay_chain.py').read_bytes())
    assert pre['inputs']['api_ranges_sha256']==sha((HERE/'api_and_ranges.json').read_bytes())
    for row in native['source']['inputs'].values():assert sha(Path(row['path']).read_bytes())==row['sha256']
    bad=next(x for x in pre['cases_detail'] if x['case']=='source_read_failure_not_checked')
    assert bad['result']=='0x0' and bad['failed_source_reads']==1
    daemon=HERE/'official_inputs/5308416/usr/local/bin/compmanager';e=Elf32(daemon)
    g=next(s for s in e.symbols if s['name']=='g_corefeatures' and s['section_index'])
    assert g['va']==0x230b4 and g['size']==1204
    r=Elf32(FILES['rest']);b=Elf32(FILES['bios'])
    refs={k:art(BASE/k) for k in ['capsule_trust_boundary_review.json','capsule_trust_replay.json','component_backend_review/component_update_recovery_review.json','rest_backend_review.json','frontend_binding.json','official_bmc_source.json','ssh_management_observation.json']}
    report={
      'schema':'sage1904-bmc-update-chain-review05/v1',
      'status':'OFFLINE_REVIEW_COMPLETE_LIVE_FLAG_AND_FULL_SAFE_PREFLIGHT_NOT_ESTABLISHED',
      'generated_utc':datetime.now(timezone.utc).isoformat(),
      'scope':{'target':'ASUS Pro WS W790E-SAGE SE 1904; official W790 BMC1.1.57','network_requests':0,'BMC_access':False,'CAP_uploads':0,'Enter_Prepare_Flash_calls':0,'device_reads_or_writes':0,'production_or_published_changes':0,'output_directory':str(HERE)},
      'method':{'native':'Pinned official ARM ELF bytes, symbols/relocations/literal pools, Ghidra12.1.4 and Capstone; actual Unicorn ARM control flow with explicit RAM-only import models.',
                'REA':'Reused existing REA capability evidence; its installed Windows provider rejects native ARM ELF, so no repeated unsupported call or new installation. Ghidra projects/output are isolated here.',
                'crypto':'Existing four pinned PDK signature replays reused; no new signing, CAP generation, key export, or crypto acceptance claim.',
                'address_convention':'ET_DYN library VAs are link-time load-bias-zero; Ghidra displays +0x10000. compmanager/spx_restservice ET_EXEC VAs already include their 0x10000 base. No value is asserted as measured live memory.'},
      'source_binding':{'official_image':art(BASE/'official_bmc/W7901157.ima'),'daemon':art(daemon),'libraries':native['source']['inputs'],'rest':art(FILES['rest']),
                        'live_limit':'Official release version and frontend bytes match the recorded deployed UI. Live native backend files and process memory have not been acquired; frontend equality is not native backend equality.'},
      'resident_key_flag':{
        'feature':'CONFIG_SPX_FEATURE_SIGNED_HASHED_IMAGE_SUPPORT',
        'branch':'libcompamibios bios_start_update ELF0x3C3C reads g_corefeatures+0x34; exactly1 invokes VerifyImageSign(1,"/var/bios.bin",0) before configuration/worker. Other values bypass that branch.',
        'initialization':'compmanager main0x10F2C, call0x10F48: RetrieveCoreFeatures(0x230B4), before loading component metadata/workers. RetrieveCoreFeatures0x1C44 maps IsFeatureEnabled return to +0x34 at0x1F18.',
        'native_daemon_word':{'symbol':'g_corefeatures','symbol_va':'0x230b4','field_offset':'0x34','expected_ET_EXEC_field_va':'0x230e8','bytes':4,'format':'u32 little-endian'},
        'source_sequence':['Process-local dictionary pointer initiallyNULL. IsFeatureEnabled0x19B8 calls IniLoadFile("/var/tmp/libfeature").','IniLoadFile0x3A20 opens rb; if absent tries wb and creates an empty file. Calling this library as a query is not inherently file-read-only.','On successful load, IsFeatureEnabled opens /etc/core_features in r mode and adds whitespace-delimited non-comment tokens under section core_features; bare key gets value1, key=value gets that value. These entries replace same-key INI values in the modeled/native data flow.','Lookup core_features:CONFIG_SPX_FEATURE_SIGNED_HASHED_IMAGE_SUPPORT, default string0. Native comparison is strncmp(value,"0",strlen(value)); empty and0 are false,1/false/00 true in the actual instruction replay.','Once dictionary is nonNULL the process does not reload files on later lookups. Files observed later may differ from cached startup state.'],
        'official_default':'Official /etc/core_features lacks the key; official image has no /var/tmp/libfeature regular member. Native fixture with no additional INI key returns0. This is a conditional default, not a live observation.',
        'provenance_search':{'files_scanned':read(HERE/'official_input_manifest.json')['scanned_regular_files'],'matches':'Only libfeaturedefine.so in scanned regular-file bytes contains the literal /var/tmp/libfeature. This is not proof that a runtime writer cannot construct the path or alter state.','manifest':art(HERE/'official_input_manifest.json')},
        'read_only_observation_if_vendor_supported_privileged_shell_becomes_available':{
          'files':['/etc/core_features','/var/tmp/libfeature','/proc/<compmanager-pid>/exe','/proc/<compmanager-pid>/maps','the exact mapped libfeaturedefine/libcompamibios/libpdkapp/libflash bytes'],
          'actual_value':'After binding live executable/mapping/symbol identity, read only4 bytes at the resolved g_corefeatures+0x34 in that running compmanager process. A permitted /proc/<pid>/mem read can be observational; do not attach/stop/patch/restart the process or invoke update functions.',
          'permissions':'Requires an already authorized vendor-supported OS diagnostic/file-read facility. Current SMASHLITE login exposed management show/help verbs, not this facility. No privilege bypass or undocumented shell is proposed.',
          'file_only_limit':'Reading both files proves present file content only; it cannot by itself prove the already-cached daemon flag. A separate newly launched helper would have a different cache and may create libfeature.'},
        'available_web_observability':'No inspected standard route exposes this daemon word or the effective INI setting. GET /api/GetFeatureList is a distinct IPMI feature payload (Enable,Feature1..20); GET /api/getbmcfeature returns a filtered static feature/catalogue table; static features.js is build/UI data. None establishes resident-key flag value.'},
      'read_only_management_interfaces':[
        {'method':'GET','path':'/api/GetFeatureList','observes':'IPMI GetSetFeatureList in get mode0; Enable andFeature1..20','does_not_observe':'CONFIG_SPX_FEATURE_SIGNED_HASHED_IMAGE_SUPPORT or compmanager cache','hardware_scope':'No update/Prepare/GPIO/SPI call in inspected handler; HTTP/session/audit bookkeeping may still occur.'},
        {'method':'GET','path':'/api/getbmcfeature','observes':'Feature catalogue filtered by that IPMI payload','does_not_observe':'Resident-key flag, keys, staged image or full flash contents','hardware_scope':'Same read-only management caveat; not a key-policy query.'},
        {'method':'GET','path':'/api/maintenance/bios/upgradestatus','observes':'Component RAM progress field','does_not_observe':'Future validation success, write extent or recovery coverage','hardware_scope':'Inspected bios_get_update_progress copies a4-byte state value; no flash action.'},
        {'method':'GET','path':'/api/maintenance/bios/verifyimagestatus','observes':'RAM state of a prior comparison job','does_not_observe':'CAP cryptographic validation, image bytes or independent preserve verification','hardware_scope':'Polling itself does not launch verification; no request sent here.'}],
      'staged_CAP_preflight_candidate':{
        'classification':'EXPOSED_FUNCTION_LEVEL_NO_PREPARE_PATH_BUT_NOT_READ_ONLY_OR_FULL_UPDATE_VALIDATION',
        'endpoint_sequence_for_review_only':[{'method':'POST','path':'/api/maintenance/bios/uploadSignature','body':'multipart field biossignature containing complete CAP; auth/CSRF still apply'},{'method':'PUT','path':'/api/maintenance/bios/verifySignature','body':'{}'}],
        'normal_UI_warning':'Do not invoke the normal Start button for isolated validation: its documented frontend first enters update mode/Prepare and its callbacks automatically proceed to upload payload/version/flash workflow.',
        'native_chain':'uploadBIOSSignature_func0x136388 creates parsed upload under/var then rename to/var/biossig.bin. VerifySignature_func0x137F1C -> CMD_Verify_BIOS_Signature -> component2 command11 -> verify_bios_signature0x2008 -> PDK_VerifyBiosSignature.',
        'native_no_prepare_evidence':'These inspected handlers/wrapper/daemon component dispatcher do not consume an updateFWID or test Enter/Prepare state for command11. Complete CAP in biossig.bin is accepted by actual read_file_append even if bios.bin is absent or stale. No observed SPI/GPIO/MTD access in that chain; the wrapper replay covers normal verdict propagation.',
        'side_effects':['HTTP multipart temporary file creation and rename can overwrite an existing/var/biossig.bin.','PDK verifier consumes/unlinks/var/biossig.bin on its handled verification paths.','Normal session/audit state and buffers change. Resident /var/bios.bin may remain untouched by this helper path, but staging concurrency/prior state is unobserved.'],
        'reversibility':'Ephemeral staging is not the host flash, but an overwritten prior staging file cannot be restored unless separately preserved. No prior-staging existence/read endpoint has been established, so this is not a zero-state-change test.',
        'not_proven':['No live authentication/router/state test or native backend byte equality.','Does not execute resident VerifyImageSign branch, version/preservation/machine-write chain, OEM boot authentication, or recovery.','No inspected standard API returns staged bios.bin bytes or a complete hash/validate-only result after NPB preservation.'],
        'performed':False},
      'resident_key_verifier_preflight':{
        'key_origin':'Existing static evidence: libflash LoadPublicKey reads BMC/dev/mtd0 FMH/SHPKIDF key, writes/tmp/public.pem; VerifyImageSign validates a separate image-tail signature format. The key presence/immutability/provisioning and live branch remain unknown.',
        'no_safe_standalone_public_route_established':True,
        'do_not_probe_by_start_update':'bios_start_update contains no validate-only argument: resident-success path proceeds through BiosConfiguration and creates the flash worker; rejection/error path invokes ActiveHostSPIDriver(1), which itself rmmods driver and switches GPIO. Neither branch is a pure query.',
        'force_boundary':'SECTION_FLASH0xff skips BiosConfiguration only; it is not evidence that this resident-key check is disabled. Force mode is not used or recommended.'},
      'stateful_operations_and_rollback_limits':[
        {'operation':'Enter update mode','effects':'Daemon creates exclusive update marker/uniqueID; wrapper writes/tmp/fwid and/var/block_chassis_ops. This is state mutation, even before SPI preparation.','rollback':'Exit removes marker/chassis block on matching-ID success; failure and prior-state restoration are not proven.'},
        {'operation':'Prepare','effects':'ActiveHostSPIDriver(0) reads CE selector, invokes board GPIO switch, waits, modprobes host_spi_flash_hw; finds hostMTD and deletes staging files.','rollback':'ActiveHostSPIDriver(1) rmmods and switches tohost, clears parsed headers. Calls ignore some system/hook status; this is an attempted normal-owner reset, not a proven transactional restoration of original state.'},
        {'operation':'verifyimage','effects':'Starts native flash-content comparison job, reads hostMTD, then calls ActiveHostSPIDriver(1), deletes or moves staged bios.bin and writes forced-update flag.','rollback':'Not a cryptographic-only or no-state-change validator; success cannot restore overwritten prior staging.'}],
      'write_extent':{
        'normal_frontend':'1904 CAP67,112,960B: remove0x1000 header, COMPONENT_DATA_LEN=0x4000000,FlashOffset=0,SECTION_FLASH=0. Native start worker uses actual staged file size (subject to optional resident trailer handling).',
        'native_loop':'flash_bios_image loops floor(length/erase_size) contiguous blocks fromFlashOffset, with noCAP ROM-table/BIOS-region filter. Actual native64MiB loop observed1024 requested64KiB blocks0..0x3FF0000 under recorded geometry fixture.',
        'per_block':'spi_write_erase_block reads and compares every byte; identical block returns without erase/write. Different block issuesMEMERASE0x40084D02 and write at that block. Read failure returns failure in this low-level function.',
        'potential_range':'With ordinary64MiB payload/offset0, all[0,0x4000000) is eligible for differing-block writes. This is not a claim allblocks are always erased. Erase-size64KiB used for replay is not a measured live BMC geometry.',
        'NPB_source':'BiosConfiguration argument4=currentMTD header, argument5=uploadedCAP header. Current major/minor bothzero bypass preservation. Uploaded table supplies ranges copied fromcurrentMTD to staged bios.bin; afterward per-block equality can suppress those writes.',
        'official_NPB':api['original_BOOTEFi_headers'][0]['records'],
        'conditional_narrowing':'If the normal/nonForce path is used, current version permits preserve, every required source byte is read correctly and copied/readback correctly, then uploadedNPB[0,48MiB) makes those bytes equal tocurrentMTD; later low-level comparator should skip them. This is a meaningful conditionalBIOS-only difference argument, not an observed host write whitelist.',
        'preserve_fault_counterexample':{'report':art(HERE/'preflight_npb_replay.json'),'case':bad['case'],'actual_instructions':bad['instructions'],'failed_source_reads':1,'native_return':0,
          'chain':'Actual PDK first sigwrap_read returns-1 in stub without populating allocatedbuffer; native code does not inspect result, writes existingbuffer to staged file, reads itback, actual comparison succeeds, function returns0.',
          'fixture_boundary':'Zero-filled allocation and synthetic boundedNPB table are explicit emulator fixtures. This proves a missing error-check path, not that the live allocator is zero or a real machine necessarily corrupts. No target memory/flash read or write occurred.',
          'implication':'Header/table/functionstatus alone cannot prove preserved bytes. A correct staged/source comparison or suitable backup/recovery evidence is still required before reducing protection/recovery scope.'},
        'recovery_scope':'Existing do_bios_recovery calls the same flash_bios_image(offset0,filelength); it is not provenBIOS-only or a complete available preflash backup. Existing file availability/contents and supported noPOST trigger remainunverified.',
        'header_only_spec':art(HERE/'bios_header_read_spec.json'),
        'header_probe_status':'Offline candidate-page specification only. Root paused hardware probe because header alone cannot close actualNPB source-read/readback boundary.'},
      'trust_conclusions':[
        'Local input-provided-key PDK validation does not prove the whole BMC accepts self-signed images; the resident-key branch is separate and currently unobserved.',
        'Keeping originalCAP keys/signatures on modifiedfirmware still fails original signature. This does not establish that OEM privatekey is the only possible accepted update chain.',
        'Neither signature-function success nor BMC write success proves CPU BootGuard policy, firmware dispatch, graphicalBIOS lock behavior or recoverability. No BootGuard enabled/disabled inference is made.',
        'There is no established state-free complete update validator or standardstaged file export in the reviewed public surface. Availability beyond that bounded review is unknown.'],
      'tests':{'native_feature_branch_and_flash_loop':art(HERE/'native_replay.json'),'preflight_helper_wrapper_NPB':art(HERE/'preflight_npb_replay.json'),'new_cases':35,'new_checks':101,
               'limits':'Closed imports explicitly recorded. No fullBMC/kernel/actuallibcrypto emulation, actual device test, or safety/release certification.'},
      'existing_evidence_reused':refs,
      'new_evidence':{p.name:art(p) for p in [HERE/'native_inspection.json',HERE/'feature_provenance.json',HERE/'api_and_ranges.json',HERE/'bios_header_read_spec.json']},
      'remaining_material_observations':['Live native backend identity and compmanager effective flag.','If enabled, actual resident key and applicable trailer format.','No-state-change staged/source readback/export method or independently sufficient backup/recovery.','Physical board-specific write/boot/recovery acceptance.'],
      'decision':'NO_ENTER_PREPARE_UPLOAD_OR_FLASH_EXECUTED; report is evidence for further review, not authorization or a formal flash-ready release.'}
    path=HERE/'update_chain_review.json';path.write_text(json.dumps(report,indent=2,ensure_ascii=False)+'\n',encoding='utf-8')
    text='''离线审查已完成；没有连接 BMC、上传 CAP、进入更新模式或刷写。

resident-key 分支开关是 CONFIG_SPX_FEATURE_SIGNED_HASHED_IMAGE_SUPPORT。它来自 compmanager 启动时缓存的 libfeature 字典，准确字段为已绑定 ELF 的 g_corefeatures+0x34（ET_EXEC VA0x230E8）。官方缺省资料和实际ARM夹具给出0，但当前公开只读接口不返回该进程字段，不能把缺省当实机值。直接调用 IniLoadFile/IsFeatureEnabled 也可能创建缺失缓存文件，不属于严格只读。

已有 GET /api/GetFeatureList、GET /api/getbmcfeature 和更新进度 GET，只提供不同的功能列表/目录/状态。没有在已审查标准接口中建立 resident-key 实际值或 staged bios.bin 全字节/哈希导出路径；当前SMASH管理会话也未提供OS文件读取。完整确认需要已授权的厂商诊断读取能力或新的有证据接口，不能靠 Enter/Prepare 探测。

POST uploadSignature + PUT verifySignature 在所查原厂路径内不要求 Enter/Prepare，不调用GPIO/SPI，但会写/删除暂存文件，只验证本地CAP两级签名，未覆盖resident-key、保留/写入/启动/恢复。它不是零副作用完整预检，未实机调用。普通网页Start会自动衔接更新流程，不适合验证单步。

普通64MiB更新遍历全片的擦除块；相同块跳过，差异块才擦写。官方上传CAP的NPB包含前48MiB及三个BIOS子范围，正常成功复制可以使这些块保持现机值。原厂NPB函数却未检查源read状态：真实ARM故障回放显示读失败后仍可复制原分配区内容、读回比较通过并返回0。分配区零值只是夹具，不是实机必然损坏结论。因此header非零和NPB表不能替代保留数据读回/备份证据。

本轮35场景101检查通过，包含上述预期故障反例。全部只在本机仿真；旧四组验签证据直接复用。bios_header_read_spec.json提供官方候选固定4KiB页，但当前OEM实际位置未证明，root已暂缓其硬件探测。完整事实、地址、输入/脚本/报告哈希与限制见 update_chain_review.json 和 evidence_manifest.json。
'''
    (HERE/'README-review.txt').write_text(text,encoding='utf-8')
    selected=[p for p in HERE.rglob('*') if p.is_file() and not any(part.startswith('ghidra-') or part=='__pycache__' for part in p.relative_to(HERE).parts) and p.name!='evidence_manifest.json']
    # No live session or HTTP captures are included; official firmware members
    # and our source/disassembly/decompilation/replay evidence only.
    manifest={'schema':'update-chain-review05-evidence/v1','review_sha256':sha(path.read_bytes()),'files':[art(p) for p in sorted(selected)],'count':len(selected)}
    dest=HERE/'evidence_manifest.json';dest.write_text(json.dumps(manifest,indent=2)+'\n',encoding='utf-8')
    for item in manifest['files']:assert sha(Path(item['path']).read_bytes())==item['sha256']
    print(json.dumps({'review':art(path),'manifest':art(dest),'count':len(selected),'cases':35,'checks':101},indent=2))
if __name__=='__main__':main()
