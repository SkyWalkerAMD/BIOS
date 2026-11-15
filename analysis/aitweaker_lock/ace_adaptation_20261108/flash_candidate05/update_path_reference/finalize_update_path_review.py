"""Bind the read-only update-route conclusions to exact archived/current evidence."""
from pathlib import Path
import hashlib, importlib.util, json, struct, sys, zipfile
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[4]
def sha(b):return hashlib.sha256(b).hexdigest()
def identity(path):
 p=path if isinstance(path,Path) else HERE/path
 return {'path':p.relative_to(ROOT).as_posix(),'bytes':p.stat().st_size,'sha256':sha(p.read_bytes())}
def write(name,obj):
 (HERE/name).write_text(json.dumps(obj,indent=2,ensure_ascii=False)+'\n',encoding='utf8')
 return identity(HERE/name)

def main():
 native=json.loads((HERE/'bmc1313_native_evidence.json').read_text(encoding='utf8'))
 def fn(lib,name):
  v=native['libraries'][lib]['functions'][name]
  return {'library':lib,'function':name,'elf_va':v['elf_va'],'function_bytes_sha256':v['bytes_sha256'],
          'decompile':{'path':v['decompile_path'],'sha256':v['decompile_sha256']},
          'annotated':{'path':v['annotated_path'],'sha256':v['annotated_sha256']}}
 spec=importlib.util.spec_from_file_location('native_reader',HERE/'annotate_bmc1313.py')
 mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod)
 rest=mod.Elf32(HERE/'bmc1313_inputs/usr/local/bin/spx_restservice')
 routes=[]
 for symbol,method in [('uploadBIOSSignature_data','POST'),('VerifySignature_data','PUT')]:
  s=next(x for x in rest.symbols if x['name']==symbol)
  rows=[rest.literal(v) for v in range(s['va'],s['va']+s['size'],4)]
  routes.append({'symbol':symbol,'elf_va':hex(s['va']),'http_method_from_current_frontend':method,
                 'native_method_value':rows[1]['raw_u32'],'native_route':rows[2]['target_string'],
                 'handler':rows[0]['target_function'],'handler_va':rows[0]['target_elf_va'],
                 'route_bytes_sha256':sha(rest.data[rest.offset(s['va'],s['size']):rest.offset(s['va'],s['size'])+s['size']])})
 evidence=[fn(a,b) for a,b in [('rest','uploadBIOSSignature_func'),('rest','VerifySignature_func'),
  ('rest','pre_call_hook'),('rest','pre_authorized_call_hook'),('rest','post_call_hook'),('rest','post_authorized_call_hook'),
  ('manager','CMD_Verify_BIOS_Signature'),('helper','send_compmngr_command'),('bios','Amibios_Command_Process'),
  ('bios','verify_bios_signature'),('pdk','read_file_append'),('pdk','PDK_VerifyBiosSignature')]]
 staging={
  'status':'STATIC_SEPARATE_NORMAL_STAGE_AND_CAP_SIGNATURE_CHECK_IDENTIFIED_LIVE_NOT_EXECUTED_BY_THIS_AGENT',
  'date':'2026-11-08','current_official_binding':identity(HERE/'bmc1313_extraction_manifest.json'),
  'routes':routes,
  'normal_call_sequence':[
   {'method':'POST','path':'/api/maintenance/bios/uploadSignature','multipart_field':'biossignature',
    'input':'Complete 67,112,960-byte ACE1904 CAP/review container, validated offline before use. This is not a suffix-only conversion.',
    'observed_effect':'Authenticated request parser stages a file under /var/; handler renames its biossignature.savepath to /var/biossig.bin.',
    'content_length_guard':'Must be nonzero and no greater than 0x04300000 including multipart envelope.',
    'updatemode_or_FWUPDATEID_in_handler':False},
   {'method':'PUT','path':'/api/maintenance/bios/verifySignature',
    'frontend_exact_options':{'type':'PUT','dataType':'json','data':{},'contentType':'application/json','processData':'not specified; jQuery default'},
    'body_interpretation':'Frontend passes an empty object, so default jQuery parameter serialization yields no application parameters. An empty request body replicates this. The native handler reads no JSON parameter fields; an explicit JSON {} likewise supplies none. No live wire capture is claimed.',
    'observed_effect':'Sends component 2 / command 11 over component-manager FIFOs, then returns empty success JSON for zero status or HTTP 500 for nonzero component status.',
    'signature_file_lifecycle':'PDK reads the complete /var/biossig.bin; read_file_append does not need /var/bios.bin when the first file is already the complete CAP. PDK normally unlinks /var/biossig.bin on completion.',
    'updatemode_or_FWUPDATEID_in_handler':False}],
  'permitted_inference':'The selected current-version route is a separately addressable, normally authenticated staging and CAP-signature check. Its inspected dispatch does not invoke update-mode entry, preparation, ActiveHostSPIDriver, GPIO, erase, flash worker, or host SPI reads/writes.',
  'not_read_only':'Temporary upload/rename/unlink, session bookkeeping, mutex and IPC writes occur. It is not a GET-only operation and is not the full firmware update dry run.',
  'shared_hooks':'post hooks return immediately. pre_authorized updates viewer/session bookkeeping. pre_call reads session-related pipes and can terminate a web session requested by its command pipe; shared web/auth/libc infrastructure is not fully emulated.',
  'important_bounds':[
   'Normal authenticated admin session and its normal CSRF mechanism are required. No credential changes or privilege bypass are proposed.',
   'Do not use the webpage Start/EntryUpdateMode/Prepare path to reach these two handlers: Prepare performs SPI/GPIO/driver changes before signature upload.',
   'Do not use ExitUpdateMode as a generic temporary-file cleanup; it belongs to the update workflow and can restore/change host SPI state.',
   'A concurrent update must not be active: staging uses a shared fixed filename. No live request or concurrent-update state was inspected by this agent.',
   'Malformed/partial upload, daemon failure or missing PDK library can leave temporary-state uncertainty; successful HTTP status alone is not hardware acceptance.',
   'The CAP check does not execute the optional resident-key tail-signature branch inside bios_start_update.',
   'The CAP check does not verify electrical SPI connection, full target backup, configuration preservation, full image compatibility, cold boot or independent recovery.'],
  'evidence':evidence,'native_original_vs05_replay':identity(HERE/'bmc1313_native_signature_replay.json'),
  'shared_stage_exclusivity':'Not established by a direct idle query. No atomic reserve or no-clobber operation was identified. A parent-controlled maintenance window, sole active management session and stable update status may support a bounded operational occupancy judgment; versions, zero progress or null Redfish fields alone are insufficient.',
  'normal_session_snapshot':{'method':'GET','path':'/api/settings/service-sessions?service_id=1',
   'handler':fn('rest','getSessionCfg_func'),'fields':['id','session_id','session_type','client_ip','user_id','user_name','user_privilege'],
   'observation':'Normal authenticated handler snapshots racsessinfo records and retains session_type below 2 for service_id=1. It performs no deletion, update-mode entry or flash operation. Session deletion is a separate DELETE route and is not part of this proposal.',
   'interpretation':'Require the expected sole current Web management session for a bounded operational judgment. An error, missing data or unexpected session is not an idle proof. A session snapshot is not an atomic exclusion lock and does not prove no detached worker exists.'},
  'BMC_access_by_this_agent':False,'firmware_upload_by_this_agent':False,'firmware_write_by_this_agent':False}
 staging_id=write('staging_validation_review.json',staging)
 state={
  'status':'NORMAL_WEB_SESSION_SNAPSHOT_IDENTIFIED_NO_AUTHORITATIVE_IDLE_QUERY_FOUND',
  'route_table_evidence':identity(HERE/'bmc1313_update_routes.json'),
  'read_candidates':[
   {'route':'GET /api/settings/service-sessions?service_id=1','handler':fn('rest','getSessionCfg_func'),
    'returns':['id','session_id','session_type','client_ip','user_id','user_name','user_privilege'],
    'scope':'Web session records where session_type<2. Does not enter update mode or delete sessions. Read-only with respect to firmware and configurations; ordinary session bookkeeping still occurs.',
    'exclusivity_limit':'Can detect another currently recorded Web session. Does not reserve the stage file, stop future sessions or reveal every detached update worker.'},
   {'route':'GET /api/firmware-info','handler':fn('rest','getFwInfo_func'),
    'returns':['device_id','revision','fw_rev_1','fw_rev_2','ipmi_version','dev_support','mfg_id_0','mfg_id_1','mfg_id_2','prod_id','aux','fw_ver','bios_ver','date','time','active_image'],
    'scope':'Reads device/version metadata and /proc/ractrends/Helper/FwInfo. No FWUPDATEID/update-mode/session ownership output is present.'},
   {'route':'GET /api/maintenance/bios/upgradestatus?COMPONENT_ID=2','handler':fn('rest','getBIOSUpgradeStatus_func'),
    'backend':fn('bios','bios_get_update_progress'),'returns':['COMPONENT_ID','PROGRESS'],
    'scope':'Reads a stored progress value. Zero can also mean prepared/waiting; it is not an ownership or idle flag.'},
   {'route':'GET /api/maintenance/flashtrack','handler':fn('rest','trackFWTime_func'),
    'returns':{'status':'ok'},'scope':'Heartbeat response, not firmware-worker status.'},
   {'route':'GET /api/maintenance/firmware/flash-progress','handler':fn('rest','getFlashProgress_func'),
    'returns':['id','action','progress','state'],'scope':'BMC flasher progress. Its response does not establish the separate host-BIOS staging file or component-manager session is unused; underlying GetFlashProgress has not been fully audited here.'}],
  'unsupported_guess':'No GET /api/maintenance/firmware entry found in the inspected compiled route objects. Current upload route is POST /maintenance/firmware/firmware.',
  'uid_rule':'unique_id is returned by PUT enter-update-mode. FWUPDATEID in GET biosversion is an input, not a status read. Do not enter update mode just to obtain an ID for an ostensibly read-only occupancy check.',
  'operational_judgment':'Parent may combine the user-authorized maintenance window, exclusive control history, previous-session logout, sole current Web session, stable update metadata and absence of actual contrary update evidence. This is bounded operational evidence, not atomic exclusion. No automatic demand for extra user permission follows from the existence of a shared file.',
  'hardware_access_by_this_agent':False}
 state_id=write('state_query_review.json',state)
 frontend=HERE.parent/'bmc_static_readonly'
 module_names=['views_maintenance_BIOSUpdateView.js','views_maintenance_BIOSOOBUpdateView.js',
  'views_maintenance_BIOSUserProfileView.js','views_maintenance_BIOSUserProfileUpdateView.js','views_maintenance_backup_config.js','features.js']
 full=(frontend/'source.min.js').read_bytes();modules=[]
 for n in module_names:
  p=frontend/'selected_modules'/n;b=p.read_bytes();offset=full.find(b)
  # Parent extraction may add a newline for readability; verify the exact non-newline module.
  if offset<0:offset=full.find(b.rstrip(b'\r\n'))
  assert offset>=0,n
  modules.append(identity(p)|{'source_offset':offset})
 front={
  'status':'REVIEWED_CURRENT_CAPTURED_FRONTEND_MATCHES_OFFICIAL_1313','source':identity(frontend/'source.min.js'),'selected_modules':modules,
  'normal_web_update_order':['Start validates selected file/host state','EntryUpdateMode PUT','PrepareComponents PUT (current backend calls ActiveHostSPIDriver(0))',
   'UploadSignature POST complete CAP','VerifySignature PUT; successful callback automatically UploadBIOS',
   'UploadBIOS POST strips filesize modulo 16MiB (4096 bytes for ACE CAP), stages 64MiB ROM body',
   'GetBIOSInfo GET and user Continue confirmation','FlashBIOS PUT starts update worker','VerifyBIOS PUT is post-write verification','ExitUpdateMode PUT'],
  'oob_order':['POST /api/oob/start-lmedia','POST /api/oob/upload_oob','POST /api/oob/modifyoob','POST /api/oob/setoobflag enables ready image; host boot/update stage follows'],
  'oob_limits':'Current OOB UI reports invalid image/model/downgrade/fTPM/relay failures; it is not a standalone signature validator and does not establish unsigned/custom image acceptance.',
  'download_scope':[
   {'module':'backup_config','output':'bmc-config.bak','purpose':'Selected BMC settings (SNMP/KVM/network/IPMI/NTP/auth/syslog/fan). Save precedes GET download; not an identified host SPI dump or direct runtime core-feature export.'},
   {'module':'BIOSUserProfileUpdateView','output':'OOB.CMO','purpose':'BIOS user-profile export via GET /redfish/v1/UserProfile, not full SPI firmware.'},
   {'module':'BIOSUserProfileView','output':'OOB.CMOS or individual .CMO','purpose':'Settings profiles via POST downloaduserprofile_v2, not full SPI firmware.'}],
  'no_full_SPI_download_found_in_reviewed_modules':True,'scope_limit':'This is bounded current module inspection, not a claim that every undocumented BMC endpoint has been exhaustively excluded.'}
 front_id=write('current_frontend_review.json',front)
 feature={
  'status':'RUNTIME_RESIDENT_SIGNATURE_FLAG_NOT_OBSERVED_NO_DIRECT_NORMAL_READ_INTERFACE_IDENTIFIED',
  'name':'CONFIG_SPX_FEATURE_SIGNED_HASHED_IMAGE_SUPPORT','runtime_location':'g_corefeatures + 0x34',
  'actual_mapping':fn('feature','RetrieveCoreFeatures'),
  'configuration_reader':fn('feature','IsFeatureEnabled'),
  'semantics':'RetrieveCoreFeatures writes result to uint32 index 0xd. IsFeatureEnabled merges /var/tmp/libfeature with /etc/core_features then caches by process. Literal comparison with default string 0 determines true/false.',
  'official_core_features':identity(HERE/'bmc1313_inputs/etc/core_features'),
  'key_present_in_archived_core_features':'CONFIG_SPX_FEATURE_SIGNED_HASHED_IMAGE_SUPPORT' in (HERE/'bmc1313_inputs/etc/core_features').read_text(),
  'normal_read_interfaces_reviewed':[
   {'function':fn('rest','GetFeatureList_func'),'result':'IPMI GetSetFeatureList Feature1..20; not the core-feature structure offset 0x34.'},
   {'function':fn('rest','getBmcFeature_func'),'result':'Web feature/description table; no direct read of offset 0x34 identified.'},
   {'function':fn('rest','get_prj_conf_func'),'result':'Reads only values after = from core_features plus selected UI booleans. Bare keys, process cache, and merged INI state are not exported.'}],
  'bulk_export':'No BMC settings export was requested. The available UI backup is unrelated configuration and may include auth/settings; it is not a verified narrow accessor for this runtime flag.',
  'limit':'Absence in official configuration and a matching frontend do not prove the running component-manager value is zero.'}
 feature_id=write('runtime_signature_flag_review.json',feature)
 recovery={
  'status':'INDEPENDENT_FULL_BACKUP_AND_NO_POST_RECOVERY_NOT_ESTABLISHED',
  'backup':{'function':fn('bios','bios_backup_image'),'observed':'Renames /mnt/sdmmc0p%d/recovery_bios.bin_tmp to recovery_bios.bin. No SPI read or backup-image creation occurs in this function.'},
  'recovery':{'entry':fn('bios','bios_perform_recovery'),'worker':fn('bios','do_bios_recovery'),
   'observed':'Launches a worker which requires an already existing nonempty recovery_bios.bin, locates Host SPI Flash MTD, opens it read/write, then calls flash_bios_image from offset zero for the stored file size.'},
  'host_device_discovery':{'function':fn('host','find_bios_spi_device'),'observed':'Parses /proc/mtd for Host SPI Flash and forms /dev/mtd%d; it does not itself create the node, switch GPIO, or attest cabling.'},
  'write_extent':{'function':fn('host','flash_bios_image'),'observed':'Writes/compares erase-sized blocks over its supplied extent. For a 64MiB offset-zero image this is a full image loop, not a BIOS-region whitelist.'},
  'normal_preparation':{'function':fn('bios','bios_prepare_comp'),'hardware_helper':fn('bios','ActiveHostSPIDriver'),
   'observed':'Normal preparation calls ActiveHostSPIDriver(0); helper unloads/loads host_spi_flash_hw, switches board GPIO/voltage mode and inspects ROM ID. It cannot be described as a read-only readiness query.'},
  'normal_ssh':'Parent reported successful user-authorized SSH authentication into SMASHLITE Scorpio, with help/show only and no advertised backup/file commands. This subagent did not connect or independently capture SSH.',
  'archived_ssh_config':identity(HERE/'bmc1313_inputs/etc/ssh/sshd_fixed_config'),
  'unknowns':['Whether current BMC exposes a usable Host SPI Flash MTD before preparation.',
   'Whether required BMC and TPM/SPI connections are present and work on this unit.',
   'Whether an existing recovery file is a byte-verified complete current-unit image and is reachable when host cannot POST.',
   'Whether normal authorized remote recovery entry is available independently of the failed host and its SPI mux/driver prerequisites.'],
  'hardware_ops_by_this_agent':False}
 recovery_id=write('backup_recovery_review.json',recovery)
 rea=HERE/'rea_ace_secflash_elevated01'
 entries=[]
 for p in sorted(rea.glob('response-*.json')):
  d=json.loads(p.read_text());s=d.get('structuredContent') or {}
  if s.get('evidence_id'):entries.append({'response':identity(p),'evidence_id':s['evidence_id'],'operation':s['operation'],'parameters':s['parameters'],'subject_sha256':s['subject']['digest']['sha256']})
 rea_report={'status':'ACE_NATIVE_PE_REA_COMPLETE_CLOSED_ARM_ELF_PROVIDER_UNSUPPORTED_RECORDED',
  'evidence':entries,'bundles':[identity(rea/'secflash_evidence.json'),identity(rea/'fmp_evidence.json')],
  'close_after_secflash':identity(rea/'response-009.json'),'close_after_fmp':identity(rea/'response-019.json'),
  'final_close':identity(rea/'final-close.json'),'ARM_ELF_rejection':identity(rea/'response-020.json'),
  'native_PE_findings':[
   'ACE SecSMIFlash 0x3470 hashes selected ROM map attributes 0x200 plus map; 0x397c performs certificate and firmware checks through the native crypto protocol. ACE flags 0x10001 select certificate material 0x228 bytes, unlike W890 flags0x10005 path.',
   'ACE FmpCapsuleUpdate 0xa48 calls FMP GetImageInfo to select matching image type/instance; 0xc1c calls protocol slot +0x10 (SetImage). This observed consumer path is not a proof of GetImage whole-SPI backup availability or a CheckImage-only workflow.'],
  'Ghidra_fallback':'Exact ARM ELF bytes analyzed through installed standalone Ghidra12.1.4 and independently cross-checked with ELF/Capstone. These results are not falsely labeled REA Evidence.',
  'native_fallback_evidence':identity(HERE/'bmc1313_native_evidence.json')}
 rea_id=write('rea_update_summary.json',rea_report)
 report={
  'status':'REFERENCE_REVIEW_COMPLETE_UPDATE_ACCEPTANCE_AND_INDEPENDENT_RECOVERY_REMAIN_OPEN',
  'date':'2026-11-08','scope':'Read archived W790/W890 projects and official/current BMC bytes. Writes confined to update_path_reference. No BMC connection, firmware upload, target native execution, firmware change or flash by this agent.',
  'shortest_route_assessment':[
   'A retained original signature is invalid for candidate05 9b038c4e…; renaming or reusing that signature cannot make it accepted by the observed normal CAP verifier.',
   'Do not conclude every BMC update requires an OEM private key: current PDK certificate and firmware checks use public moduli inside the CAP itself. Engineering NON-OEM CAP e330039e… independently passed this actual native PDK control flow with mathematical public-key crypto imports; that result is narrower than live update acceptance.',
   'The normal independently addressable temporary upload+CAP verifier can be assessed separately from GPIO/flash, with the documented staging side effects. Passing it is narrower than update acceptance.',
   'The later resident-key tail-signature branch is conditional on an unobserved live runtime flag. No direct normal GET/export accessor for this precise flag was established.',
   'With only BMC access and no independently established recovery path, a modified image cannot yet be designated flash-ready. External programmer/physical FlashBack are not currently available user resources, and software presence is not backup/recovery proof.'],
  'original_and_candidate_crypto':identity(HERE/'ace_capsule_signature_review05.json'),
  'native_crypto_control_flow':identity(HERE/'bmc1313_native_signature_replay.json'),
  'independent_engineering_CAP_replay':identity(HERE/'bmc1313_engineering_signature_replay.json'),
  'live_official_package_binding':identity(HERE/'bmc1313_extraction_manifest.json'),
  'public_anchor_scan':identity(HERE/'bmc1313_public_anchor_metadata.json'),
  'local_tool_inventory':identity(HERE/'local_tool_inventory.json'),
  'focused_reports':[staging_id,state_id,front_id,feature_id,recovery_id,rea_id],
  'prior_project_limits':[
   {'project':'W790E-SAGE-SE1904','reference':'analysis/aitweaker_lock/lock_sage_1904/review/flash_readiness/remote_only/update_chain_review05/update_chain_review.json',
    'reuse':'Review methods and format clues; its BMC1.1.57 addresses/feature state are not current ACE1.03.13 evidence.'},
   {'project':'W890 SAGE0603','reference':'analysis/aitweaker_lock/lock_w890_sage/release_review/release_matrix.json',
    'reuse':'Capsule/FMP trust boundaries and check structure. G10 update acceptance/G11 hardware boot/G12 independent backup-recovery were open; no successful custom-flash precedent to inherit.'}],
  'tool_route_assessment':[
   {'tool':'BIOSRenamer','status':'Found in official BIOS bundles; file naming utility, not signing or acceptance proof.'},
   {'tool':'AFU','status':'No board-specific engineering AFU binary/package found in bounded local inventory. AMI documentation says modern update requests are checked by secure firmware; generic AFU availability does not establish custom-image acceptance.'},
   {'tool':'FPT / external programmer / flashrom','status':'No usable board-specific engineering route established in this workspace. Full current-unit backup, correct layout/protection/boot policy and independent recovery would have to be proven. User currently has BMC only.'},
   {'tool':'ASUS YafuFlash / FWUpdateWin / FWUpdateLinux','status':'Official tools for BMC firmware; not evidence that modified host BIOS can be flashed.'},
   {'tool':'OpenSSL','status':'Existing D:/OpenSSL-Win64 used for public signature verification only by this agent; engineering-key generation/signing belongs to a separate parent-assigned review.'}],
  'primary_sources':[
   {'url':'https://www.asus.com/supportonly/ipmi%20expansion%20card/helpdesk_bios/','observed':'ASUS1.3.13 released2026-02-26; published ZIP SHA E1ED36367666737D27A41725756DABD02CFCBB38C7EEE9D606B3A682955A5175 matches local archive.'},
   {'url':'https://dlcdnets.asus.com/pub/ASUS/mb/Add-on_card/IPMI_EXPANSION_CARD/Compatible_Model_List.pdf','observed':'W790-ACE supports Remote BIOS Forced Update; BMC and TPM/SPI header connections are mandatory. This is capability documentation, not this-unit cable or custom-image acceptance evidence.'},
   {'url':'https://www.asus.com/us/supportonly/pro%20ws%20w790-ace/helpdesk_bios/','observed':'Official ACE1904 bundle/FlashBack filename PWW790A.CAP; not custom signature acceptance.'},
   {'url':'https://dlcdnets.asus.com/pub/ASUS/mb/LGA4677/Pro_WS_W790-ACE/E22143_Pro_WS_W790-ACE_UM_V3_WEB.pdf?model=Pro+WS+W790-ACE','observed':'FlashBack needs specified USB port, standby power and physical button; unavailable merely by remote filename change.'},
   {'url':'https://www.ami.com/resources/ami-firmware-utility-afu-a-secure-update-utility-for-aptio-v-uefi-bios-firmware/','observed':'AFU update requests are processed under firmware secure-update policy.'},
   {'url':'https://uefi.org/specs/UEFI/2.10/23_Firmware_Update_and_Reporting.html','observed':'FMP GetImageInfo/GetImage/SetImage/CheckImage are distinct operations; protocol presence does not prove a whole-SPI backup route.'}],
  'claims_not_made':['No claim of live signature acceptance, full firmware update acceptance, modified cold boot, physical recovery, real persistent Save/Reset or final flash readiness.',
   'No claim the BMC public frontend hash attests every active backend byte.',
   'No blanket claim that the OEM private key is required for every path, or that any self-signed CAP is trusted by native host firmware.']}
 report_id=write('update_path_reference.json',report)
 text='''ACE1904 刷写链参考复核（2026-11-08）

当前 1.03.13 官方 KODO1313.ima 与 188 抓取前端逐字节一致；镜像来自 ASUS 官方 ZIP，公开 SHA 相符。真实 ARM 后端另由 Ghidra 与 ELF/Capstone 复核；REA 已完成 ACE SecSMIFlash/FMP 并关闭，Windows REA 拒绝 ARM ELF 的证据完整保留。

05 review 9b038c4e… 保留的固件签名失败。原厂 CAP 成功、05 失败已经 Python/OpenSSL 以及当前 PDK 真实 ARM 指令回放交叉证明。这不等于所有 BMC 路线必须有厂商私钥：PDK 的两次公钥都来自 CAP；独立工程重签 e330039e… 已通过同一真实 PDK 回放，但后续 bios_start_update 还有可选的 BMC 驻留根尾签分支，当前运行开关仍未观测。

已发现正常独立暂存/验签接口：uploadSignature POST 完整 CAP、verifySignature PUT。所审调用链无进入模式/Prepare/GPIO/刷写；只包含暂存文件、会话及 IPC 副作用。它可证明的范围仅是 CAP 两次验签，不是整条更新 dry-run。详见 staging_validation_review.json。不要通过网页 Start 或 ExitUpdateMode 把它扩成硬件操作。

bios_backup_image 只是把已有恢复临时文件改名，不生成 SPI 备份；恢复函数依赖已有完整文件与 Host SPI Flash MTD。当前仍未证明可在 host 无 POST 时独立恢复。Settings/CMO 下载不是整片 BIOS 备份，SMASH 管理登录也不自动等于 Linux shell。

最短候选路线是：明确标记自有工程签名身份，单独证明 CAP 验签；同时完成本机完整备份、运行时尾签条件、SPI 接线/访问与独立恢复证据。上述门槛未齐前，不标为可刷。OEM 正式签发、物理 FlashBack、编程器各有不同前提；不能用改名或旧签名替代。

本代理没有连接 BMC、上传、切换 GPIO、刷写或更改已有驱动源。所有结论、准确函数地址、哈希、REA Evidence 和官方链接见 update_path_reference.json 及其引用。
'''
 (HERE/'README-update-path.txt').write_text(text,encoding='utf8')
 print(json.dumps({'report':report_id,'staging':staging_id,'native_functions':sum(len(v['functions']) for v in native['libraries'].values())}))

if __name__=='__main__':main()
