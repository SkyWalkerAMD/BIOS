"""Offline contract from pinned official frontend/backend; does not access a target."""
from pathlib import Path
import hashlib
import json

HERE = Path(__file__).resolve().parent
REF = HERE.parent
F05 = REF.parent
ROOT = F05.parents[3]
CAP_SHA = 'e330039ecd2c334c4f9d502589e7f9503000b34462a7e21f6b97b1b581794d08'
PAYLOAD_SHA = '2dd240c1ddb8890500ce028bb7de25d2db8f687117f4c0d2a57ba400ffbe9809'
SIZE = 67108864
CAP = F05/'engineering_signature/W790-ACE-1904-CANDIDATE05-ENGINEERING-NONOEM-NOT-FLASH-READY.CAP'
UI = F05/'bmc_static_readonly/selected_modules/views_maintenance_BIOSUpdateView.js'

def sha(p): return hashlib.sha256(p.read_bytes()).hexdigest()
def ident(p): return {'path':p.relative_to(ROOT).as_posix(),'sha256':sha(p),'bytes':p.stat().st_size}
def save(p,x): p.write_text(json.dumps(x,indent=2,ensure_ascii=False)+'\n',encoding='utf8')

cap=CAP.read_bytes()
assert len(cap)==SIZE+4096 and hashlib.sha256(cap).hexdigest()==CAP_SHA
assert hashlib.sha256(cap[4096:]).hexdigest()==PAYLOAD_SHA
header=cap[4096+0x3ecc75c:4096+0x3ecc75c+203]
expected = {'MajorVersion':header[12], 'MinorVersion':header[13], 'HardwareVersion':header[11],
 'BaseboardId':header[14:].split(b'\0')[0].decode(), 'ProjectPath':header[106:].split(b'\0')[0].decode()}
assert expected=={'MajorVersion':19,'MinorVersion':4,'HardwareVersion':0,'BaseboardId':'Pro-WS-W790-ACE','ProjectPath':'A5336'}
assert int.from_bytes(header[117:121],'little')==SIZE
echo={'COMPONENT_ID':2,'COMPONENT_DATA_LEN':SIZE,'FWUPDATEID':'uid'}
info={prefix+'_'+k:v for prefix in ['Mtd','Cap'] for k,v in expected.items()}
base='/api/maintenance/bios/'
steps=[
 {'step':1,'operation':'enter','method':'PUT','path':base+'updatemode','body':'zero bytes','content_type':'application/json',
  'success_http':200,'success_json':{'unique_id':'integer in [0,2147483647], including zero'},
  'error_http':500,'error_json':{'code':1373,'error':'Error in Firmware Upgrade Status'}},
 {'step':2,'operation':'prepare','method':'PUT','path':base+'preparecomponents','body':{**echo,'IS_MMC':0},
  'success_http':200,'success_json':echo,'error_http':500,'error_json':{'code':1373,'error':'Error in initial Upgrade Action'},
  'meaning':'Returns request echo, not measured JEDEC or MTD capacity. Changes GPIO and loads Host SPI driver; no inspected program/erase call in preparation.'},
 {'step':3,'operation':'upload_signature','method':'POST','path':base+'uploadSignature',
  'multipart_field':'biossignature','file_bytes':SIZE+4096,'file_sha256':CAP_SHA,
  'success_http':200,'success_json':{'cc':0}},
 {'step':4,'operation':'verify_signature','method':'PUT','path':base+'verifySignature','body':'zero bytes','content_type':'application/json',
  'success_http':200,'success_json':{},'error_http':500,'error_json':{'code':1305,'error':'Error in Firmware Upgrade Status'}},
 {'step':5,'operation':'upload_payload','method':'POST','path':base+'biosfw','multipart_field':'hpmbios',
  'input':'Exactly CAP[4096:] from the already SHA-bound in-memory CAP buffer; one complete multipart file, not arbitrary chunks.',
  'file_bytes':SIZE,'file_sha256':PAYLOAD_SHA,'success_http':200,'success_json':{'cc':0}},
 {'step':6,'operation':'read_native_board_info','method':'GET','path':'/api/maintenance/biosversion',
  'query':{'FWUPDATEID':'uid','COMPONENT_ID':2},'success_http':200,'this_target_required_json':info,
  'types':'Version fields JSON integers; BaseboardId and ProjectPath JSON strings.',
  'normal_ui_gate':'Host Off; Mtd major/minor not both zero; Cap/Mtd BaseboardId and ProjectPath equal; Cap HardwareVersion >= Mtd HardwareVersion. This known 1904 target additionally binds the exact observed version and expected metadata above.',
  'errors':{'http':500,'code':1373,'error':['Error in open Mtd or BIOS file','Error in get BIOS file Version']},
  'limit':'HTTP200 also wraps backend 0xf0 current-header-read failure; empty/zero current fields are therefore rejection, never ForceMode admission.'},
 {'step':7,'operation':'flash_start_once','method':'PUT','path':base+'flash',
  'body':{**echo,'SECTION_FLASH':0,'FlashOffset':0},'success_http':200,'success_json':echo,
  'error_http':500,'error_json':{'code':1373,'error':'Error in Finish Firmware Upload'},
  'effect':'Starts asynchronous worker after existing optional resident signature check and BiosConfiguration preservation. Never retry after ambiguous response.'},
 {'step':8,'operation':'flash_status','method':'GET','path':base+'upgradestatus','query':{'COMPONENT_ID':2},
  'success_http':200,'success_json':{'COMPONENT_ID':2,'PROGRESS':'integer'},
  'progress':{'-1':'explicit flash failure','0..99':'in progress','100':'write worker has completed writes; separate verification still required'},
  'error_http':500,'error_json':{'code':1373,'error':'Error in Finish Firmware Upload'}},
 {'step':9,'operation':'verify_image_start_once','method':'PUT','path':base+'verifyimage',
  'body':{**echo,'FlashOffset':0},'success_http':200,'success_json':{'COMPONENT_ID':2},
  'error_http':500,'error_json':{'code':1373,'error':'Error in Finish Firmware Upload'},
  'note':'Only COMPONENT_ID is returned, despite frontend attempting to pass returned FWUPDATEID onwards. Status GET does not take FWUPDATEID.'},
 {'step':10,'operation':'verify_image_status','method':'GET','path':base+'verifyimagestatus','query':{'COMPONENT_ID':2},
  'success_http':200,'success_json':{'COMPONENT_ID':2,'PROGRESS':'integer'},
  'progress':{'-1':'explicit readback/compare failure','0..99':'in progress','100':'all requested blocks compared to the preserved staged payload'},
  'error_http':500,'error_json':{'code':1373,'error':'Error in Finish Firmware Upload'}},
 {'step':11,'operation':'exit_owned_update_mode','method':'PUT','path':base+'exitupdatemode',
  'body':{'FWUPDATEID':'uid','COMPONENT_ID':2},'success_http':200,'success_json':{'cc':0},
  'error_http':500,'error_json':{'code':1373,'error':'Error in Firmware Upgrade Status'}}
]
ui=UI.read_text(encoding='utf8')
for step in steps:
    if step['operation'] in ['upload_signature','upload_payload']:
        assert '"'+base+'"' in ui and '"'+step['path'].rsplit('/',1)[1]+'"' in ui
    else:
        assert step['path'] in ui

sources=[
 'bmc1313_annotated/rest/0012b96c-putBIOSUpdateMode_func.c',
 'bmc1313_annotated/rest/0012d0b4-setBIOSPrepareComponents_func.c',
 'bmc1313_annotated/rest/001300c4-uploadBIOSSignature_func.c',
 'bmc1313_annotated/rest/00131920-VerifySignature_func.c',
 'bmc1313_annotated/rest/0012fce8-uploadBIOSFWImage_func.c',
 'bmc1313_annotated/rest/00131200-getBIOSVersion_func.c',
 'bmc1313_annotated/rest/0012d73c-putBIOSStartFlashMode_func.c',
 'bmc1313_annotated/rest/0012ddb8-getBIOSUpgradeStatus_func.c',
 'bmc1313_annotated/rest/0012e8a4-BIOSVerifyImage_func.c',
 'bmc1313_annotated/rest/0012e32c-BIOSVerifyImageStatus_func.c',
 'bmc1313_annotated/rest/0012be58-putBIOSExitUpdateMode_func.c',
 'bmc1313_bios_decompile/000131f4-bios_prepare_comp.c',
 'bmc1313_bios_decompile/00013930-get_bios_mtd_size.c',
 'bmc1313_annotated/bios/00013964-bios_get_version.c',
 'update_preservation/0001380c-PDK_GetASUSBIOSInfo.c',
 'bmc1313_annotated/bios/00013ce4-bios_start_update.c',
 'bmc1313_annotated/bios/000137fc-bios_flash.c',
 'bmc1313_annotated/host/000115d0-flash_bios_image.c',
 'bmc1313_annotated/host/00011360-spi_write_erase_block.c',
 'bmc1313_annotated/host/00011788-verify_bios_img.c',
 'bmc1313_annotated/bios/00013668-bios_verify_comp.c',
 'bmc1313_annotated/bios/00014054-bios_verify_flash.c',
 'recovery_kernel_decompile/00010ba4-host_spi_flash_write.c',
 'recovery_kernel_decompile/00010d3c-host_spi_flash_erase.c',
 'recovery_extension/daemon-0001192c-FUN_0001192c.c',
 'recovery_extension/daemon-00011aa8-FUN_00011aa8.c',
 'recovery_extension/prepare_exit_review.json',
 'update_preservation/update_preservation_review.json',
 'runtime_signature_flag_review.json'
]
report={
 'status':'OFFLINE_NORMAL_UPDATE_CONTRACT_CONFIRMED_LIVE_PREFLIGHT_REQUIRED',
 'scope':'Official BMC 1.3.13 ARM ELF and byte-identical archived/live frontend. Existing Ghidra/native evidence reused; no new REA session, network request or target mutation.',
 'candidate':ident(CAP),'payload':{'offset':4096,'bytes':SIZE,'sha256':PAYLOAD_SHA},
 'frontend':ident(UI),'source_provenance':ident(REF/'bmc1313_extraction_manifest.json'),
 'builder':ident(Path(__file__).resolve()),'steps':steps,
 'authentication':'Normal administrator session from POST /api/session form login; QSESSIONID cookie jar plus X-CSRFTOKEN from that session; passwordStatus must be 0. Credentials and CSRF are not part of this report.',
 'upload_limits':{'max_content_length_including_multipart':0x4300000,
  'missing_or_zero_content_length':{'http':411,'json':{'cc':5,'error':'Invalid Content Length received'}},
  'too_large':{'http':413,'json':{'cc':6,'error':'Invalid Content Length received'}},
  'rename_failed':{'http':500,'json':{'cc':-1}},
  'note':'Single complete normal multipart uploads. No frontend five-minute retransmission timer should be copied into an explicit one-shot state machine.'},
 'capacity_and_board_admission':{
  'prepare':'Requires request ID, Check_FeatureList==1, Host SPI MTD found, freeram>=requested length. ActiveHostSPIDriver ignores several shell/GPIO results; no capacity comparison here.',
  'native_board_read':'bios_get_version opens MTD_Device, gets lseek(SEEK_END), then PDK scans from offset zero in 2KiB increments for $BOOTEFI$. The actual MTD metadata is returned separately from staged CAP metadata.',
  'not_exported':['JEDEC ID','MTD byte capacity','offset where $BOOTEFI$ was found'],
  'header_read_inference':'Matching returned header confirms an ACE header was read via the selected Host SPI MTD. Because the search position and MTD size are not returned, this alone does not mathematically prove 64MiB capacity.',
  'candidate_declared_flash_bytes':SIZE,
  'parent_verified_context':{'ASUS_specification':'512 Mb Flash ROM = 64 MiB',
   'official_url':'https://www.asus.com/ca-en/motherboards-components/motherboards/workstation/pro-ws-w790-ace/techspec/',
   'official_manual':'E22143, independently checked by parent',
   'host_live_fd_range':'0x00000000..0x03ffffff inclusive, independently captured by parent',
   'scope':'These context facts were supplied by the parent; this offline reviewer did not repeat that web/hardware collection.'},
  'decision':'With the existing specification/FD/layout agreement, a successful fresh Prepare, exact native ACE1904/A5336/HW0 metadata, and CAP verification satisfy the normal observable non-force updater admission for the user-authorized operation. Do not invent a mandatory unavailable JEDEC API; do not describe echoed length as a measurement.'},
 'first_erase_bounds':{
  'bios_start_update':'Checks requested COMPONENT_DATA_LEN >= staged file size. Does not compare against actual MTD capacity before pthread_create.',
  'worker':'bios_flash -> flash_bios_image -> spi_write_erase_block. Iterates entire staged payload in configured blocks; each block must first seek/read fully. Equal blocks skip; different blocks invoke MEMERASE followed by write.',
  'kernel':'Host SPI erase/write callbacks reject addr+len beyond mtd->size. These are per-operation bounds, not an up-front whole-image transaction or guarantee that no earlier block changed before a later failure.',
  'range_for_this_operation':'SECTION_FLASH=0, FlashOffset=0, staged payload64MiB. Normal BiosConfiguration first copies the candidate NPB preservation intervals from current SPI into staged data. No arbitrary offsets, forced SECTION_FLASH255, or alternate target.'},
 'terminal_and_cleanup':{
  'success':'Observe flash PROGRESS100, then successful verifyimage start and verifyimagestatus100, then normal Exit HTTP200 cc0. Boot and AI Tweaker acceptance are separate post-update evidence.',
  'signature_gate':'Optional resident-key VerifyImageSign in bios_start_update executes before worker creation; full CAP verification is not evidence that this optional gate is disabled or already passed. Keep that check unchanged.',
  'before_start_failure':'For a known owned uid and no issued/accepted flash request, failed prepare/upload/signature/info validation may use official Exit. Preparation itself may already attempt ActiveHostSPIDriver(1) on failure.',
  'explicit_start_rejection':'A structurally valid native HTTP500/code1373 start error represents an immediate pre-worker or pthread_create failure in the inspected path. Preserve failure and perform owned normal Exit; do not turn it into a retry or ForceMode.',
  'ambiguous_after_start':'Timeout, dropped response, malformed status, or connection loss does not prove worker termination. Do not retransmit flash or invoke Exit as a generic cancellation while work may continue. Reconcile using normal status observations and retain the host Off.',
  'progress_negative':'PROGRESS -1 is explicit backend failure, including read/erase/write/compare failures. Preserve failed status; normal Exit restores update ownership without claiming original SPI contents restored.',
  'progress_other':'Values outside integer[-1,100] or a mismatched component are unknown/reject; do not normalize to success.',
  'normal_exit_effects':'For component2 REST runs rmmod host_spi_flash_hw, then GPIO5/15/101/13 inputs and GPIO97 output/high, unlinks bios.bin; only then CMD_Exit validates the uid and removes FWmode. Logical success unlinks block_chassis_ops; REST writes biosflashing0.',
  'exit_ownership':'Because electrical cleanup precedes uid validation, never issue Exit with fabricated uid0 after failed/missing Entry. A genuine returned uid0 is valid.',
  'restoration_limit':'The normal cleanup is the official available path, not a claim of exact original GPIO/controller/address-mode restoration. HTTP200 cc0 attests the logical operation, not every ignored shell/GPIO result.',
  'post_exit':'Confirm normal management remains available and host/media/Boot state as appropriate. Only the parent coordinates power/POST; this contract does not call activatecomponents.'},
 'preservation_scope':'Normal NPB preservation is automatic; the normal BIOS UI exposes no NVRAM/SMBIOS/logo checkbox. Existing custom SHUANG splash and native NVRAM are not covered by the preserved ranges. Refer to the bound preservation review for exact offsets.',
 'evidence':[ident(REF/p) for p in sources],
 'BMC_accessed':False,'hardware_or_firmware_operation_performed':False
}
save(HERE/'contract.json',report)
note='''官方 BMC 1.3.13 / ACE 1904 候选05正常更新契约（离线复核）

实际 CAP 固定 e330039ecd2c334c4f9d502589e7f9503000b34462a7e21f6b97b1b581794d08。
完整 CAP 为67112960字节；biosfw 单次 multipart hpmbios 上传其去4096字节头的67108864字节 payload，SHA256 2dd240c1ddb8890500ce028bb7de25d2db8f687117f4c0d2a57ba400ffbe9809。

顺序与确切方法/JSON见 contract.json 的11步：Entry→Prepare→完整CAP暂存验签→payload上传→原生MTD板号核对→一次flash→写进度100→一次verifyimage→读回进度100→正常Exit。
全部正常认证 Cookie + CSRF。Entry unique_id 为0..2147483647，0有效；不可凭空补0。
Prepare/flash 回 COMPONENT_ID、COMPONENT_DATA_LEN、FWUPDATEID；verifyimage 只回 COMPONENT_ID；Exit 回 cc0。
MTD/CAP应为 Pro-WS-W790-ACE / A5336 / Hardware0 / Major19 / Minor4；不得将空或未知MTD数据改为强制模式。

Prepare的容量是请求回显，无JEDEC/实测容量。官方512Mb规格、既有host FD覆盖64MiB、候选布局一致，以及本次实际读取的原生MTD身份，共同支持原厂普通模式准入；不把不可取得的JEDEC字段增加成新门槛。
worker首次擦除前没有整片容量预扫。每块先完整读取，内核另有addr+len不超MTD边界；这不是全片事务。实际写入仍须读回验证100及后续开机功能验收。
发出flash后响应丢失不代表未启动；不重复flash、不把Exit当作可安全中断。只有已知自身uid和已确定阶段才走官方Exit。Exit有固定GPIO/驱动清理，不能声称精确恢复每个电气状态。

本报告没有访问BMC或执行任何写入；已有1.3.13离线反编译与原始字节证据复用。所有字段、来源哈希及能力边界保存在contract.json。
'''
(HERE/'README-contract.txt').write_text(note,encoding='utf8')
print(json.dumps({'contract':ident(HERE/'contract.json'),'readme':ident(HERE/'README-contract.txt'),'steps':len(steps),'BMC_accessed':False}))
