"""Write the bounded, source-bound Creator P6 behavior review; no target I/O."""
from pathlib import Path
import hashlib,json
P=Path(__file__).resolve().parent;ROOT=P.parents[2]
manifest=json.loads((P/'artifact-manifest.json').read_text())
index=json.loads((P/'rea-evidence-index.json').read_text())
mapping=json.loads((P/'creator-post-status-mapping.json').read_text())
def evidence(response):
 return next(x for x in index if x['response'].replace('\\','/').endswith(response))['evidence_id']
def refs(name,*addresses):
 return {'module':name,'addresses':list(addresses)}
ev={
 'watchdog_core':evidence('004-frb-behavior.json'),
 'watchdog_callbacks':evidence('015-frb-callbacks.json'),
 'ipv4':evidence('009-ip4-behavior.json'),
 'sel_helpers':evidence('014-sel-behavior.json'),
 'sel_boot_callback':evidence('003-sel-callback.json'),
 'elog_core':evidence('019-elog-behavior.json'),
 'elog_methods':evidence('007-elog-methods.json'),
 'time_sync_sel':evidence('011-init-sel.json')}
fields=[
 ('OS Watchdog Timer',0x1a,'u8',{0:'Disabled',1:'Enabled'}),
 ('OS Wdt Timer Timeout',0x1b,'u8; 1..30 minutes',None),
 ('OS Wdt Timer Policy',0x1c,'u8',{0:'Do Nothing',1:'Reset',2:'Power Down',3:'Power Cycle'}),
 ('SEL Components',0x1d,'u8',{0:'Disabled',1:'Enabled'}),
 ('Erase SEL',0x1e,'u8',{0:'No',1:'Yes, On next reset',2:'Yes, On every reset'}),
 ('When SEL is Full',0x1f,'u8',{0:'Do Nothing',1:'Erase Immediately',2:'Delete Oldest Record'}),
 ('Log EFI Status Codes',0x20,'u8',{0:'Disabled',1:'Both',2:'Error code',3:'Progress code'}),
 ('LAN1 address source',0x26,'u8',{0:'Unspecified',1:'Static',2:'DynamicBmcDhcp'}),
 ('LAN1 station IP',0x27,'CHAR16[15]',None),('LAN1 subnet',0x45,'CHAR16[15]',None),
 ('LAN1 gateway IP',0x63,'CHAR16[15]',None),('LAN1 gateway MAC',0x81,'CHAR16[18]',None),
 ('LAN2 address source',0xa5,'u8; present in IFR; not applied by inspected IPv4 driver',None)]
report={
 'scope':{'task':'Creator 3002 behavior evidence for HERO P6 IPMI settings',
 'date':'2026-11-04','method':'Read-only firmware artifact analysis; local REA/Ghidra and independent Capstone decoding.',
 'hardware_actions':'None; no BMC connection, target execution, BIOS modification, network setting, watchdog, or SEL command was sent.',
 'not_a_compatibility_certificate':True},
 'artifacts':manifest,'rea_evidence':ev,
 'server_setup':{'name':'ServerSetup','guid':'01239999-FC0E-4B6E-9E79-D54D5DB6CD20','size':615,
 'field_sources':['analysis/hero_ipmi_p1c/reference/creator-config-map.json','analysis/hero_ipmi_p1/reference/creator-ifr.json','analysis/hero_ipmi_p1/reference/creator-en-us.json'],
 'fields':[{'name':n,'offset':hex(o),'encoding':t,'options':v} for n,o,t,v in fields],
 'boundary':'These are Creator-owned offsets. Their existence does not authorize editing HERO ServerSetup wholesale; a separate HERO-owned config layout may be appropriate.'},
 'watchdog':{
 'observed':[
 'DxeFrb main 0xAD8 reads ServerSetup once during DXE. Read failure defaults OS watchdog disabled, timeout 10 minutes, policy Reset. FRB2 has separate offsets 0x17..0x19.',
 'OS watchdog enabled 0x1A gates callback-specific registration and arm routine. The UI range is 1..30 minutes; 0x84C multiplies byte 0x1B by 60,000,000 microseconds; 0x414 divides by 100,000 for IPMI countdown ticks. Thus 600 ticks/minute.',
 'BeforeBoot callback 0x910 stops FRB2 use 1 if enabled and calls OS arm 0x84C if OS enabled. LegacyBoot callback 0x8B8 does the same after locating the AMI LegacyBoot protocol.',
 'Arm 0x4D4 obtains Get Watchdog Timer (06/25); with transport available, matching data, and nonzero duration, sends Set Watchdog Timer (06/24), then Reset Watchdog Timer (06/22). OS timer use=3, action=0x1C low3 bits, pretimeout=0, preinterrupt=0, clear-expiration flag=0x08.',
 'Example raw Set payload for 10 min, Reset action is 03 01 00 08 70 17. TimerUse does not set the do-not-stop bit.',
 'SetupEnter callback 0x944 stops OS use 3 and sets PCD token 0x214. Shell notifications both call 0xA0C -> stop use3. AfterFirstBootOption callback 0xA20 clears the PCD flag; it does not directly arm or stop the timer.',
 'Stop 0x708 first obtains 06/25; it sends 06/24 with zero duration only when running bit0x40 is set and TimerUse low3 matches requested use. It does not Reset afterwards; it returns NOT_FOUND for a different timer use and NOT_STARTED for an already stopped timer.',
 'Disabled config prevents subsequent OS arming. The main path does not unconditionally stop an already running OSLoad timer when config is disabled. Saved config is loaded on the next driver initialization.',
 'No ReadyToBoot/ExitBootServices arm or stop registration is present in the inspected DxeFrb OS watchdog paths. This is a module-bounded conclusion, not a claim about all BIOS components.'
 ],
 'notify_guids':{
 'BeforeBoot':'3677770F-EFB2-43B2-B8AE-B302E9604882',
 'SetupEnter':'71202EEE-5F53-40D9-AB3D-9E0C26D96657',
 'AmiLegacyBoot':'120D28AA-6630-46F0-8157-C0ADC2383BF5',
 'AfterFirstBootOption':'C48D651C-9D0E-4CE7-AD39-EDD1AB836B30',
 'ShellEnvironment2':'47C7B221-C42A-11D2-8E57-00A0C969723B',
 'ShellProtocol':'6302D008-7F9B-4F30-87AC-60C9FEF5DA4E'},
 'registration':'0x1010 is CreateEvent(0x200, TPL, callback) + RegisterProtocolNotify. BeforeBoot/SetupEnter/LegacyBoot TPL=8; Shell registrations TPL=0x10 in Creator. Shell GUIDs are stack constants in 0xAD8, registrations around 0xE26..0xE47.',
 'hero_evidence':{'file':'hero-beforeboot-publication.json','target_sha256':'f48b8729b53e1bcd196a533576d0b228d2df175c631f314d56623a5a88bcb02c',
 'guid_construction_rvas':['0xD0B9','0x4E98C'],'publishing_calls':['0xD29F','0xD534','0xD9D9','0x4EB9C'],
 'publisher_helper':'0x176C; InstallProtocolInterface then UninstallProtocolInterface',
 'critical_limit':'HERO call0x4EB9C lies after LoadImage success and before StartImage. BeforeBoot is not intrinsically OS-only; a generic UEFI tool can trigger it. Shell notifications only cover applications that publish a matching Shell marker.'},
 'sources':[refs('DxeFrb','0xAD8','0x910','0x8B8','0x84C','0x414','0x4D4','0x708','0x944','0xA0C','0xA20','0x1010')],
 'unverified':['Actual HERO event ordering and the new resident callback lifetime.','OS management agent adoption/disarming of an armed OSLoad watchdog.','Behavior when a UEFI tool does not publish Shell markers or does not return to Setup.','Completion-code/error translation for every AMI transport call; do not clone unchecked status handling.']},
 'sel':{
 'components':{
 'meaning':'Enable Creator host-side error/progress event logging and the gated DXE boot-time erase/full policy; it is not the BMC global system-event-logging enable bit.',
 'source':'HII help string65; DxeSelStatusCode callback0x1304; PeiSelStatusCode entry0xFFF82D4C.',
 'filter':'ServerSetup[0x20]=0 disabled,1 both,2 error,3 progress. PEI entry checks Components!=0 and LogEFI!=0 before registering; variable-read failure defaults Components1/Erase0/WhenFull0/LogEFI2.',
 'dxelog_separation':'DxeBmcElog status method0x16D8 reads 06/2F and manipulates global enable bit3 via 06/2E. No ServerSetup read links this directly to Components in that module. It is an independent BMC-global control.'},
 'erase':{
 'owner':'DxeSelStatusCode 0x10C4 creates a TPL8 protocol-notify event for AMI IPMI transport; callback0x1304 obtains the transport and config then closes its event.',
 'no_0':'No explicit boot-time erase. Other producers/full policies may still clear when separately configured.',
 'next_reset_1':'With Components enabled, call ClearSEL helper, then write Erase=0 back to ServerSetup. The donor resets the flag even when clear returns failure; the caller ignores that result.',
 'every_reset_2':'With Components enabled, call the same helper and retain Erase=2. This means each boot that reaches and invokes this initialization callback, not a BMC periodic service.',
 'clear_payload':'GetSELInfo 0A/40 -> optional ReserveSEL 0A/42 if operation support bit1 -> ClearSEL 0A/47 with reservationLE + ASCII CLR + 0xAA. Poll with final byte0x00 until low4 erase status=1; up to512 polls; C5 causes reservation refresh.',
 'source_addresses':['DxeSelStatusCode:0x1304','DxeSelStatusCode:0x168C','DxeSelStatusCode:0x1514','DxeSelStatusCode:0x1564']},
 'when_full':{
 'trigger':'GetSELInfo response operation-support/overflow byte bit7. This code does not use a free-space threshold.',
 '0':'No automatic deletion/erase by the policy. PEI mapped event writer returns EFI_DEVICE_ERROR on overflow when no suitable policy is selected; different callers can still attempt their AddSEL.',
 '1':'Clear the complete SEL, then the PEI mapped writer attempts AddSEL. DxeSelStatusCode also does a one-shot overflow check and clear at its boot callback.',
 '2':'If DeleteSEL operation support bit3 is available, reserve if required, send DeleteSEL0A/46 for record ID0 (first/oldest), then the mapped writer attempts AddSEL. Unsupported-delete returns an error; no whole-SEL fallback is observed in this path.',
 'frequency':[{'owner':'PeiSelStatusCode:0xFFF830F9','when':'Before each eligible mapped host status event; calls policy helper0xFFF82FDB.'},
 {'owner':'DxeSelStatusCode:0x1304','when':'One boot notification callback; policy1 only; no per-record logging loop.'},
 {'owner':'DxeIpmiInitialize:0x13AC','when':'Before each of the before/after SEL time-synchronization records if clock update is required; reads ServerSetup[0x1F], helper0x31A0.'},
 {'owner':'DxeBmcElog:0x1320','when':'Queries overflow before AddSEL; returns OUT_OF_RESOURCES when full and does not apply ServerSetup policy itself.'}],
 'boundary':'There is no evidence here of a permanent BMC full-log policy or continuous polling daemon. Producer-specific host code owns the observed handling.',
 'donor_error_handling':'PEI mapped writer does not check the clear/delete helper return before trying AddSEL. Do not copy this behavior as an intended robustness requirement.'},
 'host_post_mapping':{
 'source':'creator-post-status-mapping.json; extracted without rewriting the immutable TE module',
 'module_sha256':mapping['sha256'],'table_va':'0xFFF832C8','table_file_offset':'0x7C0','entries':59,'entry_size':12,
 'record_lookup':'FFF82EF2 exact matches 32-bit StatusValue and low8 StatusCodeType. FFF82C73 rejects types other than1/2; FFF82CE3 applies LogEFI filter.',
 'registration':'PEI entry0xFFF82D4C registers callback0xFFF82C73 through the RSC handler PPI at0xFFF83248 after its config gates pass.',
 'record_builder':'FFF830F9 sends NetFn0A/Cmd44, 16-byte payload: recordID0, type2, timestamp0, generatorID1, EvMrev4, table sensorType, sensorNumber0, eventType0x6F, table data1/2/3.',
 'example':mapping['rows'][0],
 'coverage_limit':'This actual donor handler is PEI. A P6 DXE logger can adopt the mapping for notifications after registration, but cannot reconstruct early PEI errors by being loaded later.',
 'table_search_limit':'The full extracted first48-byte signature was found only in PeiSelStatusCode among extracted Creator PE/TE bodies. This is not proof that no other differently encoded logger exists.'},
 'unverified':['All producers in the entire Creator BIOS have not been exhaustively analyzed.','No BMC Clear/Delete/Add SEL behavior was exercised; record ownership and delete support are device-specific.','Actual HERO EFI status codes delivered after P6 registration, and BMC display labels for them.']},
 'lan':{
 'observed':[
 'ServerMgmtSetup IFR holds source and text addresses in ServerSetup; its IPv4 validation callback0x30C8 works through browser data. The apply path found is the separate Ip4BmcLanConfig DXE entry0x4E0, not a direct LAN write on ordinary field edit.',
 'Ip4BmcLanConfig reads615B config, captures LAN1 source0x26, sets that byte to0, parses IP/mask/gateway/MAC strings, and writes the complete variable before calling the BMC SetLAN operations. Thus source is a consumed next-driver-init request; it is not a persistent forced DHCP/static mode.',
 'Source0 Unspecified does not change BMC addressing. Source1 writes static source then IP, mask, gatewayIP, gatewayMAC. Source2 writes DHCP source and skips static address writes.',
 'SetLAN is NetFn0C/Cmd01; param4=source; param3=stationIPv4; param6=subnet; param12=gatewayIPv4; param13=gatewayMAC. No port MAC write is observed.',
 'Before each write, 0xA5C reads GetLAN0C/02 param0 SetInProgress, up to10 iterations with1000us stall while low2 bits are nonzero. No paired SetInProgress start/commit write is observed in these routines.',
 'Channel helper0xAF8 reads PCD token0xC array/length. If cache is empty, scans channels1..11 with GetChannelInfo06/42, accepts successful CC0 and medium low7bits=4 Ethernet, and caches results. Entry requests one channel and applies to that first returned channel.',
 'Although IFR has LAN2 source0xA5, this concrete IPv4 apply routine reads/writes only the first LAN fields. The selected numeric channel is runtime-dependent; it is not statically proven to be1,2,or8.',
 'A failed/partially completed BMC update can leave source0 because the request was consumed beforehand. The donor top-level returns success after some ignored lower-level errors, so its UI/source reset does not prove BMC acceptance.'
 ],
 'sources':[refs('Ip4BmcLanConfig','0x4E0','0x2EC','0xA5C','0xAF8'),refs('ServerMgmtSetup','0x30C8')],
 'unverified':['Runtime numeric LAN channel and LAN1/LAN2 association on each BMC.','Network reachability after changing address, DHCP lease behavior, or gatewayMAC requirement.','Additional LAN2 logic in other unrelated producers has not been excluded.']},
 'implementation_recommendations':[
 'Use owned HERO config and expose actual supported semantics rather than transplanting the whole Creator ServerSetup variable.',
 'Keep OS watchdog disabled by default; use validated BeforeBoot notification with owned-OSLoad stop paths, and document that ordinary UEFI applications may also trigger it.',
 'Only stop a matching owned watchdog; do not treat TimerUse3 alone as definitive ownership by the new driver.',
 'Keep host POST logging and BMC-global system event logging as distinct labels/settings. State DXE-only coverage if no PEI producer is integrated.',
 'For destructive SEL policies, enforce operation-support bits, completion codes, response lengths, bounded polling, and reserve invalidation handling. Only consume one-shot intent after verified success if choosing a safer behavior than the donor.',
 'Select LAN channel from runtime Ethernet channel evidence, preserve unrelated parameters, and read back each change. Treat deferred application and request-consumption timing as explicit UI behavior.',
 'Serialize logging callbacks with existing transport users and defer work out of unsafe callback TPL; a menu label alone does not provide communication locking.'
 ],
 'overall':'Static behavioral evidence is sufficient to implement the requested menu semantics with explicit DXE coverage limits; this report does not validate new firmware boot, write acceptance, or real BMC effects.'}
for p in ['analysis/hero_ipmi_p1c/reference/creator-config-map.json','analysis/hero_ipmi_p1/reference/creator-ifr.json','analysis/hero_ipmi_p1/reference/creator-en-us.json']:
 report.setdefault('metadata_bindings',[]).append({'path':p,'sha256':hashlib.sha256((ROOT/p).read_bytes()).hexdigest()})
(P/'creator-behavior-review.json').write_text(json.dumps(report,indent=2,ensure_ascii=False)+'\n',encoding='utf-8')
summary='''Creator 3002 -> HERO P6 行为证据审查（静态，2026-11-04）

本轮仅分析固件文件。未接触 BMC、未发 IPMI 命令、未修改任何 CAP/P5/P6 源码。
详尽字段、命令、地址、REA evidence ID 见 creator-behavior-review.json；所有模块的原始路径和 SHA256 见 artifact-manifest.json。

1. OS 看门狗
ServerSetup 长615字节、GUID01239999-FC0E-4B6E-9E79-D54D5DB6CD20。
0x1A=开关；0x1B=1..30分钟；0x1C=0无动作/1复位/2关机/3电源循环。
Creator DxeFrb 0x84C 将分钟乘60000000us，0x414转为100ms单位；10分钟Reset的SetWDT原始载荷03 01 00 08 70 17。
0x910 BeforeBoot、0x8B8 AMI LegacyBoot 启动OSLoad(use3)：Get06/25 -> Set06/24 -> Reset06/22。
0x944 SetupEnter和0xA0C两个Shell通知停止正在运行且use匹配的计时器：Get后Set零超时，不Reset。
此模块的OS路径未见ReadyToBoot或ExitBootServices启动/停止；关闭设置不等于无条件清除原先运行的计时器。
BeforeBoot GUID=3677770F-EFB2-43B2-B8AE-B302E9604882。
ShellEnvironment2=47C7B221-C42A-11D2-8E57-00A0C969723B；ShellProtocol=6302D008-7F9B-4F30-87AC-60C9FEF5DA4E。
HERO3107 AMITSE 实际发布BeforeBoot：栈GUID构造0xD0B9/0x4E98C，对应调用0xD29F/0xD534/0xD9D9/0x4EB9C ->0x176C瞬时Install/Uninstall。
关键边界：0x4EB9C位于LoadImage成功后、StartImage前。BeforeBoot不是仅OS信号，一般UEFI工具也可能启动此计时；Shell停止只保护发布Shell标记的应用。

2. SEL
0x1D Components=主机启动错误/进度日志开关，同时门控DXE启动清除逻辑；不是BMC全局logging bit3。
0x20 LogEFI=0关闭/1两者/2错误/3进度；变量读取失败默认Components=1、LogEFI=2。
0x1E Erase=0不主动清除/1下次/2每次。DxeSelStatusCode0x1304在传输协议通知回调内执行，完成关闭事件。
下次=1在Clear调用后无论是否成功均回写0；每次=2保留，表示每次实际执行到该启动初始化，不是BMC后台周期清除。
0x1F WhenFull=0不清除/1全清/2删除最旧；触发条件是GetSELInfo overflow bit7，不是剩余空间阈值。
执行者不止一个：PEI每条已映射事件前检查；DXE Sel模块只做一次启动检查且仅处理policy1；DxeIpmiInitialize时间同步事件前也处理1/2；DxeBmcElog写满时只返回OUT_OF_RESOURCES。
真正POST映射在 IA32 PeiSelStatusCode，非名字相近的DxeSelStatusCode。FFF82C73=RSC回调；FFF82EF2=查表；FFF830F9=构造16字节SEL并发0A/44。
59条表位于VA FFF832C8、TE文件偏移0x7C0；完整映射见creator-post-status-mapping.json。
记录固定字段：ID0/type2/timestamp0/generator1/EvMrev4/sensorNumber0/eventType6F；sensorType及data1/2/3来自表。
P6若仅DXE注册，只能记录注册之后的事件，不能声称已包含Creator早期PEI错误日志。

3. IPv4网络
LAN1 source0x26：0 Unspecified/1Static/2DHCP；IP0x27、mask0x45、gateway0x63、gatewayMAC0x81。
实际应用在Ip4BmcLanConfig DXE入口0x4E0。先保存待用source，再将变量source清0并SetVariable成功，然后写BMC。
因此是下一次初始化消费的一次请求；写失败也可能已经清0，不能从菜单恢复Unspecified推断BMC成功。
0C/01参数4来源、3IP、6mask、12gateway、13gatewayMAC。0xA5C写前查询SetInProgress，最多10次/每次1ms。
通道从PCD0xC缓存或GetChannelInfo扫描1..11/medium4获得；请求一个通道。实际通道号须运行时验证，不能硬编码推断。
IFR虽然含LAN2 source0xA5，本轮确认的IPv4驱动仅应用第一组字段。

未验证：P6实机通知顺序、OS接管看门狗、BMC完成码/删除支持/网络变化、HERO真实POST事件覆盖。不能将静态研究写成实机功能验收通过。
所有本轮REA会话均已关闭。种子来源及每次目标记录见rea-seeded/seed-history.json。
'''
(P/'creator-behavior-review.txt').write_text(summary,encoding='utf-8')
print(json.dumps({'report':str(P/'creator-behavior-review.json'),'rea_evidence':ev,'mapping_entries':len(mapping['rows'])},indent=2))
