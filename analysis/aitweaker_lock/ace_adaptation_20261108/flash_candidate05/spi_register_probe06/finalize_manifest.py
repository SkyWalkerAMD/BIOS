"""Bind the exact already-built06 media and evidence; never rebuild/deploy."""
from pathlib import Path
import hashlib
import json
import sys

HERE=Path(__file__).resolve().parent
ROOT=next(p for p in HERE.parents if (p/'tools/pydeps').is_dir())
OUT=HERE/'build'
sys.path.insert(0,str(ROOT/'tools/pydeps'))
import pefile
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
read=lambda p:json.loads(p.read_text(encoding='utf8'))
def record(p):return {'path':p.relative_to(ROOT).as_posix(),'sha256':sha(p),'bytes':p.stat().st_size}
def save(p,d):
 pending=p.with_suffix(p.suffix+'.pending')
 pending.write_text(json.dumps(d,ensure_ascii=False,indent=2)+'\n',encoding='utf8')
 pending.replace(p)
build=read(OUT/'build.json');local=read(OUT/'local_verification.json');vm=read(OUT/'ovmf_verification.json');prep=read(HERE/'preparation.json')
efi=OUT/'BOOTX64.EFI';iso=OUT/'ACE1904-SPI-PROBE06.iso'
assert sha(efi)=='b290d3e5a78c013d992d03c8bed4e17fa739917eb5da9f8c4d2f9a8380788743'
assert sha(iso)=='988a70a57b59881dccabd6b6a154f0389569ef3008b9740d7e3eab9edcbd9f32'
for report in [build,local,vm]:assert report['efi_sha256']==sha(efi) and report['iso_sha256']==sha(iso)
assert local['status']=='PASS_LOCAL_SIMULATION_ONLY' and local['case_count']==179
assert vm['status']=='PASS_LOCAL_OVMF_ONLY' and len(vm['cases'])==2
assert local['source_sha256']==sha(HERE/'source/inventory.c')
assert local['test_source_sha256']==sha(HERE/'verify_inventory.py') and vm['test_source_sha256']==sha(HERE/'verify_ovmf.py')
assert local['build_sha256']==sha(OUT/'build.json') and local['map_sha256']==sha(OUT/'inventory.map')
assert local['qr_test_dll_sha256']==sha(OUT/'qr_test.dll') and build['builder_sha256']==sha(HERE/'build_probe.py')
for path,expected in build['source_files'].items():assert sha(HERE/path)==expected,path
for path,expected in prep['frozen05_inputs'].items():assert sha(HERE.parent/'layout_recovery/probe'/path)==expected,path
assert hashlib.sha256(json.dumps(build['identity_preimage'],sort_keys=True,separators=(',',':')).encode()).hexdigest()==build['source_bundle_sha256']
for case in vm['cases']:
 assert case['owned_process_finished'] and case['qr_matches_console']
 log=HERE/case['folder']/'RESTORED-LOG.TXT'
 assert sha(log)==case['restored_log_sha256'] and build['source_bundle_sha256'].encode() in log.read_bytes()
native=HERE/'native/OriginalCpuIo2.efi'
assert sha(native)==prep['original_cpu_module']['efi_sha256']
native_binding=read(HERE/'native_binding_verification.json')
assert native_binding['header_sha256']==sha(HERE/'source/cpu_reference.h')
assert native_binding['status']=='PASS_ACTUAL_INSTRUCTION_AND_FINGERPRINT_BINDING'
pe=pefile.PE(str(native));mapped=pe.get_memory_mapped_image()
rea=HERE/'rea/cpuio2';tables_rea=HERE/'rea/cpuio2_tables';evidence=[]
for p in sorted((rea/'responses').glob('00*.json'))+sorted((tables_rea/'responses').glob('00*.json')):
 reply=read(p);assert not reply.get('error') and not reply.get('result',{}).get('isError')
 d=reply['result'].get('structuredContent',{})
 if d.get('operation') not in ['analyze_function','read_bytes']:continue
 n=d['normalized_result'];row={'operation':d['operation'],'evidence_id':d['evidence_id'],'provider':d['provider'],'response':record(p)}
 if d['operation']=='analyze_function':row['address']=n['procedure']['address']
 else:
  a=int(n['address'],16);b=bytes.fromhex(n['bytes_hex']);assert n['complete'] and b==mapped[a:a+len(b)]
  row.update(address=n['address'],bytes=len(b),original_bytes_equal=True)
 evidence.append(row)
close=read(rea/'close-status.json');assert close['process_exit_code']==0 and close['close_response_present']
assert read(rea/'responses/999-close.json')['result']['structuredContent']=={'result':None}
tables_close=read(tables_rea/'close-status.json');assert tables_close['process_exit_code']==0 and tables_close['close_response_present']
assert read(tables_rea/'responses/999-close.json')['result']['structuredContent']=={'result':None}
provenance=read(rea/'provenance.json');seed=(rea/'seeds.tsv').read_bytes()
canonical=''.join(x+'\n' for x in seed.decode().splitlines() if x.strip() and not x.lstrip().startswith('#')).encode()
assert hashlib.sha256(seed).hexdigest()==provenance['raw_seed_sha256']
assert hashlib.sha256(canonical).hexdigest()==provenance['canonical_seed_sha256']
design={
 'status':'LOCAL_SAFETY_GATES_VERIFIED_PHYSICAL_READS_NOT_ATTEMPTED','observed_ACE05':prep['hardware_log'],
 'identity':{'SMBIOS':'Pro WS W790-ACE /1904','CPU':'GenuineIntel CPUID.1:EAX=000806F8',
 'SPI':{'location':'0000:00:1F.5','VID_DID':'7AA48086','REV_CLASS':'0C800011','COMMAND_STATUS':'00000402','BAR0':'FE010000','BIOS_CNTL':'100008AA'},
 'LPC':{'location':'0000:00:1F.0','VID_DID':'7A8A8086','REV_CLASS':'06010011','COMMAND_STATUS':'00000547','BAR0':'00000000','BIOS_CNTL':'000000A6'}},
 'CPU_IO2_ABI':{'GUID':'ad61f191-ae5f-4c0e-b9fa-e869d288c64f','Mem.Read_slot':0,'parameters':'This, UINT32 Width=2, UINT64 Address, UINTN Count=1, UINT32 *Buffer',
 'unused_opaque_write_and_port_slots':[8,16,24],'phase':'Boot Services only'},
 'original_ACE_CPU_IO2':prep['original_cpu_module'],
 'native_fingerprint_instruction_verification':record(HERE/'native_binding_verification.json'),
 'independent_review_correction':record(HERE/'review_correction.json'),
 'live_provider_binding':['Unique initial CPU_IO2 handle, exact static interface at Mem.Read-0x3D4+0x730.',
 'All4 interface pointers equal original relocated offsets3D4/484/534/624; only Mem.Read is callable by the application.',
 'Full parameter-check bytes30C..3D3, Mem.Read bytes3D4..480, stride tables750..76F and GUID720..72F match original ACE bytes.',
 'Code ranges must be fully covered by exactly one non-RP/non-XP EFI code mapping; interface/data ranges must have unambiguous readable RAM coverage.',
 'Before every read and after the final read: resolve same owner/interface, refresh map, compare original code/tables and complete PCI snapshots.'],
 'MMIO_gate':{'range_inclusive':['FE010000','FE010097'],'descriptor_exact_start':'FE010000','descriptor_exact_pages':1,'type':11,
 'required_attribute_bits':'0000000000000001 UC capability','optional_attribute_bits':['8000000000000000 RUNTIME','0000000000004000 XP','0000000000020000 RO'],
 'reject':['Missing/overlapping/fragmented/broader/non-MMIO descriptor','Read protection, conflicting cache capability or unknown attributes','Any change of the accepted attributes during collection'],
 'qualification':'UEFI map attributes describe capabilities, not active cache mode or permission. They are an additional conservative admission condition alongside live PCI identity and original provider binding.'},
 'register_offsets':[hex(x) for x in [0,4,0x50,0x54,0x58,0x5c,0x60,0x64,0x68,0x84,0x88,0x8c,0x90,0x94]],
 'stop_on':['Any failed prerequisite or changed identity/provider/resource','EFI error or all-ones data','HSFSTS descriptor-valid clear or cycle-in-progress set'],
 'no_fallback':['EFI_PCI_IO.Mem.Read','RootBridgeIo.Mem.Read','application raw volatile MMIO','port access for SPI','RDMSR','SPI READ/program/erase cycles'],
 'REA':{'evidence':evidence,'close':close,'table_followup_close':tables_close,'provenance':record(rea/'provenance.json'),'table_followup_provenance':record(tables_rea/'provenance.json'),'seed_digest_rule':'Evidence uses effective noncomment TSV rows joined with LF and final LF; raw file digest is separately retained.'},
 'tests':{'actual_application_plus_original_CPU_IO2_cases':179,'OVMF_cases':2,'synthetic_positive_QR_pages':local['qr_pages'],
 'positive_path':'Each actual original CPU_IO2 DWORD load and all native stride-table reads at752/762 are traced; synthetic MMIO writes trap. PCI/MMIO writes and unapproved services trap. Error cases explicitly intercept provider return status.',
 'negative_scope':'Exact CPU/PCI/LPC identity, SMBIOS/map bounds, duplicates/unknown providers, altered code/tables, per-read owner/permission/PCI mutations, errors/all-ones/busy/FDV, no fallback.'},
 'current_missing_physical_evidence':['ACE05 log has not measured the MMIO page descriptor/attributes or live CPU_IO2 provider bytes.06 checks these at runtime and refuses rather than assuming SAGE observations.',
 'CPU_IO2 availability/success on188 remains untested. A rejection remains useful metadata; no fallback follows.',
 'Readiness checks do not provide atomic exclusion against unrelated firmware/SMM activity.'],
 'limits':['No flash contents/density/full read permission/Boot Guard policy or recovery path is established.',
 'No BMC, power control or target operation performed by this builder.',
 'GOP/console/keyboard/serial display uses frozen05 framework and updates display buffers; zero PCI/SPI diagnostic writes is not a claim of zero display hardware activity.',
 'Normal platform boot may update its own variables; this application has no SetVariable, file-write or network path.'],
 'references':{'CpuIo2.h':'https://github.com/tianocore/edk2/blob/edk2-stable202502/MdePkg/Include/Protocol/CpuIo2.h',
 'UefiSpec.h':'https://github.com/tianocore/edk2/blob/edk2-stable202502/MdePkg/Include/Uefi/UefiSpec.h',
 'provenance':'Existing archived primary-source snapshots copied with explicit hashes; no new web refetch or change to imported implementations.',
 'files':prep['archived_primary_references']}}
save(HERE/'design_review.json',design)
readme='''ACE1904-SPI-PROBE06：固定寄存器只读采集介质

制作时状态：本地验证通过，尚未在188运行。本介质不是BIOS、备份或刷写器，不安装AI Tweaker驱动。
只在188实测ACE1904/CPUID806F8、SPI0000:00:1F.5的7AA48086/0C800011/0402/FE010000/100008AA，
以及LPC0000:00:1F.0的7A8A8086/06010011/0547/BAR0=0/BIOS_CNTL=A6全部相符时继续。

使用正常EFI_CPU_IO2.Mem.Read，Width32、Count1，只允许14个固定地址：
FE010000、FE010004、FE010050、FE010054、FE010058、FE01005C、FE010060、FE010064、FE010068、
FE010084、FE010088、FE01008C、FE010090、FE010094；最大触及字节FE010097。
CPU_IO2必须为唯一提供者，接口位置、4个方法指针、参数检查/读取函数/stride表/GUID字节均与原ACE模块一致。
每次读前刷新内存图，重新解析同一CPU_IO2接口，核对代码指纹、SMBIOS/CPUID及SPI和LPC完整快照；末尾再复核。
内存图必须唯一覆盖FE010000的一个4KiB MMIO页，UC能力存在，且无读保护、冲突缓存属性或未知属性。
允许该页另外带RUNTIME/XP/RO。能力位不是当前缓存模式或硬件读许可的证明；任何条件不满足均拒绝读取。
CPU_IO2错误、全1、FDV无效或SCIP忙立即停止，不启动任何其他读取路径。

程序无PCI/SPI控制器写入、隐藏设备使能、SPI cycle、RDMSR、SetVariable、网络或文件写入。
无PCI_IO.Mem.Read、RootBridge或应用直接解引用MMIO的fallback。
既有QR/GOP/控制台仍更新显示缓冲区；UEFI引导本身可能改变自己的启动变量。
只禁用watchdog以保留二维码显示；本程序不重启机器、不改变Secure Boot设置。

显示操作沿用05：N/Enter下一页，P上一页，Home第一页，T文本，Q回二维码，Esc返回固件。
保存全部页面；使用probe_p3_kvm/decode_captures.py的通用帧解码(require_inventory=False)，
核对ToolSourceSHA256、总页数及CRC/SHA。合成成功样本为7页；实际页数以屏幕/帧为准。
PARTIAL_OR_REFUSED保留拒绝原因。DEFINED_REGISTER_SNAPSHOT_COMPLETE只表示14个定义寄存器读取完毕。
FLASH_BYTES_ACQUIRED=0、actual_component_capacity=null、Boot Guard UNKNOWN均保持不变。

本地结果：179个实际EFI/原厂CPU_IO2故障及边界场景通过；两次非目标OVMF启动通过，包含真实QR截图复原、
翻页/Home、文本/QR切换与Esc退出。所有正例寄存器值为合成数据，绝不是188实测结果。
本轮REA会话已关闭，完整原厂入口/参数校验/读取函数Evidence在rea/cpuio2。
只有主代理可安排实机只读采集；新实机日志须绑定本media_manifest.json中的EFI/ISO/source哈希。
'''
(HERE/'README-先读.txt').write_text(readme,encoding='utf8')
paths=[efi,iso,OUT/'build.json',OUT/'local_verification.json',OUT/'ovmf_verification.json',OUT/'inventory.map',OUT/'qr_test.dll',OUT/'synthetic-positive-log.txt']
paths+=sorted(p for p in (HERE/'source').rglob('*') if p.is_file())
paths+=sorted(p for p in (HERE/'reference_documents').iterdir() if p.is_file())
paths+=sorted(p for p in (HERE/'native').iterdir() if p.is_file())
paths+=[HERE/n for n in ['prepare_probe.py','preparation.json','build_probe.py','prepare_tests.py','test_derivation.json','verify_inventory.py','verify_ovmf.py','verify_native_binding.py','native_binding_verification.json','review_correction.json','finalize_manifest.py','run_cpu_rea.py','rea_runner.py','rea_runner_binding.json','design_review.json','README-先读.txt']]
for session in [rea,tables_rea]:
 for sub in ['commands','responses']:paths+=sorted((session/sub).glob('*.json'))
 paths+=[session/n for n in ['plan.json','provenance.json','initialize.json','seeds.tsv','close-status.json','rea-stderr.log']]
for case in vm['cases']:
 folder=HERE/case['folder'];paths+=[folder/n for n in ['result.json','RESTORED-LOG.TXT','command.json']]+sorted(folder.glob('*.png'))
report={'status':'READY_FOR_ROOT_REVIEW_LOCAL_VALIDATION_PASSED','build_id':'ACE1904-SPI-PROBE06',
 'hardware_tested_at_media_build':False,'bmc_access_performed_by_builder':False,'firmware_write_performed':False,
 'source_bundle_sha256':build['source_bundle_sha256'],'efi':record(efi),'iso':record(iso),
 'local_cases':179,'ovmf_cases':2,'local_positive_qr_pages':local['qr_pages'],'all_bound_hashes_verified':True,
 'original05_sources_and_media_untouched':True,'original_ACE_CPU_IO2_sha256':sha(native),'fresh_REA_session_closed':True,
 'local_visual_review':'synthetic_ace qr-1.png inspected: probe06 title, complete QR, partial-result label and navigation are readable.',
 'actual_flash_bytes_acquired':0,'spi_backup_complete':False,'flash_candidate_ready':False,
 'review_limits':design['current_missing_physical_evidence']+design['limits'],'files':[record(p) for p in paths]}
save(HERE/'media_manifest.json',report)
print(json.dumps({'manifest':record(HERE/'media_manifest.json'),'efi':report['efi'],'iso':report['iso'],'source_bundle_sha256':report['source_bundle_sha256'],'local_cases':179,'ovmf_cases':2},indent=2))
