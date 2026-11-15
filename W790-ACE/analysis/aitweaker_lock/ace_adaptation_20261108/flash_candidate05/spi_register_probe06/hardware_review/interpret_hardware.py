"""Read-only interpretation of the received06 log and actual candidate05 bytes."""
from pathlib import Path
import datetime
import hashlib
import json
import re
import struct
import xml.etree.ElementTree as ET
import zlib

HERE=Path(__file__).resolve().parent
PROBE=HERE.parent
CASE=PROBE.parent
ROOT=next(p for p in HERE.parents if (p/'tools/pydeps').is_dir())
REF=CASE/'layout_recovery/reference_documents'
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
read=lambda p:json.loads(p.read_text(encoding='utf8'))
def rec(p):return {'path':p.relative_to(ROOT).as_posix(),'sha256':sha(p),'bytes':p.stat().st_size}
def save(p,d):p.write_text(json.dumps(d,ensure_ascii=False,indent=2)+'\n',encoding='utf8')

log_path=CASE/'bmc_spi06/inventory-results/hardware-log.txt'
transport_path=log_path.with_name('manifest.json')
log=log_path.read_bytes();transport=read(transport_path);media=read(PROBE/'media_manifest.json')
assert sha(log_path)=='d8305e6f0fe91a836f94a3c3040f44f4596d5e33ec206e82397c1efdda572c72'
assert len(log)==5264 and zlib.crc32(log)==0x9d7c2fe0 and transport['transport']['pages']==7
assert transport['transport']['sha256']==sha(log_path)
assert transport['media_manifest_sha256']==sha(PROBE/'media_manifest.json')
for key,sub in [('iso_sha256','iso'),('efi_sha256','efi')]:assert transport[key]==media[sub]['sha256']
assert transport['source_bundle_sha256']==media['source_bundle_sha256']
assert b'ToolSourceSHA256='+media['source_bundle_sha256'].encode()+b'\r\n' in log
for token in [b'CPU_IO2_GATE=ORIGINAL_ACE_READ_CODE_EXACT_PCI_AND_MMIO_PAGE',b'COLLECTION_STATUS=DEFINED_REGISTER_SNAPSHOT_COMPLETE',
 b'Warnings=0x00000000',b'LogOverflow=0x00000000',b'FLASH_READ_CYCLES=0',b'FLASH_BYTES_ACQUIRED=0']:
 assert token in log
matches=re.findall(rb'^(BFPR|HSFSTS_HSFC|FRAP|FREG[0-5]|PR[0-4]) OFFSET=0x([0-9A-F]+) STATUS=0x([0-9A-F]+) VALUE=0x([0-9A-F]+)',log,re.M)
assert len(matches)==14 and all(int(m[2],16)==0 for m in matches)
values={m[0].decode():int(m[3],16) for m in matches}
offsets={m[0].decode():int(m[1],16) for m in matches}
assert list(offsets.values())==[0,4,0x50,0x54,0x58,0x5c,0x60,0x64,0x68,0x84,0x88,0x8c,0x90,0x94]
xml=ET.parse(REF/'spibar0.xml').getroot()
registers={x.attrib['name']:x for x in xml.findall('./registers/register')}
def decode(name,value,table=registers):
 fields=[];mask=0
 for f in table[name].findall('field'):
  a=f.attrib;bit=int(a['bit']);size=int(a['size']);m=((1<<size)-1)<<bit;mask|=m
  fields.append({'name':a['name'],'bit':bit,'width':size,'value':(value>>bit)&((1<<size)-1),'reference_description':a['desc']})
 return {'raw':f'0x{value:08X}','fields':fields,'bits_outside_reference_fields':f'0x{value&~mask:08X}'}
status=decode('HSFS',values['HSFSTS_HSFC']);access=decode('FRAP',values['FRAP'])
bc_xml=ET.parse(REF/'spi0.xml').getroot();bc_table={x.attrib['name']:x for x in bc_xml.findall('./registers/register')}
bios_control=decode('BC',0x100008aa,bc_table)
assert values['HSFSTS_HSFC']==0x0010e800 and values['FRAP']==0x4acf
region_permissions=[{'region_low8_index':i,'BIOS_read_access_bit':bool(values['FRAP']&(1<<i)),
                    'BIOS_write_access_bit':bool(values['FRAP']&(1<<(8+i)))} for i in range(8)]

official_path=ROOT/'analysis/aitweaker_lock/official_W790_ACE_1904/W790_ACE_1904/Pro-WS-W790-ACE-ASUS-1904.CAP'
candidate_report_path=CASE/'lock_1904_candidate05/lab/asus_review/W790-ACE-1904-lock.review.json'
candidate_report=read(candidate_report_path);candidate_path=Path(candidate_report['candidate']);driver_path=Path(candidate_report['driver'])
official=official_path.read_bytes();candidate=candidate_path.read_bytes()
assert sha(official_path)=='03e4330430b2510d5e9e5c9868ca64c730844992b82c6a272b815aef3d20bf29'
assert sha(candidate_path)==candidate_report['candidate_sha256']=='9b038c4eae111a985c5c5fef460f0874338d16764b0ead6f89a3e55c775f5455'
assert sha(driver_path)==candidate_report['driver_sha256']=='71b05ebe21fd0b4de496fc9684f57e4acc79431e38a403dec9017501605eca98'
assert len(official)==len(candidate)==0x4001000
header=0x1000;orig=official[header:];cand=candidate[header:]
assert struct.unpack_from('<I',orig,0x10)[0]==0x0ff0a55a
assert cand[:0x1000]==orig[:0x1000]
flmap0=struct.unpack_from('<I',orig,0x14)[0];region_table=((flmap0>>16)&255)*16
assert region_table==0x40
names={0:'Descriptor',1:'BIOS',2:'ME',3:'GbE',4:'Platform data',5:'Device expansion1',9:'Device expansion2 (conventional label only)'}
regions=[]
for i in range(16):
 raw=struct.unpack_from('<I',orig,region_table+4*i)[0];new=struct.unpack_from('<I',cand,region_table+4*i)[0];assert raw==new
 base=(raw&0x7fff)<<12;end=(((raw>>16)&0x7fff)<<12)+0x1000;enabled=base<end
 row={'index':i,'conventional_name':names.get(i,'other/reserved'), 'public_raw':f'0x{raw:08X}',
      'candidate_descriptor_equal':True,'base_in_raw_SPI':f'0x{base:08X}','end_exclusive_in_raw_SPI':f'0x{end:08X}','enabled_in_public_descriptor':enabled}
 if enabled:
  assert end<=len(orig);row.update(bytes=end-base,public_region_sha256=hashlib.sha256(orig[base:end]).hexdigest(),
      candidate_region_sha256=hashlib.sha256(cand[base:end]).hexdigest(),candidate_region_bytes_unchanged=orig[base:end]==cand[base:end])
 if i<6:
  row.update(live_register=f'FREG{i}',live_raw=f'0x{values[f"FREG{i}"]:08X}',live_range_matches_public_and_candidate=values[f'FREG{i}']==raw)
  assert row['live_range_matches_public_and_candidate']
 else:row['live_register_measured']=False
 regions.append(row)
assert values['BFPR']==values['FREG1']
container=int(candidate_report['outer_container_offset'],16)-header;allocation=candidate_report['outer_container_original_allocation']
assert orig[:container]==cand[:container] and orig[container+allocation:]==cand[container+allocation:]
assert 0x3000000<=container and container+allocation<=0x4000000
changed_blocks=[a for a in range(0,len(orig),0x1000) if orig[a:a+0x1000]!=cand[a:a+0x1000]]
different=[i for i,(a,b) in enumerate(zip(orig[container:container+allocation],cand[container:container+allocation])) if a!=b]
assert different and changed_blocks
layout={'official_cap':rec(official_path),'actual_candidate05':rec(candidate_path),'candidate_report':rec(candidate_report_path),'driver':rec(driver_path),
 'capsule_header_bytes':header,'payload_bytes':len(orig),'descriptor_bytes_equal_official_candidate':True,
 'live_FREG0_to5_all_match':True,'BFPR_equals_live_FREG1':True,'regions':regions,
 'changed_container_raw_start':hex(container),'changed_container_raw_end_exclusive':hex(container+allocation),
 'all_changes_within_measured_BIOS_region':True,'all_bytes_outside_container_equal':True,
 'changed_4KiB_blocks':len(changed_blocks),'changed_bytes':len(different),'first_changed_raw_offset':hex(container+different[0]),
 'last_changed_raw_offset_inclusive':hex(container+different[-1]),'live_flash_bytes_compared':0,
 'qualification':'Matches live register layout, not live content. Candidate retains an old signature that does not authenticate changed payload; this does not confer flash acceptance.'}

protected=[]
for i in range(5):
 raw=values[f'PR{i}'];assert raw==0
 protected.append({'index':i,'raw':'0x00000000','RPE':False,'WPE':False,'active_protected_range':False,
 'encoded_base':0,'encoded_limit':0xfff,'meaning':'Geometric fields describe first4KiB but both enable bits are0; no enabled protection from this particular slot.'})
sources=[{'file':rec(REF/n),'used_for':purpose} for n,purpose in [
 ('spibar0.xml','BFPR/HSFSTS/FRAP/FREG/PR field positions'),('spi0.xml','SPI BIOS_CNTL field positions'),
 ('spi-intel-pci.c','7AA4 maps to CNL controller implementation'),('spi-intel.c','CNL offsets, FCYCLE8 RDSR, hardware READ uses transient control-register writes')]]
report={'status':'PHYSICAL06_REGISTER_SNAPSHOT_DECODED_LAYOUT_MATCHED_NO_FLASH_READBACK',
 'created_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'target':'188 / Pro WS W790-ACE /1904',
 'hardware_access_by_this_interpreter':False,'media_modified':False,'frozen_media_manifest':rec(PROBE/'media_manifest.json'),
 'physical_log':rec(log_path),'transport_manifest':rec(transport_path),'transport_verified':{'pages':7,'bytes':len(log),'crc32':'9D7C2FE0','sha256':sha(log_path)},
 'registers':{name:{'offset':hex(offsets[name]),'raw':f'0x{value:08X}','EFI_STATUS':'0x0000000000000000'} for name,value in values.items()},
 'controller_status':status,'access_permissions_low8':access,'region_access_bits':region_permissions,'SPI_BIOS_CNTL_reference_decode':bios_control,
 'PR_slots':protected,'candidate_layout':layout,'primary_local_references':sources,
 'observations':[
 'Live original CPU_IO2 read-code/table identity and a single UC-capable MMIO page were accepted by the exact frozen probe; all14 register reads and final checks succeeded.',
 'FDV=1, FLOCKDN=1, WRSDIS=1; SCIP/FDONE/FCERR/AEL=0 at observation.',
 'FCYCLE=8 corresponds to RDSR in the CNL reference, but FGO=0 and SCIP=0. This idle control field is not evidence this probe executed a flash cycle.',
 'FRAP BRRA=CF sets read bits0,1,2,3,6,7; BRWA=4A sets write bits1,3,6. BMRAG/BMWAG are0 in this captured dword. No interpretation extends these low8 fields to slot9.',
 'All5 measured PR slots have RPE=WPE=0. Other protections remain: BIOSWE=0, BLE=1, SMM_BWP=1, BILD=1 and reference ASE_BWP=1; FLOCKDN=1.',
 'Measured descriptor/BIOS/ME/disabled-region boundary registers match public1904 and actual05 candidate. Descriptor, ME and public slot9 bytes remain unchanged in candidate; changed bytes are confined to BIOS.'],
 'careful_interpretations':[
 'FDOPSS=1 and PR34LKD=0 are raw field values. This report does not infer override-pin electrical polarity or hardware grant state beyond the archived field definitions.',
 'SPI BIOS_CNTL includes0x10000000 outside the archived field mask; it is preserved as unknown, not decoded from another generation.',
 'FLOCKDN config lock is not itself proof all reads are denied. Conversely zero PR does not allow writes: region grants, BIOS control, SMM, descriptor rules, flash status and authentication remain separate.',
 'Read access bits are controller policy indicators, not successful flash READ operations or proof that every byte in a complete image is accessible.',
 'UEFI map attributes are capabilities, not a direct measurement of active cache settings or complete access permission.'],
 'remaining_unknowns':['Actual component count/capacity and live descriptor bytes','Live slot9 range/permission and any additional policy not represented by low8 FRAP',
 'Live FIT/ACM/KM/BPM/IBB and Boot Guard provisioning','Live flash contents and all device-specific bytes','Supported authenticated update and BIOS-independent recovery'],
 'backup_next_steps':[
 {'priority':1,'route':'Finish static review of an existing normal full-image export/read API, if one exists in the exact firmware/toolchain',
  'status':'NO_COMPLETE_EXPORT_ROUTE_ESTABLISHED_BY_THIS_REGISTER_LOG',
  'acceptance':'Trace actual read implementation, length/address coverage and target component. A GetImage name, update inventory or CAP copy is insufficient.',
  'action_here':'No API call, upload, BMC operation or hardware write.'},
 {'priority':2,'route':'If no normal export API exists, separately review a minimal standard hardware-sequencing FLASH READ implementation',
  'basis':'Actual7AA4 + original CPU_IO2 + valid descriptor + low8 read indicators provide concrete starting evidence for original documented controller access.',
  'important_boundary':'A real hardware-sequencing READ requires transient FADDR/HSFSTS_CTL writes to choose address/count/READ and start the cycle; ordinary read-only flash intent is not zero controller writes. This is outside06 and not implemented/authorized by this report.',
  'preconditions':['Exact7AA4 register/API mapping with no protection-bit changes','Identify real density/component layout and live descriptor/master tables, including slot9',
 'Allow only READ, bounded FIFO<=64bytes and no4KiB crossing, finite busy/error timeout; no program/erase/write-status/unhide/unlock path',
 'Reject every failed or incomplete range; do not synthesize bytes or substitute public firmware','Review any provider initialization for hidden writes and preserve diagnostics'],
  'action_here':'Source analysis only, no new hardware reader or execution.'},
 {'priority':3,'route':'Establish a supported bulk output transport before attempting a full acquisition',
  'observed_transport':'Read-only virtual CD plusQR; no writable data destination demonstrated by this report.',
  'declared64MiB_QR_pages_at768bytes':(0x4000000+767)//768,
  'acceptance':'Offset/count/status/hash for every chunk, no holes/overlap/alias substitution, full received-image SHA, two acquisitions with mutable regions handled explicitly.',
  'action_here':'No assumption of undocumented BMC download, writable virtual media or host networking.'}],
 'not_a_backup':['No flash bytes were acquired by06; register snapshot is not a whole-device dump.',
 'Public CAP is not a unit-specific backup. A16MiB BIOS-only/CPU-mapped view cannot substitute for declared64MiB SPI.',
 'Even a correct whole-device backup does not establish a recovery channel usable when the host BIOS fails.'],
 'release_conclusion':'Normal full readback feasibility is better characterized but still unproven. This result does not release candidate05 as flashable.'}
save(HERE/'hardware06_interpretation.json',report)
text='''06实机结果核对完成：7页、5264字节、CRC9D7C2FE0及SHA全部与冻结媒体绑定一致，14个寄存器读取和末尾复核成功。

BFPR/FREG1：BIOS原始SPI偏移03000000..03FFFFFF，共16MiB。
FREG0：00000000..00000FFF，4KiB描述符区域；FREG2：00001000..00692FFF，6,889,472字节ME区域。
FREG3/4/5禁用。以上6个原始寄存器值与公版1904及05候选逐项相同。
05候选9b038c4e…的改变全部位于该BIOS范围内；FD、ME、公开镜像slot9与其它容器外字节未变。
这仅验证边界布局一致，没有取得任何实时flash内容，不能证明实机内容与公版相同。

HSFSTS=E800：FDV/FLOCKDN/WRSDIS为1；SCIP、FDONE、FCERR、AEL为0。
控制字段FCYCLE=8在CNL参考中是RDSR；FGO与SCIP均为0，因此不能推断本探针发起了周期。
FRAP=00004ACF：低8区读允许位0/1/2/3/6/7，写允许位1/3/6；slot9不在这8位范围内。
PR0..4全零只说明这5个slot没有启用RPE/WPE。BIOSWE=0、BLE/SMM_BWP/BILD/ASE_BWP=1和FLOCKDN仍在。
无PR保护绝不等于无限写权限，读允许位也不是一次成功的flash读取。

实际芯片容量、实时descriptor/slot9权限、FIT/Boot Guard及完整设备内容仍未知。
正常完整备份应优先查证确实存在的原厂完整导出接口；当前日志未证明该接口存在。
若另行评审标准硬件FLASH READ，必须明确它需要FADDR/HSFSTS控制寄存器的瞬态写入；这不等于擦写flash，
但已超出06零控制器写入范围。不能直接部署通用工具并假设初始化没有附带写入。
还需真实容量与全范围访问证据、可靠批量输出通道、逐块状态/哈希和两次完整读取比较。
64MiB按现有768字节QR页需87,382页，现有只读CD+QR不构成合理的完整备份传输路线。

本次解释没有访问BMC、改动探针/媒体或写入硬件；完整备份和可刷写版本仍未完成。
'''
(HERE/'hardware06解读.txt').write_text(text,encoding='utf8')
print(json.dumps({'status':report['status'],'report':rec(HERE/'hardware06_interpretation.json'),
 'candidate_sha256':sha(candidate_path),'live_region_matches':6,'changed_4KiB_blocks':len(changed_blocks),
 'changed_raw_range':[layout['first_changed_raw_offset'],layout['last_changed_raw_offset_inclusive']],'flash_bytes_acquired':0},indent=2))
