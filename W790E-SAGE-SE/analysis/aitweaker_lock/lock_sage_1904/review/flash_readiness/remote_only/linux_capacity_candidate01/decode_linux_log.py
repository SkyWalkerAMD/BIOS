"""Strict semantic decoder for LC01 complete or pending P3 log bytes.

A1/A2 CSV: signed ioctl_return,errno,hex status,masked,msg,host,driver,
signed residual,hex info,decimal sense_length,guard,data8hex,sensehex.
The application preserves both replies. Bytes are data, never instructions.
"""
from pathlib import Path
import argparse,hashlib,json,re,struct,zlib
UA=bytes.fromhex('700006000000000a00000000290000000000')
def decode(data,allow_lab=False,allow_pending=False):
 def need(cond,msg):
  if not cond:raise ValueError(msg)
 need(0<len(data)<=768,'Log byte bound');s=data.decode('ascii');need(s.endswith('\r\n') and '\x00' not in s,'Text encoding/ending')
 lines=s[:-2].split('\r\n');need(len(lines)==14,'Exact line count')
 def match(index,pattern):
  m=re.fullmatch(pattern,lines[index]);need(m is not None,'Line '+str(index));return m.groups()
 variant,=match(0,r'LINUX-CAPACITY-01 (PRODUCTION|LAB_SELECTOR_ONLY)');need(variant=='PRODUCTION' or allow_lab,'Lab payload forbidden')
 match(1,r'KERNEL=6\.12\.114-0-lts');dmi,=match(2,r'EXPECTED_BOARD=Pro WS W790E-SAGE SE BIOS=1904 DMI_MATCH=([01])')
 stage,err,errno,checks=match(3,r'STAGE=([1-8]) ERROR=(0|-1) ERRNO=(\d+) CHECKS=([0-9A-F]{3})')
 vid,pid,devices,interfaces=match(4,r'USB=([0-9A-F]{4}):([0-9A-F]{4}) DEVICES=(\d+) INTERFACES=(\d+)')
 need((vid,pid)==(('046B','FF31') if variant=='PRODUCTION' else ('46F4','0001')),'Variant target mismatch')
 target,sg,count,modules=match(5,r'TARGET=([0-9.:-]{0,63}) SG=(sg[0-9]{1,28}|) COUNT=(\d+) MODULES=([0-8])')
 calls,=match(6,r'SG_IO_CALLS=([0-2]) CDB=25000000000000000000 TIMEOUT_MS=2000');calls=int(calls)
 packets=[]
 for index in range(2):
  raw,=match(7+index,r'A'+str(index+1)+r'=(.*)')
  if index>=calls:need(raw=='NONE','Unexpected packet without command');continue
  p=re.fullmatch(r'(-?\d+),(\d+),([0-9A-F]{2}),([0-9A-F]{2}),([0-9A-F]{2}),([0-9A-F]{4}),([0-9A-F]{4}),(-?\d+),([0-9A-F]{8}),(\d+),([01]),([0-9A-F]{16}),([0-9A-F]{0,64})',raw);need(p is not None,'Packet format')
  values=p.groups();types=[10,10,16,16,16,16,16,10,16,10,10];keys=['return','errno','status','masked','msg','host','driver','residual','info','sense_length','guard']
  row=dict(zip(keys,(int(v,b) for v,b in zip(values,types))));row['data8']=values[11];row['sense']=values[12];need(len(row['sense'])==min(row['sense_length'],32)*2,'Sense byte length')
  packets.append(row)
 valid,last,block=match(9,r'VALID=([01]) LAST_LBA=([0-9A-F]{8}) BLOCK_BYTES=([0-9A-F]{8})')
 match(10,r'PROBE_BLOCK_READS=0 PROBE_STORAGE_WRITES=0 PROBE_RESETS=0');match(11,r'KERNEL_SCAN_RECOVERY_MAY_ISSUE_COMMANDS')
 result,=match(12,r'RESULT=(PENDING|CAPACITY_OBSERVED|REFUSED_OR_FAILED)');marker,=match(13,r'(PROBE_PENDING|PROBE_COMPLETE)')
 stage,err,errno,checks,dmi,devices,interfaces,count,modules,valid,last,block=int(stage),int(err),int(errno),int(checks,16),int(dmi),int(devices),int(interfaces),int(count),int(modules),int(valid),int(last,16),int(block,16)
 need(bool(checks&256)==bool(dmi),'DMI check consistency');need(checks<=511 and devices<=128 and interfaces<=128 and count<=128,'Inventory/check bound')
 if calls or result=='PENDING':need(stage==8 and dmi==1 and checks==511 and devices==interfaces==count==1 and modules==8 and target and sg,'Ownership gates')
 if calls==2:
  a=packets[0];need(a=={'return':0,'errno':0,'status':2,'masked':1,'msg':0,'host':0,'driver':8,'residual':8,'info':1,'sense_length':18,'guard':1,'data8':'0000000000000000','sense':UA.hex().upper()},'Second call without exact accepted first UA')
 if result=='PENDING':need(allow_pending and marker=='PROBE_PENDING' and calls==0 and valid==0 and err==0,'Pending is not complete')
 else:need(marker=='PROBE_COMPLETE','Final marker required')
 if valid:
  need(calls>=1 and result=='CAPACITY_OBSERVED' and err==0 and errno==0,'Valid/result mismatch');p=packets[-1]
  need(all(p[k]==0 for k in ['return','errno','status','masked','msg','host','driver','residual','sense_length']) and p['guard']==1 and p['info']&1==0,'Invalid successful packet')
  need((last,block)==struct.unpack('>II',bytes.fromhex(p['data8'])) and last!=0xffffffff and block>0,'Capacity result bytes')
 else:need(result!='CAPACITY_OBSERVED','False successful result')
 if result=='REFUSED_OR_FAILED':need(err==-1,'Refusal missing failure status')
 return {'status':result,'variant':variant,'complete':marker=='PROBE_COMPLETE','capacity_valid':bool(valid),'dmi_match':bool(dmi),'stage':stage,'error':err,'errno':errno,'checks':f'{checks:03X}','target':target,'sg':sg,'usb_vid':vid,'usb_pid':pid,'devices':devices,'interfaces':interfaces,'sg_count':count,'modules':modules,'userspace_rc10_calls':calls,'packets':packets,'last_lba':last,'block_bytes':block,'capacity_bytes':(last+1)*block if valid else None,'probe_storage_writes':0,'probe_block_reads':0,'probe_resets':0,'kernel_scan_and_recovery_can_issue_additional_commands':True,'log_bytes':len(data),'crc32':f'{zlib.crc32(data):08X}','sha256':hashlib.sha256(data).hexdigest()}

if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('log');p.add_argument('--allow-lab',action='store_true');p.add_argument('--allow-pending',action='store_true');p.add_argument('--out');ns=p.parse_args();result=decode(Path(ns.log).read_bytes(),ns.allow_lab,ns.allow_pending);raw=json.dumps(result,indent=2)
 if ns.out:Path(ns.out).write_text(raw,encoding='utf8')
 print(raw)
