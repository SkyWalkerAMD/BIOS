"""Actual .15 launcher PE: identity, read-only preflight and no synthetic trigger.
UEFI services are doubles. Passing this is not real UEFI BDF or BMC evidence.
"""
from pathlib import Path
import hashlib,json,re,struct,uuid
import verify_launcher as old
from unicorn.x86_const import *
OUT=Path(__file__).resolve().parent;ROOT=OUT.parents[2]
ERR=old.ERR
HOST=json.loads((ROOT/'analysis/hero15_rc5_live_20261108/host-read-01.json').read_text('utf-8'))
import base64
TABLE=base64.b64decode(HOST['smbios']['DMI'])
CONFIG=bytes.fromhex(next(r['config64'] for r in HOST['aspeed_pci'] if r['device']=='0x2402'))
symbols={m[1]:int(m[2],16)-0x140000000+0x100000 for line in (OUT/'launcher.map').read_text().splitlines() if (m:=re.match(r'\s+\d+:[0-9a-f]+\s+([\w.]+)\s+([0-9a-f]{16})',line,re.I))}

class Machine(old.Machine):
 def __init__(self,case='first'):
  super().__init__(case)
  self.guard_case=case;self.keys=list('QQ' if case.startswith('existing') else 'DLFFQQ' if case.startswith('marker') else 'DQQ' if case=='diagnostic_only' else 'LQQ' if case=='without_D' else 'DLQQ')
  self.rt=self.alloc(bytes(112));self.w64(self.st+0x58,self.rt);self.w64(self.rt+0x48,self.stub('PreflightVariable'));self.w64(self.rt+0x58,self.stub('FORBIDDEN'))
  for offset,name in ((0x38,'PreflightMap'),(0x138,'PreflightHandles'),(0x48,'PreflightFree')):self.w64(self.bs+offset,self.stub(name))
  self.table=bytearray(TABLE)
  if case in ('wrong_uuid','zero_uuid','wrong_board','wrong_bios'):
   self.table=bytearray(TABLE);at=0
   while at<len(self.table):
    t=self.table[at];size=self.table[at+1];end=self.table.find(b'\0\0',at+size)+2;assert end>at
    if t==1 and case in ('wrong_uuid','zero_uuid'):
     if case=='zero_uuid':self.table[at+8:at+24]=bytes(16)
     else:self.table[at+8]^=1
    if t==2 and case=='wrong_board':self.table[at+size+len(b'ASUSTeK COMPUTER INC.')+1]^=1
    if t==0 and case=='wrong_bios':self.table[at+size+len(b'American Megatrends Inc.')+1]=ord('9')
    at=end
  self.tableptr=self.alloc(bytes(self.table));ep=bytearray(24);ep[:5]=b'_SM3_';ep[6:9]=bytes([24,3,5]);ep[10]=1
  struct.pack_into('<IQ',ep,12,len(self.table),self.tableptr);ep[5]=(-sum(ep))&255
  if case=='bad_smbios_checksum':ep[5]^=1
  self.ep=self.alloc(bytes(ep));self.ct=self.alloc(uuid.UUID('f2fd1544-9794-4a2c-992e-e5bbcf20e394').bytes_le+struct.pack('<Q',self.ep))
  self.w64(self.st+0x68,1);self.w64(self.st+0x70,self.ct)
  self.pci=self.alloc(bytes(160));self.config=bytearray(CONFIG);self.bus=0x74;self.var_reads=0;self.location_reads=0;self.map_reads=0;self.handle_reads=0;self.pci_reads=0
  if case=='existing_old_r4':self.logdata=b'HERO-IPMI-R4 CORE / test fixture\r\n';self.u.mem_write(self.log,self.logdata+b'\0')
  if case=='loaded_options_pointer':self.w64(self.child+0x38,0x123456)
  for off,name in ((0x30,'PreflightReadConfig'),(0x38,'FORBIDDEN'),(0x10,'FORBIDDEN'),(0x18,'FORBIDDEN'),(0x70,'PreflightLocation'),(0x80,'PreflightBar')):self.w64(self.pci+off,self.stub(name))
  if case=='bad_subsystem':self.config[44]^=1
  if case=='bad_class':self.config[11]^=1
  self.vars={}
  if case=='existing_default_cfg':self.vars['HeroIpmiCfg']=(3,struct.pack('<IBBBB',0x31495048,1,1,0,0))
  if case=='disabled_cfg':self.vars['HeroIpmiCfg']=(3,struct.pack('<IBBBB',0x31495048,0,1,0,0))
  if case=='bad_cfg_length':self.vars['HeroIpmiCfg']=(3,bytes(7))
  if case=='bad_cfg_attrs':self.vars['HeroIpmiCfg']=(7,struct.pack('<IBBBB',0x31495048,1,1,0,0))
  if case=='sensor_attempt':self.vars['HeroIpmiAttempt']=(3,b'\x01')
  if case=='dashboard_attempt':self.vars['HeroIpmiDmiAttempt']=(3,b'\x01')
  if case=='crc_bypass_bad_sha':
   data=bytes(self.u.mem_read(0x100000,0x200000));frozen=(OUT.parent/'USB/EFI/HERO/HeroIpmiR5.efi').read_bytes();off=data.find(frozen);assert off>=0
   self.u.mem_write(0x100000+off+100,b'X')
   import zlib
   self.u.mem_write(symbols['probe_crc32'],b'\xb8'+struct.pack('<I',zlib.crc32(frozen))+b'\xc3')
 def wide(self,where):
  data=bytearray()
  for i in range(512):
   ch=bytes(self.u.mem_read(where+2*i,2))
   if not any(ch):return data.decode('utf-16-le')
   data+=ch
  raise AssertionError('unterminated')
 def finish_hook(self,u,result):
  u.reg_write(UC_X86_REG_RAX,result)
  for reg in (UC_X86_REG_RCX,UC_X86_REG_RDX,UC_X86_REG_R8,UC_X86_REG_R9,UC_X86_REG_R10,UC_X86_REG_R11):u.reg_write(reg,0xcccccccccccccccc)
 def hook(self,u,addr,size,user):
  name=self.stubs.get(addr)
  if not name:return
  rsp=u.reg_read(UC_X86_REG_RSP);a,b,c,d=[u.reg_read(r) for r in (UC_X86_REG_RCX,UC_X86_REG_RDX,UC_X86_REG_R8,UC_X86_REG_R9)];e=self.r64(rsp+0x28);result=0;case=self.guard_case
  if name=='PreflightMap':
   self.map_reads+=1
   if case=='uuid_changed' and self.map_reads==3:
    at=0
    while self.table[at]!=1:at=self.table.find(b'\0\0',at+self.table[at+1])+2
    self.u.mem_write(self.tableptr+at+8,bytes([self.table[at+8]^1]))
   ranges=[(0x100000,0x200000),(0x500000,0x100000)]
   desc=b''.join(struct.pack('<IIQQQQ',11 if case=='mmio_map' else 4,0,base,0,length//4096,0) for base,length in ranges)
   assert self.r64(a)>=len(desc);u.mem_write(b,desc);self.w64(a,len(desc));self.w64(c,1);self.w64(d,40);u.mem_write(e,struct.pack('<I',1))
   if case=='map_error':result=ERR(7)
  elif name=='PreflightHandles':
   self.handle_reads+=1
   count=2 if case=='duplicate_card' or (case=='count_changed' and self.handle_reads==2) else 0 if case=='no_card' else 1
   self.w64(d,count);self.w64(e,self.alloc(struct.pack('<Q',0x7777)*max(count,1)))
  elif name=='PreflightFree':pass
  elif name=='LocateProtocol' and self.guid(a)=='30cfe3e7-3de1-4586-be20-deaba1b3b793':
   self.w64(c,0);result=ERR(14) if case=='enum_missing' else 0
  elif name=='HandleProtocol' and self.guid(b)=='4cf5b200-68b8-4ca5-9eec-b23e3f50029a':self.w64(c,self.pci)
  elif name=='PreflightReadConfig':
   self.pci_reads+=1
   if case=='bar_changed' and self.pci_reads==2:self.config[22]^=1
   assert (a,b,c,d)==(self.pci,0,0,64);u.mem_write(e,bytes(self.config));result=ERR(7) if case=='pci_read_error' else 0
  elif name=='PreflightLocation':
   self.location_reads+=1
   bus=256 if case=='bus_overflow' else 0x75 if case=='preload_changed' and self.location_reads>1 else self.bus
   for p,v in ((b,0),(c,bus),(d,1),(e,0)):self.w64(p,v)
  elif name=='PreflightBar':
   assert a==self.pci and (b&255)==1;desc=bytearray(46);desc[:4]=b'\x8a\x2b\0\0';struct.pack_into('<Q',desc,14,int.from_bytes(self.config[20:24],'little'));struct.pack_into('<Q',desc,38,0x100 if case=='short_bar' else 0x40000)
   self.w64(c,0);self.w64(d,self.alloc(bytes(desc)))
  elif name=='PreflightVariable':
   assert self.guid(b)=='c2614243-a877-4acf-a458-ce2904ec3e10';name2=self.wide(a);assert name2 in ('HeroIpmiCfg','HeroIpmiAttempt','HeroIpmiDmiAttempt')
   self.var_reads+=1
   if case=='cfg_changed' and self.var_reads>=4:self.vars['HeroIpmiCfg']=(3,struct.pack('<IBBBB',0x31495048,0,1,0,0))
   if case=='cfg_created_same_default' and self.var_reads>=4:self.vars['HeroIpmiCfg']=(3,struct.pack('<IBBBB',0x31495048,1,1,0,0))
   if case=='lock_appeared' and self.var_reads>=4:self.vars['HeroIpmiAttempt']=(3,b'\1')
   row=self.vars.get(name2)
   if case=='variable_error':result=ERR(7)
   elif row is None:result=ERR(14)
   else:
    attrs,val=row;u.mem_write(c,struct.pack('<I',attrs));n=self.r64(d);self.w64(d,len(val))
    if n<len(val):result=ERR(5)
    else:u.mem_write(e,val)
  else:return super().hook(u,addr,size,user)
  self.calls.append(name);self.finish_hook(u,result)
 def execute(self):
  rsp=0x8ff000-8;stop=0x70fff0;self.w64(rsp,stop);self.u.reg_write(UC_X86_REG_RSP,rsp);self.u.reg_write(UC_X86_REG_RCX,0x9090);self.u.reg_write(UC_X86_REG_RDX,self.st)
  self.u.emu_start(self.entry,stop,count=12000000);assert self.u.reg_read(UC_X86_REG_RIP)==stop,(self.guard_case,'instruction budget')
  result=self.u.reg_read(UC_X86_REG_RAX);assert 'FORBIDDEN' not in self.calls
  return result
 def call(self,name,*args):
  rsp=0x8ff000-8;stop=0x70fff0;self.w64(rsp,stop);self.u.reg_write(UC_X86_REG_RSP,rsp)
  for reg,arg in zip((UC_X86_REG_RCX,UC_X86_REG_RDX,UC_X86_REG_R8,UC_X86_REG_R9),args):self.u.reg_write(reg,arg)
  self.u.emu_start(symbols[name],stop,count=12000000);assert self.u.reg_read(UC_X86_REG_RIP)==stop
  return self.u.reg_read(UC_X86_REG_RAX)

def main():
 rows=[]
 success=['first','existing_default_cfg','existing_ready','diagnostic_only','marker_missing_repeat','marker_bad_repeat']
 denied=['wrong_uuid','zero_uuid','wrong_board','wrong_bios','bad_smbios_checksum','map_error','mmio_map',
         'bad_subsystem','bad_class','duplicate_card','no_card','enum_missing','pci_read_error','bus_overflow','short_bar',
         'disabled_cfg','bad_cfg_length','bad_cfg_attrs','sensor_attempt','dashboard_attempt','variable_error','preload_changed',
         'watchdog_error','lookup_error','load_error','loaded_error','loaded_options','start_error','corrupt_embedded',
         'crc_bypass_bad_sha','existing_old_r3','existing_old_r4','existing_manual','existing_missing_v2',
         'without_D','uuid_changed','bar_changed','count_changed','cfg_changed','cfg_created_same_default','lock_appeared','loaded_options_pointer']
 for case in success+denied:
  m=Machine(case)
  # Existing_default_cfg means configuration exists, not a preexisting core.
  if case=='existing_default_cfg':m.protocols=False;m.keys=list('DLQQ')
  status=m.execute()
  should_load=case in ('first','existing_default_cfg','marker_missing_repeat','marker_bad_repeat')
  assert (m.calls.count('StartImage')==1)==(should_load or case=='start_error'),(case,hex(status),m.calls,m.output)
  if case in ('first','existing_default_cfg'):
   assert status==0 and m.calls.count('LoadImage')==1 and m.location_reads==2
   assert 'FIRST_PASS_NO_BMC_QUERY' in m.output
  if case=='diagnostic_only':assert status==0 and not m.loaded and m.location_reads==1
  if case=='existing_ready':assert status==0 and not m.loaded and 'SECOND_PASS_OBSERVER' in m.output
  if case in ('sensor_attempt','dashboard_attempt','disabled_cfg','preload_changed','without_D','uuid_changed','bar_changed','count_changed','cfg_changed','cfg_created_same_default','lock_appeared'):assert not m.loaded
  assert m.call('make_snapshot',1)==0
  n=m.r64(symbols['snapshot_len']);log=bytes(m.u.mem_read(symbols['snapshot'],n)).decode('ascii')
  if case=='diagnostic_only':assert 'PCI_BDF=0000:0000000000000074:01.0' in log and 'NO KCS OR CONFIGURATION WRITES' in log
  if case=='preload_changed':assert 'PRELOAD_CHANGED_OR_UNSAFE' in log
  rows.append({'case':case,'passed':True,'status':f'{status:016X}','load_calls':m.calls.count('LoadImage'),'start_calls':m.calls.count('StartImage'),'calls':m.calls})
 result={'passed':True,'count':len(rows),'cases':rows,'launcher_sha256':hashlib.sha256((OUT/'USB/EFI/BOOT/BOOTX64.EFI').read_bytes()).hexdigest(),
         'input_evidence':'Actual .15 Linux DMI + PCI configuration; UEFI service behavior is synthetic',
         'no_manual_run_or_synthetic_event_or_variable_pci_mmio_write':True}
 (OUT/'guarded-launcher-verification.json').write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8');print('GUARDED LAUNCHER PE PASS',len(rows))

if __name__=='__main__':main()
