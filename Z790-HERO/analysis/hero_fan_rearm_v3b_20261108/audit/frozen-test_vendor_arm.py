"""Exact vendor ARM leaf emulation with external dependencies mocked.
No BMC connection, physical I2C/EC or background scheduler is modelled.
"""
from pathlib import Path
import hashlib,json,struct,sys
P=Path(__file__).resolve().parent;ROOT=P.parents[1];sys.path.insert(0,str(ROOT/'analysis'));sys.path.insert(0,str(ROOT/'tools/pydeps'))
from bmc_arm_inspect import Elf32,Cs,CS_ARCH_ARM,CS_MODE_ARM
from unicorn import Uc,UC_ARCH_ARM,UC_MODE_ARM,UC_HOOK_CODE
from unicorn.arm_const import UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2,UC_ARM_REG_R3,UC_ARM_REG_SP,UC_ARM_REG_LR,UC_ARM_REG_PC
REGS=(UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2,UC_ARM_REG_R3)
class Arm:
 def __init__(self,name,get_enabled=0,raw_read=0):
  self.e=Elf32(P/'sources'/name);self.u=Uc(UC_ARCH_ARM,UC_MODE_ARM);self.u.mem_map(0,0x8000000)
  self.globals={};self.plt={};self.calls=[];self.get_enabled=get_enabled;self.raw_read=raw_read;self.i2c=[]
  for s in self.e.sections:
   if s['flags']&2 and s['size'] and s['type']!=8:self.u.mem_write(s['addr'],self.e.data[s['off']:s['off']+s['size']])
  for a,r in self.e.relocs.items():
   if r['type'] not in (2,21):continue
   name=r['symbol'];value=r['value']
   if not value:
    if name not in self.globals:self.globals[name]=0x400000+len(self.globals)*0x100000
    value=self.globals[name];assert value<0x5800000
   addend=struct.unpack('<I',self.e.read(a,4))[0] if r['type']==2 else 0
   self.u.mem_write(a,struct.pack('<I',(value+addend)&0xffffffff))
  for s in self.e.sections:
   if s['name']!='.plt':continue
   for i in Cs(CS_ARCH_ARM,CS_MODE_ARM).disasm(self.e.read(s['addr'],s['size']),s['addr']):
    if i.mnemonic=='add' and i.op_str.startswith('ip, pc, #'):
     stub=list(Cs(CS_ARCH_ARM,CS_MODE_ARM).disasm(self.e.read(i.address,12),i.address))
     def imm(ins):
      word=int.from_bytes(ins.bytes,'little');v=word&255;rot=((word>>8)&15)*2
      return ((v>>rot)|(v<<(32-rot)))&0xffffffff if rot else v
     word=int.from_bytes(stub[2].bytes,'little');disp=(word&4095)*(1 if word&(1<<23) else -1)
     got=i.address+8+imm(stub[0])+imm(stub[1])+disp
     self.plt[i.address]=self.e.relocs[got]['symbol']
  self.u.hook_add(UC_HOOK_CODE,self.hook)
 def put(self,n,b,offset=0):self.u.mem_write(self.globals[n]+offset,b)
 def get(self,n,size,offset=0):return bytes(self.u.mem_read(self.globals[n]+offset,size))
 def word(self,a):return struct.unpack('<I',self.u.mem_read(a,4))[0]
 def hook(self,u,a,size,user):
  name=self.plt.get(a)
  if name is None:return
  args=[u.reg_read(r) for r in REGS];self.calls.append((name,args));value=0
  if name=='memset':u.mem_write(args[0],bytes([args[1]&255])*args[2]);value=args[0]
  elif name in ('printf','puts','pthread_mutex_lock','pthread_mutex_unlock'):pass
  elif name=='ASUS_API_GetSensorEnable':assert args[0]==0x20;value=self.get_enabled
  elif name=='ASUS_API_SetSensorEnable':assert args[0]==0x20 and args[1] in (0,1)
  elif name=='ASUS_SDR_HideSDR':assert args[0]==0x20 and args[1] in (0,1)
  elif name=='dev_ast2600_i2c_2_rwi2c':
   ctx=args[0];buf=self.word(ctx+16);n=self.word(ctx+20);rn=self.word(ctx+12)
   self.i2c.append(dict(address=int(u.mem_read(ctx+0x2d,1)[0]),write=bytes(u.mem_read(buf,n)).hex(),read_count=rn))
   if rn:assert rn==1;u.mem_write(self.word(ctx+8),bytes([self.raw_read]));u.mem_write(ctx,bytes(4))
  else:raise AssertionError(('unexpected external call',name,args))
  u.reg_write(UC_ARM_REG_R0,value);u.reg_write(UC_ARM_REG_PC,u.reg_read(UC_ARM_REG_LR))
 def call(self,name,args):
  self.calls=[];self.i2c=[]
  for r,v in zip(REGS,args):self.u.reg_write(r,v)
  self.u.reg_write(UC_ARM_REG_SP,0x7000000);self.u.reg_write(UC_ARM_REG_LR,0x7100000)
  self.u.emu_start(self.e.byname[name]['value'],0x7100000,count=20000)
  assert self.u.reg_read(UC_ARM_REG_PC)==0x7100000 and self.u.reg_read(UC_ARM_REG_SP)==0x7000000
  return self.u.reg_read(UC_ARM_REG_R0)
 def handler(self,name,payload):
  self.u.mem_write(0x6000000,payload);self.u.mem_write(0x6001000,b'\xa5'*64)
  n=self.call(name,[0x6000000,len(payload),0x6001000,1]);assert n<=16 and self.u.mem_read(0x6001010,48)==b'\xa5'*48
  return bytes(self.u.mem_read(0x6001000,n))

def main():
 rows=[]
 def passed(name,**more):rows.append(dict(case=name,passed=True,**more))
 a=Arm('libipmipdkcmds.so.13.0.0');a.put('g_MBFanMode',b'\0');a.put('g_MBFanRPM',bytes(15));a.put('g_MBFanPWM',bytes(15));a.put('g_FCType',bytes(8)+bytes([1])*15)
 baseline={n:a.get(n,1024) for n in a.globals}
 for sub in range(4):
  r=a.handler('OemMBFanControl',bytes([sub,0]));assert {n:a.get(n,1024) for n in a.globals}==baseline
  assert r==[b'\0\0',bytes(16),bytes(16),b'\0'+bytes([1])*15][sub]
  passed('current71_get_'+str(sub),response=r.hex())
 candidate=bytes([0,0,0x62])+bytes(12)
 for label,rpm in [('candidate',candidate),('restore',bytes(15))]:
  r=a.handler('OemMBFanControl',b'\x01\x01'+rpm);assert r==b'\0'+rpm
  assert [n for n,_ in a.calls]==['memset','printf']
  after={n:a.get(n,1024) for n in a.globals};assert after['g_MBFanRPM']==rpm+baseline['g_MBFanRPM'][15:]
  assert all(after[n]==baseline[n] for n in baseline if n!='g_MBFanRPM')
  passed('rpm_'+label+'_only',request=(b'\x01\x01'+rpm).hex(),external_calls=[n for n,_ in a.calls])
 for present in (0,1):
  for enable in (0,1):
   a=Arm('libipmipdkcmds.so.13.0.0',get_enabled=present);a.put('g_SensorStatus',struct.pack('<I',2),0x20*4)
   r=a.handler('OemEnDisSensor',bytes([0x20,enable]));assert r==b'\0'
   calls=[(n,args[:3]) for n,args in a.calls]
   if enable==1 and present==0:
    assert [x[0] for x in calls]==['ASUS_API_GetSensorEnable','ASUS_SDR_HideSDR','ASUS_API_SetSensorEnable'];assert calls[1][1]==[0x20,0,1];assert a.get('g_SensorStatus',4,0x80)==bytes(4)
   elif enable==0 and present==1:
    assert [x[0] for x in calls]==['ASUS_API_GetSensorEnable','ASUS_SDR_HideSDR','ASUS_API_SetSensorEnable'];assert calls[1][1]==[0x20,1,1];assert a.get('g_SensorStatus',4,0x80)==struct.pack('<I',3)
   else:assert [x[0] for x in calls]==['ASUS_API_GetSensorEnable'];assert a.get('g_SensorStatus',4,0x80)==struct.pack('<I',2)
   passed(f'enable_{enable}_when_get_{present}',calls=calls,sensor_status=struct.unpack('<I',a.get('g_SensorStatus',4,0x80))[0])
 for initial in (0,1,2):
  a=Arm('libipmipdkapi.so.13.1.0');a.put('g_BMCInfo',struct.pack('<I',initial),0x8a000+0x6e4+0x20*130)
  assert a.call('ASUS_API_GetSensorEnable',[0x20,0,0,0])==(initial==1);passed('api_get_field_'+str(initial))
 for enable in (0,1):
  a=Arm('libipmipdkapi.so.13.1.0');base=0x8a000+0x20*130;a.put('g_BMCInfo',struct.pack('<I',1),base+0x6e4);a.put('g_BMCInfo',b'\xa0',base+0x707)
  assert a.call('ASUS_API_SetSensorEnable',[0x20,enable,0,0])==0
  assert a.get('g_BMCInfo',1,base+0x707)==bytes([0xe3 if enable else 0xa0]) and a.call('ASUS_API_GetSensorEnable',[0x20,0,0,0])==1
  passed('api_set_'+str(enable)+'_does_not_change_get_field',status_byte=a.get('g_BMCInfo',1,base+0x707).hex())
 for source,raw,status in [(0,0,0),(0,0,1),(0,0,2),(0x62,22,0),(0x62,22,1),(0x62,22,2),(0x62,0,0)]:
  a=Arm('libipmipar.so.13.16.0',raw_read=raw);a.put('asus_board_id',struct.pack('<I',0x80));a.put('g_MBFanRPM',bytes([0,0,source])+bytes(12));a.put('g_SensorStatus',struct.pack('<I',status),0x80)
  ctx=0x6000000;readp=0x6001000;buf=0x6002000;a.u.mem_write(ctx,bytes(64));a.u.mem_write(ctx+8,struct.pack('<I',readp));a.u.mem_write(ctx+16,struct.pack('<I',buf));a.u.mem_write(readp,b'\x00')
  assert a.call('dev_virtualminusfan_32_0_32_read_device',[ctx,0,0,0])==0
  assert len(a.i2c)==2 and a.i2c[0]==dict(address=0x9c,write=bytes([0,0x80,source]).hex(),read_count=0) and a.i2c[1]==dict(address=0x9c,write='81',read_count=1)
  set_calls=[args[:2] for n,args in a.calls if n=='ASUS_API_SetSensorEnable'];final=struct.unpack('<I',a.get('g_SensorStatus',4,0x80))[0]
  if source==0x62 and raw==22 and status<=1:assert not set_calls and final==1
  if source==0x62 and raw==22 and status==2:assert set_calls==[[0x20,0]] and final==2
  passed(f'scanner_source_{source:02X}_mock_raw_{raw}_state_{status}',i2c=a.i2c,set_calls=set_calls,final_state=final,raw_output=int(a.u.mem_read(readp,1)[0]))
 out=dict(passed=True,cases=rows,case_count=len(rows),kind='EXACT_VENDOR_ARM_OFFLINE_EMULATION',hardware_test=False,limitations=['External functions are mocked, except the separately emulated API leaf bodies.','No scheduler, physical EC, I2C or mutex concurrency is modelled.','Source62 receiving mock raw22 does not prove HERO physical identity.','No persistence or SDR hide rollback proven.'])
 (P/'arm-verification.json').write_text(json.dumps(out,indent=2)+'\n');print('PASS',len(rows))
if __name__=='__main__':main()
