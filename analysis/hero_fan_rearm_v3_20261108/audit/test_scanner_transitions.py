"""Connect exact vendor OEM/API/SDR/scanner bodies using isolated ARM VMs.

The EC/I2C, SDR repository service and scheduler are explicit models. No live
device calls occur. Standard event-enable is executed as vendor machine code.
"""
from pathlib import Path
import hashlib,importlib.util,json,struct,sys
P=Path(__file__).resolve().parent;ROOT=P.parents[1]
spec=importlib.util.spec_from_file_location('arm_model',ROOT/'analysis/hero_fan_mapping_20261108/test_vendor_arm.py')
v=importlib.util.module_from_spec(spec);spec.loader.exec_module(v);v.P=P
R0,R1,R2,R3=v.REGS;PC=v.UC_ARM_REG_PC;LR=v.UC_ARM_REG_LR
SENSOR=0x20;INSTANCE=1;STRIDE=130
INFO=0x7f14c+0xb598+SENSOR*STRIDE
assert INFO==0x8a000+0x6e4+SENSOR*STRIDE
CONTROL=INFO+0x23
assert CONTROL==0x8a000+0x707+SENSOR*STRIDE
SDR=(ROOT/'analysis/hero_fan_mapping_v2_20261108/fixtures/mb-cha-fan1-sdr.bin').read_bytes()
assert hashlib.sha256(SDR).hexdigest()=='a253da27c190c2973891597bfb1fe61c52c828b420dfb46388916cdcac4784d8'

class Connected(v.Arm):
 def __init__(self,name,shared):
  self.shared=shared
  super().__init__(name)
 def hook(self,u,address,size,user):
  name=self.plt.get(address)
  if not name:return
  args=[u.reg_read(r) for r in v.REGS]
  value=0;handled=True
  if name=='ASUS_API_GetSensorEnable':
   assert args[0]==SENSOR;value=self.shared.call_api(name,[SENSOR,0,0,0])
  elif name=='ASUS_API_SetSensorEnable':
   assert args[0]==SENSOR and args[1] in (0,1);value=self.shared.call_api(name,args)
  elif name=='ASUS_SDR_HideSDR':
   assert args[:3]==[SENSOR,args[1],INSTANCE] and args[1] in (0,1)
   value=self.shared.call_core(name,args)
  elif name=='ReadSDRRepositoryAll':
   assert args[1]==INSTANCE and args[0] in (0,0x6020000)
   value=0x6020000 if not args[0] else 0
   u.mem_write(value or 0x6020000,SDR)
  elif name=='SDR_ReserveSDRRepository':
   assert args[0]==INSTANCE;self.shared.reservations+=1;value=self.shared.reservations
  elif name in ('SDR_DeleteSDR','SDR_UnDeleteSDR'):
   assert args[1:3]==[0x22,INSTANCE]
   self.shared.hidden=name=='SDR_DeleteSDR'
   self.shared.repo_actions.append(dict(operation=name,record_id=args[1],instance=args[2]))
  elif name=='GetSensorInfo':
   assert args[:3]==[SENSOR,0,INSTANCE]
   value=self.globals['g_BMCInfo']+INFO
  elif name=='memcpy':
   assert 0<=args[2]<=256
   u.mem_write(args[0],bytes(u.mem_read(args[1],args[2])));value=args[0]
  elif name=='fflush':pass
  else:handled=False
  if not handled:return super().hook(u,address,size,user)
  self.calls.append((name,args));self.shared.external.append((name,args[:3]))
  u.reg_write(R0,value);u.reg_write(PC,u.reg_read(LR))

class State:
 def __init__(self,status=2,present=1,flags=0xa0):
  self.bytes=bytearray(0x100000);self.hidden=not present;self.reservations=0;self.repo_actions=[];self.external=[]
  self.status=status;self.rpm=bytes(15);self.trace=[]
  self.bytes[INFO:INFO+4]=struct.pack('<I',present)
  self.bytes[INFO+0x10]=SDR[13] # Event/reading type 1 = threshold, not fan sensor type 4.
  self.bytes[INFO+0x11]=SDR[11] # Sensor capabilities = 0x68.
  assert SDR[11]==0x68 and SDR[13]==1
  self.bytes[CONTROL]=flags
  self.bytes[INFO+0x24:INFO+0x28]=bytes.fromhex('70057005')
  # Mark neighboring records so unintended changes are detectable.
  self.bytes[INFO-STRIDE:INFO]=b'\x57'*STRIDE
  self.bytes[INFO+STRIDE:INFO+STRIDE*2]=b'\x69'*STRIDE
  self.api=Connected('libipmipdkapi.so.13.1.0',self)
  self.core=Connected('libipmimsghndlr.so.13.22.0',self)
  self.cmd=Connected('libipmipdkcmds.so.13.0.0',self)
  self.scan=Connected('libipmipar.so.13.16.0',self)
 def copy_in(self,arm):arm.put('g_BMCInfo',bytes(self.bytes))
 def copy_out(self,arm):
  self.bytes[:]=arm.get('g_BMCInfo',len(self.bytes))
  assert self.bytes[INFO-STRIDE:INFO]==b'\x57'*STRIDE
  assert self.bytes[INFO+STRIDE:INFO+STRIDE*2]==b'\x69'*STRIDE
 def call_api(self,name,args):
  self.copy_in(self.api);value=self.api.call(name,args);self.copy_out(self.api);return value
 def call_core(self,name,args):
  self.copy_in(self.core);value=self.core.call(name,args);self.copy_out(self.core);return value
 def snapshot(self,label):
  item=dict(label=label,presence=int.from_bytes(self.bytes[INFO:INFO+4],'little'),
    vendor_status=self.status,control_hex=f'{self.bytes[CONTROL]:02x}',hidden=self.hidden,
    rpm_hex=self.rpm.hex(),reservation_calls=self.reservations,
    assert_deassert_masks_hex=self.bytes[INFO+0x24:INFO+0x28].hex())
  self.trace.append(item);return item
 def oem_enable(self,enable):
  self.cmd.put('g_SensorStatus',struct.pack('<I',self.status),SENSOR*4)
  assert self.cmd.handler('OemEnDisSensor',bytes([SENSOR,enable]))==b'\0'
  self.status=int.from_bytes(self.cmd.get('g_SensorStatus',4,SENSOR*4),'little')
  return self.snapshot('oem_enable_'+str(enable))
 def map(self,source):
  self.rpm=bytes([0,0,source])+bytes(12)
  assert self.cmd.handler('OemMBFanControl',b'\x01\x01'+self.rpm)==b'\0'+self.rpm
  return self.snapshot(f'map_{source:02x}')
 def sensor_event(self,flags):
  self.copy_in(self.core)
  response=self.core.handler('SetSensorEventEnable',bytes([SENSOR,flags]))
  self.copy_out(self.core)
  assert response==b'\0',response.hex()
  return self.snapshot(f'standard_set_event_{flags:02x}')
 def sensor_event_get(self):
  self.copy_in(self.core);old=bytes(self.bytes)
  response=self.core.handler('GetSensorEventEnable',bytes([SENSOR]))
  self.copy_out(self.core);assert old==bytes(self.bytes)
  return response
 def tick(self,raw):
  a=self.scan;a.raw_read=raw
  a.put('asus_board_id',struct.pack('<I',0x80));a.put('g_MBFanRPM',self.rpm)
  a.put('g_SensorStatus',struct.pack('<I',self.status),SENSOR*4)
  ctx=0x6000000;readp=0x6001000;buf=0x6002000
  a.u.mem_write(ctx,bytes(64));a.u.mem_write(ctx+8,struct.pack('<I',readp));a.u.mem_write(ctx+16,struct.pack('<I',buf))
  assert a.call('dev_virtualminusfan_32_0_32_read_device',[ctx,0,0,0])==0
  self.status=int.from_bytes(a.get('g_SensorStatus',4,SENSOR*4),'little')
  self.snapshot('manual_scanner_tick_mockraw_'+str(raw))
  return dict(i2c=a.i2c,calls=[(n,args[:2]) for n,args in a.calls],output=int(a.u.mem_read(readp,1)[0]))

def main():
 rows=[]
 def done(name,state,**extra):rows.append(dict(case=name,passed=True,trace=state.trace,repo_actions=state.repo_actions,**extra))
 s=State();s.snapshot('baseline');r=s.sensor_event_get();assert r==bytes.fromhex('008070057005');done('standard_get_event_flags_excludes_unavailable_readonly',s,reply=r.hex())
 s=State();s.snapshot('baseline');s.map(0x62);s.oem_enable(1)
 assert s.status==2 and s.bytes[CONTROL]==0xa0 and not s.repo_actions
 s.tick(22);assert s.status==2 and s.bytes[CONTROL]==0xa0
 done('visible_oem_enable_is_noop_even_after_map',s)
 s=State();s.map(0x62);s.sensor_event(0xc0)
 assert s.status==2 and s.bytes[CONTROL]==0xc0 and not s.repo_actions
 s.tick(22);assert s.status==2 and s.bytes[CONTROL]==0x80
 s.sensor_event(0x80);assert s.status==2 and s.bytes[CONTROL]==0x80
 done('standard_scan_enable_does_not_reset_vendor_state_and_scanner_disables_again',s)
 s=State();s.snapshot('baseline');s.map(0x62);s.oem_enable(0)
 assert s.hidden and s.status==3 and int.from_bytes(s.bytes[INFO:INFO+4],'little')==0
 s.oem_enable(1)
 assert not s.hidden and s.status==0 and s.bytes[CONTROL]==0xe3
 tick=s.tick(22);assert s.status==1 and s.bytes[CONTROL]==0xe3
 s.map(0);s.tick(0)
 assert s.status==1 # map zero does NOT return state 2 by itself
 s.sensor_event(0x80)
 assert not s.hidden and s.status==1 and s.bytes[CONTROL]==0xa3
 assert s.reservations==4 and [x['operation'] for x in s.repo_actions]==['SDR_DeleteSDR','SDR_UnDeleteSDR']
 done('map_hide_unhide_mock_positive_restore_array_and_standard_flags_does_not_restore_vendor_state',s,tick=tick)
 s=State();s.snapshot('baseline');s.map(0x62);s.oem_enable(0);s.oem_enable(1);s.tick(0)
 assert s.status==2 and s.bytes[CONTROL]==0xa0 and not s.hidden
 s.map(0);s.sensor_event(0x80)
 assert s.status==2 and s.bytes[CONTROL]==0xa0
 done('map_hide_unhide_mock_zero_returns_unavailable_baseline_after_array_restore',s)
 s=State();s.snapshot('baseline');s.oem_enable(0)
 assert s.hidden and s.status==3
 done('interruption_between_hide_unhide_leaves_target_hidden_not_recoverable_by_map_restore',s)
 s=State();s.map(0x62);s.oem_enable(0);s.oem_enable(1);s.tick(22);s.map(0);s.oem_enable(0);s.oem_enable(1);s.tick(0)
 assert s.status==2 and s.bytes[CONTROL]==0xa0 and not s.hidden and s.reservations==8
 done('modelled_second_hide_unhide_after_zero_map_reconstructs_visible_unavailable_state_but_changes_repository',s)
 for initial in (0,1,2,3):
  s=State(status=initial);s.sensor_event(0xc0)
  assert s.status==initial and not s.repo_actions
  done('standard_set_never_resets_vendor_status_'+str(initial),s)
 result=dict(passed=True,count=len(rows),cases=rows,hardware_test=False,
  exact_bodies=['OemMBFanControl','OemEnDisSensor','ASUS_API_GetSensorEnable','ASUS_API_SetSensorEnable','ASUS_SDR_HideSDR','GetSensorEventEnable','SetSensorEventEnable','dev_virtualminusfan_32_0_32_read_device'],
  field_identity=dict(instance_stride=hex(0x7f14c),sensor_stride=130,presence_offset=hex(INFO),control_offset=hex(CONTROL)),
  limitations=['I2C returns mock raw value; no physical source proven.',
   'Scheduler and locks are mocked; ticks explicitly invoked even when scanning disabled.',
   'SDR_DeleteSDR/UnDeleteSDR and Reserve are recorded models; backing repository modifications are not emulated.',
   'No claimed complete rollback of repository reservation, vendor status, timestamps or readings.'])
 (P/'scanner-transition-verification.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(dict(passed=True,count=len(rows))))
if __name__=='__main__':main()
