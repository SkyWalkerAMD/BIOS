"""Actual vendor SDR repository code, with only platform storage/time mocked.

No BMC or filesystem-storage backend is invoked. Three distinct SDR records
exercise first/middle/last traversal and protection of adjacent records.
"""
from pathlib import Path
import importlib.util,json,struct
P=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('transitions',P/'test_scanner_transitions.py')
t=importlib.util.module_from_spec(spec);spec.loader.exec_module(t)
v=t.v;REPO=0x6100000;WRITE=0x6150000;INST=0x7f14c
EXACT=('SDR_DeleteSDR','SDR_UnDeleteSDR','SDR_ReserveSDRRepository',
       'ReadSDRRepository','ReadMarkSDRRepository','ReadSDRRepositoryAll')

class Backend(t.Connected):
 def __init__(self,s):
  super().__init__('libipmimsghndlr.so.13.22.0',s)
  self.storage=[];self.flushes=[];self.clock=0x12345678;self.random=0x200;self.target_index=1;self.write_failure=False
  self.u.mem_write(self.globals['g_PDKHandle']+0x1c8,struct.pack('<I',WRITE))
 def hook(self,u,address,size,user):
  name=self.plt.get(address);args=[u.reg_read(r) for r in v.REGS]
  if name in EXACT:
   if name=='SDR_ReserveSDRRepository':self.shared.reservations+=1
   if name in ('SDR_DeleteSDR','SDR_UnDeleteSDR'):
    self.shared.repo_actions.append(dict(operation=name,record_id=args[1],instance=args[2]))
   self.calls.append((name,args));u.reg_write(t.PC,self.e.byname[name]['value']);return
  value=0
  if address==WRITE:
   assert args[3]==1 and args[0]==REPO+args[1] and args[2] in (1,4)
   self.storage.append(dict(offset=args[1],length=args[2],hex=bytes(u.mem_read(args[0],args[2])).hex()))
   value=0xffffffff if self.write_failure else 0
  elif name=='GetSDRSELNVRAddr':
   assert args[1]==1 and args[0] in (0,0x10);value=REPO+args[0]
  elif name=='generate_random_number':
   assert args[1]==2;self.random+=1;u.mem_write(args[0],struct.pack('<H',self.random))
  elif name=='GetSelTimeStamp':
   assert args[0]==1;value=self.clock;self.clock+=1
  elif name=='FlushIPMI':
   assert args[0]==args[1] and args[3]==0x4b
   self.flushes.append(dict(source_offset=args[0]-self.globals['g_BMCInfo'],length=args[3],
     instance=self.word(u.reg_read(v.UC_ARM_REG_SP)),hex=bytes(u.mem_read(args[0],args[3])).hex()))
  elif name=='GetCommandEnabledStatus':value=0
  else:return super().hook(u,address,size,user)
  self.calls.append((name or 'PDK_STORAGE_WRITE',args));u.reg_write(t.R0,value);u.reg_write(t.PC,u.reg_read(t.LR))
 def setup(self,target_index=1):
  self.target_index=target_index;raw=bytearray(16+3*64)
  struct.pack_into('<HH',raw,4,3,len(raw))
  for i in range(3):
   r=bytearray(t.SDR);r[0]=0x21+i;r[7]=0x1f+i;r[-1]=ord('0')+i
   if i==target_index:r[:]=t.SDR
   elif r[7]==0x20:r[0]=0x44;r[7]=0x44
   off=16+i*64;raw[off:off+2]=bytes([0x5a,64]);raw[off+2:off+2+len(r)]=r
  self.initial_repo=bytes(raw);self.u.mem_write(REPO,bytes(raw))
  self.shared.bytes[INST+0x30294:INST+0x30298]=struct.pack('<I',REPO)
  self.shared.bytes[INST+0xb559]=64
 def repo(self):return bytes(self.u.mem_read(REPO,len(self.initial_repo)))
 def verify_record_bytes(self):
  raw=self.repo();target=16+self.target_index*64
  for i in range(3):
   off=16+i*64
   if i==self.target_index:assert raw[off+1:off+64]==self.initial_repo[off+1:off+64]
   else:assert raw[off:off+64]==self.initial_repo[off:off+64]
  return raw[target]

def run(index=1,storage_fail=False):
 s=t.State();s.core=Backend(s);a=s.core;a.setup(index);a.write_failure=storage_fail
 s.map(0x62);s.oem_enable(0)
 assert a.verify_record_bytes()==1 and s.status==3
 assert int.from_bytes(a.repo()[4:6],'little')==2
 assert int.from_bytes(s.bytes[INST+0x30290:INST+0x30292],'little')==1
 assert s.bytes[t.INFO:t.INFO+4]==bytes(4)
 hidden=dict(repo_hex=a.repo().hex(),trace=s.snapshot('hidden_backend_verified'))
 s.oem_enable(1)
 assert a.verify_record_bytes()==0x5a and s.status==0 and s.bytes[t.CONTROL]==0xe3
 assert int.from_bytes(a.repo()[4:6],'little')==3
 assert s.bytes[INST+0x30290:INST+0x30292]==bytes(2)
 assert s.bytes[t.INFO:t.INFO+4]==b'\x01\0\0\0'
 assert len(a.storage)==3 and [(w['offset'],w['length']) for w in a.storage]==[(16+index*64,1),(16+index*64,1),(8,4)]
 assert len(a.flushes)==1 and a.flushes[0]['length']==0x4b
 assert s.reservations==4
 assert a.repo()[:8]==a.initial_repo[:8] and a.repo()[16:]==a.initial_repo[16:]
 assert a.repo()[8:16]!=a.initial_repo[8:16]
 assert bool(s.bytes[INST+0x4e72c]&0x40)==storage_fail
 return dict(case='target_'+str(index)+'_of_three_actual_backend'+('_storage_failure' if storage_fail else ''),passed=True,hidden=hidden,
   final=s.snapshot('unhidden_backend_verified'),storage_hook_calls=a.storage,flush_calls=a.flushes,
   changed_repository_bytes=[i for i,(x,y) in enumerate(zip(a.initial_repo,a.repo())) if x!=y],
   records_unchanged_after_cycle=True,metadata_unchanged_after_cycle=False)

def missing_target():
 s=t.State();s.core=Backend(s);a=s.core;a.setup(1)
 a.u.mem_write(REPO+16+64+2+7,b'\x60')
 s.oem_enable(0)
 assert s.status==3 and s.bytes[t.INFO:t.INFO+4]==b'\x01\0\0\0'
 assert not a.storage and not a.flushes and s.reservations==0
 assert a.repo()[16+64]==0x5a and s.bytes[t.CONTROL]==0xa0
 return dict(case='OEM_success_when_backend_does_not_find_target_is_not_visibility_proof',passed=True,
  trace=s.trace,storage_hook_calls=a.storage,flush_calls=a.flushes)

def main():
 rows=[*[run(i) for i in range(3)],run(1,True),missing_target()]
 out=dict(passed=True,count=len(rows),cases=rows,hardware_test=False,
  exact_bodies=['OemMBFanControl','OemEnDisSensor','ASUS_API_GetSensorEnable','ASUS_API_SetSensorEnable','ASUS_SDR_HideSDR',*EXACT,'anonymous_repository_summary_at_0x5bb98'],
  limitations=['Storage callbacks, FlushIPMI, clock and RNG are recorded stubs; physical persistence is not tested.',
    'No scheduler or parallel SDR reader/writer emulated. Successful handler response does not certify backend persistence.',
    'Target record content and adjacent records preserved, but repository metadata and backing-storage writes occur.'])
 (P/'sdr-backend-verification.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps(dict(passed=True,count=len(rows))))
if __name__=='__main__':main()
