"""Execute native Ip4 Start -> CreateService -> Config2Init -> SetData code.

Only firmware services and lower-layer network helpers are simulated. The
private read/save stubs, default initialization, caller error branches, policy
replay and Start success/failure exits execute from the actual pinned PE.
No machine or BMC is contacted.
"""
from pathlib import Path
import hashlib, json, struct, sys
BASE=Path(__file__).resolve().parents[1]; ROOT=BASE.parents[2]
sys.path.insert(0,str(ROOT/'tools/pydeps'))
import pefile, unicorn
from unicorn.x86_const import *
ERR=lambda n:0x8000000000000000|n
def run(data, case='success'):
 p=pefile.PE(data=data);u=unicorn.Uc(unicorn.UC_ARCH_X86,unicorn.UC_MODE_64)
 u.mem_map(0,0x20000);u.mem_write(0,p.get_memory_mapped_image())
 u.mem_map(0x300000,0x100000);u.mem_map(0x500000,0x20000);u.mem_map(0x700000,0x10000)
 bs=0x700000;rt=0x701000;controller=0x702000;binding=0xbda0
 service=0x300000;cfg=service+0x548;mnp=0x302000;route=0x303000;ipif=0x304000
 mac=0x305000;enable=0x306000;events=0;stop=0x70f000;stubs={};calls=[];timers=0
 def w64(a,x):u.mem_write(a,struct.pack('<Q',x))
 def r64(a):return struct.unpack('<Q',u.mem_read(a,8))[0]
 def r32(a):return struct.unpack('<I',u.mem_read(a,4))[0]
 def stub_at(at,name):stubs[at]=name
 def svc(table,offset,name):at=0x708000+len(stubs)*0x10;w64(table+offset,at);stub_at(at,name)
 w64(0xc4a0,bs);w64(0xc4a8,rt);w64(binding+0x28,0x703000)
 w64(0xbe70,0xbe70);w64(0xbe78,0xbe70)
 u.mem_write(mac,'001122334455\0'.encode('utf-16le'));u.mem_write(enable,bytes([0 if case=='enable_zero' else 1]))
 for off,name in ((0x18,'RaiseTPL'),(0x20,'RestoreTPL'),(0x48,'FreePool'),(0x50,'CreateEvent'),(0x58,'SetTimer'),(0x68,'SignalEvent'),(0x118,'OpenProtocol'),(0x148,'Install'),(0x150,'Uninstall')):svc(bs,off,name)
 svc(rt,0x48,'ForbiddenGetVariable');svc(rt,0x58,'ForbiddenSetVariable')
 svc(mnp,0,'MnpMode');svc(mnp,8,'MnpConfigure')
 for at,name in ((0x91c0,'AllocateZeroService'),(0x7c40,'CreateRoute'),(0xa904,'MnpCreateChild'),(0x78b8,'JoinGroup'),(0xaa64,'MacString'),(0x4cbc,'CreateInterface'),(0xa630,'ReadEnableVariable'),(0xa1ac,'GetDevicePath'),(0x5984,'StartReceive'),(0x3c2,'Random'),(0xc3c,'Cleanup')):stub_at(at,name)
 observed=[];before_replay=None
 def hook(_,at,size,ctx):
  nonlocal events,timers,before_replay
  if at in (0x890,0x7558,0x5bbc,0x5d88,0x7144,0x6980):observed.append(hex(at))
  if at==0xec5:
   # Completed native initialization must precede the only changed call.
   assert r32(service)==0x53345049 and r32(cfg)==0x32435049
   assert r64(cfg+0x20)==0x7144 and r64(cfg+0x168)==cfg+0xc0
   assert r64(cfg+0x170)==4 and r32(cfg+0xc0)==0
   for n in (2,3,4):
    assert r64(cfg+0x110+n*0x58)==0 and r64(cfg+0x118+n*0x58)==0
   before_replay=bytes(u.mem_read(cfg,0x338))
  if at==stop:u.emu_stop();return
  if at not in stubs:return
  name=stubs[at];calls.append(name);sp=u.reg_read(UC_X86_REG_RSP)
  a,b,c,d=[u.reg_read(r) for r in (UC_X86_REG_RCX,UC_X86_REG_RDX,UC_X86_REG_R8,UC_X86_REG_R9)];result=0
  if name.startswith('Forbidden'):raise AssertionError(name)
  if name=='AllocateZeroService':
   assert a==0x890
   if case=='allocation_failure':result=0
   else:u.mem_write(service,b'\0'*0x890);result=service
  elif name=='CreateRoute':result=route
  elif name=='CreateEvent':events+=1;w64(r64(sp+0x28),0x704000+events*0x10);result=ERR(9) if case=='event_failure' and events==2 else 0
  elif name=='MnpCreateChild':w64(d,0x705000)
  elif name=='OpenProtocol':
   if c==0:result=0 if case=='already_started' else ERR(14)
   else:w64(c,mnp)
  elif name=='MnpMode':
   assert c==service+0x294
   u.mem_write(c,b'\0'*0x290);u.mem_write(service+0x298,struct.pack('<I',6));u.mem_write(service+0x2a0,struct.pack('<I',1500));u.mem_write(service+0x4bc,bytes.fromhex('001122334455'));u.mem_write(service+0x51c,b'\x01')
  elif name=='MnpConfigure':result=ERR(7) if case=='mnp_failure' else 0
  elif name=='MacString':w64(c,mac)
  elif name=='CreateInterface':u.mem_write(ipif,b'\0'*0x100);result=ipif
  elif name=='ReadEnableVariable':
   assert a==mac
   if case=='enable_not_found':result=ERR(14)
   else:w64(c,enable)
  elif name=='GetDevicePath':result=0
  elif name=='Install':
   assert r64(a)==controller and c==service+8 and r64(sp+0x28)==cfg+0x20
   result=ERR(9) if case=='install_failure' else 0
  elif name=='StartReceive':
   assert a==ipif and d==service
   result=ERR(7) if case=='receive_failure' else 0
  elif name=='SetTimer':
   timers+=1;assert b==1 and c in (10000000,5000000)
   result=ERR(7) if case=='timer_failure' and timers==2 else 0
  elif name=='Random':u.mem_write(a,struct.pack('<I',123456));result=1
  elif name=='RaiseTPL':assert a==8;result=4
  elif name in ('RestoreTPL','SignalEvent','FreePool','JoinGroup','Uninstall','Cleanup'):pass
  else:raise AssertionError(name)
  u.reg_write(UC_X86_REG_RAX,result);u.reg_write(UC_X86_REG_RIP,r64(sp));u.reg_write(UC_X86_REG_RSP,sp+8)
 u.hook_add(unicorn.UC_HOOK_CODE,hook)
 stack=0x51f008;w64(stack,stop);u.reg_write(UC_X86_REG_RSP,stack);u.reg_write(UC_X86_REG_RCX,binding);u.reg_write(UC_X86_REG_RDX,controller);u.reg_write(UC_X86_REG_R8,0)
 try:u.emu_start(0xdf8,stop+1,count=200000)
 except Exception as exc:raise AssertionError((case,hex(u.reg_read(UC_X86_REG_RIP)),calls,observed)) from exc
 assert u.reg_read(UC_X86_REG_RIP)==stop
 result=u.reg_read(UC_X86_REG_RAX)
 return {'case':case,'status':f'{result:016X}','observed_native_functions':observed,'services_and_helpers':calls,'completed_defaults_verified':before_replay is not None,'timers_started':timers}

def main():
 current=(BASE/'staged-drivers/I5IP4DXE.EFI').read_bytes()
 prior=(BASE.parent/'capture_fix/staged-drivers/I5IP4DXE.EFI').read_bytes()
 rows=[]
 old=run(prior);assert old['status']==f'{ERR(14):016X}' and old['completed_defaults_verified'] and 'StartReceive' not in old['services_and_helpers'];old['copy']='frozen_I5C';rows.append(old)
 for case,expected in [('success',0),('enable_zero',0),('enable_not_found',0),('allocation_failure',ERR(9)),('event_failure',ERR(9)),('already_started',ERR(20)),('mnp_failure',ERR(7)),('install_failure',ERR(9)),('receive_failure',ERR(7)),('timer_failure',ERR(7))]:
  row=run(current,case);assert row['status']==f'{expected:016X}',row
  if expected==0:
   assert row['completed_defaults_verified'] and row['timers_started']==2 and '0x7144' in row['observed_native_functions'] and '0x6980' in row['observed_native_functions']
   assert row['observed_native_functions'].count('0x5bbc')==(1 if case=='success' else 0)
  row['copy']='I5D';rows.append(row)
 report={'passed':True,'cases':len(rows),'driver_sha256':hashlib.sha256(current).hexdigest(),'native_code_executed':['DriverBinding.Start','Ip4CreateService','Ip4Config2Init','Ip4Config2.SetData','Policy setter','first saved configuration read stub','save no-op stub'],'no_GetVariable_or_SetVariable_from_config_read_save':True,'limits':['Boot services and lower-layer network helpers are simulated. Does not prove physical BMC network connectivity.'],'results':rows}
 (BASE/'tests/ip4-start-native.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({k:v for k,v in report.items() if k!='results'}))
if __name__=='__main__':main()
