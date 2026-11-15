"""Actual captured P15 PE display/storage functions, explicit console/owner endpoints."""
from pathlib import Path
import hashlib,json,sys,re,struct,zlib,types
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent;D04=HERE.parent
ROOT=next(p for p in HERE.parents if (p/'tools/pydeps').is_dir());sys.path.insert(0,str(ROOT/'tools/pydeps'))
import pefile,unicorn as U
from unicorn import x86_const as R
REV=HERE/'provider_revisions'/sys.argv[1]
EFI=REV/'build/AiTweakerSplitProvider15.UNSIGNED.local.efi'
pe=pefile.PE(str(EFI));BASE=pe.OPTIONAL_HEADER.ImageBase
S={n:int(v,16)for n,v in re.findall(r'^\s+[0-9A-Fa-f]{4}:[0-9A-Fa-f]{8}\s+(\S+)\s+([0-9A-Fa-f]{16})\s',(REV/'build/provider.map').read_text(),re.M)}
DECODER=ROOT/'analysis/aitweaker_lock/lock_sage_1904/review/flash_readiness/remote_only/continuation12/decode_diagnostic09.py'
decoder=types.ModuleType('independent_c12_decoder');exec(compile(DECODER.read_text(),str(DECODER),'exec'),decoder.__dict__)
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
q=lambda v:struct.pack('<Q',v);d=lambda v:struct.pack('<I',v)
HEAP=0x60000000;STACK=0x70000000;STOP=0x50000000;OUT=STOP+0x100;REGION=HEAP+0x3000;VIEW=HEAP+0x4000

def record(serial=1,valid=0xa90ff):
 b=bytearray(256)
 for off,value in [(0,5),(4,11),(8,0xffffffff),(12,0x02000003),(32,0),(36,1),(40,0),(44,1),(56,0),(60,0x02000003),(84,4),(88,1),(100,0x6d6f0),(120,0xffffffff),(124,5),(212,3)]:struct.pack_into('<I',b,off,value)
 for off,value in [(16,valid),(24,5),(48,0x99998888),(64,0x800000000000000e),(112,0x99887766),(240,serial)]:struct.pack_into('<Q',b,off,value)
 struct.pack_into('<I',b,232,zlib.crc32(b)&0xffffffff);return bytes(b)
def region():
 b=bytearray(576);struct.pack_into('<QII',b,0,0x3930474149444753,1,576)
 struct.pack_into('<QQQQQ',b,16,2,2,1,0,0);struct.pack_into('<I',b,60,4)
 b[64:320]=record(0);b[320:576]=record(1);return b

class VM:
 def __init__(self):
  self.u=U.Uc(U.UC_ARCH_X86,U.UC_MODE_64);self.lines=[];self.calls=[];self.writes=[];self.end_after=None;self.request_records=[]
  image=pe.get_memory_mapped_image();self.u.mem_map(BASE,(pe.OPTIONAL_HEADER.SizeOfImage+4095)&~4095);self.u.mem_write(BASE,image)
  for b,n in [(HEAP,0x10000),(STACK,0x100000),(STOP,0x1000)]:self.u.mem_map(b,n)
  self.u.mem_write(S['system_table'],q(HEAP));self.u.mem_write(S['boot_services_ended'],d(0))
  self.u.mem_write(HEAP+0x40,q(HEAP+0x1000));self.u.mem_write(HEAP+0x1008,q(OUT));self.u.mem_write(REGION,bytes(region()))
  self.request=self.getq(S['native_provider']+40)
  for p in [STOP,OUT,S['split_diagnostic_region'],self.request]:self.u.hook_add(U.UC_HOOK_CODE,self.hook,begin=p,end=p)
  self.u.hook_add(U.UC_HOOK_MEM_WRITE,self.write_hook);self.u.reg_write(R.UC_X86_REG_CR4,0x600)
 def getq(self,p):return struct.unpack('<Q',self.u.mem_read(p,8))[0]
 def ret(self,v):
  sp=self.u.reg_read(R.UC_X86_REG_RSP);self.u.reg_write(R.UC_X86_REG_RIP,self.getq(sp));self.u.reg_write(R.UC_X86_REG_RSP,sp+8);self.u.reg_write(R.UC_X86_REG_RAX,v)
 def write_hook(self,u,access,address,size,value,data):
  assert STACK<=address and address+size<=STACK+0x100000 or REGION<=address and address+size<=REGION+576,('out-of-scope machine write',hex(address),size)
  self.writes.append([hex(address),size])
 def hook(self,u,a,n,data):
  if a==STOP:u.emu_stop();return
  if a==S['split_diagnostic_region']:self.calls.append('modeled owned-region accessor');self.ret(REGION);return
  if a==self.request:
   self.calls.append('modeled native_provider.Request');self.request_records.append(bytes(u.mem_read(REGION+320,256)).hex());self.ret(0x800000000000000f);return
  if a==OUT:
   assert u.reg_read(R.UC_X86_REG_RCX)==HEAP+0x1000
   p=u.reg_read(R.UC_X86_REG_RDX);text=[]
   for i in range(80):
    value=int.from_bytes(u.mem_read(p+i*2,2),'little')
    if not value:break
    assert value<128;text.append(chr(value))
   else:raise AssertionError('unterminated output')
   line=''.join(text);assert line.endswith('\r\n') and len(line.rstrip('\r\n'))<=72
   self.lines.append(line);self.calls.append('modeled ConsoleOut')
   if self.end_after==len(self.lines):u.mem_write(S['boot_services_ended'],d(1))
   self.ret(0)
 def call(self,name,*args):
  sp=STACK+0xffe08;self.u.mem_write(sp,q(STOP)+bytes(0x100));self.u.reg_write(R.UC_X86_REG_RSP,sp)
  for reg,v in zip([R.UC_X86_REG_RCX,R.UC_X86_REG_RDX,R.UC_X86_REG_R8,R.UC_X86_REG_R9],args):self.u.reg_write(reg,v)
  self.u.emu_start(S[name],0,count=10000000);assert self.u.reg_read(R.UC_X86_REG_RIP)==STOP,name
  return self.u.reg_read(R.UC_X86_REG_RAX)
 def output(self):return decoder.decode(''.join(self.lines))

checks=[];rows=[];OUTDIR=REV/'display_test';assert not (OUTDIR/'result.json').exists(),'Preserve prior exact-byte results.';OUTDIR.mkdir(exist_ok=True)
def check(name,value):assert value,name;checks.append(name)
def save(label,v):
 text=''.join(v.lines);(OUTDIR/(label+'.txt')).write_text(text,encoding='ascii',newline='')
 decoded=v.output()if len(v.lines)==6 else None
 rows.append({'case':label,'lines':len(v.lines),'decoded':decoded,'explicit_model_calls':v.calls,'machine_write_events':len(v.writes)})
 return decoded['fields_by_printed_label']if decoded else None

v=VM();v.call('diagnostic_unconfigured');f=save('kind4',v)
check('actual PE six lines match100B decoder',f['D09']=={'R':1,'P':1,'A':0} and f['S']['V']==3)
check('kind4 exact displayed owner failure',f['R']=={'H':5,'E':11,'D':0x02000003,'C':0xffffffff} and f['C']=={'K':4,'T':0xffffffff,'V':0x6d6f0,'H':5,'O':0xffffffff})
check('all output lines bounded ASCII72',all(len(s.rstrip('\r\n'))<=72 for s in v.lines))
v.call('diagnostic_acknowledged');v.lines=[];v.call('diagnostic_unconfigured');f=save('same_pending_second_prompt_after_ack',v)
check('actual prompt and ack counters update separately from request',f['D09']=={'R':1,'P':2,'A':1})

for label,mutate,expected_valid,expected_flags in [
 ('bad_header',lambda b:struct.pack_into('<Q',b,0,0),0,8),
 ('busy_writer',lambda b:struct.pack_into('<I',b,56,1),0,8),
 ('bad_request_crc',lambda b:b.__setitem__(320+128,b[320+128]^1),1,4),
 ('bad_first_crc',lambda b:b.__setitem__(64+128,b[64+128]^1),2,4),
 ('sticky_dropped',lambda b:struct.pack_into('<I',b,60,6),1,6),
 ('sticky_incomplete',lambda b:struct.pack_into('<I',b,60,12),1,12),
 ('no_pending',lambda b:struct.pack_into('<I',b,60,0),1,0),
 ('prompt_overflow',lambda b:struct.pack_into('<Q',b,40,0xffffffffffffffff),1,5),
]:
 v=VM();b=region();mutate(b);v.u.mem_write(REGION,bytes(b));v.call('diagnostic_unconfigured');f=save(label,v)
 check(label+' validity and flags',f['S']['V']==expected_valid and f['S']['F']==expected_flags)
 if not expected_valid&2:check(label+' current record unavailable',f['D09']['R']==0 and all(x==0xffffffff for x in f['R'].values())and all(x==0xffffffff for x in f['P'].values())and all(x==0xffffffff for x in f['C'].values()))

for n in range(1,7):
 v=VM();v.end_after=n;v.call('diagnostic_unconfigured');save('end_after_print'+str(n),v)
 check('ending after print'+str(n)+' prevents later output',len(v.lines)==n)
 prior=list(v.calls);v.call('diagnostic_acknowledged');check('ending after print'+str(n)+' prevents ack accessor',v.calls==prior)
v=VM();v.u.mem_write(S['boot_services_ended'],d(1));v.call('diagnostic_unconfigured');v.call('diagnostic_render_values',0);v.call('diagnostic_acknowledged')
check('pre-ended diagnostic functions make no modeled calls',not v.calls and not v.lines);save('pre_ended',v)

v=VM();b=region();struct.pack_into('<I',b,60,0);v.u.mem_write(REGION,bytes(b));status=v.call('diagnostic_verify_request')
check('actual direct verification preserves modeled denial',status==0x800000000000000f and len(v.request_records)==1)
raw=bytes.fromhex(v.request_records[0]);check('actual direct FFE2 has own unknown classification and serial',struct.unpack_from('<III',raw,0)==(9,32,0xffffffff) and struct.unpack_from('<Q',raw,240)[0]==2 and struct.unpack_from('<Q',raw,16)[0]==1<<14)
check('actual direct completion clears matching pending',struct.unpack('<I',v.u.mem_read(REGION+60,4))[0]&4==0)
(OUTDIR/'direct_verify_record.json').write_text(json.dumps({'record':raw.hex(),'calls':v.calls},indent=2)+'\n')

report={'status':'PASS_ACTUAL_P15_DIAGNOSTIC_PE_FUNCTIONS_WITH_EXPLICIT_MODELS','checks':len(checks),'check_names':checks,'rows':rows,
 'efi_sha256':sha(EFI),'map_sha256':sha(REV/'build/provider.map'),'decoder_sha256':sha(DECODER),'script_sha256':sha(Path(__file__)),
 'scope':['Exact P15 diagnostic_render_values, diagnostic_unconfigured, diagnostic_acknowledged, diagnostic_verify_request, CRC/storage code and secure-zero execute under Unicorn.','ConsoleOut, owned-region accessor and provider.Request are explicit models. No LoadImage/StartImage/full provider owner validation or actual UEFI is represented by this test.','The decoder checks only100 displayed scalar bytes. Full record integrity is exercised separately through the actual d09_prompt validation using supplied256B record fixtures.','Each emitted line is checked; end flags after each print stop subsequent output and ack service/model calls. Modeled flag injection is not a hardware ExitBootServices event.','Observed machine writes are restricted to the modeled stack and576B diagnostic region. No original modules, variables, passwords, disk, BMC or physical firmware were accessed.']}
(OUTDIR/'result.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({'status':report['status'],'checks':len(checks),'result_sha256':sha(OUTDIR/'result.json')}))
