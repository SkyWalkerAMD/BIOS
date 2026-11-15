"""Original EFI functions, with synthetic transport/boot-services only.

No USB/SMI/I/O operation executes; calls outside the bounded original routines
must hit an explicit in-memory stub, otherwise emulation aborts.
"""
from pathlib import Path
import hashlib,json,struct,sys
from inspect_uhcd import HERE,ROOT
sys.path.insert(0,str(ROOT/'tools/pydeps'))
import pefile
import unicorn as U
from unicorn import x86_const as R

BASE=0x100000;H=0x70000000;STACK=0x71000000;STOP=0x60000000
DEV=H+0x5000;G1=H;G2=H+0x2000;RESP=H+0x8000;CDB=H+0x9000
BS=H+0xa000;URP=H+0xb000;ST=H+0xc000;CONTROLLER=H+0xd000
OBJ=H+0xe000;MEDIA=H+0xf000;STUB=H+0x18000
P=lambda x:struct.pack('<I',x&0xffffffff)
Q=lambda x:struct.pack('<Q',x&0xffffffffffffffff)
FILES={'rt':'171F43DC-C4D9-47A6-9641-65DDCDD5AA30.efi','smm':'04EAAAA1-29A1-11D7-8838-00500473D4EB.efi','uhcd':'580DD900-385D-11D7-883A-00500473D4EB.efi'}
ROUTINES={'rt':{'alloc':0x2f1c,'free':0x30f0,'transport':0x9640,'g1':0x1b2c0,'g2':0x1ab98,'start':0x9bd0,'end':0x9d58},
          'smm':{'alloc':0x4150,'free':0x4324,'transport':0xabf0,'g1':0x29600,'g2':0x1e800,'start':0xb1b4,'end':0xb33c}}

class VM:
    def __init__(self,which):
        raw=(HERE/FILES[which]).read_bytes();pe=pefile.PE(data=raw)
        self.source_sha256=hashlib.sha256(raw).hexdigest()
        self.u=U.Uc(U.UC_ARCH_X86,U.UC_MODE_64)
        self.u.mem_map(BASE,(pe.OPTIONAL_HEADER.SizeOfImage+4095)&~4095)
        self.u.mem_map(H,0x20000);self.u.mem_map(STACK,0x20000);self.u.mem_map(STOP,4096)
        mapped=bytearray(pe.get_memory_mapped_image())
        for block in pe.DIRECTORY_ENTRY_BASERELOC:
            for item in block.entries:
                if item.type==10:struct.pack_into('<Q',mapped,item.rva,struct.unpack_from('<Q',mapped,item.rva)[0]+BASE)
                else:assert item.type==0
        self.u.mem_write(BASE,bytes(mapped));self.calls=[];self.which=which;self.ranges=[];self.install=None
        self.u.hook_add(U.UC_HOOK_CODE,self.hook)
    def q(self,p):return struct.unpack('<Q',self.u.mem_read(p,8))[0]
    def p(self,p):return struct.unpack('<I',self.u.mem_read(p,4))[0]
    def ret(self,value=0):
        sp=self.u.reg_read(R.UC_X86_REG_RSP);address=self.q(sp)
        self.u.reg_write(R.UC_X86_REG_RAX,value);self.u.reg_write(R.UC_X86_REG_RSP,sp+8);self.u.reg_write(R.UC_X86_REG_RIP,address)
    def hook(self,u,address,size,data):
        if address==STOP:u.emu_stop();return
        if any(BASE+a<=address<BASE+b for a,b in self.ranges):return
        args=[u.reg_read(r) for r in [R.UC_X86_REG_RCX,R.UC_X86_REG_RDX,R.UC_X86_REG_R8,R.UC_X86_REG_R9]]
        if self.which in ROUTINES:
            row=ROUTINES[self.which]
            if address==BASE+row['alloc']:
                assert args[0]==1;self.calls.append({'stub':'allocate_CDB_synthetic'});self.ret(CDB);return
            if address==BASE+row['free']:
                assert args[:2]==[CDB,1];self.calls.append({'stub':'free_CDB_synthetic'});self.ret();return
            if address==BASE+row['transport']:
                assert args[0]==DEV and self.q(args[1])==CDB
                cmd=bytes(u.mem_read(CDB,12));assert cmd[0]==0x25
                self.calls.append({'stub':'USB_transport_synthetic','CDB_hex':cmd.hex(),'synthetic_response':self.response.hex(),'return':self.transfer_result})
                if self.transfer_result:u.mem_write(RESP,self.response)
                self.ret(self.transfer_result);return
        else:
            if address==STUB:
                assert args[0]==4 and args[1] in (0xa0,0x30)
                target=OBJ if args[1]==0xa0 else MEDIA
                u.mem_write(args[2],Q(target));self.calls.append({'stub':'AllocatePool_synthetic','bytes':args[1]});self.ret();return
            if address==STUB+0x10:
                assert args[0]==URP and args[1]==0x1f
                u.mem_write(URP,bytes(0x1f));self.calls.append({'stub':'SetMem_synthetic','bytes':31});self.ret();return
            if address==STUB+0x20:
                self.install=args[2];assert args[2]==OBJ+8
                self.calls.append({'stub':'InstallMultipleProtocolInterfaces_synthetic','interface':args[2]});self.ret();return
            if address==BASE+0x3d5c:
                self.calls.append({'stub':'SMI_or_runtime_dispatch_NOT_EXECUTED'});self.ret();return
            if address==BASE+0xd074:
                self.calls.append({'stub':'format_only_synthetic'});self.ret();return
        raise AssertionError('Unapproved call at '+hex(address))
    def call(self,rva,args,end):
        self.ranges=[(rva,end)];sp=STACK+0x18008;self.u.mem_write(sp,Q(STOP));self.u.reg_write(R.UC_X86_REG_RSP,sp)
        for reg,val in zip([R.UC_X86_REG_RCX,R.UC_X86_REG_RDX,R.UC_X86_REG_R8,R.UC_X86_REG_R9],args):self.u.reg_write(reg,val)
        try:self.u.emu_start(BASE+rva,STOP+1,count=20000)
        except U.UcError:
            print(json.dumps({'emulation_error_RIP':hex(self.u.reg_read(R.UC_X86_REG_RIP)),'calls':self.calls}));raise
        assert self.u.reg_read(R.UC_X86_REG_RIP)==STOP
        return self.u.reg_read(R.UC_X86_REG_RAX)

def parse_capacity(name,response,last_count=0,block_size=0,transfer_result=8,flags=3,which='rt'):
    v=VM(which);v.response=response;v.transfer_result=transfer_result;row=ROUTINES[which]
    v.u.mem_write(BASE+row['g1'],Q(G1));v.u.mem_write(BASE+row['g2'],Q(G2));v.u.mem_write(G2+0x62,Q(RESP))
    v.u.mem_write(DEV,bytes([flags]));v.u.mem_write(DEV+0x58,b'\x06');v.u.mem_write(DEV+0x5e,struct.pack('<H',block_size));v.u.mem_write(DEV+0x60,Q(last_count))
    rc=v.call(row['start'],[DEV],row['end'])
    return {'name':name,'module':which,'EFI_sha256':v.source_sha256,'initial_block_size':block_size,'initial_total_blocks':last_count,
            'return_low8':rc&255,'final_block_size':struct.unpack('<H',v.u.mem_read(DEV+0x5e,2))[0],
            'final_total_blocks':v.q(DEV+0x60),'calls':v.calls}

def publish(name,block_size,blocks,flags=9):
    v=VM('uhcd')
    for rva,p in [(0x10438,G1),(0x10458,G2),(0x10460,URP),(0x104c0,BS),(0x104b8,ST),(0x10568,H+0x11000)]:v.u.mem_write(BASE+rva,Q(p))
    v.u.mem_write(H+0x11000,Q(CONTROLLER))
    v.u.mem_write(G1+0x716,b'\x02');v.u.mem_write(G2+0x42,Q(DEV-0x1c0))
    v.u.mem_write(DEV+0xb,b'\x01');v.u.mem_write(DEV+0x4c,b'\x01');v.u.mem_write(DEV+0xa0,bytes([flags]))
    v.u.mem_write(DEV+0x5e,struct.pack('<H',block_size));v.u.mem_write(DEV+0x60,Q(blocks));v.u.mem_write(ST+8,P(0x2001f))
    for off,ptr in [(0x40,STUB),(0x168,STUB+0x10),(0x148,STUB+0x20)]:v.u.mem_write(BS+off,Q(ptr))
    rc=v.call(0x995c,[0x1234,DEV],0x9ce8);assert rc==0 and v.install==OBJ+8
    return {'name':name,'EFI_sha256':v.source_sha256,'input_block_size':block_size,'input_total_blocks':blocks,
            'input_flags':flags,'media_present':bytes(v.u.mem_read(MEDIA+5,1))[0],
            'block_size':v.p(MEDIA+12),'last_block':v.q(MEDIA+24),'blockio_revision':v.q(OBJ+8),'calls':v.calls}

def main():
    expected=bytes.fromhex('00007fff00000200');observed=bytes.fromhex('0004000000000400')
    cases=[]
    for which in ['rt','smm']:
        group=[parse_capacity('normal_RC10',expected,which=which),parse_capacity('observed_geometry_as_input_RC10',observed,which=which),
               parse_capacity('transport_fail_initial_zero',expected,transfer_result=0,which=which),
               parse_capacity('transport_fail_preserves_prior_observed_geometry',expected,262145,1024,0,which=which),
               parse_capacity('zero_blocksize_response_preserves_prior_geometry',bytes(8),262145,1024,which=which),
               parse_capacity('device_flags_inactive_preserves_prior_geometry',expected,262145,1024,flags=0,which=which)]
        assert group[0]['final_block_size']==512 and group[0]['final_total_blocks']==32768 and group[0]['return_low8']==0
        assert group[1]['final_block_size']==1024 and group[1]['final_total_blocks']==262145
        assert all(group[i]['return_low8']==255 for i in [2,3,4,5])
        assert group[2]['final_total_blocks']==0
        assert all(group[i]['final_total_blocks']==262145 and group[i]['final_block_size']==1024 for i in [3,4,5])
        cases.extend(group)
    pcases=[publish('normal_DEV_INFO',512,32768),publish('observed_DEV_INFO',1024,262145),
            publish('media_flag_absent',1024,262145,8),publish('zero_count',1024,0),publish('zero_blocksize',0,262145)]
    assert pcases[0]['block_size']==512 and pcases[0]['last_block']==32767 and pcases[0]['media_present']==1
    assert pcases[1]['block_size']==1024 and pcases[1]['last_block']==262144 and pcases[1]['media_present']==1
    assert all(x['media_present']==0 and x['last_block']==0 for x in pcases[2:])
    out={'status':'PASS','scope':'17 original x64 function executions with synthetic USB/SMI/BootServices boundaries; no firmware/hardware operation.',
         'parser_cases':cases,'publication_cases':pcases,'case_count':len(cases)+len(pcases),
         'limitation':'Preserved geometry is a local conditional behavior. These tests do not establish that complete firmware initialization leaves stale fields or ignores parser failure on real hardware.'}
    (HERE/'oem_geometry_replay.json').write_text(json.dumps(out,indent=2),encoding='utf8');print(json.dumps({'status':out['status'],'cases':out['case_count'],'parser':[{k:v for k,v in c.items() if k!='calls'} for c in cases],'publisher':[{k:v for k,v in c.items() if k!='calls'} for c in pcases]},indent=2))
if __name__=='__main__':main()
