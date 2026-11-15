"""Original advisory0x18 ARM handler, memory fixtures only; timer is a stub."""
from pathlib import Path
import hashlib,json,struct,sys
HERE=Path(__file__).resolve().parent
ROOT=next(p for p in HERE.parents if (p/'tools/pydeps').is_dir());sys.path.insert(0,str(ROOT/'tools/pydeps'))
import unicorn as U
from unicorn import arm_const as R
import capstone
EXPECTED='b28de2e50628434371c14a77695384fa901bb02c165fd3e95b27abfba98c6e28'
def main():
    raw=(HERE/'backend/usr/local/bin/adviserd').read_bytes();assert hashlib.sha256(raw).hexdigest()==EXPECTED
    phoff=struct.unpack_from('<I',raw,28)[0];sz,num=struct.unpack_from('<HH',raw,42)
    segments=[struct.unpack_from('<8I',raw,phoff+i*sz) for i in range(num)]
    def off(va):
        for typ,o,a,pa,fs,ms,flags,al in segments:
            if typ==1 and a<=va<a+fs:return o+va-a
        raise ValueError(hex(va))
    table=struct.unpack_from('<I',raw,off(0x1a358))[0];entries=[]
    for i in range(32):
        op,pad,addr=struct.unpack_from('<HHI',raw,off(table)+i*8)
        entries.append({'slot':i,'opcode':hex(op),'function':hex(addr)})
        if op==0xffff:break
    assert next(x for x in entries if x['opcode']=='0x18')['function']=='0x19754'
    (HERE/'adviser_command_table.json').write_text(json.dumps({'table_va':hex(table),'entries':entries},indent=2),encoding='utf8')
    code=raw[off(0x19754):off(0x19790)]
    dis=capstone.Cs(capstone.CS_ARCH_ARM,capstone.CS_MODE_ARM|capstone.CS_MODE_LITTLE_ENDIAN)
    instructions=[{'va':hex(i.address),'bytes':i.bytes.hex(),'mnemonic':i.mnemonic,'operands':i.op_str} for i in dis.disasm(code,0x19754)]
    results=[];HEAP=0x70000000;STACK=0x71000000;STOP=0x60000000
    for status in [0,1,2,65535]:
        u=U.Uc(U.UC_ARCH_ARM,U.UC_MODE_ARM|U.UC_MODE_LITTLE_ENDIAN)
        u.mem_map(0x10000,0x30000);u.mem_write(0x19754,code);u.mem_map(HEAP,0x2000);u.mem_map(STACK,0x2000);u.mem_map(STOP,0x1000)
        u.mem_write(HEAP+20,struct.pack('<I',0x55));u.mem_write(HEAP+0x10c,struct.pack('<I',0xa5a5a5a5))
        frame=struct.pack('<HIH',24,0,status);u.mem_write(HEAP+0x1000,frame)
        calls=[];writes=[]
        def hook(uc,addr,size,unused):
            if addr==STOP:uc.emu_stop();return
            if addr==0x21050:
                calls.append({'call':'sm_reset_kvm_timer','session_id':uc.reg_read(R.UC_ARM_REG_R0)})
                uc.reg_write(R.UC_ARM_REG_PC,uc.reg_read(R.UC_ARM_REG_LR));return
            if not 0x19754<=addr<0x19790:raise AssertionError('Unexpected branch '+hex(addr))
        def on_write(uc,access,address,size,value,unused):
            if not STACK<=address<STACK+0x2000:
                assert address==HEAP+0x10c and size==4;writes.append({'session_offset':hex(address-HEAP),'bytes':size,'value':value})
        u.hook_add(U.UC_HOOK_CODE,hook);u.hook_add(U.UC_HOOK_MEM_WRITE,on_write)
        u.reg_write(R.UC_ARM_REG_R0,HEAP);u.reg_write(R.UC_ARM_REG_R1,HEAP+0x1000);u.reg_write(R.UC_ARM_REG_SP,STACK+0x1000);u.reg_write(R.UC_ARM_REG_LR,STOP)
        u.emu_start(0x19754,STOP+4,count=1000);assert u.reg_read(R.UC_ARM_REG_PC)==STOP
        expected=1 if status==1 else 0;assert writes==[{'session_offset':'0x10c','bytes':4,'value':expected}]
        assert calls==([{'call':'sm_reset_kvm_timer','session_id':0x55}] if status==1 else [])
        results.append({'input_status':status,'frame_hex':frame.hex(),'nonstack_writes':writes,'calls':calls,'return':u.reg_read(R.UC_ARM_REG_R0)})
    result={'status':'PASS','source_sha256':EXPECTED,'handler_va':'0x19754','handler_bytes_sha256':hashlib.sha256(code).hexdigest(),
            'scope':'Offline original ARM handler only; timer callback stub; no devices or networks',
            'instruction_evidence':instructions,'cases':results,'conclusion':'Only stores the session media-running flag and resets KVM inactivity timer on status1. No USB/NBD/media insertion function call in this handler.'}
    (HERE/'kvm_state_replay.json').write_text(json.dumps(result,indent=2),encoding='utf8');print(json.dumps({'status':'PASS','cases':len(results)}))
if __name__=='__main__':main()
