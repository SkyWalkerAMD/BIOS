"""Emulate the extracted ARM OEM handler, with all external calls mocked.

This does not execute BMC firmware on the host, connect to a BMC, or model the
EC/I2C hardware. It checks which branches/memory the exact handler touches.
"""
from pathlib import Path
import hashlib,json,struct,sys
from bmc_arm_inspect import Elf32,Cs,CS_ARCH_ARM,CS_MODE_ARM
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools/pydeps'))
from unicorn import Uc,UC_ARCH_ARM,UC_MODE_ARM,UC_HOOK_CODE
from unicorn.arm_const import UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2,UC_ARM_REG_R3,UC_ARM_REG_SP,UC_ARM_REG_LR,UC_ARM_REG_PC

ROOT=Path(__file__).resolve().parent.parent
LIB=ROOT/'analysis/bmc_1_3_13_official/selected-rootfs/usr/local/lib/libipmipdkcmds.so.13.0.0'
ELF=Elf32(LIB)
assert hashlib.sha256(LIB.read_bytes()).hexdigest()=='cc104323a4813a4b00bb19d2c016c486a5f3634c584d27652372c773d8b78e44'

class Handler:
    def __init__(self):
        self.u=Uc(UC_ARCH_ARM,UC_MODE_ARM);self.u.mem_map(0,0x900000)
        for s in ELF.sections:
            if s['flags']&2 and s['size'] and s['type']!=8:
                self.u.mem_write(s['addr'],ELF.data[s['off']:s['off']+s['size']])
        self.globals={}; self.calls=[];self.plt={}
        for a,r in ELF.relocs.items():
            if r['type']==2:
                sym=r['symbol']
                if r['value']:value=r['value']
                else:
                    if sym not in self.globals:self.globals[sym]=0x500000+len(self.globals)*0x1000
                    value=self.globals[sym]
                addend=struct.unpack('<I',ELF.read(a,4))[0]
                self.u.mem_write(a,struct.pack('<I',(value+addend)&0xffffffff))
        cs=Cs(CS_ARCH_ARM,CS_MODE_ARM)
        for sec in ELF.sections:
            if sec['name']!='.plt':continue
            for i in cs.disasm(ELF.read(sec['addr'],sec['size']),sec['addr']):
                if i.mnemonic=='add' and i.op_str.startswith('ip, pc, #'):
                    stub=list(cs.disasm(ELF.read(i.address,12),i.address))
                    add0=int(stub[0].op_str.split('#')[1].rstrip(', '),0)
                    assert add0==0
                    got=i.address+8+int(stub[1].op_str.split('#')[1],0)+int(stub[2].op_str.split('#')[1].rstrip(']!'),0)
                    self.plt[i.address]=ELF.relocs[got]['symbol']
        self.u.hook_add(UC_HOOK_CODE,self.hook)
        self.put('g_MBFanMode',b'\0')
        self.put('g_MBFanRPM',bytes([0x60,0x61,0,0x63,0x64,0x65,0,0,0,0,0,0x67,0,0,0]))
        self.put('g_MBFanPWM',bytes(range(15)))
        self.put('g_FCType',bytes(range(23)))
        self.put('g_FCexist',b'\x12\x34\x56')
    def put(self,n,d):self.u.mem_write(self.globals[n],d)
    def get(self,n,z):return bytes(self.u.mem_read(self.globals[n],z))
    def snapshot(self):return {n:self.get(n,1024) for n in self.globals}
    def hook(self,uc,a,size,user):
        name=self.plt.get(a)
        if name is None:return
        args=[uc.reg_read(r) for r in (UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2,UC_ARM_REG_R3)]
        self.calls.append((name,args))
        result=0
        if name=='memset':uc.mem_write(args[0],bytes([args[1]&255])*args[2]); result=args[0]
        elif name in ('printf','puts'):pass
        elif name=='ASUS_API_GetSensorEnable':assert args[0]==0x20
        elif name=='ASUS_SDR_HideSDR':assert args[:3]==[0x20,0,1]
        elif name=='ASUS_API_SetSensorEnable':assert args[:2]==[0x20,1]
        else:raise AssertionError(('Unexpected external call',name,args))
        uc.reg_write(UC_ARM_REG_R0,result);uc.reg_write(UC_ARM_REG_PC,uc.reg_read(UC_ARM_REG_LR))
    def run(self,payload,func='OemMBFanControl'):
        self.calls=[]
        self.u.mem_write(0x680000,payload or b'\0');self.u.mem_write(0x681000,b'\xa5'*64)
        for r,v in [(UC_ARM_REG_R0,0x680000),(UC_ARM_REG_R1,len(payload)),(UC_ARM_REG_R2,0x681000),
                    (UC_ARM_REG_R3,1),(UC_ARM_REG_SP,0x800000),(UC_ARM_REG_LR,0x880000)]:self.u.reg_write(r,v)
        self.u.emu_start(ELF.byname[func]['value'],0x880000,count=10000)
        assert self.u.reg_read(UC_ARM_REG_PC)==0x880000
        assert self.u.reg_read(UC_ARM_REG_SP)==0x800000
        n=self.u.reg_read(UC_ARM_REG_R0); assert n<=16
        assert self.u.mem_read(0x681010,48)==b'\xa5'*48
        return bytes(self.u.mem_read(0x681000,n))

def main():
    results=[]
    for sub in range(4):
        h=Handler();before=h.snapshot();resp=h.run(bytes([sub,0]));assert h.snapshot()==before
        expected=[b'\0\0',b'\0'+h.get('g_MBFanRPM',15),b'\0'+h.get('g_MBFanPWM',15),b'\0'+h.get('g_FCType',23)[8:]][sub]
        assert resp==expected
        results.append(dict(case=f'get_{sub}_read_only',passed=True,response=resp.hex()))
    h=Handler();before=h.snapshot();new=bytearray(h.get('g_MBFanRPM',15));new[2]=0x62
    resp=h.run(b'\x01\x01'+new); assert resp==b'\0'+new
    after=h.snapshot()
    for n in before:
        if n=='g_MBFanRPM':assert after[n]==before[n][:2]+b'\x62'+before[n][3:]
        else:assert after[n]==before[n]
    assert [n for n,_ in h.calls]==['memset','printf']
    results.append(dict(case='set_rpm_changes_only_requested_array_byte',passed=True,external_calls=[n for n,_ in h.calls]))
    for payload in (b'',b'\x01',b'\x01\x01',b'\x01\x01'+bytes(16),b'\xff\0'):
        h=Handler();before=h.snapshot();resp=h.run(payload);assert resp[0]==0xc7 and h.snapshot()==before
        results.append(dict(case='reject_'+payload.hex(),passed=True))
    h=Handler();before=h.snapshot();resp=h.run(b'\x20\x01','OemEnDisSensor');assert resp==b'\0'
    assert [n for n,_ in h.calls]==['ASUS_API_GetSensorEnable','ASUS_SDR_HideSDR','ASUS_API_SetSensorEnable']
    assert h.snapshot()==before # g_SensorStatus[0x20] is reset to the already-zero mock value.
    results.append(dict(case='enable_only_sensor_20',passed=True,external_calls=h.calls))
    out=ROOT/'analysis/bmc_1_3_13_official/fan-handler-verification.json'
    out.write_text(json.dumps(dict(status='OFFLINE_ARM_FUNCTION_EMULATION_ONLY',library_sha256=hashlib.sha256(LIB.read_bytes()).hexdigest(),
        hardware_not_modelled=['EC/I2C','BMC task concurrency','actual RPM mapping','complete sensor-scan backend'],scenarios=results),indent=2),encoding='utf-8')
    print('ARM OEM handler:',len(results),'cases passed')
if __name__=='__main__':main()
