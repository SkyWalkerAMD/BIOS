"""Execute the compiled HII callback under Unicorn, never on the host CPU.

UEFI EFI_BROWSER_ACTION_REQUEST is UINTN (8 bytes on x64). The caller supplies
nonzero high bits plus adjacent canaries. Modal UI and original callbacks are
explicit stubs; this test does not claim firmware UI execution.
"""
from pathlib import Path
import argparse, hashlib, json, re, struct, sys

HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE.parents[3]/'tools/pydeps'))
import pefile, unicorn as U
from unicorn import x86_const as R

BASE=0x140000000;HEAP=0x60000000;STACK=0x70000000;STOP=0x50000000
P=HEAP+0x1000;CANARY=0xB19A3147C652D80E;SENTINEL=0xA5A5A5A55A5A5A5A
q=lambda v:struct.pack('<Q',v)

def execute(driver,mapfile,action,qid,accepted=True,nullable=False,chain=False):
    symbols={n:int(v,16) for n,v in re.findall(r'^\s+[0-9A-Fa-f]{4}:[0-9A-Fa-f]{8}\s+(\S+)\s+([0-9A-Fa-f]{16})\s',mapfile.read_text(),re.M)}
    u=U.Uc(U.UC_ARCH_X86,U.UC_MODE_64)
    pe=pefile.PE(str(driver));pe.relocate_image(BASE);image=pe.get_memory_mapped_image()
    u.mem_map(BASE,(len(image)+4095)&~4095);u.mem_write(BASE,image)
    for base in [HEAP,STACK,STOP]:u.mem_map(base,0x10000)
    u.mem_write(P-8,q(CANARY)+q(SENTINEL)+q(CANARY))
    u.mem_write(symbols['original_callback'],q(STOP+0x100))
    u.mem_write(symbols['loop_depth'],struct.pack('<I',1))
    u.mem_write(symbols['password_core']+200,b'\1')
    sp=STACK+0xff08;request=0 if nullable else P
    u.mem_write(sp,q(STOP)+b'\0'*32+q(HEAP+0x200)+q(request))
    args=[HEAP+0x100,action,qid,3]
    for reg,value in zip([R.UC_X86_REG_RCX,R.UC_X86_REG_RDX,R.UC_X86_REG_R8,R.UC_X86_REG_R9],args):u.reg_write(reg,value)
    u.reg_write(R.UC_X86_REG_RSP,sp);u.reg_write(R.UC_X86_REG_CR4,0x600)
    calls=[]
    def get(a):return struct.unpack('<Q',u.mem_read(a,8))[0]
    def ret(value):
        s=u.reg_read(R.UC_X86_REG_RSP);u.reg_write(R.UC_X86_REG_RAX,value);u.reg_write(R.UC_X86_REG_RIP,get(s));u.reg_write(R.UC_X86_REG_RSP,s+8)
    def hook(uc,address,size,data):
        if address==STOP:uc.emu_stop()
        elif address==symbols['manage_password']:
            calls.append(('manage',uc.reg_read(R.UC_X86_REG_RCX)));ret(int(accepted))
        elif address==STOP+0x100:
            s=uc.reg_read(R.UC_X86_REG_RSP)
            seen=[uc.reg_read(reg) for reg in [R.UC_X86_REG_RCX,R.UC_X86_REG_RDX,R.UC_X86_REG_R8,R.UC_X86_REG_R9]]
            assert seen==args and get(s+40)==HEAP+0x200 and get(s+48)==request
            calls.append(('original',0));uc.mem_write(request,q(0x1122334455667788));ret(0x8000000000000003)
    for address in [STOP,STOP+0x100,symbols['manage_password']]:u.hook_add(U.UC_HOOK_CODE,hook,begin=address,end=address)
    u.emu_start(symbols['config_callback'],STOP+0x200,count=100000)
    assert u.reg_read(R.UC_X86_REG_RIP)==STOP
    status=u.reg_read(R.UC_X86_REG_RAX)
    expected=(0x8000000000000003 if chain or action==2 else 0 if accepted or action==1 else 0x800000000000000F)
    assert status==expected,(status,expected)
    assert get(P-8)==CANARY and get(P+8)==CANARY
    assert calls==([('original',0)] if chain else [('manage',int(qid==0xffe1))] if action==0 else [])
    value=get(P)
    passed=value==(0x1122334455667788 if chain else SENTINEL if nullable else 0)
    return {'action':action,'qid':hex(qid),'status':hex(status),'request':hex(value),'adjacent_canaries_preserved':True,'passed':passed}

def main():
    p=argparse.ArgumentParser();p.add_argument('--baseline',action='store_true');a=p.parse_args()
    folder=HERE.parent/'baselines/P5-445585c3' if a.baseline else CANDIDATE/'build'
    driver=folder/'AiTweakerLock1904.efi';mapfile=folder/'driver.map'
    cases=[('set changed',1,0xffe0,True,False,False),('clear changed',1,0xffe1,True,False,False),
           ('unsupported action',2,0xffe0,True,False,False),('set success',0,0xffe0,True,False,False),
           ('clear success',0,0xffe1,True,False,False),('cancel',0,0xffe0,False,False,False),
           ('optional null output',1,0xffe0,True,True,False),('original 64-bit ABI forwarding',0x100000002,0x7fff,True,False,True)]
    results=[{'case':name,**execute(driver,mapfile,*args)} for name,*args in cases]
    if a.baseline:
        assert [r['passed'] for r in results]==[False]*6+[True]*2
        status='LEGACY_UPPER_32_BITS_DEFECT_REPRODUCED'
    else:
        assert all(r['passed'] for r in results),results
        status='PASS'
    report={'status':status,'driver_sha256':hashlib.sha256(driver.read_bytes()).hexdigest(),'cases':results,'scope':__doc__,
      'reference':'https://raw.githubusercontent.com/tianocore/edk2/master/MdePkg/Include/Protocol/FormBrowser2.h'}
    (folder/'hii_abi_test.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf8')
    print(json.dumps({'status':status,'driver_sha256':report['driver_sha256'],'cases':len(results)}))

if __name__=='__main__':main()
