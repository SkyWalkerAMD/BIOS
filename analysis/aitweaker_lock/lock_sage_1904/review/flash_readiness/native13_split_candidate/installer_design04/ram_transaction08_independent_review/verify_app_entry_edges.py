"""Actual app entry instructions with explicit firmware/adapter substitutes.

Builds an isolated test carrier, never an installable UEFI artifact. The core
object is the author's pinned object. The app source/header bytes are copied
before compile; placeholder adapters always refuse and do not touch OEM RAM.
"""
from pathlib import Path
from datetime import datetime,timezone
import hashlib, json, os, re, struct, subprocess, sys
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent
D04=HERE.parent
TX=D04/'ram_transaction05'
ROOT=next(path for path in HERE.parents if (path/'tools/zig-x86_64-windows-0.14.1/zig.exe').exists())
sys.path.insert(0,str(ROOT/'tools/pydeps'))
import pefile,unicorn as U
from unicorn import x86_const as R
sha=lambda path:hashlib.sha256(path.read_bytes()).hexdigest()
q=lambda value:struct.pack('<Q',value)
ERR=lambda value:(1<<63)|value
BASE=0x140000000
DATA=0x50000000
ST=DATA;BS=DATA+0x1000;RT=DATA+0x2000;OUT=DATA+0x3000;IN=DATA+0x4000
STACK=0x70000000;STOP=DATA+0x10000;TRAMP=STOP+0x1000
FUNCTIONS={name:STOP+0x100+16*i for i,name in enumerate(['create','create_ex','watchdog','attribute','clear','output','input','stall'])}


def build():
    dest=HERE/'app_entry_carrier';source=dest/'source';output=dest/'build'
    source.mkdir(parents=True,exist_ok=True);output.mkdir(exist_ok=True)
    originals=[]
    for path in sorted((TX/'source').glob('*.h'))+[TX/'source/app.c']:
        target=source/path.name;target.write_bytes(path.read_bytes())
        originals.append({'path':str(path),'sha256':sha(path),'copy':str(target.relative_to(HERE))})
    (source/'stubs.c').write_text('''#include "app.h"
int platform_inventory(void){return 0;}
int platform_prepare(RAM_SESSION *s,unsigned m){(void)s;(void)m;return 0;}
uint32_t platform_install(RAM_SESSION *s){(void)s;return TX_REFUSED;}
int platform_start_provider(RAM_SESSION *s){(void)s;return 0;}
uint32_t platform_remove(RAM_SESSION *s){(void)s;return TX_REFUSED;}
int ui_capture_initial(void){return 0;}
int ui_open_management(RAM_SESSION *s){(void)s;return 0;}
int ui_open_original_setup(RAM_SESSION *s){(void)s;return 0;}
int ui_restore_credential(RAM_SESSION *s){(void)s;return 0;}
int ui_compare_original_stores(void){return 0;}
ES kvm_present(ST *st,const char *p,size_t n,unsigned w){(void)st;(void)p;(void)n;(void)w;return 0;}
''',encoding='utf8')
    zig=ROOT/'tools/zig-x86_64-windows-0.14.1/zig.exe'
    env=os.environ.copy();env.update(ZIG_LOCAL_CACHE_DIR=str(output/'zig-local'),ZIG_GLOBAL_CACHE_DIR=str(output/'zig-global'))
    commands=[]
    for name in ['app','stubs']:
        commands.append([str(zig),'clang','-target','x86_64-unknown-windows-msvc','-nostdinc','-isystem',str(zig.parent/'lib/include'),
                         '-I',str(source),'-std=c11','-O2','-Wall','-Wextra','-Werror','-ffreestanding','-fno-builtin','-fno-stack-protector',
                         '-mno-red-zone','-mno-stack-arg-probe','-fshort-wchar','-c',str(source/(name+'.c')),'-o',str(output/(name+'.obj'))])
    core=TX/'build/transaction.obj';assert sha(TX/'build/TransactionCore05.TESTONLY.efi')=='3a04ddeca96cd62d4cbad9a453735cfb096f98f7e1731579c7ce938eaeb47767'
    efi=output/'APP-ENTRY-TEST-CARRIER-NEVER-BOOT.efi';linkmap=output/'app.map'
    commands.append([str(zig),'lld-link','/subsystem:efi_application','/entry:app_main','/nodefaultlib','/machine:x64','/dynamicbase','/fixed:no','/nxcompat','/timestamp:0',
                     '/map:'+str(linkmap),'/out:'+str(efi),str(output/'app.obj'),str(output/'stubs.obj'),str(core)])
    for command in commands:subprocess.run(command,check=True,env=env,cwd=ROOT,capture_output=True)
    pe=pefile.PE(str(efi))
    symbols={name:int(address,16)-pe.OPTIONAL_HEADER.ImageBase+BASE for name,address in re.findall(r'^\s+[0-9A-Fa-f]{4}:[0-9A-Fa-f]+\s+(\S+)\s+([0-9A-Fa-f]{16})',linkmap.read_text(),re.M)}
    assert all(name in symbols for name in ['app_main','app_hold','app_hold_reason','app_ended'])
    return output,efi,symbols,originals,commands


class VM:
    def __init__(self,efi,symbols,ending=None,failed=None,missing=None,failure_handle=False):
        self.symbols=symbols;self.ending=ending;self.failed=failed;self.calls=[];self.after_end=[];self.callback=0
        self.failure_handle=failure_handle;self.result=None;self.end_fired=False
        self.u=U.Uc(U.UC_ARCH_X86,U.UC_MODE_64)
        pe=pefile.PE(str(efi));pe.relocate_image(BASE);raw=pe.get_memory_mapped_image()
        self.u.mem_map(BASE,(pe.OPTIONAL_HEADER.SizeOfImage+4095)&~4095);self.u.mem_write(BASE,raw)
        self.u.mem_map(DATA,0x20000);self.u.mem_map(STACK,0x20000)
        for offset,value in [(0x60,BS),(0x58,RT),(0x40,OUT),(0x30,IN)]:self.u.mem_write(ST+offset,q(value))
        for name,offset in [('create',0x50),('create_ex',0x170),('watchdog',0x100),('stall',0xf8)]:self.u.mem_write(BS+offset,q(0 if name==missing else FUNCTIONS[name]))
        for name,offset in [('attribute',0x28),('clear',0x30),('output',8)]:self.u.mem_write(OUT+offset,q(FUNCTIONS[name]))
        self.u.mem_write(IN+8,q(FUNCTIONS['input']))
        self.u.hook_add(U.UC_HOOK_CODE,self.code)
        self.u.hook_add(U.UC_HOOK_MEM_INVALID,self.invalid)
    def invalid(self,u,access,address,size,value,context):
        raise AssertionError(('fixture mapping failure',self.ending,self.failed,hex(u.reg_read(R.UC_X86_REG_RIP)),hex(address),size,self.calls))
    def getq(self,address):return struct.unpack('<Q',self.u.mem_read(address,8))[0]
    def arg(self,index):
        if index<4:return self.u.reg_read([R.UC_X86_REG_RCX,R.UC_X86_REG_RDX,R.UC_X86_REG_R8,R.UC_X86_REG_R9][index])
        return self.getq(self.u.reg_read(R.UC_X86_REG_RSP)+0x28+(index-4)*8)
    def ret(self,value):
        sp=self.u.reg_read(R.UC_X86_REG_RSP);self.u.reg_write(R.UC_X86_REG_RAX,value)
        self.u.reg_write(R.UC_X86_REG_RIP,self.getq(sp));self.u.reg_write(R.UC_X86_REG_RSP,sp+8)
    def end_then_return(self,status):
        assert self.callback
        self.end_fired=True
        code=b'\x48\x83\xec\x28\x48\xb9'+q(0xdead0000)+b'\x31\xd2\x48\xb8'+q(self.callback)+b'\xff\xd0\x48\xb8'+q(status)+b'\x48\x83\xc4\x28\xc3'
        self.u.mem_write(TRAMP,code);self.u.reg_write(R.UC_X86_REG_RIP,TRAMP)
    def code(self,u,address,size,context):
        reason=struct.unpack('<I',u.mem_read(self.symbols['app_hold_reason'],4))[0]
        if reason:self.result=('resident_hold',reason);u.emu_stop();return
        if address==STOP:self.result=('returned',u.reg_read(R.UC_X86_REG_RAX));u.emu_stop();return
        name=next((key for key,value in FUNCTIONS.items() if value==address),None)
        if name is None:return
        self.calls.append(name)
        if self.end_fired:self.after_end.append(name)
        status=ERR(7) if name==self.failed else 0
        if name in ['create','create_ex']:
            self.callback=self.arg(2)
            self.u.mem_write(self.arg(4 if name=='create'else 5),q(0 if status and not self.failure_handle else 0xdead0000))
        if name==self.ending:self.end_then_return(status);return
        if name=='input':self.result=('menu_reached',0);u.emu_stop();return
        self.ret(status)
    def run(self):
        sp=STACK+0x1fe08;self.u.mem_write(sp,q(STOP)+bytes(0x100));self.u.reg_write(R.UC_X86_REG_RSP,sp)
        self.u.reg_write(R.UC_X86_REG_RCX,0x12345000);self.u.reg_write(R.UC_X86_REG_RDX,ST)
        self.u.emu_start(self.symbols['app_main'],0,count=2000000)
        assert self.result is not None
        return self.result


def main():
    output,efi,symbols,originals,commands=build();cases=[]
    for ending in ['create','create_ex','watchdog','attribute','clear','output','input']:
        for failure in [False,True]:
            vm=VM(efi,symbols,ending=ending,failed=ending if failure else None)
            result=vm.run();assert result==('resident_hold',0xe0000001) and not vm.after_end
            cases.append({'case':f'ending during {ending}, return '+('error'if failure else 'success'),
                          'status':'PASS','result':result,'firmware_calls':vm.calls,'calls_after_ending':vm.after_end})
    for label,kwargs,expected in [
        ('normal create failure without event',{'failed':'create'},('returned',ERR(7))),
        ('create failure with nonzero event',{'failed':'create','failure_handle':True},('resident_hold',0xe000000f)),
        ('create_ex failure after registered exit callback',{'failed':'create_ex'},('resident_hold',0xe0000010)),
        ('watchdog method missing',{'missing':'watchdog'},('resident_hold',0xe0000012)),
        ('watchdog disable failure',{'failed':'watchdog'},('resident_hold',0xe0000013)),
        ('baseline refusal menu stays resident',{},('menu_reached',0)),
    ]:
        vm=VM(efi,symbols,**kwargs);result=vm.run();assert result==expected,(label,result)
        cases.append({'case':label,'status':'PASS','result':result,'firmware_calls':vm.calls})
    for row in originals:assert sha(Path(row['path']))==row['sha256'],row['path']
    result={'status':'PASS_ACTUAL_APP_ENTRY_BOUNDARIES_WITH_EXPLICIT_SERVICE_AND_ADAPTER_MODELS',
            'generated_utc':datetime.now(timezone.utc).isoformat(),'cases':len(cases),'records':cases,
            'app_source_sha256':sha(TX/'source/app.c'),'test_carrier_sha256':sha(efi),'core_object_sha256':sha(TX/'build/transaction.obj'),
            'test_source_sha256':sha(Path(__file__)),'source_inputs':originals,'build_commands':commands,
            'explicit_substitutes':['UEFI service methods including event callbacks are fixtures.',
                                    'Every platform/UI adapter and QR presenter is a refusal stub; no original-module write or password operation occurs.'],
            'scope':['Actual compiled app.c entry/service order/hold paths execute; original ending callback and tx_end instructions execute.',
                     'The first CreateEvent error-after-ending counterexample is closed in this app source snapshot.',
                     'Watchdog absence/failure prevents reaching menu or any adapter operation.',
                     'Not a final EFI/ISO or transport/installer/provider acceptance. Never boot this carrier.']}
    out=HERE/'app_entry_edges_result.json';out.write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n',encoding='utf8')
    print(json.dumps({'status':result['status'],'cases':len(cases),'app_source_sha256':result['app_source_sha256'],'report_sha256':sha(out)}))
if __name__=='__main__':main()
