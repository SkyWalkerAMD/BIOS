"""Local P13 fixture; owned images/vars only, no NIC or host disks."""
from pathlib import Path
import datetime,hashlib,json,os,queue,re,shutil,struct,subprocess,sys,threading,time,zlib
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent;D04=HERE.parent;CAND=D04/'provider13';CASE=HERE.parents[4]
ROOT=next(p for p in HERE.parents if (p/'tools/pydeps').is_dir())
sys.path[:0]=[str(ROOT/'tools/pydeps'),str(ROOT/'analysis/aitweaker_lock/uefi_vm_20261015')]
import pefile,disk_images
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
manifest_path=CAND/'local_candidate_manifest.json'
assert sha(manifest_path)=='2f7738e0cdfdb75a9557cf8c7bba233d512c17ac63063fea23d8e77975566e8a'
manifest=json.loads(manifest_path.read_text(encoding='utf8'))
def frozen_intact():
    assert sha(manifest_path)=='2f7738e0cdfdb75a9557cf8c7bba233d512c17ac63063fea23d8e77975566e8a'
    for a in manifest['artifacts']:
        p=D04/a['path'];assert p.stat().st_size==a['bytes']and sha(p)==a['sha256'],str(p)
frozen_intact()
assert len(manifest['artifacts'])==60
provider=CAND/'build/AiTweakerSplitProvider13.UNSIGNED.local.efi'
assert sha(provider)=='caa80df1fa6414d635d28a3b65fec1c265968482ddb66268412483eff95deca9'
inputs={'TSE':D04.parent/'boot_context/AMITSE.original.efi','SETUP':D04.parent/'boot_context/Setup.original.efi','PROVIDER':provider}
expected={'TSE':'531ed4993b27252df7bc9c2104e0b752857868e3e40691707e4e490b362de3b1','SETUP':'719bad779e9ae60340187c7aae6c12ab9dff3ee398c58a9fca2a4e027a33f21d'}
for key,digest in expected.items():assert sha(inputs[key])==digest
BUILD=HERE/'build';BUILD.mkdir(parents=True,exist_ok=True)
lines=[]
for name,path in inputs.items():
    lines.append(f'#define {name}_FILE_BYTES {path.stat().st_size}u')
    lines.append(f'static const uint8_t {name.lower()}_file_hash[32]={{'+','.join(f'0x{x:02x}'for x in bytes.fromhex(sha(path)))+'};')
lines.append('#define TSE_IMAGE_BYTES AMITSE_IMAGE_BYTES')
p=pefile.PE(str(inputs['TSE']));prefix=p.get_data(0xe1ca,24);assert prefix[:7]==bytes.fromhex('4881ec88000000')
lines.append('static const uint8_t original_body_prefix[24]={'+','.join(f'0x{x:02x}'for x in prefix)+'};')
(BUILD/'binding.h').write_text('\n'.join(lines)+'\n',encoding='utf8')
zig=ROOT/'tools/zig-x86_64-windows-0.14.1/zig.exe';env=os.environ.copy();env.update(ZIG_GLOBAL_CACHE_DIR=str(BUILD/'zig-global'),ZIG_LOCAL_CACHE_DIR=str(BUILD/'zig-local'))
compile_cmd=[str(zig),'clang','-target','x86_64-unknown-windows-msvc','-nostdinc','-isystem',str(zig.parent/'lib/include'),'-I',str(BUILD),'-I',str(CAND/'source'),'-std=c11','-O2','-Wall','-Wextra','-Werror','-ffreestanding','-fno-builtin','-fno-stack-protector','-mno-red-zone','-mno-stack-arg-probe','-fshort-wchar','-c',str(HERE/'persist_ui.c'),'-o',str(BUILD/'persist_ui.obj')]
subprocess.run(compile_cmd,check=True,env=env,cwd=ROOT)
app=BUILD/'P13-OVMF-FIXTURE-NOT-FOR-HARDWARE.EFI';link=[str(zig),'lld-link','/subsystem:efi_application','/entry:efi_main','/nodefaultlib','/machine:x64','/dynamicbase','/fixed:no','/nxcompat','/timestamp:0','/out:'+str(app),str(BUILD/'persist_ui.obj'),str(CAND/'build/password_crypto.obj')]
subprocess.run(link,check=True,env=env,cwd=ROOT);p=pefile.PE(str(app));p.OPTIONAL_HEADER.CheckSum=p.generate_checksum();app.write_bytes(p.write())
(BUILD/'build.json').write_text(json.dumps({'fixture_sha256':sha(app),'source_sha256':sha(HERE/'persist_ui.c'),'extra_source_sha256':sha(HERE/'fixture_extra.inc'),'provider_sha256':sha(provider),'commands':[compile_cmd,link]},indent=2)+'\n')
run=HERE/'runs'/datetime.datetime.now().strftime('%Y%m%d_%H%M%S');run.mkdir(parents=True)
snapshot=run/'fixture-snapshot';snapshot.mkdir()
for p in [HERE/'persist_ui.c',HERE/'fixture_extra.inc',Path(__file__),BUILD/'build.json',BUILD/'binding.h',app]:shutil.copyfile(p,snapshot/p.name)
qemu=ROOT/'tools/qemu-11.1.0';share=qemu/'share';varsfile=run/'shared-vars.fd';shutil.copyfile(share/'edk2-i386-vars.fd',varsfile);initial_vars=sha(varsfile)
disk_images.OUT=run;disk_images.VOLUME_SIZE=16*1024*1024;image=run/'readonly-boot.img'
disk_images.create(image,'superfloppy',16,{'/EFI/BOOT/BOOTX64.EFI':app.read_bytes(),**{f'/{name}.EFI':path.read_bytes()for name,path in inputs.items()}});image_hash=sha(image)
class QMP:
 def __init__(self,proc):
    self.count=0;self.proc=proc;self.queue=queue.Queue()
    def reader():
        for line in iter(proc.stdout.readline,b''):self.queue.put(line)
        self.queue.put(b'')
    threading.Thread(target=reader,daemon=True).start()
    hello=json.loads(self.queue.get(timeout=5));assert'QMP'in hello;self.command('qmp_capabilities')
 def command(self,name,args=None):
    self.count+=1;n=self.count;obj={'execute':name,'id':n}
    if args is not None:obj['arguments']=args
    self.proc.stdin.write(json.dumps(obj).encode()+b'\n');self.proc.stdin.flush()
    while True:
        line=self.queue.get(timeout=5)
        if not line:raise EOFError('QMP disconnected')
        reply=json.loads(line)
        if reply.get('id')==n:
            if'error'in reply:raise RuntimeError(reply['error'])
            return reply.get('return')
 def key(self,ch):self.command('send-key',{'keys':[{'type':'qcode','data':'ret'if ch=='\r'else'esc'if ch=='\x1b'else ch}],'hold-time':25})
 def screen(self,path):
    ppm=path.with_suffix('.ppm');self.command('screendump',{'filename':str(ppm)});raw=ppm.read_bytes()
    header=re.match(rb'P6\s+(\d+)\s+(\d+)\s+255\s',raw);assert header,'Unexpected QEMU screenshot format'
    w,h=map(int,header.groups());rgb=raw[header.end():];assert len(rgb)==w*h*3
    def chunk(kind,data):return struct.pack('>I',len(data))+kind+data+struct.pack('>I',zlib.crc32(kind+data)&0xffffffff)
    scan=b''.join(b'\0'+rgb[y*w*3:(y+1)*w*3]for y in range(h))
    path.write_bytes(b'\x89PNG\r\n\x1a\n'+chunk(b'IHDR',struct.pack('>IIBBBBB',w,h,8,2,0,0,0))+chunk(b'IDAT',zlib.compress(scan))+chunk(b'IEND',b''))
 def close(self):self.proc.stdin.close();self.proc.stdout.close()
# Explicit disposable fixture strings, never real user or BMC credentials.
A='testpass1904a';BNEW='testpass1904b';WRONG='wrongpass1904'
steps={1:[('enroll_a',A+'\r'+A+'\r\r'),('wrong_a',WRONG+'\r\r'),('unlock_a',A+'\r'),('change_to_b',A+'\r'+BNEW+'\r'+BNEW+'\r\r')],
       2:[('old_a_rejected',A+'\r\r'),('unlock_b',BNEW+'\r'),('cancel_b','\x1b'),('clear_b',BNEW+'\ry\r')]}
reports=[];error=None
def readlog(path):return path.read_text(encoding='ascii',errors='replace')if path.exists()else''
try:
 for phase in [1,2]:
    boot=run/f'boot{phase}';boot.mkdir();log=boot/'debug.log';before_vars=sha(varsfile)
    args=[str(qemu/'qemu-system-x86_64.exe'),'-L',str(share),'-machine','q35','-accel','tcg,thread=single','-cpu','max','-m','512','-smp','1','-nic','none','-display','none','-monitor','none','-qmp','stdio','-serial','file:'+str(boot/'serial.log'),'-debugcon','file:'+str(log),'-global','isa-debugcon.iobase=0x402','-device','isa-debug-exit,iobase=0xf4,iosize=0x4','-drive','if=pflash,format=raw,unit=0,readonly=on,file='+str(share/'edk2-x86_64-code.fd'),'-drive','if=pflash,format=raw,unit=1,file='+str(varsfile),'-drive','if=none,id=boot,format=raw,readonly=on,file='+str(image),'-device','qemu-xhci,id=xhci','-device','usb-storage,bus=xhci.0,drive=boot,bootindex=1']
    (boot/'command.json').write_text(json.dumps(args,indent=2)+'\n');start=time.monotonic();sent=[];screens=[];proc=None;qmp=None;boot_error=None
    with (boot/'stderr.log').open('wb')as stderr:
      try:
        proc=subprocess.Popen(args,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=stderr,creationflags=subprocess.CREATE_NO_WINDOW);qmp=QMP(proc)
        for name,keys in steps[phase]:
            deadline=time.monotonic()+240
            while f'STEP_BEGIN {name}\n'not in readlog(log):
                if proc.poll()is not None:raise RuntimeError('QEMU exited before '+name)
                if time.monotonic()>deadline:raise TimeoutError('Step not reached: '+name)
                time.sleep(.1)
            print(f'BOOT {phase}: actual UI step {name}',flush=True);time.sleep(1)
            png=boot/(name+'-prompt.png');qmp.screen(png);screens.append(png)
            for ch in keys:
                if proc.poll()is not None:raise RuntimeError('QEMU exited while typing '+name)
                qmp.key(ch);time.sleep(.075 if ch!='\r'else .2)
            sent.append({'step':name,'key_events':len(keys),'transport':'QMP send-key -> emulated standard keyboard -> OVMF console input'})
            restored=False
            while f'STEP_DONE {name}\n'not in readlog(log):
                if proc.poll()is not None:raise RuntimeError('QEMU exited before completion of '+name)
                if not restored and f'RESTORE_CAPTURE_BEGIN {name}\n'in readlog(log):
                    png=boot/(name+'-restored.png');qmp.screen(png);screens.append(png);restored=True
                if time.monotonic()>deadline:
                    png=boot/(name+'-timeout.png');qmp.screen(png);screens.append(png);raise TimeoutError('Step completion timeout: '+name)
                time.sleep(.1)
            print(f'BOOT {phase}: completed {name}',flush=True)
        code=proc.wait(timeout=30)
      except Exception as ex:
        boot_error=repr(ex)
        if proc and proc.poll()is None:
            if qmp:
                try:png=boot/'failure.png';qmp.screen(png);screens.append(png)
                except Exception:pass
            proc.terminate();proc.wait(timeout=5)
        code=proc.returncode if proc else None
      finally:
        if qmp:qmp.close()
    raw=readlog(log);ok=code==33 and'P13_UI_OVMF_PASS'in raw and'FAIL 'not in raw and not boot_error
    report={'phase':phase,'status':'PASS'if ok else'FAIL','exit_code':code,'error':boot_error,'seconds':round(time.monotonic()-start,2),'checks':raw.count('PASS '),
            'debug_log':str(log),'debug_sha256':sha(log)if log.exists()else None,'vars_before_sha256':before_vars,'vars_after_sha256':sha(varsfile),
            'standard_keyboard_actions':sent,'screenshots':[{'path':str(p),'sha256':sha(p)}for p in screens]}
    (boot/'result.json').write_text(json.dumps(report,indent=2)+'\n');reports.append(report)
    print(json.dumps({'phase':phase,'status':report['status'],'checks':report['checks'],'seconds':report['seconds'],'error':boot_error}),flush=True)
    if not ok:raise RuntimeError('Boot '+str(phase)+' failed; inspect retained artifacts')
except Exception as ex:error=repr(ex)
frozen_intact()
result={'status':'PASS_TWO_PROCESS_OVMF_REAL_STORAGE_AND_CONSOLE_UI'if not error and len(reports)==2 else'FAILED_OR_INCOMPLETE_REAL_UI_SIMULATION',
        'error':error,'provider_sha256':sha(provider),'bound_modules':{k:sha(v)for k,v in inputs.items()if k!='PROVIDER'},'fixture_sha256':sha(app),
        'fixture_source_sha256':sha(HERE/'persist_ui.c'),'runner_sha256':sha(Path(__file__)),'frozen_candidate_60_bindings_unchanged':True,
        'ovmf_code_sha256':sha(share/'edk2-x86_64-code.fd'),'initial_vars_sha256':initial_vars,'final_vars_sha256':sha(varsfile),
        'shared_writable_vars_file':str(varsfile),'readonly_boot_disk_unchanged':sha(image)==image_hash,'boot_reports':reports,
        'scope':'Actual immutable P13 PE, real OVMF HII database + ConfigAccess callbacks/password UI/GetVariable/SetVariable; real detached guard with declared TCG body substitution. Two processes reuse one owned writable VAR copy.',
        'substitutions':['Exactly twelve reviewed detours are installed in loaded VM copies of original modules; OEM text outside those sites remains unchanged.',
                         'Only execution at the original loop continuation is redirected by a TCG-only #DB saved-context change. No OEM body bytes are patched.',
                         'LoadedImage FV-file paths and module BootServices globals are supplied. OEM DXE entrypoints and native ASUS browser body are not executed.',
                         'Guard RX and state RW-NX permissions use real OVMF CPU Arch services; this fixture is not the production allocation/publication transaction.'],
        'limits':['No physical board, BMC, flashing, host disk attachment, or actual user credential involved.','OVMF persistence and console behavior do not establish ASUS NVRAM or KVM compatibility.']}
(run/'result.json').write_text(json.dumps(result,indent=2)+'\n');(HERE/'latest_result.json').write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps({'status':result['status'],'result':str(run/'result.json'),'error':error}),flush=True)
assert result['status'].startswith('PASS')and result['readonly_boot_disk_unchanged'],error
