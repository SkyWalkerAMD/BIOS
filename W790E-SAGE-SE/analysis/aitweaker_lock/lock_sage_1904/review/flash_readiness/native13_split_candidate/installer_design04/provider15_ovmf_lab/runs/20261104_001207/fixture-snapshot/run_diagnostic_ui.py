"""One local OVMF run: actual P15 unconfigured diagnostics, no credential setup."""
from pathlib import Path
import datetime,hashlib,json,os,queue,re,shutil,struct,subprocess,sys,threading,time,zlib,types
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent;D04=HERE.parent;INPUT=HERE/'inputs'
ROOT=next(p for p in HERE.parents if (p/'tools/pydeps').is_dir())
sys.path[:0]=[str(ROOT/'tools/pydeps'),str(ROOT/'analysis/aitweaker_lock/uefi_vm_20261015')]
import pefile,disk_images
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
provider=INPUT/'provider.efi';assert sha(provider)=='d15438fde33bf0fada0a33f9f62a9ca8ff72cf21bb924ceaeca0bc75a0b0a5cf'
meta=json.loads((INPUT/'provider-build.json').read_text())
for name,digest in meta['sources'].items():assert sha(INPUT/'source'/name)==digest,name
inputs={'TSE':D04.parent/'boot_context/AMITSE.original.efi','SETUP':D04.parent/'boot_context/Setup.original.efi','PROVIDER':provider}
for name,digest in {'TSE':'531ed4993b27252df7bc9c2104e0b752857868e3e40691707e4e490b362de3b1','SETUP':'719bad779e9ae60340187c7aae6c12ab9dff3ee398c58a9fca2a4e027a33f21d'}.items():assert sha(inputs[name])==digest
BUILD=HERE/'build';BUILD.mkdir(exist_ok=True);lines=[]
for name,path in inputs.items():
 lines.extend([f'#define {name}_FILE_BYTES {path.stat().st_size}u',f'static const uint8_t {name.lower()}_file_hash[32]={{'+','.join(f'0x{x:02x}'for x in bytes.fromhex(sha(path)))+'};'])
lines.append('#define TSE_IMAGE_BYTES AMITSE_IMAGE_BYTES');prefix=pefile.PE(str(inputs['TSE'])).get_data(0xe1ca,24)
assert prefix[:7]==bytes.fromhex('4881ec88000000')
lines.append('static const uint8_t original_body_prefix[24]={'+','.join(f'0x{x:02x}'for x in prefix)+'};')
(BUILD/'binding.h').write_text('\n'.join(lines)+'\n')
zig=ROOT/'tools/zig-x86_64-windows-0.14.1/zig.exe';env=os.environ.copy();env.update(ZIG_GLOBAL_CACHE_DIR=str(BUILD/'zig-global'),ZIG_LOCAL_CACHE_DIR=str(BUILD/'zig-local'))
commands=[]
for source,out in [(HERE/'diagnostic_ui.c',BUILD/'diagnostic_ui.obj'),(INPUT/'source/password_crypto.c',BUILD/'password_crypto.obj')]:
 cmd=[str(zig),'clang','-target','x86_64-unknown-windows-msvc','-nostdinc','-isystem',str(zig.parent/'lib/include'),'-I',str(BUILD),'-I',str(INPUT/'source'),'-std=c11','-O2','-Wall','-Wextra','-Werror','-ffreestanding','-fno-builtin','-fno-stack-protector','-mno-red-zone','-mno-stack-arg-probe','-fshort-wchar','-c',str(source),'-o',str(out)]
 subprocess.run(cmd,check=True,env=env,cwd=ROOT);commands.append(cmd)
app=BUILD/'P15-DIAGNOSTIC-OVMF-FIXTURE-NOT-FOR-HARDWARE.EFI'
cmd=[str(zig),'lld-link','/subsystem:efi_application','/entry:efi_main','/nodefaultlib','/machine:x64','/dynamicbase','/fixed:no','/nxcompat','/timestamp:0','/out:'+str(app),str(BUILD/'diagnostic_ui.obj'),str(BUILD/'password_crypto.obj')]
subprocess.run(cmd,check=True,env=env,cwd=ROOT);commands.append(cmd);p=pefile.PE(str(app));p.OPTIONAL_HEADER.CheckSum=p.generate_checksum();app.write_bytes(p.write())
(BUILD/'build.json').write_text(json.dumps({'fixture_sha256':sha(app),'source_sha256':sha(HERE/'diagnostic_ui.c'),'extra_sha256':sha(HERE/'fixture_extra.inc'),'provider_sha256':sha(provider),'commands':commands},indent=2)+'\n')
qmp_source=D04/'provider14_ovmf_lab/run_persist_ui.py'
assert sha(qmp_source)=='7d8fbd7b47046a6b5c3783cf50e86a25142f0eeed849fa71c927eb6dd4c1bffb'
qmp_text=qmp_source.read_text().split('class QMP:',1)[1].split('# Explicit disposable',1)[0]
exec(compile('class QMP:'+qmp_text,str(qmp_source)+' [QMP class only]','exec'))
decoder_path=ROOT/'analysis/aitweaker_lock/lock_sage_1904/review/flash_readiness/remote_only/continuation12/decode_diagnostic09.py'
decoder=types.ModuleType('c12_decoder');exec(compile(decoder_path.read_text(),str(decoder_path),'exec'),decoder.__dict__)
run=HERE/'runs'/datetime.datetime.now().strftime('%Y%m%d_%H%M%S');run.mkdir(parents=True)
snap=run/'fixture-snapshot';snap.mkdir()
for path in [HERE/'diagnostic_ui.c',HERE/'fixture_extra.inc',Path(__file__),BUILD/'build.json',BUILD/'binding.h',app,decoder_path]:shutil.copyfile(path,snap/path.name)
qemu=ROOT/'tools/qemu-11.1.0';share=qemu/'share';varsfile=run/'owned-vars.fd';shutil.copyfile(share/'edk2-i386-vars.fd',varsfile);vars_before=sha(varsfile)
disk_images.OUT=run;disk_images.VOLUME_SIZE=16*1024*1024;image=run/'readonly-boot.img'
disk_images.create(image,'superfloppy',16,{'/EFI/BOOT/BOOTX64.EFI':app.read_bytes(),**{f'/{name}.EFI':path.read_bytes()for name,path in inputs.items()}});image_hash=sha(image)
log=run/'debug.log';serial=run/'serial.log'
args=[str(qemu/'qemu-system-x86_64.exe'),'-L',str(share),'-machine','q35','-accel','tcg,thread=single','-cpu','max','-m','512','-smp','1','-nic','none','-display','none','-monitor','none','-qmp','stdio','-serial','file:'+str(serial),'-debugcon','file:'+str(log),'-global','isa-debugcon.iobase=0x402','-device','isa-debug-exit,iobase=0xf4,iosize=0x4','-drive','if=pflash,format=raw,unit=0,readonly=on,file='+str(share/'edk2-x86_64-code.fd'),'-drive','if=pflash,format=raw,unit=1,file='+str(varsfile),'-drive','if=none,id=boot,format=raw,readonly=on,file='+str(image),'-device','qemu-xhci,id=xhci','-device','usb-storage,bus=xhci.0,drive=boot,bootindex=1']
(run/'command.json').write_text(json.dumps(args,indent=2)+'\n')
def readlog(path):return path.read_text(encoding='ascii',errors='replace')if path.exists()else''
def six_blocks():
 text=re.sub(r'\x1b\[[0-?]*[ -/]*[@-~]','',readlog(serial));found=[];lines=text.splitlines()
 for i,line in enumerate(lines):
  at=line.find('D09 R=')
  if at<0 or i+5>=len(lines):continue
  candidate='\n'.join([line[at:].strip()]+[s.strip()for s in lines[i+1:i+6]])
  try:decoded=decoder.decode(candidate)
  except ValueError:continue
  found.append((candidate,decoded))
 return found
proc=None;qmp=None;error=None;screens=[];actions=[];decoded_blocks=[];start=time.monotonic()
def wait_for(predicate,label,seconds=180):
 deadline=time.monotonic()+seconds
 while not predicate():
  if proc.poll()is not None:raise RuntimeError('QEMU exited before '+label)
  if time.monotonic()>deadline:raise TimeoutError(label)
  time.sleep(.1)
def screen(name):
 png=run/(name+'.png');qmp.screen(png);screens.append(png)
with (run/'stderr.log').open('wb')as stderr:
 try:
  proc=subprocess.Popen(args,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=stderr,creationflags=subprocess.CREATE_NO_WINDOW);qmp=QMP(proc)
  for index,name in enumerate(['form_verify_one','direct_verify_two','sticky_trace_unavailable','invalid_header_unavailable']):
   wait_for(lambda:f'STEP_BEGIN {name}\n'in readlog(log),'step '+name)
   if index==0:
    time.sleep(.5);screen('form-before-verify')
    for key in ['down','down','down','\r']:qmp.key(key);time.sleep(.15)
   wait_for(lambda:len(six_blocks())>=index+1,'six diagnostic lines '+name)
   time.sleep(.5);screen(name)
   text,decoded=six_blocks()[index];(run/(name+'.six-lines.txt')).write_text(text+'\n',encoding='ascii');decoded_blocks.append({'step':name,**decoded})
   qmp.key('\x1b');time.sleep(.5)
   if index==0:qmp.key('\x1b')
   actions.append({'step':name,'keys':['down','down','down','Enter','Esc','Esc']if index==0 else['Esc'],'transport':'QMP standard emulated keyboard; no injected ConsoleIn method'})
   wait_for(lambda:f'STEP_DONE {name}\n'in readlog(log),'return '+name)
   print('Completed actual P15 OVMF '+name,flush=True)
  code=proc.wait(timeout=30)
 except Exception as exc:
  error=repr(exc)
  if proc and proc.poll()is None:
   if qmp:
    try:screen('failure')
    except Exception:pass
   proc.terminate();proc.wait(timeout=5)
  code=proc.returncode if proc else None
 finally:
  if qmp:qmp.close()
raw=readlog(log);expected=[(1,1,0,2),(2,2,1,2),(0,3,2,0),(0,0,0,0)]
if not error:
 try:
  assert code==33 and 'P15_DIAGNOSTIC_OVMF_PASS'in raw and 'FAIL 'not in raw
  assert len(decoded_blocks)==4
  for row,(r,p,a,valid)in zip(decoded_blocks,expected):
   f=row['fields_by_printed_label'];assert f['D09']=={'R':r,'P':p,'A':a}and f['S']['V']==valid,(row['step'],f)
   if valid:assert f['R']['H']==9 and f['R']['E']==32 and f['R']['C']==0xffffffff
   else:assert all(x==0xffffffff for x in f['R'].values())
 except Exception as exc:error=repr(exc)
result={'status':'PASS_ACTUAL_P15_OVMF_DIAGNOSTIC_ONLY'if not error else'FAILED_OR_INCOMPLETE','error':error,'exit_code':code,'process_reaped':proc is not None and proc.poll()is not None,'seconds':round(time.monotonic()-start,2),'checks':raw.count('PASS '),'provider_sha256':sha(provider),'fixture_sha256':sha(app),'source_sha256':sha(HERE/'diagnostic_ui.c'),'runner_sha256':sha(Path(__file__)),'decoder_sha256':sha(decoder_path),'readonly_boot_disk_unchanged':sha(image)==image_hash,'vars_before_sha256':vars_before,'vars_after_sha256':sha(varsfile),'actions':actions,'decoded_diagnostic_screens':decoded_blocks,'screenshots':[{'path':str(p),'sha256':sha(p)}for p in screens],
 'scope':['Actual P15 entry/owner/HII/ConfigAccess/UNCONFIGURED UI and real OVMF console/GOP/keyboard/GetVariable/ExitBootServices. First Verify selected through actual OVMF FormBrowser; later callbacks direct actual ConfigAccess.','Exact guard and original PE text apart from12 declared fixture detours. TCG-only #DB context redirects OEM browser body to declared lab stub; OEM DXE entries, actual ASUS rendering/input and page classification do not execute.','Sticky/header mutations affect only owned diagnostic RAM and are explicitly lab fault fixtures. No password fixture, credential input, credential creation, native field change beyond disclosed boot-service globals/detours, RT replacement or flash operation.','No network or host disk attached. Readonly boot image and owned writable OVMF VAR copy only. This does not accept ASUS native M/B behavior or hardware/permanent lock readiness.']}
(run/'result.json').write_text(json.dumps(result,indent=2)+'\n');assert not (HERE/'latest_result.json').exists(),'Keep prior latest result; use new sibling';(HERE/'latest_result.json').write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps({'status':result['status'],'result':str(run/'result.json'),'error':error}),flush=True)
assert not error and result['readonly_boot_disk_unchanged'],error
