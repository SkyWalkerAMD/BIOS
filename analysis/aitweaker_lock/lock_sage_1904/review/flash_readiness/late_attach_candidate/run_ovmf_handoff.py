"""Build and run an isolated TCG-only EBS fixture, using candidate services.obj."""
from pathlib import Path
import datetime,hashlib,json,os,shutil,subprocess,sys,time
HERE=Path(__file__).resolve().parent;CASE=HERE.parents[2];ROOT=CASE.parents[2];DRIVER=CASE/'driver'
sys.path[:0]=[str(ROOT/'tools/pydeps'),str(CASE.parent/'uefi_vm_20261015')]
import pefile,disk_images
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
build=json.loads((HERE/'build/build.json').read_text(encoding='utf8'))
assert sha(HERE/'services.c')==build['candidate_source_sha256']
for object_path, digest in build['object_sha256'].items():
 assert sha(CASE/object_path)==digest,object_path
assert sha(HERE/'build/AiTweakerLock1904.efi')==build['candidate_driver_sha256']

zig=ROOT/'tools/zig-x86_64-windows-0.14.1/zig.exe';OUT=HERE/'ovmf_build';OUT.mkdir(exist_ok=True)
env=os.environ.copy();env.update(ZIG_GLOBAL_CACHE_DIR=str(ROOT/'tools/zig-cache-global'),ZIG_LOCAL_CACHE_DIR=str(ROOT/'tools/zig-cache-local'))
cmd=[str(zig),'clang','-target','x86_64-unknown-windows-msvc','-nostdinc','-isystem',str(zig.parent/'lib/include'),'-I',str(HERE),'-I',str(DRIVER),'-I',str(CASE.parent/'probe_p3_kvm/source'),'-std=c11','-Oz','-Wall','-Wextra','-Werror','-ffreestanding','-fno-builtin','-fno-stack-protector','-mno-red-zone','-fshort-wchar','-c',str(HERE/'ovmf_handoff.c'),'-o',str(OUT/'ovmf_handoff.obj')]
subprocess.run(cmd,check=True,env=env)
objects=[OUT/'ovmf_handoff.obj',HERE/'build/services.obj']+[DRIVER/'build'/(n+'.obj') for n in ['cpu_entropy','password_core','password_crypto','probe_core']]
app=OUT/'OVMF-EBS-ONLY.EFI'
link=[str(zig),'lld-link','/subsystem:efi_application','/entry:efi_main','/nodefaultlib','/machine:x64','/dynamicbase','/fixed:no','/nxcompat','/timestamp:0','/out:'+str(app)]+[str(p) for p in objects]
subprocess.run(link,check=True,env=env);pe=pefile.PE(str(app));pe.OPTIONAL_HEADER.CheckSum=pe.generate_checksum();app.write_bytes(pe.write())
run=HERE/'vm'/datetime.datetime.now().strftime('%Y%m%d_%H%M%S');run.mkdir(parents=True)
qemu=ROOT/'tools/qemu-11.1.0';share=qemu/'share'
varsfile=run/'vars.fd';shutil.copyfile(share/'edk2-i386-vars.fd',varsfile)
disk_images.OUT=run;disk_images.VOLUME_SIZE=16*1024*1024;image=run/'boot.img'
disk_images.create(image,'superfloppy',16,{'/EFI/BOOT/BOOTX64.EFI':app.read_bytes()})
log=run/'debug.log'
args=[str(qemu/'qemu-system-x86_64.exe'),'-L',str(share),'-machine','q35,accel=tcg','-cpu','max','-m','512','-smp','1','-nic','none','-display','none','-monitor','none','-serial','file:'+str(run/'serial.log'),'-debugcon','file:'+str(log),'-global','isa-debugcon.iobase=0x402','-device','isa-debug-exit,iobase=0xf4,iosize=0x4','-drive','if=pflash,format=raw,unit=0,readonly=on,file='+str(share/'edk2-x86_64-code.fd'),'-drive','if=pflash,format=raw,unit=1,file='+str(varsfile),'-drive','if=none,id=boot,format=raw,file='+str(image),'-device','ide-hd,drive=boot,bus=ide.0,bootindex=1']
(run/'command.json').write_text(json.dumps(args,indent=2),encoding='utf8')
start=time.monotonic()
with (run/'stdout.log').open('wb') as stdout,(run/'stderr.log').open('wb') as stderr:
 proc=subprocess.Popen(args,stdin=subprocess.DEVNULL,stdout=stdout,stderr=stderr,creationflags=subprocess.CREATE_NO_WINDOW)
 try:code=proc.wait(timeout=60)
 except subprocess.TimeoutExpired:
  proc.terminate();proc.wait(timeout=5);raise TimeoutError('Owned OVMF EBS fixture did not finish in 60 seconds')
text=log.read_text(encoding='ascii',errors='replace')
report={'status':'PASS' if code==33 and 'EBS_CANDIDATE_OVMF_PASS' in text and 'FAIL ' not in text else 'FAIL','exit_code':code,'seconds':round(time.monotonic()-start,2),'checks':text.count('PASS '),'candidate_driver_sha256':sha(HERE/'build/AiTweakerLock1904.efi'),'candidate_services_obj_sha256':sha(HERE/'build/services.obj'),'fixture_sha256':sha(app),'fixture_source_sha256':sha(HERE/'ovmf_handoff.c'),'original_ovmf_code_sha256':sha(share/'edk2-x86_64-code.fd'),'debug_log':str(log),'debug_sha256':sha(log),'scope':'Actual candidate services object, real OVMF memory attributes/RT table/event delivery/invalid-MapKey retry. Owner predicates are explicit false stubs; no navigation or password writes run. No ASUS navigation, physical boot, or hardware flash claim.'}
(run/'result.json').write_text(json.dumps(report,indent=2),encoding='utf8');(HERE/'ovmf_handoff_result.json').write_text(json.dumps(report,indent=2),encoding='utf8')
print(text);print(json.dumps(report,indent=2));assert report['status']=='PASS'
