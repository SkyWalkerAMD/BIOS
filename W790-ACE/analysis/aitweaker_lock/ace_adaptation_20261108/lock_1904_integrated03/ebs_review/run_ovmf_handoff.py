"""Validate current services.obj with real local OVMF event/page-table services."""
from pathlib import Path
import datetime,hashlib,json,os,shutil,subprocess,sys,time
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent;CASE=HERE.parent;DRIVER=CASE/'driver';OUT=HERE/'build'
ROOT=next(p for p in HERE.parents if (p/'tools/qemu-11.1.0/qemu-system-x86_64.exe').is_file())
sys.path[:0]=[str(ROOT/'tools/pydeps'),str(ROOT/'analysis/aitweaker_lock/uefi_vm_20261015')]
import pefile,disk_images
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
build=json.loads((OUT/'build.json').read_text(encoding='utf8'))
assert all(sha(ROOT/p)==h for p,h in build['sources'].items())
assert sha(OUT/'services.obj')==build['services_obj_sha256']
zig=ROOT/'tools/zig-x86_64-windows-0.14.1/zig.exe'
env=os.environ.copy();env.update(ZIG_GLOBAL_CACHE_DIR=str(OUT/'.zig-global'),ZIG_LOCAL_CACHE_DIR=str(OUT/'.zig-local'),PYTHONDONTWRITEBYTECODE='1')
cmd=[str(zig),'clang','-target','x86_64-unknown-windows-msvc','-nostdinc','-isystem',str(zig.parent/'lib/include'),'-I',str(DRIVER),'-I',str(ROOT/'analysis/aitweaker_lock/probe_p3_kvm/source'),'-std=c11','-Oz','-Wall','-Wextra','-Werror','-ffreestanding','-fno-builtin','-fno-stack-protector','-mno-red-zone','-fshort-wchar','-c',str(HERE/'ovmf_handoff.c'),'-o',str(OUT/'ovmf_handoff.obj')]
subprocess.run(cmd,check=True,env=env,creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
objects=[OUT/(n+'.obj') for n in ['ovmf_handoff','services','cpu_entropy','password_core','password_crypto','probe_core']]
app=OUT/'OVMF-EBS-ONLY.EFI'
link=[str(zig),'lld-link','/subsystem:efi_application','/entry:efi_main','/nodefaultlib','/machine:x64','/dynamicbase','/fixed:no','/nxcompat','/timestamp:0','/out:'+str(app)]+[str(p) for p in objects]
subprocess.run(link,check=True,env=env,creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
pe=pefile.PE(str(app));pe.OPTIONAL_HEADER.CheckSum=pe.generate_checksum();app.write_bytes(pe.write());pe.close()
run=HERE/'vm'/datetime.datetime.now().strftime('%Y%m%d_%H%M%S');run.mkdir(parents=True)
qemu=ROOT/'tools/qemu-11.1.0';share=qemu/'share';varsfile=run/'vars.fd'
shutil.copyfile(share/'edk2-i386-vars.fd',varsfile)
disk_images.OUT=run;disk_images.VOLUME_SIZE=16*1024*1024;image=run/'boot.img'
disk_images.create(image,'superfloppy',16,{'/EFI/BOOT/BOOTX64.EFI':app.read_bytes()})
log=run/'debug.log'
args=[str(qemu/'qemu-system-x86_64.exe'),'-L',str(share),'-machine','q35,accel=tcg','-cpu','max','-m','512','-smp','1','-nic','none','-display','none','-monitor','none','-serial','file:'+str(run/'serial.log'),'-debugcon','file:'+str(log),'-global','isa-debugcon.iobase=0x402','-device','isa-debug-exit,iobase=0xf4,iosize=0x4','-drive','if=pflash,format=raw,unit=0,readonly=on,file='+str(share/'edk2-x86_64-code.fd'),'-drive','if=pflash,format=raw,unit=1,file='+str(varsfile),'-drive','if=none,id=boot,format=raw,file='+str(image),'-device','ide-hd,drive=boot,bus=ide.0,bootindex=1']
(run/'command.json').write_text(json.dumps(args,indent=2),encoding='utf8')
start=time.monotonic()
with (run/'stdout.log').open('wb') as stdout,(run/'stderr.log').open('wb') as stderr:
 proc=subprocess.Popen(args,stdin=subprocess.DEVNULL,stdout=stdout,stderr=stderr,creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
 try:code=proc.wait(timeout=45)
 except subprocess.TimeoutExpired:
  proc.terminate();proc.wait(timeout=5);raise TimeoutError('Owned EBS OVMF fixture did not finish in 45 seconds')
text=log.read_text(encoding='ascii',errors='replace')
report={'status':'PASS' if code==33 and 'ACE03_EBS_OVMF_PASS' in text and 'FAIL ' not in text else 'FAIL','exit_code':code,'seconds':round(time.monotonic()-start,2),'checks':text.count('PASS '),
 'services_obj_sha256':sha(OUT/'services.obj'),'fixture_sha256':sha(app),'fixture_source_sha256':sha(HERE/'ovmf_handoff.c'),
 'build_manifest_sha256':sha(OUT/'build.json'),'original_ovmf_code_sha256':sha(share/'edk2-x86_64-code.fd'),
 'debug_log':str(log.relative_to(ROOT)),'debug_sha256':sha(log),'source_sha256':build['sources'],
 'commands':[cmd,link],
 'scope':'Actual new ACE service object, real OVMF Before/Exit delivery, RT CRC, page-permission path and invalid MapKey retry. Browser ownership/navigation absent; no ASUS physical boot, flash or recovery claim.'}
(run/'result.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf8')
(HERE/'ovmf_handoff_result.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf8')
print('\n'.join(line for line in text.splitlines() if line.startswith(('PASS ','FAIL ','ACE03_','WRONG_MAP_KEY_STATUS=','BEFORE_COUNT_','OBSERVE_','CHECKS='))))
print(json.dumps({k:report[k] for k in ['status','checks','exit_code','seconds','services_obj_sha256','fixture_sha256','debug_log']},indent=2));assert report['status']=='PASS'
