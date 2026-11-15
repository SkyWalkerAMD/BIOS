from pathlib import Path
import datetime,hashlib,json,os,re,shutil,subprocess,sys
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent;D04=HERE.parents[2]
ROOT=next(p for p in HERE.parents if (p/'tools/pydeps').is_dir())
sys.path[:0]=[str(ROOT/'tools/pydeps'),str(ROOT/'analysis/aitweaker_lock/uefi_vm_20261015')]
import pefile,disk_images
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
provider=D04/'provider13/build/AiTweakerSplitProvider13.UNSIGNED.local.efi'
assert sha(provider)=='caa80df1fa6414d635d28a3b65fec1c265968482ddb66268412483eff95deca9'
p=pefile.PE(str(provider));mapped=p.get_memory_mapped_image().ljust(p.OPTIONAL_HEADER.SizeOfImage,b'\0')
asset=(HERE/'provider_asset.h').read_text();recorded=bytes(int(x)for x in re.search(r'provider_mapped_hash\[\]=\{(.*?)\}',asset)[1].split(','))
assert hashlib.sha256(mapped).digest()==recorded
(HERE/'canonical.h').write_text('static const uint8_t canonical[]={'+','.join(str(x)for x in mapped)+'};\n')
ranges=[(0,p.OPTIONAL_HEADER.SizeOfHeaders)]+[(s.VirtualAddress,s.Misc_VirtualSize)for s in p.sections]
(HERE/'regions.h').write_text('static const uint32_t regions[][2]={'+','.join('{'+str(a)+','+str(n)+'}'for a,n in ranges)+'};\n')
zig=ROOT/'tools/zig-x86_64-windows-0.14.1/zig.exe';build=HERE/'build';build.mkdir(exist_ok=True)
env=os.environ.copy();env.update(ZIG_GLOBAL_CACHE_DIR=str(build/'zig-global'),ZIG_LOCAL_CACHE_DIR=str(build/'zig-local'))
commands=[];objs=[]
for name in ['probe','password_crypto']:
    obj=build/(name+'.obj');objs.append(obj)
    cmd=[str(zig),'clang','-target','x86_64-unknown-windows-msvc','-nostdinc','-isystem',str(zig.parent/'lib/include'),'-I',str(HERE),'-O2','-std=c11','-Wall','-Wextra','-Werror','-ffreestanding','-fno-builtin','-fno-stack-protector','-mno-red-zone','-mno-stack-arg-probe','-fshort-wchar','-c',str(HERE/(name+'.c')),'-o',str(obj)]
    commands.append(cmd);subprocess.run(cmd,check=True,env=env,cwd=ROOT)
app=build/'LOADIMAGE-ONLY-TCG-NOT-FOR-HARDWARE.EFI'
cmd=[str(zig),'lld-link','/subsystem:efi_application','/entry:efi_main','/nodefaultlib','/machine:x64','/dynamicbase','/fixed:no','/timestamp:0','/out:'+str(app),*[str(o)for o in objs]]
commands.append(cmd);subprocess.run(cmd,check=True,env=env,cwd=ROOT)
run=HERE/'runs'/datetime.datetime.now().strftime('%Y%m%d_%H%M%S');run.mkdir(parents=True)
snapshot=run/'source_snapshot';snapshot.mkdir()
for source in ['probe.c','run.py','provider_asset.h','canonical.h','regions.h','efi.h','password_core.h','password_crypto.c']:
    shutil.copyfile(HERE/source,snapshot/source)
shutil.copyfile(app,snapshot/app.name)
qemu=ROOT/'tools/qemu-11.1.0';share=qemu/'share';varsfile=run/'vars.fd';shutil.copyfile(share/'edk2-i386-vars.fd',varsfile)
disk_images.OUT=run;disk_images.VOLUME_SIZE=16*1024*1024;boot=run/'readonly-boot.img';disk_images.create(boot,'superfloppy',16,{'/EFI/BOOT/BOOTX64.EFI':app.read_bytes()});before=sha(boot)
cmd=[str(qemu/'qemu-system-x86_64.exe'),'-L',str(share),'-machine','q35','-accel','tcg,thread=single','-cpu','max','-m','512','-smp','1','-nic','none','-display','none','-monitor','none','-serial','file:'+str(run/'serial.log'),'-debugcon','file:'+str(run/'debug.log'),'-global','isa-debugcon.iobase=0x402','-device','isa-debug-exit,iobase=0xf4,iosize=0x4','-drive','if=pflash,format=raw,unit=0,readonly=on,file='+str(share/'edk2-x86_64-code.fd'),'-drive','if=pflash,format=raw,unit=1,file='+str(varsfile),'-drive','if=none,id=boot,format=raw,readonly=on,file='+str(boot),'-device','qemu-xhci,id=xhci','-device','usb-storage,bus=xhci.0,drive=boot,bootindex=1']
(run/'command.json').write_text(json.dumps(cmd,indent=2)+'\n')
with (run/'stderr.log').open('wb')as err:
    proc=subprocess.Popen(cmd,stdout=subprocess.DEVNULL,stderr=err,creationflags=subprocess.CREATE_NO_WINDOW)
    try:code=proc.wait(timeout=45)
    finally:
        if proc.poll()is None:proc.terminate();proc.wait(timeout=5)
raw=(run/'debug.log').read_text(encoding='ascii',errors='replace');part=raw[raw.index('LOADIMAGE_IDENTITY_BEGIN'):]
assert code==33 and 'LOADIMAGE_IDENTITY_COMPLETE'in part and sha(boot)==before
items=dict(re.findall(r'^([A-Za-z0-9_]+)=([a-f0-9]+)$',part,re.M))
result={'status':'PASS_OBSERVATION_NOT_PLATFORM_ACCEPTANCE','provider_sha256':sha(provider),'canonical_mapped_sha256':recorded.hex(),
        'loadimage_started_provider':False,'exit_code':code,'readonly_boot_unchanged':True,'observations':items,'raw_observation':part,
        'app_sha256':sha(app),'ovmf_code_sha256':sha(share/'edk2-x86_64-code.fd'),
        'build_commands':commands,'source_bindings':[{'path':str(x),'bytes':x.stat().st_size,'sha256':sha(x)}for x in snapshot.iterdir()if x.is_file()]}
(run/'result.json').write_text(json.dumps(result,indent=2)+'\n');(HERE/'latest_result.json').write_text(json.dumps({'run':str(run),'result':result},indent=2)+'\n');print(part)
