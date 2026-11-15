"""Actual local UEFI PE loader/provider/EBS smoke test, no OEM StartImage."""
from pathlib import Path
import datetime,hashlib,json,os,re,shutil,subprocess,sys,time
HERE=Path(__file__).resolve().parent;CASE=HERE.parents[2];ROOT=CASE.parents[2]
sys.path[:0]=[str(ROOT/'tools/pydeps'),str(CASE.parent/'uefi_vm_20261015')]
import pefile,disk_images
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
BUILD=HERE/'build';OUT=HERE/'ovmf_build';OUT.mkdir(exist_ok=True)
build=json.loads((BUILD/'build.json').read_text());binding=json.loads((HERE/'guard_binding.json').read_text())
provider=BUILD/'AiTweakerNativeProvider1904.UNSIGNED.review.efi';assert sha(provider)==build['efi_sha256']
assert sha(HERE/'guard_binding.json')==build['guard_binding_sha256']
inputs={'TSE':Path(binding['modules']['AMITSE']['module_file']),'SETUP':Path(binding['modules']['Setup']['module_file']),'PROVIDER':provider}
for key,name in [('TSE','AMITSE'),('SETUP','Setup')]:assert sha(inputs[key])==binding['modules'][name]['module_sha256']
lines=[]
for name,path in inputs.items():
    lines.append(f'#define {name}_FILE_BYTES {path.stat().st_size}u')
    lines.append(f'static const uint8_t {name.lower()}_file_hash[32]={{'+','.join(f'0x{x:02x}'for x in bytes.fromhex(sha(path)))+'};')
for key,value in [('TSE_IMAGE_BYTES',binding['modules']['AMITSE']['image_bytes']),('TSE_GUARD_RVA',binding['modules']['AMITSE']['payload_rva']),('TSE_CONTEXT_RVA',binding['modules']['AMITSE']['context_head_rva'])]:lines.append(f'#define {key} 0x{value:x}u')
(OUT/'ovmf_binding.h').write_text('\n'.join(lines)+'\n')
zig=ROOT/'tools/zig-x86_64-windows-0.14.1/zig.exe';env=os.environ.copy();env.update(ZIG_GLOBAL_CACHE_DIR=str(ROOT/'tools/zig-cache-global'),ZIG_LOCAL_CACHE_DIR=str(ROOT/'tools/zig-cache-local'))
cmd=[str(zig),'clang','-target','x86_64-unknown-windows-msvc','-nostdinc','-isystem',str(zig.parent/'lib/include'),'-I',str(OUT),'-I',str(HERE/'source'),'-std=c11','-O2','-Wall','-Wextra','-Werror','-ffreestanding','-fno-builtin','-fno-stack-protector','-mno-red-zone','-mno-stack-arg-probe','-fshort-wchar','-c',str(HERE/'ovmf_load.c'),'-o',str(OUT/'ovmf_load.obj')]
subprocess.run(cmd,check=True,env=env,cwd=ROOT)
app=OUT/'OVMF-LOAD-ONLY.EFI';link=[str(zig),'lld-link','/subsystem:efi_application','/entry:efi_main','/nodefaultlib','/machine:x64','/dynamicbase','/fixed:no','/nxcompat','/timestamp:0','/out:'+str(app),str(OUT/'ovmf_load.obj'),str(BUILD/'password_crypto.obj')]
subprocess.run(link,check=True,env=env,cwd=ROOT);p=pefile.PE(str(app));p.OPTIONAL_HEADER.CheckSum=p.generate_checksum();app.write_bytes(p.write())
run=HERE/'vm'/datetime.datetime.now().strftime('%Y%m%d_%H%M%S');run.mkdir(parents=True)
qemu=ROOT/'tools/qemu-11.1.0';share=qemu/'share';varsfile=run/'vars.fd';shutil.copyfile(share/'edk2-i386-vars.fd',varsfile)
disk_images.OUT=run;disk_images.VOLUME_SIZE=16*1024*1024;image=run/'boot.img'
disk_images.create(image,'superfloppy',16,{'/EFI/BOOT/BOOTX64.EFI':app.read_bytes(),**{f'/{name}.EFI':path.read_bytes()for name,path in inputs.items()}})
image_hash=sha(image);log=run/'debug.log'
args=[str(qemu/'qemu-system-x86_64.exe'),'-L',str(share),'-machine','q35,accel=tcg','-cpu','max','-m','512','-smp','1','-nic','none','-display','none','-monitor','none','-serial','file:'+str(run/'serial.log'),'-debugcon','file:'+str(log),'-global','isa-debugcon.iobase=0x402','-device','isa-debug-exit,iobase=0xf4,iosize=0x4','-drive','if=pflash,format=raw,unit=0,readonly=on,file='+str(share/'edk2-x86_64-code.fd'),'-drive','if=pflash,format=raw,unit=1,file='+str(varsfile),'-drive','if=none,id=boot,format=raw,readonly=on,file='+str(image),'-device','qemu-xhci,id=xhci','-device','usb-storage,bus=xhci.0,drive=boot,bootindex=1']
(run/'command.json').write_text(json.dumps(args,indent=2)+'\n');start=time.monotonic()
with (run/'stdout.log').open('wb')as stdout,(run/'stderr.log').open('wb')as stderr:
    proc=subprocess.Popen(args,stdin=subprocess.DEVNULL,stdout=stdout,stderr=stderr,creationflags=subprocess.CREATE_NO_WINDOW)
    try:code=proc.wait(timeout=60)
    except subprocess.TimeoutExpired:proc.terminate();proc.wait(timeout=5);raise TimeoutError('Owned local loader fixture timeout')
text=log.read_text(encoding='ascii',errors='replace');success=code==33 and'NATIVE_PROVIDER_LOAD_OVMF_PASS'in text and'FAIL 'not in text
attrs={k:int(v,16)for k,v in re.findall(r'(TSE_GUARD_PAGE_ATTRS|TSE_CONTEXT_PAGE_ATTRS)=([0-9a-f]{16})',text)}
report={'status':'PASS_OVMF_LOAD_PROVIDER_EBS_ONLY'if success else'FAIL','exit_code':code,'seconds':round(time.monotonic()-start,2),
 'check_count':text.count('PASS '),'efi_sha256':sha(provider),'guard_binding_sha256':sha(HERE/'guard_binding.json'),
 'fixture_sha256':sha(app),'fixture_source_sha256':sha(HERE/'ovmf_load.c'),'runner_sha256':sha(Path(__file__)),
 'ovmf_code_sha256':sha(share/'edk2-x86_64-code.fd'),'debug_log':str(log),'debug_sha256':sha(log),'page_attributes':attrs,
 'page_attribute_bits':{'present':1,'writable':2,'NX':4},'input_disk_unchanged':sha(image)==image_hash,
 'OEM_entrypoints_started':False,'provider_entrypoint_started':'PASS actual provider driver starts in OVMF'in text,'password_enrollment_or_unlock_attempted_inside_owner':False,
 'scope':'Actual OVMF LoadImage of both modified PE modules, StartImage of complete provider, protocol refusal outside owner and final real EBS notification. No OEM module StartImage, no platform navigation, no physical flash or recovery acceptance.'}
(run/'result.json').write_text(json.dumps(report,indent=2)+'\n');(HERE/'ovmf_load_result.json').write_text(json.dumps(report,indent=2)+'\n')
print('\n'.join(line for line in text.splitlines()if line.startswith(('NATIVE_PROVIDER_','PASS ','FAIL ','LOAD_','TSE_','CHECKS='))))
print(json.dumps(report,indent=2));assert success and report['input_disk_unchanged']
