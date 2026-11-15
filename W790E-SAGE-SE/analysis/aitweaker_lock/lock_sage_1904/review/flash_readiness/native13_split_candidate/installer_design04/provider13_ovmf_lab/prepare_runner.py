"""Generate a NEW bounded local runner, preserving the reference unchanged."""
from pathlib import Path
HERE=Path(__file__).resolve().parent
OLD=HERE.parents[2]/'native_provider12_ui_simulation/run_persist_ui.py'
old=OLD.read_text(encoding='utf8')
middle=old[old.index('class QMP:'):]
middle=middle.replace("'PERSIST_UI_OVMF_PASS'","'P13_UI_OVMF_PASS'")
middle=middle.replace("'-machine','q35,accel=tcg'","'-machine','q35','-accel','tcg,thread=single'")
middle=middle.replace("'bound_modules':{k:v['module_sha256']for k,v in B.items()}","'bound_modules':{k:sha(v)for k,v in inputs.items()if k!='PROVIDER'}")
middle=middle.replace("'frozen_candidate_63_artifacts_unchanged':True","'frozen_candidate_60_bindings_unchanged':True")
middle=middle.replace("'scope':'Real OVMF GetVariable/SetVariable, actual frozen provider and password UI, standard QMP keyboard, real modified AMITSE wrapper ownership. Two independent QEMU processes reuse one writable VAR copy.',",
"'scope':'Actual immutable P13 PE, real OVMF HII database + ConfigAccess callbacks/password UI/GetVariable/SetVariable; real detached guard with declared TCG body substitution. Two processes reuse one owned writable VAR copy.',")
start=middle.index("        'substitutions':[")
end=middle.index("        'limits':",start)
middle=middle[:start]+"""        'substitutions':['Exactly twelve reviewed detours are installed in loaded VM copies of original modules; OEM text outside those sites remains unchanged.',
                         'Only execution at the original loop continuation is redirected by a TCG-only #DB saved-context change. No OEM body bytes are patched.',
                         'LoadedImage FV-file paths and module BootServices globals are supplied. OEM DXE entrypoints and native ASUS browser body are not executed.',
                         'Guard RX and state RW-NX permissions use real OVMF CPU Arch services; this fixture is not the production allocation/publication transaction.'],
"""+middle[end:]
prefix='''"""Local P13 fixture; owned images/vars only, no NIC or host disks."""
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
(BUILD/'binding.h').write_text('\\n'.join(lines)+'\\n',encoding='utf8')
zig=ROOT/'tools/zig-x86_64-windows-0.14.1/zig.exe';env=os.environ.copy();env.update(ZIG_GLOBAL_CACHE_DIR=str(BUILD/'zig-global'),ZIG_LOCAL_CACHE_DIR=str(BUILD/'zig-local'))
compile_cmd=[str(zig),'clang','-target','x86_64-unknown-windows-msvc','-nostdinc','-isystem',str(zig.parent/'lib/include'),'-I',str(BUILD),'-I',str(CAND/'source'),'-std=c11','-O2','-Wall','-Wextra','-Werror','-ffreestanding','-fno-builtin','-fno-stack-protector','-mno-red-zone','-mno-stack-arg-probe','-fshort-wchar','-c',str(HERE/'persist_ui.c'),'-o',str(BUILD/'persist_ui.obj')]
subprocess.run(compile_cmd,check=True,env=env,cwd=ROOT)
app=BUILD/'P13-OVMF-FIXTURE-NOT-FOR-HARDWARE.EFI';link=[str(zig),'lld-link','/subsystem:efi_application','/entry:efi_main','/nodefaultlib','/machine:x64','/dynamicbase','/fixed:no','/nxcompat','/timestamp:0','/out:'+str(app),str(BUILD/'persist_ui.obj'),str(CAND/'build/password_crypto.obj')]
subprocess.run(link,check=True,env=env,cwd=ROOT);p=pefile.PE(str(app));p.OPTIONAL_HEADER.CheckSum=p.generate_checksum();app.write_bytes(p.write())
(BUILD/'build.json').write_text(json.dumps({'fixture_sha256':sha(app),'source_sha256':sha(HERE/'persist_ui.c'),'extra_source_sha256':sha(HERE/'fixture_extra.inc'),'provider_sha256':sha(provider),'commands':[compile_cmd,link]},indent=2)+'\\n')
run=HERE/'runs'/datetime.datetime.now().strftime('%Y%m%d_%H%M%S');run.mkdir(parents=True)
qemu=ROOT/'tools/qemu-11.1.0';share=qemu/'share';varsfile=run/'shared-vars.fd';shutil.copyfile(share/'edk2-i386-vars.fd',varsfile);initial_vars=sha(varsfile)
disk_images.OUT=run;disk_images.VOLUME_SIZE=16*1024*1024;image=run/'readonly-boot.img'
disk_images.create(image,'superfloppy',16,{'/EFI/BOOT/BOOTX64.EFI':app.read_bytes(),**{f'/{name}.EFI':path.read_bytes()for name,path in inputs.items()}});image_hash=sha(image)
'''
assert not(HERE/'run_persist_ui.py').exists()
(HERE/'run_persist_ui.py').write_text(prefix+middle,encoding='utf8',newline='\n')
print('Created independent P13 runner')
