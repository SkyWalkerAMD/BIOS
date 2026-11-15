"""Three isolated cold boots using real OVMF variable services and GOP."""
from pathlib import Path
from datetime import datetime,timezone
import hashlib,json,shutil,subprocess,sys,time,traceback
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent;TASK=HERE.parent;ROOT=TASK.parents[3]
sys.path[:0]=[str(ROOT/'analysis/aitweaker_lock/uefi_vm_20261015'),str(ROOT/'tools/kvm-pydeps')]
import disk_images,pycdlib
Q=ROOT/'tools/qemu-11.1.0';SHARE=Q/'share'
sha=lambda p:hashlib.sha256(Path(p).read_bytes()).hexdigest()
def save(path,value):path.write_text(json.dumps(value,indent=2)+'\n',encoding='utf8')
build=json.loads((TASK/'build/build.json').read_text());app=TASK/'build'/build['lab_file'];component=TASK/'build'/build['component_file']
assert sha(app)==build['lab']['sha256'] and sha(component)==build['component']['sha256']
assert sha(HERE/'lab_fixture.c')==build['lab_source_sha256']
folder=HERE/'runs'/datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S');folder.mkdir(parents=True)
inputs=folder/'inputs';inputs.mkdir()
for source in [TASK/'build/build.json',app,component,HERE/'lab_fixture.c',HERE/'profile_fixture.h']:
    shutil.copyfile(source,inputs/source.name)
source_manifest={}
for relative,expected in build['sources'].items():
    source=ROOT/relative
    assert sha(source)==expected,relative
    dest=inputs/relative;dest.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(source,dest)
    source_manifest[relative]=expected
save(inputs/'source-manifest.json',source_manifest)
varsfile=folder/'vars.fd';shutil.copyfile(SHARE/'edk2-i386-vars.fd',varsfile)
disk_images.OUT=folder;disk_images.VOLUME_SIZE=16*1024*1024
boot=folder/'boot.img';disk_images.create(boot,'superfloppy',16,{'/EFI/BOOT/BOOTX64.EFI':app.read_bytes()})
iso=folder/'runtime02-lab.iso';cd=pycdlib.PyCdlib();cd.new(interchange_level=3,vol_ident='W890_RUNTIME_LAB',joliet=3)
cd.add_file(str(boot),iso_path='/EFIBOOT.IMG;1',joliet_path='/EFIBOOT.IMG');cd.add_eltorito('/EFIBOOT.IMG;1',bootcatfile='/BOOT.CAT;1',boot_load_size=boot.stat().st_size//512,platform_id=0xef,efi=True,media_name='noemul');cd.write(str(iso));cd.close()
report={'status':'RUNNING','scope':'Real OVMF NVRAM/RNG/timer/GOP, scripted input in separate TCG-only carrier and modeled native owner. Hardware writes0.',
        'component_sha256':sha(component),'lab_sha256':sha(app),'build_sha256':sha(TASK/'build/build.json'),
        'iso_sha256_before':sha(iso),'firmware_sha256':sha(SHARE/'edk2-x86_64-code.fd'),'boots':[]}
try:
    for phase,code,marker in [(0,37,'INTERRUPT_BEFORE_COMMIT'),(1,39,'INTERRUPT_AFTER_COMMIT_BEFORE_READBACK'),(2,33,'W890_RUNTIME02_LAB_PASS')]:
        run=folder/f'boot{phase}';run.mkdir();debug=run/'debug.log'
        cmd=[str(Q/'qemu-system-x86_64.exe'),'-L',str(SHARE),'-machine','q35,accel=tcg','-cpu','max','-m','512','-smp','1','-nic','none',
             '-display','none','-monitor','none','-serial','file:'+str(run/'serial.log'),'-debugcon','file:'+str(debug),'-global','isa-debugcon.iobase=0x402',
             '-device','isa-debug-exit,iobase=0xf4,iosize=0x4','-device','virtio-rng-pci',
             '-drive','if=pflash,format=raw,unit=0,readonly=on,file='+str(SHARE/'edk2-x86_64-code.fd'),
             '-drive','if=pflash,format=raw,unit=1,file='+str(varsfile),
             '-drive','if=none,id=boot,format=raw,media=cdrom,readonly=on,file='+str(iso),'-device','ide-cd,drive=boot,bus=ide.0,bootindex=1']
        save(run/'command.json',cmd);print('START',phase,str(run),flush=True);start=time.monotonic()
        with (run/'stderr.log').open('wb')as err,(run/'stdout.log').open('wb')as out:
            p=subprocess.Popen(cmd,stdin=subprocess.DEVNULL,stdout=out,stderr=err,creationflags=subprocess.CREATE_NO_WINDOW)
            try:actual=p.wait(timeout=240)
            except subprocess.TimeoutExpired:p.terminate();p.wait(timeout=10);raise TimeoutError('OVMF carrier exceeded240s; retained original log')
        text=debug.read_text(encoding='ascii',errors='replace')
        item={'phase':phase,'exit_code':actual,'expected_exit_code':code,'seconds':round(time.monotonic()-start,3),
              'checks':text.count('PASS '),'marker':marker,'passed':actual==code and marker in text and 'FAIL 'not in text,
              'debug_sha256':sha(debug),'nvram_sha256':sha(varsfile)}
        report['boots'].append(item);save(run/'result.json',item)
        print(json.dumps(item),flush=True);assert item['passed'],text[-5000:]
    report['iso_sha256_after']=sha(iso);assert report['iso_sha256_after']==report['iso_sha256_before']
    report['status']='PASS_THREE_COLD_BOOTS_COMMIT_INTERRUPTION_RECOVERY'
except Exception as e:
    report['status']='FAILED_RETAINED_EVIDENCE';report['error']=str(e);report['traceback']=traceback.format_exc();raise
finally:
    report['finished_utc']=datetime.now(timezone.utc).isoformat();save(folder/'result.json',report)
    print('REPORT',str(folder/'result.json'),flush=True)
