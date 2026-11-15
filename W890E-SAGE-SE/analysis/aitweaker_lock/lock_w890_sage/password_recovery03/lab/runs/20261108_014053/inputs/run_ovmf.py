from pathlib import Path
from datetime import datetime,timezone
import hashlib,json,shutil,socket,subprocess,sys,time,traceback
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent;TASK=HERE.parent;ROOT=TASK.parents[3]
sys.path[:0]=[str(TASK),str(ROOT/'analysis/aitweaker_lock/uefi_vm_20261015'),str(ROOT/'tools/kvm-pydeps')]
import disk_images,pycdlib,handoff
Q=ROOT/'tools/qemu-11.1.0';SHARE=Q/'share';sha=lambda p:hashlib.sha256(Path(p).read_bytes()).hexdigest()
def save(path,value):path.write_text(json.dumps(value,indent=2)+'\n',encoding='utf8')
build=json.loads((TASK/'build/build.json').read_text());app=TASK/'build'/build['lab']['file'];component=TASK/'build'/build['component']['file']
assert sha(app)==build['lab']['sha256']and sha(component)==build['component']['sha256']
folder=HERE/'runs'/datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S');folder.mkdir(parents=True);inputs=folder/'inputs';inputs.mkdir()
for source in [TASK/'build/build.json',app,component,TASK/'handoff.py',HERE/'handoff-fixture.dpapi',Path(__file__)]:shutil.copyfile(source,inputs/source.name)
for relative,expected in (build['sources']|build['lab_sources']).items():
    source=TASK/relative;assert sha(source)==expected
    destination=inputs/relative;destination.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(source,destination)
varsfile=folder/'vars.fd';shutil.copyfile(SHARE/'edk2-i386-vars.fd',varsfile)
disk_images.OUT=folder;disk_images.VOLUME_SIZE=16*1024*1024;boot=folder/'boot.img'
disk_images.create(boot,'superfloppy',16,{'/EFI/BOOT/BOOTX64.EFI':app.read_bytes()})
iso=folder/'recovery03-lab.iso';cd=pycdlib.PyCdlib();cd.new(interchange_level=3,vol_ident='W890_RECOVERY_LAB',joliet=3)
cd.add_file(str(boot),iso_path='/EFIBOOT.IMG;1',joliet_path='/EFIBOOT.IMG');cd.add_eltorito('/EFIBOOT.IMG;1',bootcatfile='/BOOT.CAT;1',boot_load_size=boot.stat().st_size//512,platform_id=0xef,efi=True,media_name='noemul');cd.write(str(iso));cd.close()
probe=socket.socket();probe.bind(('127.0.0.1',0));port=probe.getsockname()[1];probe.close()
debug=folder/'debug.log';cmd=[str(Q/'qemu-system-x86_64.exe'),'-L',str(SHARE),'-machine','q35,accel=tcg','-cpu','max','-m','512','-smp','1','-nic','none',
 '-display','none','-monitor','none','-serial','file:'+str(folder/'serial.log'),'-debugcon','file:'+str(debug),'-global','isa-debugcon.iobase=0x402',
 '-qmp',f'tcp:127.0.0.1:{port},server=on,wait=off','-device','isa-debug-exit,iobase=0xf4,iosize=0x4',
 '-drive','if=pflash,format=raw,unit=0,readonly=on,file='+str(SHARE/'edk2-x86_64-code.fd'),'-drive','if=pflash,format=raw,unit=1,file='+str(varsfile),
 '-drive','if=none,id=boot,format=raw,media=cdrom,readonly=on,file='+str(iso),'-device','ide-cd,drive=boot,bus=ide.0,bootindex=1']
save(folder/'command.json',cmd);report={'status':'RUNNING','component_sha256':sha(component),'lab_sha256':sha(app),
 'build_sha256':sha(TASK/'build/build.json'),'iso_sha256_before':sha(iso),'physical_operations':0,'qmp_key_payloads_logged':False}
p=None;keyboard=None
try:
    with (folder/'stderr.log').open('wb')as err,(folder/'stdout.log').open('wb')as out:
        p=subprocess.Popen(cmd,stdin=subprocess.DEVNULL,stdout=out,stderr=err,creationflags=subprocess.CREATE_NO_WINDOW)
        deadline=time.monotonic()+120
        while time.monotonic()<deadline:
            output=debug.read_text(encoding='ascii',errors='replace')if debug.exists()else''
            if 'READY_FOR_DPAPI_HANDOFF'in output:break
            if p.poll()is not None:raise RuntimeError('Carrier exited before handoff; inspect retained debug log')
            time.sleep(.1)
        else:raise TimeoutError('Carrier did not request handoff')
        target='QEMU-W890-RECOVERY03-ISOLATED';keyboard=handoff.LocalQmpKeyboard(port,target)
        report['handoff']=handoff.deliver_candidate(HERE/'handoff-fixture.dpapi',target,'before',keyboard)
        keyboard.key(['y']);time.sleep(5);keyboard.key(['spc']);keyboard.close();keyboard=None
        result=p.wait(timeout=90)
    output=debug.read_text(encoding='ascii',errors='replace')
    # Check for accidental plaintext disclosure without emitting the strings.
    fixture=handoff.journal.open_fixture(HERE/'handoff-fixture.dpapi',target)
    assert all(fixture[k]not in output for k in ['before','after']),'unexpected credential disclosure; output withheld'
    report.update(exit_code=result,check_count=output.count('PASS '),debug_sha256=sha(debug),vars_sha256=sha(varsfile),
                  no_plaintext_password_in_debug=True,iso_sha256_after=sha(iso))
    assert result==33 and 'RECOVERY03_LAB_PASS'in output and 'FAIL 'not in output
    assert report['iso_sha256_after']==report['iso_sha256_before']
    report['status']='PASS_REAL_OVMF_RECOVERY_AND_DPAPI_KEYBOARD_HANDOFF'
except Exception as error:
    report['status']='FAILED_RETAINED_EVIDENCE';report['error_type']=type(error).__name__
    if p and p.poll()is None:p.terminate();p.wait(timeout=10)
    raise
finally:
    if keyboard:keyboard.close()
    report['finished_utc']=datetime.now(timezone.utc).isoformat();save(folder/'result.json',report)
    print(json.dumps({'status':report['status'],'checks':report.get('check_count'),'report':str(folder/'result.json')}),flush=True)
