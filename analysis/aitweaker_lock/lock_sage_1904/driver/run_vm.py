"""Real QEMU execution. Production DXE auto-dispatch on non-ASUS OVMF plus
actual services/UI/core in a TCG-only integration application. Separate scope
from OEM navigation and ASUS firmware boot compatibility."""
from pathlib import Path
import datetime,hashlib,json,os,shutil,subprocess,sys,time,traceback
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[3];LAB=HERE.parent/'lab'
sys.path[:0]=[str(LAB),str(HERE.parent.parent/'uefi_vm_20261015'),str(ROOT/'tools/kvm-pydeps')]
import disk_images,pycdlib
from inject_ovmf import inject
Q=ROOT/'tools/qemu-11.1.0';SHARE=Q/'share'
def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def save(p,o):p.write_text(json.dumps(o,indent=2),encoding='utf8')
def main():
 folder=HERE/'vm_runs'/datetime.datetime.now().strftime('%Y%m%d_%H%M%S');folder.mkdir(parents=True)
 driver=HERE/'build/AiTweakerLock1904.efi';app=HERE/'build/VM-INTEGRATION-ONLY.EFI'
 binding=json.loads((HERE/'build/vm_build.json').read_text(encoding='utf8'))
 assert binding['driver_sha256']==sha(driver) and binding['fixture_sha256']==sha(app)
 assert binding['production_build_sha256']==sha(HERE/'build/build.json')
 assert binding['fixture_source_sha256']==sha(HERE/'vm_fixture.c') and binding['build_script_sha256']==sha(HERE/'build_vm.py')
 for name,digest in binding['shared_objects'].items():assert sha(HERE/'build'/name)==digest
 firmware=LAB/'build/OVMF-ACTUAL-1904.fd';injected=inject(driver,firmware)
 report={'scope':'Production DXE automatic dispatch and unsupported-board refusal; actual compiled storage/UI/HII/policy/crypto adapter fixture on OVMF with original 1904 HII resources; OEM navigation not emulated by these VM boots.','driver_sha256':sha(driver),'fixture_sha256':sha(app),'firmware_sha256':sha(firmware),'groups':[],'all_passed':False}
 report['fixture_build_manifest_sha256']=sha(HERE/'build/vm_build.json')
 try:
  for cd in (False,True):
   group=folder/('readonly_iso' if cd else 'fat');group.mkdir();varsfile=group/'vars.fd';shutil.copyfile(SHARE/'edk2-i386-vars.fd',varsfile)
   disk_images.OUT=HERE;disk_images.VOLUME_SIZE=16*1024*1024
   image=group/'boot.img';disk_images.create(image,'superfloppy',16,{'/EFI/BOOT/BOOTX64.EFI':app.read_bytes()});medium=image
   if cd:
    medium=group/'integration.iso';iso=pycdlib.PyCdlib();iso.new(interchange_level=3,vol_ident='VM_TEST_ONLY',joliet=3)
    iso.add_file(str(image),iso_path='/EFIBOOT.IMG;1',joliet_path='/EFIBOOT.IMG');iso.add_eltorito('/EFIBOOT.IMG;1',bootcatfile='/BOOT.CAT;1',boot_load_size=image.stat().st_size//512,platform_id=0xef,efi=True,media_name='noemul');iso.write(str(medium));iso.close()
   result={'readonly_iso':cd,'medium_sha256_before':sha(medium),'boots':[]};report['groups'].append(result)
   for phase in range(3):
    run=group/('boot'+str(phase));run.mkdir();log=run/'debug.log'
    args=[str(Q/'qemu-system-x86_64.exe'),'-L',str(SHARE),'-machine','q35,accel=tcg','-cpu','max','-m','512','-smp','1','-nic','none','-display','none','-monitor','none','-serial','file:'+str(run/'serial.log'),'-debugcon','file:'+str(log),'-global','isa-debugcon.iobase=0x402','-device','isa-debug-exit,iobase=0xf4,iosize=0x4','-device','virtio-rng-pci','-drive','if=pflash,format=raw,unit=0,readonly=on,file='+str(firmware),'-drive','if=pflash,format=raw,unit=1,file='+str(varsfile),'-drive','if=none,id=boot,format=raw,file='+str(medium)+(',media=cdrom,readonly=on' if cd else ''),'-device',('ide-cd' if cd else 'ide-hd')+',drive=boot,bus=ide.0,bootindex=1']
    save(run/'command.json',args);started=time.monotonic();print('START',group.name,phase,flush=True)
    with (run/'stderr.log').open('wb') as err,(run/'stdout.log').open('wb') as out:
     proc=subprocess.Popen(args,stdin=subprocess.DEVNULL,stdout=out,stderr=err,creationflags=subprocess.CREATE_NO_WINDOW)
     try:code=proc.wait(timeout=240)
     except subprocess.TimeoutExpired:
      proc.terminate();proc.wait(timeout=5);raise TimeoutError('VM integration fixture exceeded 240 seconds; inspect debug log')
    text=log.read_text(encoding='ascii',errors='replace');r={'phase':phase,'exit_code':code,'seconds':round(time.monotonic()-started,2),'debug_sha256':sha(log),'nvram_sha256':sha(varsfile),'checks':text.count('PASS '),'passed':code==33 and 'INTEGRATION_PASS' in text and 'FAIL ' not in text and f'PHASE={phase:016x}' in text};result['boots'].append(r)
    save(run/'result.json',r);print('PASS' if r['passed'] else 'FAIL',group.name,phase,'seconds',r['seconds'],flush=True)
    assert r['passed'],text[-6000:]
   result['medium_sha256_after']=sha(medium)
   if cd:assert result['medium_sha256_before']==result['medium_sha256_after']
  report['all_passed']=True
 except Exception as exc:report['error']=str(exc);report['traceback']=traceback.format_exc();raise
 finally:
  report['finished_utc']=datetime.datetime.now(datetime.timezone.utc).isoformat();save(folder/'result.json',report);save(HERE/'build/vm_integration.json',report)
 print('All six integration cold boots PASS',folder,flush=True)
if __name__=='__main__':main()
