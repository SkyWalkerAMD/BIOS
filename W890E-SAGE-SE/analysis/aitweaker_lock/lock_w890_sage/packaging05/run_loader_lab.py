from pathlib import Path
from datetime import datetime,timezone
import sys,shutil,json,hashlib,subprocess,time
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[3]
sys.path[:0]=[str(ROOT/'tools/pydeps'),str(ROOT/'tools/kvm-pydeps'),str(ROOT/'analysis/aitweaker_lock/uefi_vm_20261015')]
import pycdlib,disk_images
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
build=json.loads((HERE/'loader_build/build_manifest.json').read_text());source=Path(build['efi']);assert sha(source)==build['sha256']
for x in build['inputs']:assert sha(Path(x['path']))==x['sha256'],x['path']
folder=HERE/'loader_runs'/datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S');folder.mkdir(parents=True)
(folder/'build_manifest.json').write_text(json.dumps(build,indent=2)+'\n',encoding='utf-8')
disk_images.OUT=folder;disk_images.VOLUME_SIZE=16*1024*1024
boot=folder/'boot.img';disk_images.create(boot,'superfloppy',16,{'/EFI/BOOT/BOOTX64.EFI':source.read_bytes()})
iso=folder/'PACKAGING-ONLY.iso';cd=pycdlib.PyCdlib();cd.new(interchange_level=3,vol_ident='PACKAGING_LAB',joliet=3)
cd.add_file(str(boot),iso_path='/EFIBOOT.IMG;1',joliet_path='/EFIBOOT.IMG');cd.add_eltorito('/EFIBOOT.IMG;1',bootcatfile='/BOOT.CAT;1',boot_load_size=boot.stat().st_size//512,platform_id=0xef,efi=True,media_name='noemul');cd.write(str(iso));cd.close()
q=ROOT/'tools/qemu-11.1.0';share=q/'share';varsfile=folder/'vars.fd';shutil.copyfile(share/'edk2-i386-vars.fd',varsfile)
debug=folder/'debug.log'
cmd=[str(q/'qemu-system-x86_64.exe'),'-L',str(share),'-machine','q35,accel=tcg','-cpu','max','-m','512','-smp','1','-nic','none','-display','none','-monitor','none','-serial','file:'+str(folder/'serial.log'),'-debugcon','file:'+str(debug),'-global','isa-debugcon.iobase=0x402','-device','isa-debug-exit,iobase=0xf4,iosize=0x4','-drive','if=pflash,format=raw,unit=0,readonly=on,file='+str(share/'edk2-x86_64-code.fd'),'-drive','if=pflash,format=raw,unit=1,file='+str(varsfile),'-drive','if=none,id=boot,format=raw,media=cdrom,readonly=on,file='+str(iso),'-device','ide-cd,drive=boot,bus=ide.0,bootindex=1']
(folder/'command.json').write_text(json.dumps(cmd,indent=2)+'\n')
result={'status':'RUNNING','iso_before':sha(iso),'efi_sha256':sha(source),'OVMF_sha256':sha(share/'edk2-x86_64-code.fd'),'scope':'Actual OVMF LoadImage/StartImage of composed AMITSE PE with a TCG-only packaging fixture. No original AMITSE entry, physical board or password driver.'}
if build.get('functional_aggregate_load_only'):
 result['scope']='Actual composed functional aggregate receives real OVMF LoadImage, exact live-layout checks and UnloadImage. StartImage compiled out; original vendor entry and all password/HII functions are not run.'
 result['aggregate_sha256']=build['composition']['merged_sha256']
print('START '+str(folder),flush=True)
try:
 start=time.monotonic()
 with (folder/'stdout.log').open('wb')as out,(folder/'stderr.log').open('wb')as err:
  proc=subprocess.Popen(cmd,stdout=out,stderr=err,stdin=subprocess.DEVNULL,creationflags=subprocess.CREATE_NO_WINDOW)
  try:code=proc.wait(timeout=120)
  except subprocess.TimeoutExpired:proc.terminate();proc.wait(timeout=10);raise RuntimeError('bounded loader lab timeout')
 log=debug.read_text(encoding='ascii',errors='replace');result.update(exit_code=code,checks=log.count('PASS '),debug_sha256=sha(debug),seconds=round(time.monotonic()-start,3),iso_after=sha(iso))
 print(log[-3500:],flush=True)
 assert result['iso_before']==result['iso_after']
 assert code==33 and 'W890_PACKAGING_LOADER_PASS'in log and 'FAIL 'not in log
 result['status']='PASS_REAL_OVMF_COMPOSED_PE_LOADER'
except Exception as error:result.update(status='FAILED_RETAINED_EVIDENCE',error=str(error));raise
finally:
 (folder/'result.json').write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8');print('REPORT '+str(folder/'result.json'),flush=True)
