"""Real OVMF memory-map/permission/CPU execution transaction lab."""
from pathlib import Path
from datetime import datetime,timezone
import hashlib,json,shutil,subprocess,sys,time
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[3]
sys.path[:0]=[str(ROOT/'tools/pydeps'),str(ROOT/'tools/kvm-pydeps'),str(ROOT/'analysis/aitweaker_lock/uefi_vm_20261015')]
import pycdlib
import disk_images
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def save(p,obj):p.write_text(json.dumps(obj,indent=2,ensure_ascii=False)+'\n',encoding='utf-8')
def main():
 watch=int(sys.argv[1]) if len(sys.argv)>1 else None
 name=datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')+(f'_watch{watch}' if watch is not None else '')
 folder=HERE/'runs'/name;folder.mkdir(parents=True)
 source=HERE/(f'watch_build/W890-ColdWatch04-{watch}.TCG-ONLY.efi' if watch is not None else 'build/W890-Installer04.TCG-ONLY.efi');app=folder/source.name;shutil.copyfile(source,app)
 manifest=json.loads((HERE/('watch_build' if watch is not None else 'build')/'build_manifest.json').read_text());assert sha(app)==(manifest['outputs'][str(watch)] if watch is not None else manifest['output'])['sha256']
 for p,s in manifest['inputs'].items():assert sha(Path(p))==s['sha256'],p
 save(folder/'build_manifest.json',manifest)
 disk_images.OUT=folder;disk_images.VOLUME_SIZE=16*1024*1024
 boot=folder/'boot.img';disk_images.create(boot,'superfloppy',16,{'/EFI/BOOT/BOOTX64.EFI':app.read_bytes()})
 iso=folder/'W890-Installer04.TCG-ONLY.iso';cd=pycdlib.PyCdlib();cd.new(interchange_level=3,vol_ident='W890_INSTALL04',joliet=3)
 cd.add_file(str(boot),iso_path='/EFIBOOT.IMG;1',joliet_path='/EFIBOOT.IMG');cd.add_eltorito('/EFIBOOT.IMG;1',bootcatfile='/BOOT.CAT;1',boot_load_size=boot.stat().st_size//512,platform_id=0xef,efi=True,media_name='noemul');cd.write(str(iso));cd.close()
 q=ROOT/'tools/qemu-11.1.0';share=q/'share';varsfile=folder/'vars.fd';shutil.copyfile(share/'edk2-i386-vars.fd',varsfile)
 debug=folder/'debug.log'
 cmd=[str(q/'qemu-system-x86_64.exe'),'-L',str(share),'-machine','q35,accel=tcg','-cpu','max','-m','512','-smp','1','-nic','none','-display','none','-monitor','none','-serial','file:'+str(folder/'serial.log'),'-debugcon','file:'+str(debug),'-global','isa-debugcon.iobase=0x402','-device','isa-debug-exit,iobase=0xf4,iosize=0x4','-drive','if=pflash,format=raw,unit=0,readonly=on,file='+str(share/'edk2-x86_64-code.fd'),'-drive','if=pflash,format=raw,unit=1,file='+str(varsfile),'-drive','if=none,id=boot,format=raw,media=cdrom,readonly=on,file='+str(iso),'-device','ide-cd,drive=boot,bus=ide.0,bootindex=1']
 save(folder/'qemu_command.json',cmd)
 result={'status':'RUNNING','scope':'Actual compiled W890 transaction under real OVMF CPU attributes/memory map/page tables and patch execution. Original firmware is present as lab-owned mapped copies, never started. Lab-only lease and return stubs do not establish physical loader/native ownership. No physical BIOS, HII, password or OC variable write.','efi_sha256':sha(app),'iso_before':sha(iso),'ovmf_sha256':sha(share/'edk2-x86_64-code.fd')}
 if watch is not None:
  result['scope']='Actual real-OVMF LoadedImage notification timing and exact original W890 image identity. Original AMITSE is LoadImage/UnloadImage only, never StartImage. No hook installed; not physical firmware ordering qualification.'
  result['preexisting_target']=watch==1
  result['fault_injection']={0:'none',1:'target loaded before arm',2:'direct nested-notify call via lab-only shim, not a real recursively dispatched UEFI event',3:'replace HandleProtocol pointer in a private Boot Services table copy, not the firmware global table'}[watch]
 print('START',folder,flush=True)
 try:
  start=time.monotonic()
  with (folder/'stdout.log').open('wb') as out,(folder/'stderr.log').open('wb') as err:
   proc=subprocess.Popen(cmd,stdin=subprocess.DEVNULL,stdout=out,stderr=err,creationflags=subprocess.CREATE_NO_WINDOW)
   try:code=proc.wait(timeout=120)
   except subprocess.TimeoutExpired:proc.terminate();proc.wait(timeout=10);raise RuntimeError('Lab timed out; evidence retained')
  text=debug.read_text(encoding='ascii',errors='replace');result.update(exit_code=code,checks=text.count('PASS '),debug_sha256=sha(debug),seconds=round(time.monotonic()-start,3),iso_after=sha(iso))
  assert code==33 and ('W890_COLD_WATCH_PASS' if watch is not None else 'W890_INSTALLER04_PASS') in text and 'FAIL ' not in text,text[-1800:]
  assert result['iso_before']==result['iso_after'];result['status']='PASS_REAL_OVMF_EARLY_LOADER_WATCH' if watch is not None else 'PASS_REAL_OVMF_OWNED_IMAGE_TRANSACTION'
 except Exception as e:result.update(status='FAILED_RETAINED_EVIDENCE',error=str(e));raise
 finally:save(folder/'result.json',result);print('REPORT',folder/'result.json',flush=True)
if __name__=='__main__':main()
