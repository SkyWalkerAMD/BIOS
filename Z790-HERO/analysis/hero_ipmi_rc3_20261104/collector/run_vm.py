"""Boot delivered ISO/USB in OVMF without R2; no network or host disk access."""
from pathlib import Path
import hashlib,json,shutil,subprocess,sys,time
P=Path(__file__).resolve().parent;ROOT=P.parents[2]
sys.dont_write_bytecode=True
sys.path.insert(0,str(ROOT/'analysis/aitweaker_lock/uefi_vm_20261015'))
sys.path.insert(0,str(ROOT/'tools/vm-pydeps'))
from run_vm_tests import QMP,ppm_to_png,QEMU,SHARE,CODE,VARS
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def run(name,usb):
 folder=P/'vm'/name;folder.mkdir(parents=True,exist_ok=True)
 shutil.copyfile(VARS,folder/'vars.fd')
 args=[str(QEMU),'-L',str(SHARE),'-machine','q35,accel=tcg','-cpu','max','-m','256','-nic','none','-display','none','-monitor','none','-qmp','stdio','-vga','none','-device','VGA,xres='+('640,yres=480' if usb else '1280,yres=800'),'-serial','file:'+str(folder/'serial.log'),'-drive','if=pflash,format=raw,unit=0,readonly=on,file='+str(CODE),'-drive','if=pflash,format=raw,unit=1,file='+str(folder/'vars.fd')]
 if usb:
  shutil.copyfile(P/'efi-boot.img',folder/'usb.img')
  args+=['-drive','if=none,id=boot,format=raw,file='+str(folder/'usb.img'),'-device','qemu-xhci,id=xhci','-device','usb-storage,drive=boot,bus=xhci.0,bootindex=1']
 else:args+=['-drive','if=none,id=cd,format=raw,media=cdrom,readonly=on,file='+str(P/'HERO-RC3-AUTO-LOG.iso'),'-device','ide-cd,drive=cd,bus=ide.0,bootindex=1']
 (folder/'command.json').write_text(json.dumps(args,indent=2)+'\n')
 proc=subprocess.Popen(args,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=(folder/'stderr.log').open('w'),text=True,encoding='utf-8',bufsize=1,creationflags=subprocess.CREATE_NO_WINDOW)
 qmp=QMP(proc,folder);qmp.command('qmp_capabilities')
 def serial():return (folder/'serial.log').read_bytes() if (folder/'serial.log').exists() else b''
 try:
  deadline=time.monotonic()+45
  while b'Enter/Esc/Q = return to firmware.' not in serial():
   if time.monotonic()>deadline:raise TimeoutError(serial()[-1800:])
   if proc.poll() is not None:raise RuntimeError('VM stopped')
   time.sleep(.1)
  before=serial();assert b'RESIDENT R2 CORE NOT AVAILABLE. No driver will be loaded.' in before
  assert b'Session result: 0x800000000000000E' in before
  time.sleep(.4) # Serial completion can precede the final console framebuffer update.
  (folder/'before-exit-serial.log').write_bytes(serial())
  assert b'BdsDxe: failed to start' not in serial(), 'application returned before exit key'
  ppm=folder/'capture-only-no-core.ppm';qmp.command('screendump',{'filename':str(ppm)});ppm_to_png(ppm,ppm.with_suffix('.png'))
  qmp.command('send-key',{'keys':[{'type':'qcode','data':'ret'}],'hold-time':70})
  time.sleep(.5)
  result=dict(case=name,passed=True,no_core_message_visible=True,no_core_loaded=True,app_return_key_sent=True,
   iso_sha256=sha(P/'HERO-RC3-AUTO-LOG.iso'),app_sha256=sha(P/'USB/EFI/BOOT/BOOTX64.EFI'),screenshot_sha256=sha(ppm.with_suffix('.png')))
  (folder/'result.json').write_text(json.dumps(result,indent=2)+'\n');print(name,'PASS',flush=True);return result
 finally:
  if proc.poll() is None:
   try:qmp.command('quit')
   except Exception:proc.terminate()
  proc.wait(timeout=10)
if __name__=='__main__':
 rows=[run('iso_readonly',False),run('usb',True)]
 report=dict(all_passed=True,cases=rows,limitations=['OVMF boot/loader/no-core path only, not motherboard firmware dispatch or R2 hardware behavior.',
  'Exploratory USB VGA 1024x768 screenshots were intermittently partial/black while serial and input remained operational; cause unresolved. Final visual checks cover ISO 1280x800 and USB 640x480 only.'])
 (P/'vm-verification.json').write_text(json.dumps(report,indent=2)+'\n')
