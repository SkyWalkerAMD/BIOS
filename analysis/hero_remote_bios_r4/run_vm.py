"""Boot the release ISO on isolated OVMF; unsupported platforms cannot write."""
from pathlib import Path
import sys,subprocess,shutil,time,json
OUT=Path(__file__).resolve().parent;ROOT=OUT.parents[1]
sys.dont_write_bytecode=True
sys.path.insert(0,str(ROOT/'analysis/aitweaker_lock/uefi_vm_20261015'))
from run_vm_tests import QMP,ppm_to_png,QEMU,SHARE,CODE,VARS
usb='--usb' in sys.argv
folder=OUT/('vm-usb' if usb else 'vm');folder.mkdir(exist_ok=True);shutil.copyfile(VARS,folder/'vars.fd')
args=[str(QEMU),'-L',str(SHARE),'-machine','q35,accel=tcg','-cpu','max','-m','256','-nic','none','-display','none','-monitor','none','-qmp','stdio','-vga','std','-serial','file:'+str(folder/'serial.log'),'-drive','if=pflash,format=raw,unit=0,readonly=on,file='+str(CODE),'-drive','if=pflash,format=raw,unit=1,file='+str(folder/'vars.fd')]
if usb:
 shutil.copyfile(OUT/'efi-boot.img',folder/'usb.img')
 args+=['-device','qemu-xhci','-drive','if=none,id=usb,format=raw,file='+str(folder/'usb.img'),'-device','usb-storage,drive=usb,bootindex=1']
else:
 args+=['-drive','if=none,id=cd,format=raw,media=cdrom,readonly=on,file='+str(OUT/'HERO-REMOTE-BIOS-R4.iso'),'-device','ide-cd,drive=cd,bus=ide.0,bootindex=1']
(folder/'command.json').write_text(json.dumps(args,indent=2))
proc=subprocess.Popen(args,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=(folder/'stderr.log').open('w'),text=True,bufsize=1,creationflags=subprocess.CREATE_NO_WINDOW)
qmp=QMP(proc,folder);qmp.command('qmp_capabilities')
def serial():return (folder/'serial.log').read_bytes() if (folder/'serial.log').exists() else b''
def wait(token,start=0):
 end=time.monotonic()+45
 while time.monotonic()<end:
  if token in serial()[start:]:return
  if proc.poll() is not None:raise RuntimeError('QEMU exited')
  time.sleep(.1)
 raise TimeoutError((token,serial()[-1500:]))
def key(k,token):
 start=len(serial());qmp.command('send-key',{'keys':[{'type':'qcode','data':k}],'hold-time':70});wait(token,start)
def shot(name):
 p=folder/(name+'.ppm');qmp.command('screendump',{'filename':str(p)});ppm_to_png(p,p.with_suffix('.png'))
try:
 wait(b'D=read O=load observer');assert b'SETUP_MAPPING_SKIPPED_WRONG_BOARD_OR_VERSION' in serial();shot('initial')
 key('o',b'OBSERVER_LOAD=0x0000000000000000')
 key('o',b'OBSERVER_LOAD=0x8000000000000014')
 key('h',b'OBSERVER_HISTORY=0x0000000000000000');assert b'DRIVER_ENTRY' in serial();shot('observer-loaded')
 key('d',b'OBSERVER_SAMPLE=0x0000000000000000')
 key('h',b'OBSERVER_HISTORY=0x0000000000000000');assert b'EXPLICIT_SAMPLE' in serial()
 key('l',b'FILE_LOG=0x0000000000000000' if usb else b'FILE_LOG=0x8000000000000008')
 key('v',b'TEXT PAGE 1/');shot('text-log');key('esc',b'D=read O=load observer')
 key('c',b'QR PAGE 1/');shot('qr-log');key('esc',b'D=read O=load observer')
 key('u',b'OBSERVER_UNLOAD=0x0000000000000000')
 key('h',b'OBSERVER_HISTORY=0x800000000000000E')
 key('o',b'OBSERVER_LOAD=0x0000000000000000')
 key('u',b'OBSERVER_UNLOAD=0x0000000000000000')
 key('q',b'Session ended.');key('ret',b'')
 assert b'SET_VARIABLE=' not in serial()
 result={'passed':True,'optical_boot':not usb,'usb_boot':usb,'observer_load':True,'duplicate_prevented':True,'read_and_history':True,'unload_and_reload':True,'text_and_qr_viewers':True,'clean_exit':True,'limitation':'OVMF validates application and observer lifecycle, not HERO protection-state transitions.'}
finally:
 if proc.poll() is None:
  try:qmp.command('quit')
  except Exception:proc.terminate()
 proc.wait(timeout=10)
if usb:
 sys.path.insert(0,str(ROOT/'tools/vm-pydeps'))
 from pyfatfs.PyFatFS import PyFatFS
 with PyFatFS(str(folder/'usb.img'),read_only=True) as fs:
  data=fs.readbytes('/R4LOG000.TXT')
  assert data.startswith(b'HERO-REMOTE-BIOS-R4\r\nRUN=') and data.endswith(b'SESSION_END\r\n')
  assert b'SET_VARIABLE=' not in data and b'SETUP_MAPPING_SKIPPED_WRONG_BOARD_OR_VERSION=' in data
  (folder/'R4LOG000.TXT').write_bytes(data)
 result['usb_file_log_readback']=True
(folder/'result.json').write_text(json.dumps(result,indent=2))
print('R4 OVMF '+('USB' if usb else 'optical')+' smoke PASS')
