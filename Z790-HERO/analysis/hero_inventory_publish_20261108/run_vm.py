"""Final I3 ISO boot, wrong-host refusal and exact QR round trip in local OVMF."""
from pathlib import Path
import hashlib,json,shutil,subprocess,sys,time
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[1]
sys.path.insert(0,str(ROOT/'analysis/aitweaker_lock/uefi_vm_20261015'))
sys.path.insert(0,str(ROOT/'tools/vm-pydeps'));sys.path.insert(0,str(ROOT/'tools/kvm-pydeps'))
from run_vm_tests import QMP,ppm_to_png,QEMU,SHARE,CODE,VARS
import decode_captures as decoder
folder=HERE/'vm';folder.mkdir(exist_ok=True);shutil.copyfile(VARS,folder/'vars.fd')
args=[str(QEMU),'-L',str(SHARE),'-machine','q35,accel=tcg','-cpu','max','-m','256','-nic','none','-display','none','-monitor','none','-qmp','stdio','-vga','none','-device','VGA,xres=1280,yres=800','-serial','file:'+str(folder/'serial.log'),'-drive','if=pflash,format=raw,unit=0,readonly=on,file='+str(CODE),'-drive','if=pflash,format=raw,unit=1,file='+str(folder/'vars.fd'),'-drive','if=none,id=cd,format=raw,media=cdrom,readonly=on,file='+str(HERE/'HERO-INVENTORY-I3-READONLY.iso'),'-device','ide-cd,drive=cd,bus=ide.0,bootindex=1']
(folder/'command.json').write_text(json.dumps(args,indent=2)+'\n')
errors=(folder/'stderr.log').open('w')
proc=subprocess.Popen(args,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=errors,text=True,encoding='utf-8',bufsize=1,creationflags=subprocess.CREATE_NO_WINDOW)
qmp=QMP(proc,folder);qmp.command('qmp_capabilities')
def serial():return (folder/'serial.log').read_bytes() if (folder/'serial.log').exists() else b''
def wait(token,start=0):
 end=time.monotonic()+45
 while token not in serial()[start:]:
  if time.monotonic()>end:raise TimeoutError(serial()[-1500:])
  if proc.poll() is not None:raise RuntimeError('VM stopped')
  time.sleep(.1)
def key(k):qmp.command('send-key',{'keys':[{'type':'qcode','data':k}],'hold-time':70})
def shot(i):
 ppm=folder/f'qr-{i:03}.ppm';qmp.command('screendump',{'filename':str(ppm)});ppm_to_png(ppm,ppm.with_suffix('.png'))
 return decoder.read_image(ppm.with_suffix('.png'))
try:
 wait(b'D=inspect');key('ret');time.sleep(.15);assert b'RETURNING TO FIRMWARE' not in serial()
 for k in ('d','u','n','p','b'):
  old=len(serial());key(k);wait(b'Exact .71 HERO3107 identity required; network action refused.',old)
 old=len(serial());key('q');wait(b'Press Q again',old);key('ret');time.sleep(.15);assert b'RETURNING TO FIRMWARE' not in serial()
 key('c');wait(b'QR PAGE 1/');time.sleep(.3)
 text=serial();start=text.index(b'KVM_LOG_BEGIN\r\n')+len(b'KVM_LOG_BEGIN\r\n');end=text.index(b'KVM_LOG_END\r\n',start);log=text[start:end]
 first=shot(1);pages=decoder.parse_frame(first)['pages'];frames=[first]
 for i in range(2,pages+1):
  old=len(serial());key('n');wait(('QR PAGE '+str(i)+'/').encode(),old);time.sleep(.2);frames.append(shot(i))
 restored,meta=decoder.assemble(frames);assert restored==log
 (folder/'OVMF-I3-QR-roundtrip.TXT').write_bytes(restored)
 key('esc');time.sleep(.15);old=len(serial());key('q');wait(b'Press Q again',old);key('q');wait(b'HERO Inventory I3 RETURNING TO FIRMWARE')
 report={'passed':True,'wrong_host_all_network_actions_refused':True,'enter_never_exits':True,'two_q_exit_verified':True,
         'qr_all_pages_exact_roundtrip':meta,'iso_sha256':hashlib.sha256((HERE/'HERO-INVENTORY-I3-READONLY.iso').read_bytes()).hexdigest(),
         'app_sha256':hashlib.sha256((HERE/'USB/EFI/BOOT/BOOTX64.EFI').read_bytes()).hexdigest(),
         'limits':['No NIC attached; this is OVMF boot/display/gate verification, not target USB/TLS execution.']}
 (HERE/'vm-verification.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report))
finally:
 if proc.poll() is None:
  try:qmp.command('quit')
  except Exception:proc.terminate()
 proc.wait(timeout=10);errors.close()
