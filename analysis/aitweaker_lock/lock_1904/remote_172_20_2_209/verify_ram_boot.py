"""Boot the exact RAM-test ISO on non-target OVMF and validate refusal/QR/exit."""
from pathlib import Path
import datetime,hashlib,json,shutil,subprocess,sys,time
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[3];OUT=HERE/'ram_test'
sys.path[:0]=[str(HERE.parents[1]/'uefi_vm_20261015'),str(HERE.parents[1]/'probe_p3_kvm')]
from run_vm_tests import QMP,ppm_to_png,QEMU,SHARE,CODE,VARS
from decode_captures import read_image,assemble
sha=lambda p:hashlib.sha256(Path(p).read_bytes()).hexdigest()
iso=OUT/'AiTweaker-P5-RAM-Test.iso';folder=OUT/'vm'/datetime.datetime.now().strftime('%Y%m%d_%H%M%S');folder.mkdir(parents=True)
shutil.copyfile(VARS,folder/'vars.fd')
args=[str(QEMU),'-L',str(SHARE),'-machine','q35,accel=tcg','-cpu','max','-m','512','-smp','1','-nic','none','-display','none','-monitor','none','-qmp','stdio','-vga','none','-device','VGA,xres=1280,yres=800','-serial','file:'+str(folder/'serial.log'),'-drive','if=pflash,format=raw,unit=0,readonly=on,file='+str(CODE),'-drive','if=pflash,format=raw,unit=1,file='+str(folder/'vars.fd'),'-drive','if=none,id=cd,format=raw,media=cdrom,readonly=on,file='+str(iso),'-device','qemu-xhci,id=xhci','-device','usb-storage,drive=cd,bus=xhci.0,bootindex=1']
(folder/'command.json').write_text(json.dumps(args,indent=2),encoding='utf8')
result={'passed':False,'iso_sha256':sha(iso),'efi_sha256':sha(OUT/'BOOTX64.EFI'),'folder':str(folder),'scope':'Exact hardware test application boots from USB CD on OVMF and refuses non-target board; this does not emulate ASUS UI.'}
proc=None
try:
 with (folder/'stderr.log').open('wb') as err:
  proc=subprocess.Popen(args,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=err,text=True,encoding='utf8',creationflags=subprocess.CREATE_NO_WINDOW)
  qmp=QMP(proc,folder);qmp.command('qmp_capabilities',timeout=15)
  deadline=time.monotonic()+45;decoded=None
  while time.monotonic()<deadline:
   time.sleep(.5)
   ppm=folder/'screen.ppm';png=folder/'screen.png';qmp.command('screendump',{'filename':str(ppm)});ppm_to_png(ppm,png)
   try:decoded=read_image(png);break
   except ValueError:pass
  assert decoded,'Expected diagnostic QR was not visible'
  data,meta=assemble([decoded]);(folder/'RESTORED-LOG.TXT').write_bytes(data)
  assert b'UNSUPPORTED_BOARD_NO_HOOKS_NO_WRITES\r\n' in data and b'Production.SMBIOS.board_match=0x0000000000000000\r\n' in data
  assert b'P5_RAM_LOCK_TEST\r\n' in data and b'BlockedSetVariableCalls=0x0000000000000000\r\n' in data
  serial=(folder/'serial.log').read_bytes();assert data==serial.split(b'KVM_LOG_BEGIN\r\n',1)[1].split(b'KVM_LOG_END\r\n',1)[0]
  qmp.command('send-key',{'keys':[{'type':'qcode','data':'esc'}],'hold-time':80});time.sleep(1)
  assert b'P3 KVM ended.' in (folder/'serial.log').read_bytes()
  qmp.command('quit');assert proc.wait(timeout=10)==0;qmp.thread.join(timeout=2)
  assert sha(iso)==result['iso_sha256'];result.update(passed=True,qr=meta,refusal_verified=True,exit_verified=True,medium_unchanged=True)
finally:
 if proc and proc.poll() is None:proc.terminate();proc.wait(timeout=5)
 (OUT/'vm_validation.json').write_text(json.dumps(result,indent=2),encoding='utf8')
 print(json.dumps(result,indent=2))
