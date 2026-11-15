"""Boot exact .15 ISO in OVMF with synthetic identity; D/QR/Q/Q only, no R5 load."""
from pathlib import Path
import sys,json,hashlib,shutil,subprocess,time
OUT=Path(__file__).resolve().parent;ROOT=OUT.parents[2]
sys.dont_write_bytecode=True
for p in ('analysis/aitweaker_lock/uefi_vm_20261015','tools/vm-pydeps'):sys.path.insert(0,str(ROOT/p))
from run_vm_tests import QMP,ppm_to_png,QEMU,SHARE,CODE,VARS
from decode_captures import read_image,parse_frame,assemble

def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 folder=OUT/'vm-preflight';n=1
 while folder.exists():n+=1;folder=OUT/f'vm-preflight-{n}'
 folder.mkdir();shutil.copyfile(VARS,folder/'vars.fd');iso=OUT/'HERO15-R5-AUTO-BDS-TEST.iso'
 args=[str(QEMU),'-L',str(SHARE),'-machine','q35,accel=tcg','-cpu','max','-m','256','-nic','none','-display','none','-monitor','none','-qmp','stdio','-device','VGA,xres=1280,yres=800','-serial','file:'+str(folder/'serial.log'),
       '-smbios','type=0,vendor=AMI,version=3107,date=11/28/2025','-smbios','type=1,uuid=b222f546-dbb3-9ac8-bbfb-581122d8be9f','-smbios','type=2,manufacturer=ASUSTeK COMPUTER INC.,product=ROG MAXIMUS Z790 HERO',
       '-drive','if=pflash,format=raw,unit=0,readonly=on,file='+str(CODE),'-drive','if=pflash,format=raw,unit=1,file='+str(folder/'vars.fd'),
       '-drive','if=none,id=cd,format=raw,media=cdrom,readonly=on,file='+str(iso),'-device','ide-cd,drive=cd,bus=ide.0,bootindex=1']
 (folder/'command.json').write_text(json.dumps(args,indent=2)+'\n',encoding='utf-8')
 proc=subprocess.Popen(args,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=(folder/'stderr.log').open('w'),text=True,encoding='utf-8',bufsize=1,creationflags=subprocess.CREATE_NO_WINDOW)
 qmp=QMP(proc,folder);qmp.command('qmp_capabilities')
 def serial():return (folder/'serial.log').read_bytes() if (folder/'serial.log').exists() else b''
 def wait(token,start=0,seconds=50):
  end=time.monotonic()+seconds
  while time.monotonic()<end:
   if token in serial()[start:]:return
   if proc.poll() is not None:raise RuntimeError('VM stopped')
   time.sleep(.1)
  raise TimeoutError((token,serial()[-1800:]))
 def press(key,token=None):
  start=len(serial());qmp.command('send-key',{'keys':[{'type':'qcode','data':key}],'hold-time':70})
  if token:wait(token,start)
 def shot(label):
  ppm=folder/(label+'.ppm');qmp.command('screendump',{'filename':str(ppm)});png=ppm.with_suffix('.png');ppm_to_png(ppm,png);return png
 def capture(page):
  end=time.monotonic()+10
  while time.monotonic()<end:
   time.sleep(.25)
   try:
    raw=read_image(shot(f'preflight-{page:03}'))
    if parse_frame(raw)['page']==page:return raw
   except ValueError:pass
  raise RuntimeError('QR capture failed')
 try:
  wait(b'FIRST PASS: D=read');shot('booted');press('d',b'READ_ONLY_PREFLIGHT=');shot('diagnostic')
  # OVMF has no ASPEED management device. Refusal is the expected result.
  assert b'READ_ONLY_PREFLIGHT=0x8000000000000021' in serial()
  press('c',b'QR PAGE 1/');first=capture(1);frames=[first]
  for page in range(2,parse_frame(first)['pages']+1):press('n');frames.append(capture(page))
  data,meta=assemble(frames);(folder/'OVMF-PREFLIGHT.TXT').write_bytes(data)
  assert b'IDENTITY=HERO / 3107 / .15 raw Type1 UUID exact' in data
  assert b'PCI_MATCHES=0000 COMPLETE=1' in data and b'API_CONNECTED=00' in data
  assert b'NO KCS OR CONFIGURATION WRITES' in data and b'HERO-IPMI-R5 CORE' not in data
  press('esc',b'PREFLIGHT_VIEWER=');press('q',b'Press Q again');press('q');time.sleep(1);shot('returned-firmware')
  assert b'LOAD_IMAGE=' not in serial() and b'START_IMAGE=' not in serial()
  result={'passed':True,'iso_sha256':sha(iso),'launcher_sha256':sha(OUT/'USB/EFI/BOOT/BOOTX64.EFI'),
          'capture':meta,'no_driver_load':True,'synthetic_identity_only':True,'no_aspeed_expected_rejection':True,
          'q_q_returned':True,'limitation':'OVMF exercises ISO boot, diagnostic refusal, QR reconstruction and exit; not real .15 PCI or BDS initialization.'}
  (folder/'result.json').write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8');print(json.dumps(result,indent=2),flush=True)
 finally:
  if proc.poll() is None:
   try:qmp.command('quit')
   except Exception:proc.terminate()
  proc.wait(timeout=10)
if __name__=='__main__':main()
