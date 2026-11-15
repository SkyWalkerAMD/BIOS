"""Boot exact I4 ISO in local OVMF; only synthetic snapshot disks, no NIC."""
from pathlib import Path
import hashlib,json,shutil,subprocess,sys,time
sys.dont_write_bytecode=True
P=Path(__file__).resolve().parent;ROOT=P.parents[1]
for path in ['analysis/aitweaker_lock/uefi_vm_20261015','tools/vm-pydeps','tools/kvm-pydeps']:sys.path.insert(0,str(ROOT/path))
from run_vm_tests import QMP,ppm_to_png,QEMU,SHARE,CODE,VARS
import decode_captures as decoder

def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 nvme_first='--nvme-first' in sys.argv
 folder=P/('vm-nvme-first' if nvme_first else 'vm');folder.mkdir(exist_ok=True);shutil.copyfile(VARS,folder/'vars.fd')
 for name in ('synthetic-sata.img','synthetic-nvme.img'):
  path=folder/name
  if not path.exists():
   with path.open('xb') as f:f.truncate(64*1024*1024)
  assert path.stat().st_size==64*1024*1024
 initial={n:sha(folder/n) for n in ['synthetic-sata.img','synthetic-nvme.img']}
 args=[str(QEMU),'-L',str(SHARE),'-machine','q35,accel=tcg','-cpu','max','-m','256','-nic','none','-display','none','-monitor','none','-qmp','stdio','-vga','none','-device','VGA,xres=1280,yres=800','-serial','file:'+str(folder/'serial.log'),
 '-drive','if=pflash,format=raw,unit=0,readonly=on,file='+str(CODE),'-drive','if=pflash,format=raw,unit=1,file='+str(folder/'vars.fd'),
 '-drive','if=none,id=cd,format=raw,media=cdrom,readonly=on,file='+str(P/'HERO-PCIE-I4-READONLY.iso'),'-device','ide-cd,drive=cd,bus=ide.0,bootindex=1',
 '-drive','if=none,id=sata,format=raw,snapshot=on,file='+str(folder/'synthetic-sata.img'),'-device','ide-hd,drive=sata,bus=ide.1',
 '-drive','if=none,id=nvme,format=raw,snapshot=on,file='+str(folder/'synthetic-nvme.img'),'-device','nvme,drive=nvme,serial=I4TEST0001']
 if nvme_first:
  args=[a.replace('ide-cd,drive=cd,bus=ide.0,bootindex=1','ide-cd,drive=cd,bus=ide.0,bootindex=3').replace('nvme,drive=nvme,serial=I4TEST0001','nvme,drive=nvme,serial=I4TEST0001,bootindex=1').replace('ide-hd,drive=sata,bus=ide.1','ide-hd,drive=sata,bus=ide.1,bootindex=2') for a in args]
 (folder/'command.json').write_text(json.dumps(args,indent=2)+'\n')
 with (folder/'stderr.log').open('w') as errors:
  proc=subprocess.Popen(args,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=errors,text=True,encoding='utf-8',bufsize=1,creationflags=subprocess.CREATE_NO_WINDOW)
  qmp=QMP(proc,folder);qmp.command('qmp_capabilities')
  def serial():return (folder/'serial.log').read_bytes() if (folder/'serial.log').exists() else b''
  def wait(*patterns):
   end=time.monotonic()+45
   while not any(p in serial() for p in patterns):
    if time.monotonic()>end:raise TimeoutError(serial()[-1600:])
    if proc.poll() is not None:raise RuntimeError('VM stopped')
    time.sleep(.1)
  def key(name):qmp.command('send-key',{'keys':[{'type':'qcode','data':name}],'hold-time':70})
  frames=[]
  try:
   wait(b'HERO PCIe I4 - FIRST TEXT / WAITING FOR D')
   key('ret');time.sleep(.2);key('esc');time.sleep(.2)
   assert b'I4_READONLY_CAPTURE_BEGIN' not in serial() and b'RETURNING TO FIRMWARE' not in serial()
   key('d');wait(b'I4_CAPTURE_READY',b'I4_CAPTURE_INCOMPLETE');assert b'I4_CAPTURE_READY' in serial()
   key('c');wait(b'QR PAGE 1/')
   pages=None;page=1
   while pages is None or page<=pages:
    wait(f'QR PAGE {page}/'.encode());time.sleep(.12)
    ppm=folder/f'page-{page:04d}.ppm';qmp.command('screendump',{'filename':str(ppm)});png=ppm.with_suffix('.png');ppm_to_png(ppm,png)
    raw=decoder.read_image(png);frame=decoder.parse_frame(raw);assert frame['page']==page
    frames.append(raw);pages=frame['pages'];print(f'QR {page}/{pages}',flush=True)
    if page<pages:key('n')
    page+=1
   capture,meta=decoder.assemble(frames);(folder/'OVMF-PCIE-I4.TXT').write_bytes(capture)
   assert b'CAPTURE_COMPLETE=0000000000000001' in capture
   assert b'CONFIG_HEX_BEGIN' in capture and b'MEDIA_FIELDS_STABLE=01' in capture
   assert b'IDENTIFY_FORMAT_SIZE_MATCH=01' in capture
   assert b'AMI_CACHE_IMPLEMENTATION_PROVEN=0' in capture
   (folder/'qr-manifest.json').write_text(json.dumps(meta,indent=2)+'\n')
   key('esc');time.sleep(.2);key('q');wait(b'Press Q again');key('q');wait(b'HERO PCIe I4 RETURNING TO FIRMWARE')
   assert {n:sha(folder/n) for n in initial}==initial
   result=dict(passed=True,iso_sha256=sha(P/'HERO-PCIE-I4-READONLY.iso'),app_sha256=sha(P/'USB/EFI/BOOT/BOOTX64.EFI'),
       all_qr_pages_decoded_exact=True,**meta,pci_config_records=capture.count(b'CONFIG_HEX_BEGIN'),
       block_metadata_records=capture.count(b'MEDIA_FIRST_HEX_BEGIN'),disk_identify_records=capture.count(b'IDENTIFY_HEX_BEGIN'),
       synthetic_backing_images_unchanged=True,synthetic_write_isolation="QEMU snapshot overlays",enter_escape_no_actions=True,double_q_exit=True,
       no_host_disk_or_NIC=True,limits=['Synthetic OVMF only. Does not validate HERO hardware, physical drive identity or firmware publication.'])
   (P/('vm-nvme-first-verification.json' if nvme_first else 'vm-verification.json')).write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result))
  finally:
   if proc.poll() is None:
    try:qmp.command('quit')
    except Exception:proc.terminate()
   proc.wait(timeout=10)
if __name__=='__main__':main()
