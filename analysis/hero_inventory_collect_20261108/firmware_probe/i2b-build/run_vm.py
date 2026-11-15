"""Boot the exact read-only I2B ISO in local OVMF, no NIC or host disk device."""
from pathlib import Path
import hashlib,json,shutil,subprocess,sys,time
sys.dont_write_bytecode=True
P=Path(__file__).resolve().parent;ROOT=P.parents[3]
for path in ['analysis/aitweaker_lock/uefi_vm_20261015','tools/vm-pydeps','tools/kvm-pydeps']:sys.path.insert(0,str(ROOT/path))
from run_vm_tests import QMP,ppm_to_png,QEMU,SHARE,CODE,VARS
import decode_captures as decoder
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 folder=P/'vm';folder.mkdir(exist_ok=True);shutil.copyfile(VARS,folder/'vars.fd')
 args=[str(QEMU),'-L',str(SHARE),'-machine','q35,accel=tcg','-cpu','max','-m','256','-nic','none','-display','none','-monitor','none','-qmp','stdio','-vga','none','-device','VGA,xres=1280,yres=800','-serial','file:'+str(folder/'serial.log'),'-drive','if=pflash,format=raw,unit=0,readonly=on,file='+str(CODE),'-drive','if=pflash,format=raw,unit=1,file='+str(folder/'vars.fd'),'-drive','if=none,id=cd,format=raw,media=cdrom,readonly=on,file='+str(P/'HERO-FW-ID-I2B-READONLY.iso'),'-device','ide-cd,drive=cd,bus=ide.0,bootindex=1']
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
  try:
   wait(b'HERO FW ID I2B - FIRST TEXT / WAITING FOR F')
   key('ret');time.sleep(.2);assert b'FIRMWARE_ID_READ_BEGIN' not in serial() and b'RETURNING TO FIRMWARE' not in serial()
   key('f');wait(b'FIRMWARE_ID_CAPTURE_READY',b'FIRMWARE_ID_CAPTURE_INCOMPLETE')
   key('c');wait(b'QR PAGE 1/');time.sleep(.4)
   blob=serial();start=blob.index(b'HERO-FW-ID-I2B\r\nRUN=');end=blob.index(b'END FW ID SNAPSHOT\r\n',start)+len(b'END FW ID SNAPSHOT\r\n')
   capture=blob[start:end];(folder/'OVMF-FW-ID-I2B.TXT').write_bytes(capture)
   assert b'FP_FV_ENUM_STATUS=0000000000000000' in capture and b'FP_MEMORY_MAP_STATUS=0000000000000000' in capture
   assert b'FP_R2_FV_FILES=0000000000000000' in capture and b'FP_P5_P6_FV_FILES=0000000000000000' in capture
   ppm=folder/'identity-qr.ppm';qmp.command('screendump',{'filename':str(ppm)});ppm_to_png(ppm,ppm.with_suffix('.png'))
   frame=decoder.parse_frame(decoder.read_image(ppm.with_suffix('.png')))
   assert frame['page']==1 and frame['data']==capture[:512] and frame['total']==len(capture)
   key('esc');time.sleep(.2);key('q');wait(b'Press Q again');key('q');wait(b'HERO FW ID I2B RETURNING TO FIRMWARE')
   result={'passed':True,'iso_sha256':sha(P/'HERO-FW-ID-I2B-READONLY.iso'),'app_sha256':sha(P/'USB/EFI/BOOT/BOOTX64.EFI'),
    'capture_bytes':len(capture),'qr_pages':frame['pages'],'ovmf_real_fv2_enum_readfile_completed':True,
    'r2_p5_absent_in_ovmf_expected':True,'decoded_first_QR_exact':True,'enter_did_not_exit_or_capture':True,'double_q_exit':True,
    'limits':['Local OVMF only, not HERO hardware. No target R2/P5 files in this OVMF; ReadFile body and compatibility allocation positive paths are tested in strict PE doubles.']}
   (P/'vm-verification.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result))
  finally:
   if proc.poll() is None:
    try:qmp.command('quit')
    except Exception:proc.terminate()
   proc.wait(timeout=10)
if __name__=='__main__':main()
