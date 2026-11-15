"""Boot the exact inventory ISO in local OVMF; no network or host disk device."""
from pathlib import Path
import hashlib
import json
import shutil
import subprocess
import sys
import time
import zlib

sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[1]
sys.path.insert(0,str(ROOT/'analysis/aitweaker_lock/uefi_vm_20261015'))
sys.path.insert(0,str(ROOT/'tools/vm-pydeps'))
sys.path.insert(0,str(ROOT/'tools/kvm-pydeps'))
from run_vm_tests import QMP,ppm_to_png,QEMU,SHARE,CODE,VARS
import decode_captures as decoder


def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()


def main():
 folder=HERE/'vm';folder.mkdir(parents=True,exist_ok=True);shutil.copyfile(VARS,folder/'vars.fd')
 args=[str(QEMU),'-L',str(SHARE),'-machine','q35,accel=tcg','-cpu','max','-m','256','-nic','none','-display','none','-monitor','none','-qmp','stdio','-vga','none','-device','VGA,xres=1280,yres=800','-serial','file:'+str(folder/'serial.log'),'-drive','if=pflash,format=raw,unit=0,readonly=on,file='+str(CODE),'-drive','if=pflash,format=raw,unit=1,file='+str(folder/'vars.fd'),'-drive','if=none,id=cd,format=raw,media=cdrom,readonly=on,file='+str(HERE/'HERO-SMBIOS-I1-READONLY.iso'),'-device','ide-cd,drive=cd,bus=ide.0,bootindex=1']
 (folder/'command.json').write_text(json.dumps(args,indent=2)+'\n')
 with (folder/'stderr.log').open('w') as errors:
  proc=subprocess.Popen(args,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=errors,text=True,encoding='utf-8',bufsize=1,creationflags=subprocess.CREATE_NO_WINDOW)
  qmp=QMP(proc,folder);qmp.command('qmp_capabilities')
  def serial():return (folder/'serial.log').read_bytes() if (folder/'serial.log').exists() else b''
  def wait(text):
   end=time.monotonic()+45
   while text not in serial():
    if time.monotonic()>end:raise TimeoutError(serial()[-1800:])
    if proc.poll() is not None:raise RuntimeError('VM stopped')
    time.sleep(.1)
  def key(name):qmp.command('send-key',{'keys':[{'type':'qcode','data':name}],'hold-time':70})
  try:
   wait(b'HERO SMBIOS I1 - FIRST TEXT / WAITING FOR S')
   key('ret');time.sleep(.2);assert b'SMBIOS_READ_BEGIN' not in serial() and b'RETURNING TO FIRMWARE' not in serial()
   key('s');wait(b'SMBIOS_CAPTURE_READY')
   key('c');wait(b'QR PAGE 1/');time.sleep(.4)
   blob=serial();start=blob.index(b'HERO-SMBIOS-I1\r\nRUN=');end=blob.index(b'END SMBIOS SNAPSHOT\r\n',start)+len(b'END SMBIOS SNAPSHOT\r\n')
   capture=blob[start:end];(folder/'OVMF-SMBIOS.TXT').write_bytes(capture)
   table=bytes.fromhex(capture.split(b'TABLE_HEX_BEGIN\r\n')[1].split(b'TABLE_HEX_END')[0].decode())
   fields=dict(line.split(b'=',1) for line in capture.splitlines() if b'=' in line)
   assert int(fields[b'CAPTURE_VALID'],16)==1 and len(table)==int(fields[b'TABLE_USED'],16)
   assert zlib.crc32(table)==int(fields[b'TABLE_CRC32'],16)
   ppm=folder/'inventory-qr.ppm';qmp.command('screendump',{'filename':str(ppm)});ppm_to_png(ppm,ppm.with_suffix('.png'))
   frame=decoder.parse_frame(decoder.read_image(ppm.with_suffix('.png')))
   assert frame['page']==1 and frame['data']==capture[:512] and frame['total']==len(capture)
   key('esc');time.sleep(.2);key('q');wait(b'Press Q again');key('q');wait(b'HERO SMBIOS I1 RETURNING TO FIRMWARE')
   result={'passed':True,'iso_sha256':sha(HERE/'HERO-SMBIOS-I1-READONLY.iso'),
           'app_sha256':sha(HERE/'USB/EFI/BOOT/BOOTX64.EFI'),'raw_table_bytes':len(table),
           'export_bytes':len(capture),'qr_pages':frame['pages'],'real_ovmf_smbios_validated':True,
           'decoded_qr_first_page_exact':True,'enter_did_not_exit_or_capture':True,
           'two_q_exit_verified':True,'limitations':['OVMF and synthetic hardware only; not .71 execution.']}
   (HERE/'vm-verification.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result))
  finally:
   if proc.poll() is None:
    try:qmp.command('quit')
    except Exception:proc.terminate()
   proc.wait(timeout=10)


if __name__=='__main__':main()
