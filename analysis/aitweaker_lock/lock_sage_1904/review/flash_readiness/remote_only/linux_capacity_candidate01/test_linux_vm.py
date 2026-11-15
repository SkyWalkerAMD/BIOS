"""Local OVMF/Linux tests; regular disposable image files, no network or passthrough.

The LAB_SELECTOR_ONLY payload differs only in compile-time PCI/USB identifiers
and its visible label. Production has no runtime override. SMBIOS overrides are
QEMU test input, not a boot option accepted by the diagnostic.
"""
from pathlib import Path
import argparse,datetime,hashlib,importlib.util,json,re,shutil,subprocess,sys,time,zlib
HERE=Path(__file__).resolve().parent;ROOT=next(p for p in HERE.parents if (p/'tools/pydeps').is_dir())
sys.path.insert(0,str(ROOT/'analysis/aitweaker_lock/uefi_vm_20261015'))
from run_vm_tests import QMP,ppm_to_png,QEMU,SHARE,CODE,VARS
sys.path.insert(0,str(ROOT/'tools/kvm-pydeps'))
from PIL import Image
import zxingcpp
OUT=HERE/'vm_tests';OUT.mkdir(exist_ok=True)
sha=lambda p:hashlib.sha256(Path(p).read_bytes()).hexdigest()
CASES=[
 {'id':'production_dmi_refusal','variant':'production','dmi':False,'usb':1,'expect_stage':3,'expect_commands':0,'expect_dmi':0,'expect_modules':0},
 {'id':'production_bios_refusal','variant':'production','dmi':True,'bios':'2003','usb':1,'expect_stage':3,'expect_commands':0,'expect_dmi':0,'expect_modules':0},
 {'id':'production_pci_refusal','variant':'production','dmi':True,'usb':1,'expect_stage':3,'expect_commands':0,'expect_dmi':1,'expect_modules':0},
 {'id':'lab_unique16m','variant':'lab_selector_only','dmi':True,'usb':1,'expect_stage':8,'expect_commands':2,'expect_dmi':1,'expect_modules':8,'capacity':(32767,512)},
 {'id':'lab_readonly16m','variant':'lab_selector_only','dmi':True,'usb':1,'readonly':True,'expect_stage':8,'expect_commands':2,'expect_dmi':1,'expect_modules':8,'capacity':(32767,512)},
 {'id':'lab_geometry32m','variant':'lab_selector_only','dmi':True,'usb':1,'size':33554432,'expect_stage':8,'expect_commands':2,'expect_dmi':1,'expect_modules':8,'capacity':(65535,512)},
 {'id':'lab_duplicate','variant':'lab_selector_only','dmi':True,'usb':2,'expect_stage':5,'expect_commands':0,'expect_dmi':1,'expect_modules':4},
 {'id':'lab_absent','variant':'lab_selector_only','dmi':True,'usb':0,'expect_stage':5,'expect_commands':0,'expect_dmi':1,'expect_modules':4},
 {'id':'lab_only_sata','variant':'lab_selector_only','dmi':True,'usb':0,'sata':True,'expect_stage':5,'expect_commands':0,'expect_dmi':1,'expect_modules':4},
]
def capture(raw):
 raw=raw.replace(b'\r\r\n',b'\r\n');out=[]
 for m in re.finditer(rb'LC01_LOG_BEGIN\r\n(.*?)LC01_LOG_END BYTES=(\d+) CRC=([0-9A-F]{8})\r\n',raw,re.S):
  body=m[1];assert len(body)==int(m[2]) and zlib.crc32(body)==int(m[3],16),'serial CRC/length mismatch'
  out.append(body)
 return out
def run(case):
 folder=OUT/case['id'];folder.mkdir(exist_ok=True)
 if (folder/'result.json').exists():raise RuntimeError('Preserve prior run: use a fresh test output or explicitly archive it first')
 shutil.copyfile(VARS,folder/'vars.fd');initrd=HERE/'build'/case['variant']/'CAPACITY01.IMG'
 args=[str(QEMU),'-L',str(SHARE),'-machine','q35,accel=tcg','-cpu','max','-m','768','-smp','1','-nic','none','-display','none','-monitor','none','-qmp','stdio','-serial','file:'+str(folder/'serial.log'),'-no-reboot',
 '-drive','if=pflash,format=raw,unit=0,readonly=on,file='+str(CODE),'-drive','if=pflash,format=raw,unit=1,file='+str(folder/'vars.fd'),
 '-kernel',str(HERE/'official/vmlinuz-lts'),'-initrd',str(initrd),'-append',(HERE/'build/commandline.txt').read_text()+' console=ttyS0,115200',
 '-device','qemu-xhci,id=xhci,addr=0x14']
 if case.get('dmi'):args+=['-smbios','type=2,product=Pro WS W790E-SAGE SE','-smbios','type=0,version='+case.get('bios','1904')]
 images=[]
 for i in range(case['usb']+(1 if case.get('sata') else 0)):
  path=folder/f'image{i}.raw'
  with path.open('wb') as f:f.truncate(case.get('size',16777216))
  images.append({'path':str(path),'sha_before':sha(path)})
  args+=['-drive',f'if=none,id=d{i},format=raw,file={path}'+(',readonly=on' if case.get('readonly') else '')]
  args+=['-device',(f'usb-storage,drive=d{i},bus=xhci.0,port={i+1}' if i<case['usb'] else f'ide-hd,drive=d{i},bus=ide.0')]
 result={'case':case,'status':'RUNNING','utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'command':args,'kernel_sha256':sha(HERE/'official/vmlinuz-lts'),'initramfs_sha256':sha(initrd),'production_board_override_exists':False,'local_only':True,'network':'none','images':images}
 (folder/'input.json').write_text(json.dumps(result,indent=2),encoding='utf8');proc=None;err=None
 try:
  err=(folder/'stderr.log').open('w',encoding='utf8');proc=subprocess.Popen(args,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=err,text=True,creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0));qmp=QMP(proc,folder);qmp.command('qmp_capabilities')
  deadline=time.monotonic()+90;final=None
  while time.monotonic()<deadline:
   if proc.poll() is not None:raise RuntimeError('QEMU exited '+str(proc.returncode))
   raw=(folder/'serial.log').read_bytes() if (folder/'serial.log').exists() else b''
   frames=capture(raw)
   finals=[b for b in frames if b.endswith(b'PROBE_COMPLETE\r\n')]
   if finals:final=finals[-1];break
   time.sleep(.2)
  if final is None:raise TimeoutError('No complete Linux report in90s')
  (folder/'linux-log.txt').write_bytes(final)
  checks=[]
  def check(name,cond):checks.append({'name':name,'pass':bool(cond)});assert cond,name
  for key,pattern in [('stage',rb'STAGE=(\d+)'),('commands',rb'SG_IO_CALLS=(\d+)'),('dmi',rb'DMI_MATCH=(\d+)'),('modules',rb'MODULES=(\d+)')]:check(key,int(re.search(pattern,final)[1])==case['expect_'+key])
  check('no storage writes/resets/block reads',b'PROBE_BLOCK_READS=0 PROBE_STORAGE_WRITES=0 PROBE_RESETS=0' in final)
  check('exact variant',b'LINUX-CAPACITY-01 '+(b'PRODUCTION' if case['variant']=='production' else b'LAB_SELECTOR_ONLY')+b'\r\n' in final)
  if 'capacity' in case:
   check('first complete exact UA',b'A1=0,0,02,01,00,0000,0008,8,00000001,18,1,0000000000000000,700006000000000A00000000290000000000\r\n' in final)
   last,block=case['capacity'];check('reported capacity',f'LAST_LBA={last:08X} BLOCK_BYTES={block:08X}'.encode() in final)
   check('second strict successful result',b'VALID=1' in final and b'RESULT=CAPACITY_OBSERVED' in final and b'CHECKS=1FF' in final and f'A2=0,0,00,00,00,0000,0000,0,00000000,0,1,{last:08X}{block:08X},\r\n'.encode() in final)
   check('pending distinct',any(b'RESULT=PENDING\r\nPROBE_PENDING\r\n' in f and b'PROBE_COMPLETE' not in f for f in frames))
  else:check('refused result',b'RESULT=REFUSED_OR_FAILED' in final and b'VALID=0' in final)
  # Serial is emitted before encoding/drawing QR. Wait for the matching final
  # page, not a fixed short delay that can capture the preceding text phase.
  qrbytes=[];qr_deadline=time.monotonic()+10
  while time.monotonic()<qr_deadline:
   time.sleep(.2);qmp.command('screendump',{'filename':str(folder/'screen.ppm')});ppm_to_png(folder/'screen.ppm',folder/'screen.png')
   qr=zxingcpp.read_barcodes(Image.open(folder/'screen.png'));qrbytes=[bytes(q.bytes) for q in qr if bytes(q.bytes).startswith(b'AITWK-P3-KVM\n')]
   if len(qrbytes)==1 and qrbytes[0].split(b'\n\n',1)[-1]==final:break
  check('one final P3 QR',len(qrbytes)==1)
  if qrbytes:
   header,body=qrbytes[0].split(b'\n\n',1);check('QR complete exact serial log',body==final);check('QR crc',f'C={zlib.crc32(final):08X}'.encode() in header)
  result.update(status='PASS',checks=checks,log_bytes=len(final),log_sha256=hashlib.sha256(final).hexdigest(),log_crc32=f'{zlib.crc32(final):08X}',screen_sha256=sha(folder/'screen.png'),serial_sha256=sha(folder/'serial.log'))
 except BaseException as e:result.update(status='FAIL',error=repr(e))
 finally:
  if proc and proc.poll() is None:
   try:qmp.command('quit');proc.wait(timeout=10)
   except Exception:proc.kill();proc.wait(timeout=10)
  if err:err.close()
  for image in images:image['sha_after']=sha(image['path']);image['unchanged']=image['sha_before']==image['sha_after']
  if not all(i['unchanged'] for i in images):result.update(status='FAIL',error='Disposable backing image changed')
  (folder/'result.json').write_text(json.dumps(result,indent=2),encoding='utf8')
 print(json.dumps({'case':case['id'],'status':result['status'],'error':result.get('error'),'log_bytes':result.get('log_bytes')}),flush=True)
 return result
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--case');p.add_argument('--out');ns=p.parse_args()
 if ns.out:OUT=HERE/ns.out;OUT.mkdir(exist_ok=True)
 rows=[run(c) for c in CASES if not ns.case or c['id']==ns.case]
 summary={'status':'PASS' if rows and all(r['status']=='PASS' for r in rows) else 'FAIL','cases':[{k:r.get(k) for k in ['case','status','error','log_bytes','log_sha256']} for r in rows],'script_sha256':sha(__file__),'hardware_executed':False}
 (OUT/'summary.json').write_text(json.dumps(summary,indent=2),encoding='utf8');sys.exit(0 if summary['status']=='PASS' else 1)
