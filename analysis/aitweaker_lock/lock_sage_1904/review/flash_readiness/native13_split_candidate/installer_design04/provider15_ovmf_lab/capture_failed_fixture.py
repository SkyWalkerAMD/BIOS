from pathlib import Path
import sys,json,os,subprocess,shutil,time,queue,threading,re,hashlib,struct,zlib,datetime
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent;ROOT=next(p for p in HERE.parents if(p/'tools/pydeps').is_dir())
source=HERE.parent/'provider14_ovmf_lab/run_persist_ui.py';txt=source.read_text().split('class QMP:',1)[1].split('# Explicit disposable',1)[0];exec(compile('class QMP:'+txt,str(source),'exec'))
old=HERE/'runs/20261104_001343';run=HERE/'counter_investigation'/('capture_'+datetime.datetime.now().strftime('%Y%m%d_%H%M%S'));run.mkdir()
qemu=ROOT/'tools/qemu-11.1.0';share=qemu/'share';var=run/'owned-vars.fd';shutil.copyfile(share/'edk2-i386-vars.fd',var)
args=json.loads((old/'command.json').read_text());args=[x.replace(str(old/'owned-vars.fd'),str(var)).replace(str(old/'debug.log'),str(run/'debug.log')).replace(str(old/'serial.log'),str(run/'serial.log'))for x in args]
i=args.index('isa-debug-exit,iobase=0xf4,iosize=0x4');del args[i-1:i+1]
(run/'command.json').write_text(json.dumps(args,indent=2)+'\n')
read=lambda name:(run/name).read_text(errors='replace')if(run/name).exists()else''
proc=None;q=None;error=None
def wait(test):
 end=time.monotonic()+90
 while not test():
  if proc.poll()is not None:raise RuntimeError('exited early')
  if time.monotonic()>end:raise TimeoutError('fixture capture')
  time.sleep(.1)
try:
 with(run/'stderr.log').open('wb')as err:
  proc=subprocess.Popen(args,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=err,creationflags=subprocess.CREATE_NO_WINDOW);q=QMP(proc)
  wait(lambda:'STEP_BEGIN form_verify_one' in read('debug.log'));time.sleep(.5)
  for key in ['down','down','down','\r']:q.key(key);time.sleep(.15)
  wait(lambda:'D09 R='in read('serial.log'));q.key('\x1b');time.sleep(.5);q.key('\x1b')
  wait(lambda:'P15_DIAGNOSTIC_OVMF_FAIL'in read('debug.log'));q.command('stop')
  regs=q.command('human-monitor-command',{'command-line':'info registers'});(run/'registers.txt').write_text(regs)
  base=int(re.search(r'Loading driver at 0x([0-9A-Fa-f]+) EntryPoint=0x[0-9A-Fa-f]+\s*\n[^\n]*\nProtectUefiImageCommon',read('debug.log')).group(1),16)if False else int(re.findall(r'Loading driver at 0x([0-9A-Fa-f]+) EntryPoint=0x[0-9A-Fa-f]+',read('debug.log'))[-4],16)
  # Last four load records are fixture, AMITSE, Setup, P15.
  glob=base+0xd108; q.command('pmemsave',{'val':glob,'size':8,'filename':str(run/'state-pointer.bin')})
  state=struct.unpack('<Q',(run/'state-pointer.bin').read_bytes())[0]
  q.command('pmemsave',{'val':state,'size':4096,'filename':str(run/'state-page.bin')})
  rbp=int(re.search(r'RBP=([0-9A-Fa-f]+)',regs).group(1),16)
  q.command('pmemsave',{'val':rbp&~4095,'size':8192,'filename':str(run/'rbp-pages.bin')})
  record={'fixture_base':hex(base),'state_global_address':hex(glob),'state':hex(state),'rbp':hex(rbp),'state_counters':list(struct.unpack_from('<QQQ',(run/'state-page.bin').read_bytes(),0x60)),'rbp_counters':list(struct.unpack_from('<QQQ',(run/'rbp-pages.bin').read_bytes(),(rbp&4095)+0x60))}
  (run/'observation.json').write_text(json.dumps(record,indent=2)+'\n');print(json.dumps(record))
except Exception as exc:error=repr(exc);print(error)
finally:
 if proc and proc.poll()is None:
  try:q.command('quit')
  except Exception:pass
  proc.wait(timeout=10)
 if q:q.close()
(run/'result.json').write_text(json.dumps({'status':'CAPTURED'if not error else'FAILED','error':error,'exit_code':proc.returncode if proc else None,'source_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest()},indent=2)+'\n')
print(run)
