"""Two bounded local VM timing controls using one pre-existing diagnostic ISO.

No production kernel/cmdline/payload/ISO changes. No network, host devices or
passthrough. All writable VM state lives under this independent review folder.
"""
from pathlib import Path
import hashlib,json,shutil,subprocess,sys,time,zlib,re
HERE=Path(__file__).resolve().parent;LC=HERE.parents[1];ROOT=next(p for p in LC.parents if (p/'tools/pydeps').is_dir())
sys.path.insert(0,str(ROOT/'analysis/aitweaker_lock/uefi_vm_20261015'));from run_vm_tests import QMP,QEMU,SHARE,CODE,VARS
sha=lambda p:hashlib.sha256(Path(p).read_bytes()).hexdigest()
reference=LC/'loader/tests/linux-runs/20261103_183119_sata_icount';ref=json.loads((reference/'result.json').read_text());iso=LC/'loader/production_provisional_serial_debug/media/boot.iso'
assert sha(iso)==ref['iso_sha256']=='6432f6a17ff5fa094ed3e196d26f753208c4d21e23746ec97724d2541b3e9cae'
rows=[]
for name,extra in [('single_no_icount',[]),('single_icount_default_rtc',['-icount','shift=3,sleep=off'])]:
 folder=HERE/name;folder.mkdir(exist_ok=False);shutil.copyfile(VARS,folder/'vars.fd')
 args=[str(QEMU),'-L',str(SHARE),'-machine','q35','-cpu','max','-m','768','-smp','1','-nic','none','-display','none','-monitor','none','-qmp','stdio','-serial','file:'+str(folder/'serial.log'),'-debugcon','file:'+str(folder/'debug.log'),'-global','isa-debugcon.iobase=0x402',
 '-drive','if=pflash,format=raw,unit=0,readonly=on,file='+str(CODE),'-drive','if=pflash,format=raw,unit=1,file='+str(folder/'vars.fd'),
 '-drive','if=none,id=boot,format=raw,media=cdrom,readonly=on,file='+str(iso),'-device','qemu-xhci,id=xhci,addr=0x14','-accel','tcg,thread=single',*extra,'-device','ide-cd,drive=boot,bus=ide.0,bootindex=1']
 (folder/'command.json').write_text(json.dumps(args,indent=2),encoding='utf8');r={'name':name,'iso_sha256':sha(iso),'kernel_sha256':ref['kernel_sha256'],'initrd_sha256':ref['initrd_sha256'],'cmdline':ref['cmdline'],'scope':'Existing serial-debug ISO, old597B refusal payload; not final production payload/physical test','status':'RUNNING'};proc=None
 try:
  with (folder/'stderr.log').open('w') as err:
   proc=subprocess.Popen(args,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=err,text=True,creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0));qmp=QMP(proc,folder);qmp.command('qmp_capabilities');started=time.monotonic();deadline=started+60
   while time.monotonic()<deadline:
    if proc.poll() is not None:raise RuntimeError('Unexpected QEMU exit')
    raw=(folder/'serial.log').read_bytes().replace(b'\r\r\n',b'\r\n')
    if b'Kernel panic - not syncing: IO-APIC + timer doesn\'t work!' in raw:r.update(status='IOAPIC_TIMER_PANIC',seconds=round(time.monotonic()-started,2));break
    m=re.search(rb'LC01_LOG_BEGIN\r\n(.*?)LC01_LOG_END BYTES=(\d+) CRC=([0-9A-F]{8})\r\n',raw,re.S)
    if m:
     data=m[1];assert len(data)==int(m[2]) and zlib.crc32(data)==int(m[3],16)
     assert b'RESULT=REFUSED_OR_FAILED' in data and b'SG_IO_CALLS=0' in data and b'MODULES=0' in data and b'PROBE_COMPLETE\r\n' in data
     (folder/'RESTORED-LOG.TXT').write_bytes(data);r.update(status='PID1_DMI_REFUSAL',seconds=round(time.monotonic()-started,2),log_bytes=len(data),log_crc32=f'{zlib.crc32(data):08X}',log_sha256=hashlib.sha256(data).hexdigest());break
    time.sleep(.2)
   else:r['status']='TIMEOUT_NO_CONCLUSION'
   for command in ['info pic','info irq','info registers']:
    try:(folder/(command.replace(' ','_')+'.txt')).write_text(qmp.command('human-monitor-command',{'command-line':command}),encoding='utf8')
    except Exception as e:r.setdefault('monitor_errors',[]).append(repr(e))
 except Exception as e:r.update(status='TEST_ERROR',error=repr(e))
 finally:
  if proc and proc.poll() is None:
   try:qmp.command('quit');proc.wait(timeout=10)
   except Exception:proc.kill();proc.wait(timeout=10)
  r['process_reaped']=proc is not None and proc.poll() is not None;r['iso_unchanged']=sha(iso)==ref['iso_sha256'];r['serial_sha256']=sha(folder/'serial.log');r['command_sha256']=sha(folder/'command.json');(folder/'result.json').write_text(json.dumps(r,indent=2),encoding='utf8')
 rows.append(r);print(json.dumps(r),flush=True)
(HERE/'timing_controls.json').write_text(json.dumps({'hardware_or_network_access':False,'production_artifacts_modified':False,'script_sha256':sha(__file__),'controls':rows},indent=2),encoding='utf8')
