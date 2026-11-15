"""Boot the exact read-only ISO on OVMF and exercise QR/text/ESC transport."""
from pathlib import Path
import datetime,hashlib,json,queue,re,shutil,struct,subprocess,sys,threading,time,zlib
HERE=Path(__file__).resolve().parent;CASE=HERE.parents[3];ROOT=CASE.parents[2];BUILD=HERE/'build'
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
class QMP:
 def __init__(self,p):
    self.p=p;self.n=0;self.q=queue.Queue()
    def reader():
        for line in iter(p.stdout.readline,b''):self.q.put(line)
        self.q.put(b'')
    threading.Thread(target=reader,daemon=True).start();assert'QMP'in json.loads(self.q.get(timeout=5));self.command('qmp_capabilities')
 def command(self,name,args=None):
    self.n+=1;n=self.n;obj={'execute':name,'id':n}
    if args is not None:obj['arguments']=args
    self.p.stdin.write(json.dumps(obj).encode()+b'\n');self.p.stdin.flush()
    while True:
        reply=json.loads(self.q.get(timeout=10))
        if reply.get('id')==n:
            if'error'in reply:raise RuntimeError(reply['error'])
            return reply.get('return')
 def key(self,ch):self.command('send-key',{'keys':[{'type':'qcode','data':ch}],'hold-time':25});time.sleep(.5)
 def screen(self,path):
    ppm=path.with_suffix('.ppm');self.command('screendump',{'filename':str(ppm)});raw=ppm.read_bytes();m=re.match(rb'P6\s+(\d+)\s+(\d+)\s+255\s',raw);assert m;w,h=map(int,m.groups());rgb=raw[m.end():];assert len(rgb)==w*h*3
    def chunk(k,d):return struct.pack('>I',len(d))+k+d+struct.pack('>I',zlib.crc32(k+d)&0xffffffff)
    scan=b''.join(b'\0'+rgb[y*w*3:(y+1)*w*3]for y in range(h));path.write_bytes(b'\x89PNG\r\n\x1a\n'+chunk(b'IHDR',struct.pack('>IIBBBBB',w,h,8,2,0,0,0))+chunk(b'IDAT',zlib.compress(scan))+chunk(b'IEND',b''))
run=HERE/'ovmf'/datetime.datetime.now().strftime('%Y%m%d_%H%M%S');run.mkdir(parents=True)
qemu=ROOT/'tools/qemu-11.1.0';share=qemu/'share';varsfile=run/'vars.fd';shutil.copyfile(share/'edk2-i386-vars.fd',varsfile);iso=BUILD/'SAGE-N13-READONLY-ENTRY-CONTEXT02.iso';log=run/'debug.log'
args=[str(qemu/'qemu-system-x86_64.exe'),'-L',str(share),'-machine','q35,accel=tcg','-cpu','max','-m','512','-smp','1','-nic','none','-display','none','-monitor','none','-qmp','stdio','-serial','file:'+str(run/'serial.log'),'-debugcon','file:'+str(log),'-global','isa-debugcon.iobase=0x402','-drive','if=pflash,format=raw,unit=0,readonly=on,file='+str(share/'edk2-x86_64-code.fd'),'-drive','if=pflash,format=raw,unit=1,file='+str(varsfile),'-drive','media=cdrom,readonly=on,file='+str(iso),'-boot','order=d']
(run/'command.json').write_text(json.dumps(args,indent=2)+'\n');p=None;checks=[];screens=[];error=None
def textlog():return log.read_bytes()if log.exists()else b''
def wait_for(marker,seconds=60):
    deadline=time.monotonic()+seconds
    while marker not in textlog():
        if p.poll()is not None:raise RuntimeError('VM exited early')
        if time.monotonic()>deadline:raise TimeoutError(marker)
        time.sleep(.1)
try:
 with(run/'stderr.log').open('wb')as stderr:
    p=subprocess.Popen(args,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=stderr,creationflags=subprocess.CREATE_NO_WINDOW);qmp=QMP(p);wait_for(b'SAGE_NATIVE13_ENTRY_CONTEXT02_END\r\n')
    raw=textlog();start=raw.index(b'AITWK-P3-KVM\r\n');end=raw.index(b'SAGE_NATIVE13_ENTRY_CONTEXT02_END\r\n',start)+len(b'SAGE_NATIVE13_ENTRY_CONTEXT02_END\r\n');payload=raw[start:end];(run/'probe.log').write_bytes(payload)
    assert b'LOG_COMPLETE=YES'in payload and b'INSTALLER_PRESENT=NO'in payload and b'ProviderStarted=NO'in payload
    checks+=['Exact ISO booted in OVMF','EFI produced complete diagnostic log','Unsupported board remained diagnostic only']
    time.sleep(2);pages=(len(payload)+767)//768
    for i in range(pages):
        png=run/f'qr-{i+1:02}.png';qmp.screen(png);screens.append(png)
        if i+1<pages:qmp.key('n')
    qmp.key('t');qmp.screen(run/'text.png');qmp.key('q');qmp.screen(run/'qr-return.png');qmp.key('esc');wait_for(b'PROBE_DISPLAY_EXIT_OK\n',10);qmp.screen(run/'after-exit.png')
    checks+=['All QR pages captured','T text view and Q QR return exercised','ESC returned successfully from display','No network NIC or physical disk attached']
    qmp.command('quit');p.wait(timeout=5)
except Exception as exc:error=repr(exc)
finally:
 if p and p.poll()is None:p.terminate();p.wait(timeout=10)
report={'status':'PASS_ACTUAL_EFI_ISO_OVMF_BOOT_TRANSPORT'if error is None else'FAIL','error':error,'checks':checks,'run':str(run),'iso_sha256':sha(iso),'efi_sha256':sha(BUILD/'SageNative13EntryContext02.efi'),'log_sha256':sha(run/'probe.log')if(run/'probe.log').exists()else None,'screens':[{'path':str(s),'sha256':sha(s)}for s in screens],'runner_sha256':sha(Path(__file__)),'scope':'Actual diagnostic application and console transport only; OVMF does not contain ASUS AMITSE/Setup. No native OEM UI or installation tested.'}
(run/'report.json').write_text(json.dumps(report,indent=2)+'\n');(HERE/'ovmf_report.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({'status':report['status'],'error':error,'run':str(run)}));sys.exit(0 if error is None else 1)
