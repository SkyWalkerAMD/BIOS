"""Boot the release ISO as a read-only CD-ROM; capture/decode its real GOP output."""
from pathlib import Path
import argparse,datetime,hashlib,json,re,shutil,subprocess,sys,time
OUT=Path(__file__).resolve().parent;ROOT=OUT.parents[2]
sys.path.insert(0,str(OUT.parent/'uefi_vm_20261015'))
from run_vm_tests import QMP,ppm_to_png,QEMU,SHARE,CODE,VARS
from decode_captures import read_image,parse_frame,assemble
ISO=OUT/'AiTweaker-P3-KVM.iso'
def sha(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def save(path,obj):path.write_text(json.dumps(obj,indent=2),encoding='utf-8')
def run(transport='sata',xres=1280,yres=800,idle=0):
    name=f'{transport}_{xres}x{yres}'+(f'_idle{idle}' if idle else '')
    folder=OUT/'vm'/name
    if folder.exists():
        i=2
        while folder.with_name(name+f'_attempt{i}').exists():i+=1
        folder=folder.with_name(name+f'_attempt{i}')
    folder.mkdir(parents=True);shutil.copyfile(VARS,folder/'vars.fd')
    args=[str(QEMU),'-L',str(SHARE),'-machine','q35,accel=tcg','-cpu','max','-m','512','-smp','1',
      '-nic','none','-display','none','-monitor','none','-qmp','stdio','-vga','none',
      '-device',f'VGA,xres={xres},yres={yres}',
      '-serial','file:'+str(folder/'serial.log'),
      '-drive','if=pflash,format=raw,unit=0,readonly=on,file='+str(CODE),
      '-drive','if=pflash,format=raw,unit=1,file='+str(folder/'vars.fd'),
      '-drive','if=none,id=cd,format=raw,media=cdrom,readonly=on,file='+str(ISO)]
    if transport=='usb':args+=['-device','qemu-xhci,id=xhci','-device','usb-storage,drive=cd,bus=xhci.0,bootindex=1']
    else:args+=['-device','ide-cd,drive=cd,bus=ide.0,bootindex=1']
    save(folder/'command.json',args)
    result={'name':name,'folder':str(folder.relative_to(OUT)),'passed':False,'iso_sha256_before':sha(ISO),
      'efi_sha256':sha(OUT/'BOOTX64.EFI'),'started_utc':datetime.datetime.now(datetime.timezone.utc).isoformat()}
    proc=None
    try:
        with (folder/'stderr.log').open('wb') as err:
            proc=subprocess.Popen(args,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=err,text=True,encoding='utf-8',creationflags=subprocess.CREATE_NO_WINDOW)
            qmp=QMP(proc,folder);qmp.command('qmp_capabilities',timeout=15)
            def serial():return (folder/'serial.log').read_bytes() if (folder/'serial.log').exists() else b''
            def wait_for(token,after=0,timeout=40):
                deadline=time.monotonic()+timeout
                while time.monotonic()<deadline:
                    if token in serial()[after:]:return
                    if proc.poll() is not None:raise RuntimeError('QEMU exited')
                    time.sleep(.1)
                raise TimeoutError(f'Console did not show {token!r}')
            def press(key):qmp.command('send-key',{'keys':[{'type':'qcode','data':key}],'hold-time':50})
            def shot(name):
                ppm=folder/(name+'.ppm');qmp.command('screendump',{'filename':str(ppm)})
                png=folder/(name+'.png');ppm_to_png(ppm,png);return png
            def capture(page,name):
                end=time.monotonic()+8;error=None
                while time.monotonic()<end:
                    time.sleep(.25)
                    try:
                        raw=read_image(shot(name))
                        if parse_frame(raw)['page']==page:return raw
                    except ValueError as e:error=e
                raise RuntimeError(f'QR page {page} did not decode: {error}')
            wait_for(b'QR PAGE 1/')
            first=capture(1,'qr-001');pages=parse_frame(first)['pages'];frames=[first]
            print(name,'booted; QR pages',pages,flush=True)
            if idle:
                start=time.monotonic()
                while time.monotonic()-start<idle:
                    if proc.poll() is not None:raise RuntimeError('VM exited while waiting for screenshots')
                    time.sleep(.25)
                assert capture(1,'idle-page')==first
                result['idle_seconds']=round(time.monotonic()-start,2)
            for page in range(2,pages+1):
                press('n');frames.append(capture(page,f'qr-{page:03}'))
            log,meta=assemble(frames);(folder/'RESTORED-LOG.TXT').write_bytes(log)
            raw=serial();expected=raw.split(b'KVM_LOG_BEGIN\r\n',1)[1].split(b'KVM_LOG_END\r\n',1)[0]
            assert log==expected,'QR bytes differ from the real UEFI console log'
            assert b'Watchdog.disable=0x0000000000000000\r\n' in log
            assert b'COLLECTION_STATUS=PARTIAL\r\n' in log
            # Boundary/navigation controls are exercised through the emulated keyboard.
            press('n');assert capture(pages,'last-clamped')==frames[-1]
            if pages>1:press('p');assert capture(pages-1,'previous')==frames[-2]
            press('home');assert capture(1,'home')==first
            press('p');assert capture(1,'first-clamped')==first
            before=len(serial());press('t');wait_for(b'TEXT PAGE 1/',after=before);time.sleep(.25);shot('text-001')
            before=len(serial());press('n');wait_for(b'TEXT PAGE 2/',after=before)
            before=len(serial());press('p');wait_for(b'TEXT PAGE 1/',after=before)
            press('q');assert capture(1,'return-qr')==first
            before=len(serial());press('esc');wait_for(b'P3 KVM ended.',after=before)
            qmp.command('quit');assert proc.wait(timeout=10)==0;qmp.thread.join(timeout=2)
            result.update({'passed':True,'qr_restoration':meta,'matches_console_byte_for_byte':True,
               'controls_checked':['next','previous','home','clamp_first','clamp_last','text_next_previous','qr_return','escape_exit'],
               'iso_sha256_after':sha(ISO),'no_writable_data_drive':True})
            assert result['iso_sha256_before']==result['iso_sha256_after']
    except Exception as exc:
        import traceback
        result.update({'error':str(exc),'traceback':traceback.format_exc()})
    finally:
        if proc and proc.poll() is None:
            proc.terminate()
            try:proc.wait(timeout=5)
            except subprocess.TimeoutExpired:proc.kill();proc.wait(timeout=5)
    result['finished_utc']=datetime.datetime.now(datetime.timezone.utc).isoformat();save(folder/'result.json',result)
    print('PASS' if result['passed'] else 'FAIL',name,result.get('error',''),flush=True)
    return result
def main():
    p=argparse.ArgumentParser();p.add_argument('--transport',choices=['sata','usb'],default='sata');p.add_argument('--width',type=int,default=1280);p.add_argument('--height',type=int,default=800);p.add_argument('--idle',type=int,default=0);a=p.parse_args()
    result=run(a.transport,a.width,a.height,a.idle);raise SystemExit(0 if result['passed'] else 1)
if __name__=='__main__':main()
