"""Read-only optical boots and exact reconstruction from actual GOP screenshots."""
from pathlib import Path
import sys,json,hashlib,shutil,subprocess,time,re
OUT=Path(__file__).resolve().parent;ROOT=OUT.parents[1]
sys.dont_write_bytecode=True;sys.path.insert(0,str(ROOT/'analysis/aitweaker_lock/uefi_vm_20261015'))
from run_vm_tests import QMP,ppm_to_png,QEMU,SHARE,CODE,VARS
from decode_captures import read_image,parse_frame,assemble
ISO=OUT/'HERO-DISPLAY-M1e.iso'
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def save(p,d):p.write_text(json.dumps(d,indent=2)+'\n')

def run_case(name,transport,xres,yres):
    folder=OUT/'vm'/name
    if folder.exists():
        n=2
        while folder.with_name(name+f'_attempt{n}').exists():n+=1
        folder=folder.with_name(name+f'_attempt{n}')
    folder.mkdir(parents=True);shutil.copyfile(VARS,folder/'vars.fd')
    before_hash=sha(ISO)
    args=[str(QEMU),'-L',str(SHARE),'-machine','q35,accel=tcg','-cpu','max','-m','256','-nic','none',
          '-display','none','-monitor','none','-qmp','stdio','-vga','none','-device',f'VGA,xres={xres},yres={yres}',
          '-serial','file:'+str(folder/'serial.log'),
          '-drive','if=pflash,format=raw,unit=0,readonly=on,file='+str(CODE),
          '-drive','if=pflash,format=raw,unit=1,file='+str(folder/'vars.fd'),
          '-drive','if=none,id=cd,format=raw,media=cdrom,readonly=on,file='+str(ISO)]
    if transport=='usb':args+=['-device','qemu-xhci,id=xhci','-device','usb-storage,drive=cd,bus=xhci.0,bootindex=1']
    else:args+=['-device','ide-cd,drive=cd,bus=ide.0,bootindex=1']
    save(folder/'command.json',args)
    proc=subprocess.Popen(args,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=(folder/'stderr.log').open('w'),text=True,encoding='utf-8',bufsize=1,creationflags=subprocess.CREATE_NO_WINDOW)
    qmp=QMP(proc,folder);qmp.command('qmp_capabilities')
    groups=[]
    def serial():return (folder/'serial.log').read_bytes() if (folder/'serial.log').exists() else b''
    def wait(token,start=0):
        deadline=time.monotonic()+45
        while time.monotonic()<deadline:
            if token in serial()[start:]:return
            if proc.poll() is not None:raise RuntimeError('VM stopped')
            time.sleep(.1)
        raise TimeoutError((name,token,serial()[-1000:]))
    def press(key,token=None):
        pos=len(serial());qmp.command('send-key',{'keys':[{'type':'qcode','data':key}],'hold-time':70})
        if token:wait(token,pos)
    def shot(name):
        p=folder/(name+'.ppm');qmp.command('screendump',{'filename':str(p)});png=p.with_suffix('.png');ppm_to_png(p,png);return png
    def capture(page,label):
        deadline=time.monotonic()+8;error=None
        while time.monotonic()<deadline:
            time.sleep(.3)
            try:
                raw=read_image(shot(label))
                if parse_frame(raw)['page']==page:return raw
            except ValueError as e:error=e
        raise RuntimeError(('QR not decoded',page,error))
    def collect(label):
        first=capture(1,label+'-001');pages=parse_frame(first)['pages'];frames=[first]
        for page in range(2,pages+1):press('n');frames.append(capture(page,f'{label}-{page:03}'))
        data,meta=assemble(frames)
        expected=serial().rsplit(b'KVM_LOG_BEGIN\r\n',1)[1].split(b'KVM_LOG_END\r\n',1)[0]
        assert data==expected,'screenshot log differs from UEFI console log'
        (folder/(label+'.TXT')).write_bytes(data)
        groups.append(dict(label=label,**meta,exact_match_with_console=True))
        print(name,label,pages,'QR pages decoded exactly',flush=True)
        return data,frames
    try:
        wait(b'D=inspect display; R=text capture; C=QR capture; Q/Esc=finish.')
        time.sleep(.4);shot('01-startup');print(name,'ISO booted',flush=True)
        press('d',b'D complete: INVENTORY_CAPTURED');time.sleep(.4);shot('02-inventory')
        press('r',b'TEXT PAGE 1/')
        wait(b'END TEXT PAGE',serial().rfind(b'KVM_LOG_BEGIN'))
        first_text=serial().rsplit(b'KVM_LOG_BEGIN\r\n',1)[1].split(b'KVM_LOG_END\r\n',1)[0]
        assert b'DISPLAY_INVENTORY_COMPLETE' in first_text
        pages=int(re.findall(rb'TEXT PAGE 1/(\d+)',serial())[-1])
        text_frames=[]
        for page in range(1,pages+1):
            if page>1:press('n',f'TEXT PAGE {page}/'.encode())
            time.sleep(.4);text_frames.append(shot(f'text-{page:03}').name)
        press('n',f'TEXT PAGE {pages}/'.encode())
        press('home',b'TEXT PAGE 1/')
        press('esc',b'D=inspect display; R=text capture; C=QR capture; Q/Esc=finish.')
        press('c',b'QR PAGE 1/');data,frames=collect('display-inventory')
        assert data==first_text,'R and C snapshots differ'
        assert b'BROWSER_SENDFORM_RVA=' in data
        assert b'ENTER_SEND_FORM' not in data and b'NEW_PACKAGES' not in data
        press('n');assert capture(len(frames),'03-last-clamped')==frames[-1]
        press('home');assert capture(1,'04-first')==frames[0]
        press('t',b'TEXT PAGE 1/');time.sleep(.4);shot('05-qr-to-text')
        press('q');assert capture(1,'06-return-qr')==frames[0]
        press('esc',b'D=inspect display; R=text capture; C=QR capture; Q/Esc=finish.')
        press('q',b'END OF SESSION');time.sleep(.4);shot('07-end-of-session')
        press('r',b'TEXT PAGE 1/')
        final=serial().rsplit(b'KVM_LOG_BEGIN\r\n',1)[1].split(b'KVM_LOG_END\r\n',1)[0]
        assert b'SESSION_END=0x0000000000000000' in final
        (folder/'final-console.TXT').write_bytes(final)
        press('esc',b'END OF SESSION');press('ret',b'M1e finished; returning to firmware.')
    finally:
        if proc.poll() is None:
            try:qmp.command('quit')
            except Exception:proc.terminate()
        proc.wait(timeout=10)
    assert sha(ISO)==before_hash
    result=dict(case=folder.name,passed=True,image_sha256=sha(OUT/'payload/EFI/BOOT/BOOTX64.EFI'),iso_sha256=before_hash,
                read_only_optical=True,no_writable_data_disk=True,never_calls_SendForm=True,text_pages=len(text_frames),text_screenshots=text_frames,groups=groups,
                screenshots={p.name:sha(p) for p in folder.glob('*.png')},logs={p.name:sha(p) for p in folder.glob('*.TXT')})
    save(folder/'result.json',result);print(name,'PASS',flush=True);return result

def main():
    rows=[run_case('sata_1280x800','sata',1280,800),run_case('usb_cd_640x480','usb',640,480)]
    report=dict(image_sha256=sha(OUT/'payload/EFI/BOOT/BOOTX64.EFI'),iso_sha256=sha(ISO),all_passed=True,cases=rows,
                limits=['OVMF is not HERO ASUS AMI firmware.','QEMU display capture does not reproduce every BMC compression mode.','R text pages were captured; QR reconstruction was checked byte-for-byte against the same R snapshot.'])
    save(OUT/'vm/results.json',report);print('ALL VM PASS',len(rows),flush=True)
if __name__=='__main__':main()
