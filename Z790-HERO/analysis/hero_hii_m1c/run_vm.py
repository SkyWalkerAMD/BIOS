"""Final M1c in QEMU/OVMF, regular virtual-disk files only."""
from pathlib import Path
import sys,json,subprocess,time,shutil,hashlib
OUT=Path(__file__).resolve().parent;ROOT=OUT.parents[1]
sys.dont_write_bytecode=True;sys.path.insert(0,str(ROOT/'analysis/aitweaker_lock/uefi_vm_20261015'))
import disk_images
from run_vm_tests import QMP,ppm_to_png
VM=OUT/'vm';VM.mkdir(exist_ok=True);disk_images.OUT=VM
CANARY=b'Keep existing M1C log byte-for-byte.\r\n'
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def run_case(name,keys,existing=False,interrupted=False):
    folder=VM/name;folder.mkdir(exist_ok=True)
    files={'/'+p.relative_to(OUT/'USB').as_posix():p.read_bytes() for p in (OUT/'USB').rglob('*') if p.is_file()}
    if existing:files['/M1C000.TXT']=CANARY
    stamp=0
    while (folder/f'usb-{stamp}.img').exists():stamp+=1
    disk=folder/f'usb-{stamp}.img';meta=disk_images.create(disk,layout='superfloppy',files=files)
    (folder/'disk.json').write_text(json.dumps(meta,indent=2)+'\n')
    qdir=ROOT/'tools/qemu-11.1.0';share=qdir/'share';variables=folder/f'vars-{stamp}.fd';shutil.copyfile(share/'edk2-i386-vars.fd',variables)
    serial=folder/'serial.log'
    args=[str(qdir/'qemu-system-x86_64.exe'),'-L',str(share),'-machine','q35,accel=tcg','-cpu','max','-m','256',
          '-nic','none','-display','none','-monitor','none','-qmp','stdio','-serial','file:'+str(serial),
          '-drive','if=pflash,format=raw,unit=0,readonly=on,file='+str(share/'edk2-x86_64-code.fd'),
          '-drive','if=pflash,format=raw,unit=1,file='+str(variables),
          '-drive','if=none,id=boot,format=raw,file='+str(disk),'-device','qemu-xhci,id=xhci',
          '-device','usb-storage,drive=boot,bus=xhci.0,bootindex=1']
    (folder/'command.json').write_text(json.dumps(args,indent=2)+'\n')
    process=subprocess.Popen(args,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=(folder/'stderr.log').open('w'),text=True,encoding='utf-8',bufsize=1,creationflags=subprocess.CREATE_NO_WINDOW)
    qmp=QMP(process,folder);qmp.command('qmp_capabilities')
    def read():return serial.read_text(encoding='utf-8',errors='replace') if serial.exists() else ''
    def wait(token,start=0):
        deadline=time.monotonic()+45
        while time.monotonic()<deadline:
            if token in read()[start:]:return
            if process.poll() is not None:raise RuntimeError('VM stopped early')
            time.sleep(.1)
        raise TimeoutError((name,token,read()[-1000:]))
    def screen(label):
        time.sleep(.4);p=folder/(label+'.ppm');qmp.command('screendump',{'filename':str(p)});ppm_to_png(p,p.with_suffix('.png'))
    try:
        wait('First pass: L, P, Q.');screen('01-startup');print(name,'startup visible',flush=True)
        for step,(key,token) in enumerate(keys,2):
            pos=len(read());qmp.command('send-key',{'keys':[{'type':'qcode','data':key}],'hold-time':100});wait(token,pos)
            if key!='q':screen(f'{step:02}-{key}')
            time.sleep(.2)
    finally:
        if process.poll() is None:
            try:qmp.command('quit')
            except Exception:process.terminate()
        process.wait(timeout=10)
    with disk_images.PyFatFS(str(disk),read_only=True) as fs:
        logs={Path(n).name:fs.readbytes(n) for n in fs.walk.files() if Path(n).name.startswith('M1C') and n.upper().endswith('.TXT')}
        assert fs.readbytes('/EFI/BOOT/BOOTX64.EFI')==(OUT/'USB/EFI/BOOT/BOOTX64.EFI').read_bytes()
        for filename,data in logs.items():(folder/filename).write_bytes(data)
        if existing:assert logs['M1C000.TXT']==CANARY
    if name=='00_startup':assert not logs
    else:
        log=logs['M1C001.TXT' if existing else 'M1C000.TXT']
        assert b'FIRST_TEXT' in log and b'P_READY_NO_SEND_FORM' in log
        if name=='01_register_only':assert b'ENTER_SEND_FORM' not in log
        if name=='02_show_return':assert b'SEND_FORM_RETURN status=0x0000000000000000' in log
        if interrupted:assert b'ENTER_SEND_FORM' in log and b'SEND_FORM_RETURN' not in log and b'SESSION_END' not in log
        else:assert b'SESSION_END status=0x0000000000000000' in log and b'UNINSTALL_PATH_AFTER status=0x0000000000000000' in log
    result=dict(case=name,passed=True,image_sha256=sha(OUT/'USB/EFI/BOOT/BOOTX64.EFI'),keys=keys,interrupted=interrupted,logs={n:hashlib.sha256(data).hexdigest() for n,data in logs.items()},screenshots={p.name:sha(p) for p in folder.glob('*.png')},disk_file=str(disk))
    (folder/'result.json').write_text(json.dumps(result,indent=2)+'\n');print(name,'PASS',flush=True);return result
def main():
    done='M1c finished; returning to firmware.'
    rows=[run_case('00_startup',[('q',done)]),
          run_case('01_register_only',[('l','L complete: LOG_VERIFIED'),('p','P complete: REGISTERED'),('q',done)],existing=True),
          run_case('02_show_return',[('l','L complete: LOG_VERIFIED'),('p','P complete: REGISTERED'),('s','M1a simple HII display test'),('esc','First pass: L, P, Q.'),('q',done)]),
          run_case('03_interrupted_show',[('l','L complete: LOG_VERIFIED'),('p','P complete: REGISTERED'),('s','M1a simple HII display test')],interrupted=True)]
    report=dict(image_sha256=sha(OUT/'USB/EFI/BOOT/BOOTX64.EFI'),all_passed=True,cases=rows,limitations=['OVMF is not ASUS AMI firmware.','Interrupted VM evidence is not a physical-device power-loss guarantee.'])
    (VM/'results.json').write_text(json.dumps(report,indent=2)+'\n');print('ALL VM PASS',len(rows),flush=True)
if __name__=='__main__':main()
