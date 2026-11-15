"""Final S0 payload in QEMU/OVMF, regular local disk files only."""
from pathlib import Path
import sys,json,subprocess,time,shutil,hashlib
OUT=Path(__file__).resolve().parent;ROOT=OUT.parents[1]
sys.dont_write_bytecode=True
HELPERS=ROOT/'analysis/aitweaker_lock/uefi_vm_20261015'
sys.path.insert(0,str(HELPERS))
import disk_images
from run_vm_tests import QMP,ppm_to_png
VM=OUT/'vm';VM.mkdir(exist_ok=True);disk_images.OUT=VM
CANARY=b'Existing S0 log canary. Preserve exactly.\r\n'
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def run_case(name,keys,marker=True,existing=False):
    folder=VM/name;folder.mkdir(exist_ok=True)
    files={'/'+p.relative_to(OUT/'USB').as_posix():p.read_bytes() for p in (OUT/'USB').rglob('*') if p.is_file()}
    if not marker:files.pop('/HERO-BOOT-S0.TAG')
    if existing:files['/HERO-S0-000.TXT']=CANARY
    # A new regular image for each invocation; preserve previous evidence.
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
    def wait_for(token):
        deadline=time.monotonic()+45
        while time.monotonic()<deadline:
            s=serial.read_text(encoding='utf-8',errors='replace') if serial.exists() else ''
            if token in s:return s
            if process.poll() is not None:raise RuntimeError('VM stopped early')
            time.sleep(.1)
        raise TimeoutError((name,token))
    def screen(label):
        time.sleep(.4)
        p=folder/(label+'.ppm');qmp.command('screendump',{'filename':str(p)});ppm_to_png(p,p.with_suffix('.png'));return p
    try:
        wait_for('No log before L is normal.');screen('01-startup')
        print(name,'startup visible',flush=True)
        for key,token in keys:
            qmp.command('send-key',{'keys':[{'type':'qcode','data':key}],'hold-time':100});wait_for(token)
            if key=='g':
                p=screen('03-graphics')
                with p.open('rb') as f:
                    assert f.readline().strip()==b'P6';dims=f.readline();assert f.readline().strip()==b'255';pixels=f.read()
                counts={c.hex():sum(pixels[i:i+3]==c for i in range(0,len(pixels),3)) for c in (b'\xff\0\0',b'\0\xff\0',b'\0\0\xff')}
                assert all(n>=4096 for n in counts.values()),counts
                (folder/'pixel-check.json').write_text(json.dumps(counts,indent=2)+'\n')
            elif key=='l':screen('02-log-result')
            time.sleep(.2)
        time.sleep(.4)
    finally:
        if process.poll() is None:
            try:qmp.command('quit')
            except Exception:process.terminate()
        process.wait(timeout=10)
    with disk_images.PyFatFS(str(disk),read_only=True) as fs:
        logs={Path(n).name:fs.readbytes(n) for n in fs.walk.files() if Path(n).name.startswith('HERO-S0-') and n.upper().endswith('.TXT')}
        assert fs.readbytes('/EFI/BOOT/BOOTX64.EFI')==(OUT/'USB/EFI/BOOT/BOOTX64.EFI').read_bytes()
        for n,data in logs.items():(folder/n).write_bytes(data)
        if existing:assert logs['HERO-S0-000.TXT']==CANARY
    text=serial.read_text(encoding='utf-8',errors='replace')
    if name=='00_startup_only':assert not logs and '10_LOADED_IMAGE_BEFORE' not in text
    if name=='01_log_graphics':
        log=logs['HERO-S0-001.TXT'];assert b'FIRST_OUTPUT' in log and b'24_USB_LOG_READY' in log and b'GRAPHICS_TEST_RETURN status=0x0000000000000000' in log and b'SESSION_END' in log
    if name=='02_missing_marker':assert not logs and '17_MARKER_OPEN_AFTER status=0x800000000000000E' in text
    assert 'SESSION_END' in text
    result=dict(case=name,passed=True,image_sha256=sha(OUT/'USB/EFI/BOOT/BOOTX64.EFI'),keys=keys,logs={n:hashlib.sha256(data).hexdigest() for n,data in logs.items()},screenshots={p.name:sha(p) for p in folder.glob('*.png')},disk_file=str(disk))
    (folder/'result.json').write_text(json.dumps(result,indent=2)+'\n');print(name,'PASS',flush=True);return result
def main():
    rows=[run_case('00_startup_only',[('q','SESSION_END')]),
          run_case('01_log_graphics',[('l','24_USB_LOG_READY'),('g','GRAPHICS_TEST_RETURN'),('q','SESSION_END')],existing=True),
          run_case('02_missing_marker',[('l','LOG_TEST_RETURN'),('q','SESSION_END')],marker=False)]
    report=dict(image_sha256=sha(OUT/'USB/EFI/BOOT/BOOTX64.EFI'),all_passed=True,cases=rows,observations=['First screen works before filesystem calls.','Q-only session creates no log by design.','Explicit L creates/flushed numbered log and preserves existing file.','G renders red, green and blue pixel blocks.','Missing marker still allows first screen and visible failure stage.'],limitations=['OVMF is not ASUS AMI firmware.','Does not establish target HERO boot success or black-screen root cause.'])
    (VM/'results.json').write_text(json.dumps(report,indent=2)+'\n');print('ALL VM PASS',len(rows),flush=True)
if __name__=='__main__':main()
