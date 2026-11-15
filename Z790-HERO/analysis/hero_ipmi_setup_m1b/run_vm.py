"""Boot final M1b + unchanged M1a driver in isolated QEMU/OVMF.
Uses only regular VM files, no network, host disks, or device passthrough.
"""
from pathlib import Path
import sys,json,subprocess,time,shutil,hashlib
OUT=Path(__file__).resolve().parent;ROOT=OUT.parents[1]
sys.dont_write_bytecode=True
sys.path.insert(0,str(ROOT/'analysis/aitweaker_lock/uefi_vm_20261015'))
import disk_images
from run_vm_tests import QMP,ppm_to_png
VM=OUT/'vm';VM.mkdir(exist_ok=True);disk_images.OUT=VM
CANARY=b'Preserve existing M1b audit exactly.\r\n'
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def run_case(name,keys,marker=True,existing=False,interrupted=False):
    folder=VM/name;folder.mkdir(exist_ok=True)
    files={'/'+p.relative_to(OUT/'USB').as_posix():p.read_bytes() for p in (OUT/'USB').rglob('*') if p.is_file()}
    if not marker:files.pop('/HERO-IPMI-M1B.TAG')
    if existing:files['/HERO-M1B-000.TXT']=CANARY
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
    def wait_for(token,start=0):
        deadline=time.monotonic()+45
        while time.monotonic()<deadline:
            content=read()
            if token in content[start:]:return
            if process.poll() is not None:raise RuntimeError('VM stopped early')
            time.sleep(.1)
        raise TimeoutError((name,token,read()[-1000:]))
    def screen(label):
        time.sleep(.5);p=folder/(label+'.ppm');qmp.command('screendump',{'filename':str(p)});ppm_to_png(p,p.with_suffix('.png'));return p
    try:
        wait_for('No log before L is normal.');screen('01-startup');print(name,'startup visible',flush=True)
        for step,(key,token) in enumerate(keys,2):
            pos=len(read());qmp.command('send-key',{'keys':[{'type':'qcode','data':key}],'hold-time':100});wait_for(token,pos)
            if key!='q':
                p=screen(f'{step:02}-{key}')
                if key=='g':
                    with p.open('rb') as f:
                        assert f.readline().strip()==b'P6';f.readline();assert f.readline().strip()==b'255';pixels=f.read()
                    counts={c.hex():sum(pixels[i:i+3]==c for i in range(0,len(pixels),3)) for c in (b'\xff\0\0',b'\0\xff\0',b'\0\0\xff')}
                    assert all(n>=4096 for n in counts.values()),counts
                    (folder/'pixel-check.json').write_text(json.dumps(counts,indent=2)+'\n')
            time.sleep(.25)
    finally:
        if process.poll() is None:
            try:qmp.command('quit')
            except Exception:process.terminate()
        process.wait(timeout=10)
    with disk_images.PyFatFS(str(disk),read_only=True) as fs:
        logs={Path(n).name:fs.readbytes(n) for n in fs.walk.files() if Path(n).name.startswith('HERO-M1B-') and n.upper().endswith('.TXT')}
        for path in ('EFI/BOOT/BOOTX64.EFI','EFI/HERO/HeroIpmiM1a.efi'):assert fs.readbytes('/'+path)==(OUT/'USB'/path).read_bytes()
        for filename,data in logs.items():(folder/filename).write_bytes(data)
        if existing:assert logs['HERO-M1B-000.TXT']==CANARY
    content=read()
    if name in ('00_startup_only','03_graphics_only'):assert not logs and '10_LOADED_IMAGE_BEFORE' not in content
    if name=='02_missing_marker':assert not logs and '13_MARKER_OPEN_AFTER status=0x800000000000000E' in content
    if name=='01_full_flow':
        log=logs['HERO-M1B-001.TXT']
        for token in (b'FIRST_OUTPUT',b'19_INITIAL_LOG_COMMITTED',b'MINIMAL_SEND_FORM_AFTER status=0000000000000000',b'FULL_SEND_FORM_AFTER status=0000000000000000',b'UNLOAD_IMAGE_AFTER status=0x0000000000000000',b'SESSION_END status=0x0000000000000000'):assert token in log,token
        assert b'M1_INITIALIZE_BEGIN' not in log and b'TX netfn=' not in log and b'CONFIG_SAVE' not in log
    if interrupted:
        log=logs['HERO-M1B-000.TXT'];assert b'MINIMAL_SEND_FORM_BEFORE' in log and b'MINIMAL_SEND_FORM_AFTER' not in log and b'SESSION_END' not in log
    else:assert 'M1b finished; returning to firmware.' in content
    result=dict(case=name,passed=True,launcher_sha256=sha(OUT/'USB/EFI/BOOT/BOOTX64.EFI'),driver_sha256=sha(OUT/'USB/EFI/HERO/HeroIpmiM1a.efi'),keys=keys,interrupted=interrupted,logs={n:hashlib.sha256(data).hexdigest() for n,data in logs.items()},screenshots={p.name:sha(p) for p in folder.glob('*.png')},disk_file=str(disk))
    (folder/'result.json').write_text(json.dumps(result,indent=2)+'\n');print(name,'PASS',flush=True);return result
def main():
    done='M1b finished; returning to firmware.';menu='No log before L is normal.'
    rows=[run_case('00_startup_only',[('q',done)]),
          run_case('01_full_flow',[('l','L complete: USB_LOG_READY'),('d','D complete: DRIVER_READY'),('s','M1a simple HII display test'),('esc',menu),('h','Auto initialize at boot'),('esc',menu),('q',done)],existing=True),
          run_case('02_missing_marker',[('l','L failed.'),('q',done)],marker=False),
          run_case('03_graphics_only',[('g','GRAPHICS_TEST_RETURN'),('q',done)]),
          run_case('04_interrupted_browser',[('l','L complete: USB_LOG_READY'),('d','D complete: DRIVER_READY'),('s','M1a simple HII display test')],interrupted=True)]
    report=dict(launcher_sha256=sha(OUT/'USB/EFI/BOOT/BOOTX64.EFI'),driver_sha256=sha(OUT/'USB/EFI/HERO/HeroIpmiM1a.efi'),all_passed=True,cases=rows,limitations=['OVMF is not ASUS AMI or target HERO hardware.','QEMU interruption verifies pre-call flush in this VM, not arbitrary physical USB power-loss behavior.'])
    (VM/'results.json').write_text(json.dumps(report,indent=2)+'\n');print('ALL VM PASS',len(rows),flush=True)
if __name__=='__main__':main()
