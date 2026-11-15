"""Actual release USB bytes in QEMU/OVMF; no host disk/device/network access.

Commands are JSON lines appended to vm/commands.jsonl. Only key input, screen
capture and quit are supported. VM disk/variable-store are ordinary local files.
"""
from pathlib import Path
import sys,subprocess,time,json,shutil,hashlib
sys.dont_write_bytecode=True
OUT=Path(__file__).resolve().parent
ROOT=OUT.parents[1]
HELPERS=ROOT/'analysis/aitweaker_lock/uefi_vm_20261015'
sys.path.insert(0,str(HELPERS))
import disk_images
disk_images.OUT=OUT/'vm'
from run_vm_tests import QMP,ppm_to_png
VM=OUT/'vm';VM.mkdir(exist_ok=True)
def main():
    files={str(p.relative_to(OUT/'USB')).replace('\\','/'):p.read_bytes() for p in (OUT/'USB').rglob('*') if p.is_file()}
    files={'/'+p:v for p,v in files.items()}
    payload_hash=hashlib.sha256(files['/EFI/HERO/HeroIpmiM1.efi']).hexdigest()
    for previous in VM.glob('HERO-M1-*.TXT'):files['/'+previous.name]=previous.read_bytes()
    disk=VM/('usb-'+payload_hash[:16]+'.img')
    metadata=disk.with_suffix('.json')
    meta=json.loads(metadata.read_text()) if disk.exists() else disk_images.create(disk,layout='superfloppy',files=files)
    metadata.write_text(json.dumps(meta,indent=2)+'\n')
    (VM/'disk.json').write_text(json.dumps(meta,indent=2)+'\n')
    qdir=ROOT/'tools/qemu-11.1.0';share=qdir/'share'
    if not (VM/'vars.fd').exists():shutil.copyfile(share/'edk2-i386-vars.fd',VM/'vars.fd')
    args=[str(qdir/'qemu-system-x86_64.exe'),'-L',str(share),'-machine','q35,accel=tcg','-cpu','max','-m','256',
      '-nic','none','-display','none','-monitor','none','-qmp','stdio','-serial','file:'+str(VM/'serial.log'),
      '-drive','if=pflash,format=raw,unit=0,readonly=on,file='+str(share/'edk2-x86_64-code.fd'),
      '-drive','if=pflash,format=raw,unit=1,file='+str(VM/'vars.fd'),
      '-drive','if=none,id=boot,format=raw,file='+str(disk),'-device','qemu-xhci,id=xhci',
      '-device','usb-storage,drive=boot,bus=xhci.0,bootindex=1']
    (VM/'command.json').write_text(json.dumps(args,indent=2)+'\n')
    commands=VM/'commands.jsonl';commands.write_text('');processed=0
    process=subprocess.Popen(args,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=(VM/'stderr.log').open('w'),text=True,encoding='utf-8',bufsize=1,creationflags=subprocess.CREATE_NO_WINDOW)
    qmp=QMP(process,VM);qmp.command('qmp_capabilities');print('VM started; accepts commands.jsonl',flush=True)
    deadline=time.monotonic()+600
    try:
        while time.monotonic()<deadline and process.poll() is None:
            lines=commands.read_text().splitlines()
            for line in lines[processed:]:
                cmd=json.loads(line);print(cmd,flush=True)
                if 'key' in cmd:
                    qmp.command('send-key',{'keys':[{'type':'qcode','data':k} for k in cmd['key'].split('+')],'hold-time':100})
                    time.sleep(.25)
                elif 'screen' in cmd:
                    dest=VM/(Path(cmd['screen']).name+'.ppm');qmp.command('screendump',{'filename':str(dest)});ppm_to_png(dest,dest.with_suffix('.png'))
                elif cmd.get('quit'):qmp.command('quit')
                else:raise ValueError(cmd)
                processed+=1
            time.sleep(.15)
    finally:
        if process.poll() is None:
            try:qmp.command('quit')
            except Exception:process.terminate()
        process.wait(timeout=10)
    print('VM stopped',flush=True)
    # Save all new audit logs from the virtual disk, never from a host volume.
    with disk_images.PyFatFS(str(disk),read_only=True) as fs:
        for name in fs.walk.files():
            if Path(name).name.startswith('HERO-M1-') and name.upper().endswith('.TXT'):(VM/Path(name).name).write_bytes(fs.readbytes(name))
if __name__=='__main__':main()
