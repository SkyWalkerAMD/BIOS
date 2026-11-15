"""Boot final optical/USB artifacts; verify manual-only core and log paths."""
from pathlib import Path
import sys,json,hashlib,shutil,subprocess,time,re,io
OUT=Path(__file__).resolve().parent;ROOT=OUT.parents[1]
sys.dont_write_bytecode=True
for f in ('analysis/aitweaker_lock/uefi_vm_20261015','tools/vm-pydeps'):sys.path.insert(0,str(ROOT/f))
from run_vm_tests import QMP,ppm_to_png,QEMU,SHARE,CODE,VARS
from pyfatfs.PyFatFS import PyFatFS
from decode_captures import read_image,parse_frame,assemble
ISO=OUT/'HERO-IPMI-R4-CORE-TEST.iso'
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def save(p,v):p.write_text(json.dumps(v,indent=2)+'\n')
def run_case(name,usb=False):
    folder=OUT/'vm'/name;attempt=1
    while folder.exists():attempt+=1;folder=OUT/'vm'/(name+f'_attempt{attempt}')
    folder.mkdir(parents=True);shutil.copyfile(VARS,folder/'vars.fd');before=sha(ISO)
    args=[str(QEMU),'-L',str(SHARE),'-machine','q35,accel=tcg','-cpu','max','-m','256','-nic','none','-display','none','-monitor','none','-qmp','stdio','-vga','none','-device','VGA,xres='+('640,yres=480' if usb else '1280,yres=800'),'-serial','file:'+str(folder/'serial.log'),'-drive','if=pflash,format=raw,unit=0,readonly=on,file='+str(CODE),'-drive','if=pflash,format=raw,unit=1,file='+str(folder/'vars.fd')]
    if usb:
        disk=folder/'usb.img';shutil.copyfile(OUT/'efi-boot.img',disk)
        args+=['-drive','if=none,id=boot,format=raw,file='+str(disk),'-device','qemu-xhci,id=xhci','-device','usb-storage,drive=boot,bus=xhci.0,bootindex=1']
    else:args+=['-drive','if=none,id=cd,format=raw,media=cdrom,readonly=on,file='+str(ISO),'-device','ide-cd,drive=cd,bus=ide.0,bootindex=1']
    save(folder/'command.json',args)
    proc=subprocess.Popen(args,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=(folder/'stderr.log').open('w'),text=True,encoding='utf-8',bufsize=1,creationflags=subprocess.CREATE_NO_WINDOW)
    qmp=QMP(proc,folder);qmp.command('qmp_capabilities');groups=[];text_pages=[]
    def serial():return (folder/'serial.log').read_bytes() if (folder/'serial.log').exists() else b''
    def wait(token,start=0,seconds=45):
        deadline=time.monotonic()+seconds
        while time.monotonic()<deadline:
            if token in serial()[start:]:return
            if proc.poll() is not None:raise RuntimeError('VM stopped')
            time.sleep(.1)
        raise TimeoutError((name,token,serial()[-1800:]))
    def press(key,token=None):
        pos=len(serial());qmp.command('send-key',{'keys':[{'type':'qcode','data':key}],'hold-time':70})
        if token:wait(token,pos)
    def shot(label):
        p=folder/(label+'.ppm');qmp.command('screendump',{'filename':str(p)});png=p.with_suffix('.png');ppm_to_png(p,png);return png
    def capture(page,label):
        deadline=time.monotonic()+8;error=None
        while time.monotonic()<deadline:
            time.sleep(.3)
            try:
                raw=read_image(shot(label))
                if parse_frame(raw)['page']==page:return raw
            except ValueError as ex:error=ex
        raise RuntimeError(('capture',page,error))
    def collect(label):
        first=capture(1,label+'-001');pages=parse_frame(first)['pages'];frames=[first]
        for page in range(2,pages+1):press('n');frames.append(capture(page,f'{label}-{page:03}'))
        data,meta=assemble(frames)
        (folder/(label+'.TXT')).write_bytes(data);groups.append(dict(label=label,**meta,snapshot_crc_verified=True))
        print(name,label,pages,'QR pages PASS',flush=True);return data
    menu=b'C=summary QR; R=summary text; A=full QR; V=full text; L=file log; Q=exit'
    try:
        wait(menu);assert b'CORE_READY' in serial() and b'Driver mode: MANUAL ONLY' in serial()
        time.sleep(.3);shot('01-core-ready');print(name,'manual core loaded',flush=True)
        press('l',b'File log result: ')
        assert (b'File log: \\R4LOG000.TXT' in serial())==usb
        press('d',b'Core operation: ');wait(menu,serial().rfind(b'Core operation: '))
        assert b'Unsupported target.' in serial()
        # Save a disabled value and verify it survives a fresh driver/boot below.
        press('0',b'Press the same action key again');press('0',b'Save configuration: 0x0000000000000000')
        wait(menu,serial().rfind(b'Save configuration: '));assert b'Auto-init: DISABLED (saved)' in serial()
        press('r',b'TEXT PAGE 1/')
        pages=int(re.findall(rb'TEXT PAGE 1/(\d+)',serial())[-1])
        for page in range(1,pages+1):
            if page>1:press('n',f'TEXT PAGE {page}/'.encode())
            time.sleep(.2);text_pages.append(shot(f'text-{page:03}').name)
        press('esc',menu);press('c',b'QR PAGE 1/');summary=collect('summary')
        assert b'LOAD manual_only=01' in summary and b'OEM_TX' not in summary
        press('esc',menu);press('a',b'QR PAGE 1/');full=collect('full');assert full.startswith(b'HERO-IPMI-R4-FULL')
        press('esc',menu);press('q',b'Session ended. Press Q again')
        assert b'Driver unload: 0x0000000000000000' in serial();shot('02-unloaded')
        press('q');time.sleep(.3)
        pos=len(serial());qmp.command('system_reset');wait(menu,pos)
        assert b'Auto-init: DISABLED (saved)' in serial()[pos:] and b'Driver mode: MANUAL ONLY' in serial()[pos:]
        assert b'OEM_TX' not in serial()[pos:]
        shot('03-config-persisted');press('q',b'Session ended. Press Q again');press('q')
    finally:
        if proc.poll() is None:
            try:qmp.command('quit')
            except Exception:proc.terminate()
        proc.wait(timeout=10)
    assert sha(ISO)==before
    if usb:
        with PyFatFS(str(disk),read_only=True) as fs:data=fs.readbytes('/R4LOG000.TXT')
        assert data.startswith(b'HERO-IPMI-R4 FILE RUN=') and b'R4_SENSORS_READ_ONLY_BEGIN' in data
        corelog=full.split(b'HERO-IPMI-R4 CORE',1)[1].split(b'FINAL requests=',1)[0]
        assert data[40:]==b'HERO-IPMI-R4 CORE'+corelog,'file core audit must match full QR bytes'
        (folder/'saved-file-log.TXT').write_bytes(data)
    result=dict(case=folder.name,passed=True,driver_sha256=sha(OUT/'USB/EFI/HERO/HeroIpmiR4.efi'),launcher_sha256=sha(OUT/'USB/EFI/BOOT/BOOTX64.EFI'),iso_sha256=before,transport='writable USB image' if usb else 'readonly optical',manual_core=True,config_persisted=True,core_unload_success=True,groups=groups,text_pages=text_pages,screenshots={p.name:sha(p) for p in folder.glob('*.png')})
    save(folder/'result.json',result);print(name,'PASS',flush=True);return result
def main():
    rows=[run_case('iso_sata_1280x800'),run_case('usb_640x480',True)]
    save(OUT/'vm/results.json',dict(all_passed=True,cases=rows,limits=['OVMF console/loader tests are not HERO firmware dispatch or real BMC validation.','VM uses a separate VARS copy, no network, no host disk or hardware passthrough.']))
    print('R4 VM ALL PASS',len(rows),flush=True)
if __name__=='__main__':main()
