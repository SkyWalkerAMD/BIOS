"""Real OVMF BDS lifetime test. QMP sends keys only, never signals EFI events."""
from pathlib import Path
import sys,json,hashlib,shutil,subprocess,time
OUT=Path(__file__).resolve().parent;ROOT=OUT.parents[2]
sys.dont_write_bytecode=True
for p in ('analysis/aitweaker_lock/uefi_vm_20261015','tools/vm-pydeps'):sys.path.insert(0,str(ROOT/p))
from run_vm_tests import QMP,ppm_to_png,QEMU,SHARE,CODE,VARS
from decode_captures import read_image,parse_frame,assemble
from pyfatfs.PyFatFS import PyFatFS
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
    usb='--usb' in sys.argv;stem='vm-usb' if usb else 'vm-final';folder=OUT/stem;n=1
    while folder.exists():n+=1;folder=OUT/f'{stem}-attempt{n}'
    folder.mkdir();shutil.copyfile(VARS,folder/'vars.fd')
    iso=OUT/'HERO-R5-AUTO-BDS-TEST.iso'
    args=[str(QEMU),'-L',str(SHARE),'-machine','q35,accel=tcg','-cpu','max','-m','256','-nic','none','-display','none','-monitor','none','-qmp','stdio','-device','VGA,xres=1280,yres=800','-serial','file:'+str(folder/'serial.log'),'-drive','if=pflash,format=raw,unit=0,readonly=on,file='+str(CODE),'-drive','if=pflash,format=raw,unit=1,file='+str(folder/'vars.fd'),'-drive','if=none,id=cd,format=raw,media=cdrom,readonly=on,file='+str(iso),'-device','ide-cd,drive=cd,bus=ide.0,bootindex=1']
    if usb:
        disk=folder/'usb.img';shutil.copyfile(OUT/'efi-boot.img',disk)
        args=args[:-4]+['-drive','if=none,id=boot,format=raw,file='+str(disk),'-device','qemu-xhci,id=xhci','-device','usb-storage,drive=boot,bus=xhci.0,bootindex=1']
    (folder/'command.json').write_text(json.dumps(args,indent=2))
    proc=subprocess.Popen(args,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=(folder/'stderr.log').open('w'),text=True,encoding='utf-8',bufsize=1,creationflags=subprocess.CREATE_NO_WINDOW)
    qmp=QMP(proc,folder);qmp.command('qmp_capabilities');groups=[]
    def serial():return (folder/'serial.log').read_bytes() if (folder/'serial.log').exists() else b''
    def wait(token,start=0,seconds=60):
        end=time.monotonic()+seconds
        while time.monotonic()<end:
            if token in serial()[start:]:return
            if proc.poll() is not None:raise RuntimeError('VM stopped')
            time.sleep(.1)
        raise TimeoutError((token,serial()[-1800:]))
    def press(k,token=None):
        pos=len(serial());qmp.command('send-key',{'keys':[{'type':'qcode','data':k}],'hold-time':70})
        if token:wait(token,pos)
    def shot(label):
        p=folder/(label+'.ppm');qmp.command('screendump',{'filename':str(p)});png=p.with_suffix('.png');ppm_to_png(p,png);return png
    def capture(page,label):
        end=time.monotonic()+8;error=None
        while time.monotonic()<end:
            time.sleep(.25)
            try:
                raw=read_image(shot(label))
                if parse_frame(raw)['page']==page:return raw
            except ValueError as ex:error=ex
        raise RuntimeError(('QR capture',page,error))
    def collect(label):
        first=capture(1,label+'-001');pages=parse_frame(first)['pages'];frames=[first]
        for page in range(2,pages+1):press('n');frames.append(capture(page,f'{label}-{page:03}'))
        data,meta=assemble(frames);(folder/(label+'.TXT')).write_bytes(data);groups.append(dict(label=label,**meta));print(label,meta,flush=True);return data
    menu=b'C=summary QR; A=full QR; R=summary text; V=full text; D=observe; F=USB file; Q=return'
    try:
        wait(b'FIRST PASS: L=load');press('l',menu);assert b'FIRST_PASS_NO_BMC_QUERY' in serial();shot('first-resident')
        if usb:press('f',b'FILE_LOG_STATUS=0x0000000000000000')
        press('a',b'QR PAGE 1/');first=collect('first-full');assert b'READY_TO_BOOT_AUTO_ENABLED' not in first and b'R3 ready_seen=00' in first and b'FINAL requests=00000000' in first
        press('esc',menu);press('q',b'Press Q again');press('q');time.sleep(1.5);shot('bds-frontpage')
        print('BDS FRONT PAGE',str(folder/'bds-frontpage.png'),flush=True)
        # Standard OVMF front page: language, Device Manager, Boot Manager.
        # Select the real Boot Manager then its first DVD entry. No reset.
        for k in ('down','down','ret'):press(k);time.sleep(.4)
        shot('bds-boot-manager');press('ret');wait(b'SECOND_PASS_OBSERVER')
        wait(menu,serial().rfind(b'SECOND_PASS_OBSERVER'));shot('second-observer')
        assert b'READY_TO_BOOT_OBSERVED' in serial();press('a',b'QR PAGE 1/');second=collect('second-full')
        assert b'R3 ready_seen=01' in second and b'FINAL requests=00000000' in second
        assert b'READY_TO_BOOT_AUTO_ENABLED' in second and b'LOAD_MODE FIRMWARE; ReadyToBoot once' in second
        assert b'R5_SENSORS_INITIALIZE_BEGIN' in second and b'R5_DASHBOARD_SYNC_BEGIN' in second
        press('esc',menu)
        if usb:press('f',b'FILE_LOG_STATUS=0x0000000000000000')
        press('q',b'Press Q again');press('q');time.sleep(.5);shot('second-return')
        result=dict(passed=True,iso_sha256=sha(iso),core_sha256=sha(ROOT/'analysis/hero_sensor_r5_20261108/USB/EFI/HERO/HeroIpmiR5.efi'),real_bds=True,no_reset_between_passes=True,no_synthetic_event=True,no_direct_core_run=True,driver_survived_app_return=True,wrong_host_bmc_requests=0,groups=groups,usb=usb)
        (folder/'result.json').write_text(json.dumps(result,indent=2)+'\n');print('REAL BDS AUTOBOOT PASS',flush=True)
    finally:
        if proc.poll() is None:
            try:qmp.command('quit')
            except Exception:proc.terminate()
        proc.wait(timeout=10)
    if usb:
        with PyFatFS(str(disk),read_only=True) as fs:
            assert fs.readbytes('/R5AUTO000.TXT')==first and fs.readbytes('/R5AUTO001.TXT')==second
        result['usb_logs_exactly_match_full_qr']=True;(folder/'result.json').write_text(json.dumps(result,indent=2)+'\n');print('USB TWO PASS FILES MATCH QR',flush=True)
if __name__=='__main__':main()
