"""Boot the exact candidate ISO and decode the real Linux PID1 framebuffer QR.

The default OVMF board is intentionally not the ASUS target; refusal is expected.
No SMBIOS spoofing, diagnostic identity override, network, or target BMC access.
"""
from pathlib import Path
import argparse,datetime,json,shutil,subprocess,sys,time,traceback
from build_loader import OUT,ROOT,sha
from run_tests import Q,SHARE,QMP,ppm_to_png,save
sys.path.insert(0,str(ROOT/'analysis/aitweaker_lock/probe_p3_kvm'))
from decode_captures import read_image,assemble
def run(manifest_path,transport='sata',vm_profile='pid1'):
    manifest=json.loads(Path(manifest_path).read_text(encoding='utf8'));iso=Path(manifest['iso']);assert sha(iso)==manifest['iso_sha256']
    folder=OUT/'tests/linux-runs'/(datetime.datetime.now().strftime('%Y%m%d_%H%M%S')+'_'+transport+'_'+vm_profile);folder.mkdir(parents=True)
    varsfile=folder/'vars.fd';shutil.copyfile(SHARE/'edk2-i386-vars.fd',varsfile)
    args=[str(Q/'qemu-system-x86_64.exe'),'-L',str(SHARE),'-machine','q35,accel=tcg','-cpu','max','-m','1024','-smp','1','-nic','none','-display','none','-monitor','none','-qmp','stdio','-vga','none','-device','VGA,xres=1280,yres=800','-serial','file:'+str(folder/'serial.log'),'-debugcon','file:'+str(folder/'debug.log'),'-global','isa-debugcon.iobase=0x402','-drive','if=pflash,format=raw,unit=0,readonly=on,file='+str(SHARE/'edk2-x86_64-code.fd'),'-drive','if=pflash,format=raw,unit=1,file='+str(varsfile),'-drive','if=none,id=boot,format=raw,media=cdrom,readonly=on,file='+str(iso)]
    if vm_profile in ['pid1','no_hpet','icount']:
        args[args.index('-m')+1]='768';i=args.index('-vga');del args[i:i+4];args+=['-device','qemu-xhci,id=xhci,addr=0x14']
    if vm_profile=='no_hpet':args[args.index('-machine')+1]='q35,accel=tcg,hpet=off'
    if vm_profile=='icount':
        args[args.index('-machine')+1]='q35';args+=['-accel','tcg,thread=single','-icount','shift=3,sleep=off','-rtc','base=utc,clock=vm']
    if transport=='usb':
        if vm_profile not in ['pid1','no_hpet','icount']:args+=['-device','qemu-xhci,id=xhci']
        args+=['-device','usb-storage,drive=boot,bus=xhci.0,bootindex=1']
    else:args+=['-device','ide-cd,drive=boot,bus=ide.0,bootindex=1']
    save(folder/'command.json',args);start=time.monotonic();proc=None
    result={'scope':'Exact candidate EFI + official kernel + custom production initramfs under OVMF; non-target DMI refusal is expected, not an ASUS hardware pass','manifest_sha256':sha(manifest_path),'iso_sha256':sha(iso),'efi_sha256':manifest['efi_sha256'],'kernel_sha256':manifest['kernel_sha256'],'initrd_sha256':manifest['initrd_sha256'],'cmdline':manifest['contract']['cmdline'],'transport':transport,'vm_profile':vm_profile,'passed':False,'hardware_pass':False}
    try:
        with (folder/'stderr.log').open('wb') as err:
            proc=subprocess.Popen(args,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=err,text=True,encoding='utf8',creationflags=subprocess.CREATE_NO_WINDOW)
            (folder/'qemu.pid').write_text(str(proc.pid),encoding='ascii')
            qmp=QMP(proc,folder);qmp.command('qmp_capabilities',timeout=15)
            deadline=time.monotonic()+180;last_error='';log=None;meta=None
            while time.monotonic()<deadline:
                if proc.poll() is not None:raise RuntimeError('QEMU exited before a terminal diagnostic QR')
                debug=(folder/'debug.log').read_text(encoding='ascii',errors='replace') if (folder/'debug.log').exists() else ''
                serial=(folder/'serial.log').read_text(encoding='ascii',errors='replace') if (folder/'serial.log').exists() else ''
                if 'Kernel panic' in serial:raise RuntimeError('Linux panic: '+serial.split('Kernel panic',1)[1].splitlines()[0])
                if 'LC01_BOOT_STOP' in debug:raise RuntimeError('Bootstrap rejected before Linux: '+debug.split('LC01_BOOT_STOP')[-1][:200])
                if 'LC01_START_PINNED_KERNEL' in debug:
                    ppm=folder/'screen.ppm';qmp.command('screendump',{'filename':str(ppm)});png=folder/'screen.png';ppm_to_png(ppm,png)
                    try:
                        raw=read_image(png);candidate,cmeta=assemble([raw],require_inventory=False)
                        if candidate.startswith(b'LINUX-CAPACITY-01 PRODUCTION\r\n') and candidate.endswith(b'PROBE_COMPLETE\r\n') and b'RESULT=PENDING' not in candidate:
                            log=candidate;meta=cmeta;break
                    except ValueError as ex:last_error=str(ex)
                time.sleep(1)
            if log is None:raise TimeoutError('No terminal PID1 QR: '+last_error)
            (folder/'RESTORED-LOG.TXT').write_bytes(log);shutil.copyfile(folder/'screen.png',folder/'terminal-qr.png')
            assert b'RESULT=REFUSED_OR_FAILED\r\n' in log and b'SG_IO_CALLS=0 ' in log and b'MODULES=0\r\n' in log
            debug=(folder/'debug.log').read_text(encoding='ascii',errors='replace');assert 'LC01_VERIFIED kernel' in debug and 'LC01_VERIFIED custom_initrd' in debug
            time.sleep(3);assert proc.poll() is None
            qmp.command('quit');assert proc.wait(timeout=10)==0;qmp.thread.join(timeout=2)
            assert sha(iso)==manifest['iso_sha256']
            result.update({'passed':True,'seconds':round(time.monotonic()-start,2),'qr':meta,'decoded_log':'RESTORED-LOG.TXT','screenshot':'terminal-qr.png','iso_unchanged':True,'SG_IO_calls':0,'modules_loaded_by_PID1':0,'non_target_refusal':True,'alive_after_result_seconds':3})
    except Exception as e:result['error']=str(e);result['traceback']=traceback.format_exc()
    finally:
        if proc and proc.poll() is None:proc.terminate();proc.wait(timeout=5)
        save(folder/'result.json',result);save(OUT/f'tests/latest_linux_{transport}_result.json',result)
    print(json.dumps(result,indent=2));return result
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('manifest',type=Path);p.add_argument('--transport',choices=['sata','usb'],default='sata');p.add_argument('--vm-profile',choices=['original','pid1','no_hpet','icount'],default='pid1');a=p.parse_args();raise SystemExit(0 if run(a.manifest,a.transport,a.vm_profile)['passed'] else 1)
