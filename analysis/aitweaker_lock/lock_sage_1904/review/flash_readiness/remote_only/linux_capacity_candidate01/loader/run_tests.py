"""Boot real bootstrap bytes in isolated QEMU/OVMF; no BMC or network."""
from pathlib import Path
import argparse,datetime,hashlib,json,shutil,subprocess,sys,time,traceback
from build_loader import OUT,ROOT,sha
sys.path.insert(0,str(ROOT/'tools/kvm-pydeps'));sys.path.insert(0,str(ROOT/'analysis/aitweaker_lock/uefi_vm_20261015'))
import disk_images,pycdlib
from run_vm_tests import QMP,ppm_to_png
disk_images.OUT=OUT
Q=ROOT/'tools/qemu-11.1.0';SHARE=Q/'share'
def save(p,obj):p.write_text(json.dumps(obj,indent=2),encoding='utf8')
def iso_for(folder,files):
    disk_images.VOLUME_SIZE=31*1024*1024
    img=folder/'eltorito.img';disk_images.create(img,'superfloppy',16,files)
    iso=pycdlib.PyCdlib();iso.new(interchange_level=3,vol_ident='LC01_LOCAL_TEST',joliet=3)
    iso.add_file(str(img),iso_path='/EFIBOOT.IMG;1',joliet_path='/EFIBOOT.IMG')
    # Full FAT extent fits the 16-bit El Torito SectorCount. In this OVMF,
    # underspecifying it produces an undersized media partition and I/O errors.
    assert img.stat().st_size//512<=65535
    iso.add_eltorito('/EFIBOOT.IMG;1',bootcatfile='/BOOT.CAT;1',boot_load_size=img.stat().st_size//512,platform_id=0xef,efi=True,media_name='noemul')
    target=folder/'boot.iso';iso.write(str(target));iso.close();return target
def run_vm(folder,medium,expected,*,cd=True,timeout=35,transport='sata',wait_seconds=2,memory=768,firmware=None):
    varsfile=folder/'vars.fd';shutil.copyfile(SHARE/'edk2-i386-vars.fd',varsfile)
    args=[str(Q/'qemu-system-x86_64.exe'),'-L',str(SHARE),'-machine','q35,accel=tcg','-cpu','max','-m',str(memory),'-smp','1','-nic','none','-display','none','-monitor','none','-qmp','stdio',
        '-serial','file:'+str(folder/'serial.log'),'-debugcon','file:'+str(folder/'debug.log'),'-global','isa-debugcon.iobase=0x402',
        '-drive','if=pflash,format=raw,unit=0,readonly=on,file='+str(firmware or SHARE/'edk2-x86_64-code.fd'),'-drive','if=pflash,format=raw,unit=1,file='+str(varsfile),
        '-drive','if=none,id=boot,format=raw,file='+str(medium)+(',media=cdrom,readonly=on' if cd else '')]
    if transport=='usb':args+=['-device','qemu-xhci,id=xhci','-device','usb-storage,drive=boot,bus=xhci.0,bootindex=1']
    else:args+=['-device',('ide-cd' if cd else 'ide-hd')+',drive=boot,bus=ide.0,bootindex=1']
    save(folder/'command.json',args);before=sha(medium);start=time.monotonic();proc=None;result={'expected':expected,'passed':False,'medium_before_sha256':before,'transport':transport}
    try:
        with (folder/'stderr.log').open('wb') as err:
            proc=subprocess.Popen(args,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=err,text=True,encoding='utf8',creationflags=subprocess.CREATE_NO_WINDOW)
            qmp=QMP(proc,folder);qmp.command('qmp_capabilities',timeout=10)
            deadline=time.monotonic()+timeout
            while time.monotonic()<deadline:
                debug=(folder/'debug.log').read_text(encoding='ascii',errors='replace') if (folder/'debug.log').exists() else ''
                serial=(folder/'serial.log').read_text(encoding='ascii',errors='replace') if (folder/'serial.log').exists() else ''
                if expected in debug+serial:break
                if proc.poll() is not None:raise RuntimeError('QEMU exited unexpectedly')
                time.sleep(.1)
            else:raise TimeoutError('Expected marker absent: '+expected)
            # A deliberately returned EFI fixture must not exit to firmware/OS.
            hold_until=time.monotonic()+wait_seconds
            while time.monotonic()<hold_until:
                assert proc.poll() is None,'VM exited during halt observation'
                time.sleep(min(.2,max(0,hold_until-time.monotonic())))
            final_debug=(folder/'debug.log').read_text(encoding='ascii',errors='replace')
            if expected.startswith('LC01_BOOT_STOP'):
                assert final_debug.count('LC01_BOOTSTRAP_BEGIN')==1 and final_debug.count('LC01_BOOT_STOP')==1,'Firmware restarted or repeated boot during observation'
            ppm=folder/'screen.ppm';qmp.command('screendump',{'filename':str(ppm)});ppm_to_png(ppm,folder/'screen.png')
            qmp.command('quit');assert proc.wait(timeout=10)==0;qmp.thread.join(timeout=2)
            result.update({'passed':True,'alive_after_marker_seconds':wait_seconds,'medium_after_sha256':sha(medium),'seconds':round(time.monotonic()-start,2),'screenshot':'screen.png'})
            assert before==result['medium_after_sha256']
    except Exception as e:result['error']=str(e);result['traceback']=traceback.format_exc()
    finally:
        if proc and proc.poll() is None:proc.terminate();proc.wait(timeout=5)
    save(folder/'result.json',result);return result
def fixture_cases(only=None):
    tag=datetime.datetime.now().strftime('%Y%m%d_%H%M%S');root=OUT/'tests/runs'/tag;root.mkdir(parents=True)
    fixture=OUT/'tests/fixture';boot=(fixture/'loader/BOOTX64.EFI').read_bytes();kernel=(fixture/'VMFIXTURE.EFI').read_bytes();initrd=(fixture/'NOT-AN-INITRAMFS.fixture').read_bytes()
    base={'/EFI/BOOT/BOOTX64.EFI':boot,'/LINUX/VMLINUX.EFI':kernel,'/LINUX/CAPACITY01.IMG':initrd}
    cases=[('positive_handshake_return_halt','kernel_returned',None),('missing_kernel','kernel status=',None),('short_kernel','payload_length_or_info',None),('changed_kernel','payload_sha256',None),('missing_initrd','custom_initrd status=',None),('short_initrd','payload_length_or_info',None),('changed_initrd','payload_sha256',None),('writable_boot_volume','kernel_returned',False),('usb_readonly_iso','kernel_returned',None)]
    report={'scope':'EFI fixture validates loader transport and rejection paths, not Linux execution or target hardware','bootstrap_sha256':hashlib.sha256(boot).hexdigest(),'cases':[],'all_passed':False}
    for name,reason,cdflag in cases:
        if only and name!=only:continue
        folder=root/name;folder.mkdir();files=base.copy();cd=cdflag is not False
        if name=='missing_kernel':del files['/LINUX/VMLINUX.EFI']
        if name=='short_kernel':files['/LINUX/VMLINUX.EFI']=kernel[:-1]
        if name=='changed_kernel':files['/LINUX/VMLINUX.EFI']=kernel[:-1]+bytes([kernel[-1]^1])
        if name=='missing_initrd':del files['/LINUX/CAPACITY01.IMG']
        if name=='short_initrd':files['/LINUX/CAPACITY01.IMG']=initrd[:-1]
        if name=='changed_initrd':files['/LINUX/CAPACITY01.IMG']=initrd[:-1]+bytes([initrd[-1]^1])
        if cd:medium=iso_for(folder,files)
        else:medium=folder/'disk.img';disk_images.VOLUME_SIZE=64*1024*1024;disk_images.create(medium,files=files)
        expected='LC01_BOOT_STOP '+reason
        result=run_vm(folder,medium,expected,cd=cd,transport='usb' if name.startswith('usb_') else 'sata')
        result['name']=name
        if result['passed']:
            debug=(folder/'debug.log').read_text(encoding='ascii',errors='replace')
            if name in ['positive_handshake_return_halt','usb_readonly_iso','writable_boot_volume']:assert 'LC01_FIXTURE_LOADFILE2_ABI_PASS' in debug and 'LC01_FIXTURE_FAIL' not in debug
            else:assert 'LC01_START_PINNED_KERNEL' not in debug and 'LC01_FIXTURE_ENTER' not in debug
        report['cases'].append(result);print(name,'PASS' if result['passed'] else 'FAIL',result.get('error',''),flush=True)
        save(root/'summary.json',report)
        if not result['passed']:break
    report['all_passed']=bool(report['cases']) and all(c['passed'] for c in report['cases']);save(root/'summary.json',report);save(OUT/'tests/latest_fixture_results.json',report)
    if not report['all_passed']:raise SystemExit(1)
    print('Evidence',root)
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--only');a=p.parse_args();fixture_cases(a.only)
