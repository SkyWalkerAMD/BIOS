"""Boot the stage-1 ISO on OVMF and restore every refusal QR page.

Only isolated VM files are attached; no network, host disk, BMC or real UEFI
variable store is accessible. Test both ordinary OVMF and spoofed SMBIOS.
"""
from pathlib import Path
import datetime,hashlib,json,os,shutil,subprocess,sys,time
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent;ROOT=next(p for p in HERE.parents if (p/'tools/qemu-11.1.0/qemu-system-x86_64.exe').is_file())
OUT=HERE/'stage1/build';VM=ROOT/'analysis/aitweaker_lock/uefi_vm_20261015';QR=ROOT/'analysis/aitweaker_lock/probe_p3_kvm'
sys.path[:0]=[str(VM),str(QR)]
from run_vm_tests import QMP,ppm_to_png,QEMU,SHARE,CODE,VARS
from decode_captures import read_image,assemble,parse_frame
sha=lambda p:hashlib.sha256(Path(p).read_bytes()).hexdigest()
manifest=json.loads((OUT/'build.json').read_text(encoding='utf8'));iso=Path(manifest['iso_path'])
assert manifest['stage']==1 and sha(iso)==manifest['iso_sha256'] and sha(OUT/'BOOTX64.EFI')==manifest['efi_sha256']
result={'status':'RUNNING','iso_sha256':sha(iso),'efi_sha256':manifest['efi_sha256'],'production_driver_sha256':manifest['production_driver_sha256'],
 'manifest_sha256':sha(OUT/'build.json'),'physical_run':False,'cases':[],
 'inputs':{str(p.relative_to(ROOT)):sha(p) for p in [Path(__file__),VM/'run_vm_tests.py',VM/'disk_images.py',QR/'decode_captures.py',QEMU,CODE,VARS]}}
for spoof in [False,True]:
    folder=HERE/'qemu_runs'/(datetime.datetime.now().strftime('%Y%m%d_%H%M%S')+('_spoof' if spoof else '_ordinary'));folder.mkdir(parents=True)
    shutil.copyfile(VARS,folder/'vars.fd')
    args=[str(QEMU),'-L',str(SHARE),'-machine','q35,accel=tcg','-cpu','max','-m','512','-smp','1','-nic','none','-display','none','-monitor','none','-qmp','stdio','-vga','none','-device','VGA,xres=1280,yres=800',
          '-serial','file:'+str(folder/'serial.log'),'-drive','if=pflash,format=raw,unit=0,readonly=on,file='+str(CODE),
          '-drive','if=pflash,format=raw,unit=1,file='+str(folder/'vars.fd'),'-drive','if=none,id=cd,format=raw,media=cdrom,readonly=on,file='+str(iso),
          '-device','qemu-xhci,id=xhci','-device','usb-storage,drive=cd,bus=xhci.0,bootindex=1']
    if spoof:args+=['-smbios','type=0,version=1904','-smbios','type=2,product=Pro WS W790-ACE']
    (folder/'command.json').write_text(json.dumps(args,indent=2)+'\n',encoding='utf8')
    proc=None;case={'spoofed_target_smbios':spoof,'passed':False,'folder':str(folder)}
    try:
        with (folder/'stderr.log').open('wb') as err:
            proc=subprocess.Popen(args,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=err,text=True,encoding='utf8',creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
            qmp=QMP(proc,folder);qmp.command('qmp_capabilities',timeout=15);frames={};deadline=time.monotonic()+50
            while time.monotonic()<deadline:
                time.sleep(.5);ppm=folder/'screen.ppm';png=folder/'screen.png';qmp.command('screendump',{'filename':str(ppm)});ppm_to_png(ppm,png)
                try:raw=read_image(png);frame=parse_frame(raw)
                except ValueError:continue
                frames[frame['page']]=raw;shutil.copyfile(png,folder/('page-%02d.png'%frame['page']))
                if len(frames)==frame['pages']:break
                qmp.command('send-key',{'keys':[{'type':'qcode','data':'n'}],'hold-time':80})
            data,meta=assemble(list(frames.values()));(folder/'RESTORED-LOG.TXT').write_bytes(data)
            assert b'ACE1904-CANDIDATE05-NV-STAGE1\r\n' in data
            assert ('DriverSHA256='+manifest['production_driver_sha256']+'\r\n').encode() in data
            assert b'NativeSetAttempts=0x0000000000000000\r\n' in data and b'CleanupDeleteAttempts=0x0000000000000000\r\n' in data
            assert b'Phase1Receipt=' not in data
            if spoof:
                assert b'PASS exact SMBIOS Pro WS W790-ACE BIOS 1904\r\n' in data
                assert b'FAIL exact original ACE1904 module fingerprints; no AMITSE hooks\r\n' in data
            else:assert b'UNSUPPORTED_BOARD_NO_HOOKS_NO_WRITES\r\n' in data
            serial=(folder/'serial.log').read_bytes();assert data==serial.split(b'KVM_LOG_BEGIN\r\n',1)[1].split(b'KVM_LOG_END\r\n',1)[0]
            qmp.command('send-key',{'keys':[{'type':'qcode','data':'esc'}],'hold-time':80});time.sleep(.8)
            assert b'P3 KVM ended.' in (folder/'serial.log').read_bytes()
            qmp.command('quit');assert proc.wait(timeout=10)==0;qmp.thread.join(timeout=2)
            case.update(passed=True,qr=meta,refusal_before_residency=True,credential_native_writes=0,exit_verified=True)
    finally:
        if proc and proc.poll() is None:proc.terminate();proc.wait(timeout=5)
        result['cases'].append(case)
        (OUT/'boot_validation.json').write_text(json.dumps(result,indent=2)+'\n',encoding='utf8')
    print(json.dumps(case,indent=2),flush=True)
assert sha(iso)==manifest['iso_sha256'] and sha(CODE)==result['inputs'][str(CODE.relative_to(ROOT))]
result['status']='PASS_TWO_OVMF_REFUSALS_AND_EXACT_QR_RESTORE'
(OUT/'boot_validation.json').write_text(json.dumps(result,indent=2)+'\n',encoding='utf8')
print(result['status'])
