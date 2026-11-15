"""Read-only inventory in local OVMF using disposable regular image files.
No host devices/passthrough/shared directories/network. The diagnostic itself
does not connect controllers. QEMU/firmware may connect boot devices normally.
"""
from pathlib import Path
import datetime,hashlib,json,shutil,subprocess,sys,time
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[6];OUT=HERE/'build'
sys.path[:0]=[str(ROOT/'analysis/aitweaker_lock/uefi_vm_20261015'),str(ROOT/'analysis/aitweaker_lock/probe_p3_kvm')]
from run_vm_tests import QMP,ppm_to_png,QEMU,SHARE,CODE,VARS
from decode_captures import read_image,parse_frame,assemble
from decode_inventory_log import parse
sys.path[:0]=[str(ROOT/'tools/pydeps'),str(ROOT/'tools/vm-pydeps')]
from pyfatfs.PyFatFS import PyFatFS
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
def save(p,x):p.write_text(json.dumps(x,indent=2)+'\n',encoding='utf8')
ISO=OUT/'SAGE1904-MEDIA-USB-INVENTORY01.iso'
def run(identity):
    boot_hd=identity.startswith('boot_');mode=identity[5:] if boot_hd else identity
    folder=HERE/'vm'/(datetime.datetime.now().strftime('%Y%m%d_%H%M%S_%f')+'_'+identity);folder.mkdir(parents=True);shutil.copyfile(VARS,folder/'vars.fd')
    args=[str(QEMU),'-L',str(SHARE),'-machine','q35,accel=tcg','-cpu','max','-m','512','-smp','1','-nic','none','-display','none','-monitor','none','-qmp','stdio','-vga','none','-device','VGA,xres=1280,yres=800','-serial','file:'+str(folder/'serial.log'),'-drive','if=pflash,format=raw,unit=0,readonly=on,file='+str(CODE),'-drive','if=pflash,format=raw,unit=1,file='+str(folder/'vars.fd'),'-drive','if=none,id=cd,format=raw,media=cdrom,readonly=on,file='+str(ISO),'-device','qemu-xhci,id=xhci','-device','usb-storage,bus=xhci.0,drive=cd,bootindex=1,port=1']
    pristine=HERE.parent/'media_writeback_review/blank_test/WRITEBACK02.img';assert sha(pristine)=='df7fa016a0f4be496d3d446db558e8de15f537aa9953faff20b4ae0c6132b4b6'
    if boot_hd:args[-1]=args[-1].replace('bootindex=1','bootindex=2')
    disks={}
    if mode!='absent':
        disk=folder/'data.img';shutil.copyfile(pristine,disk)
        if mode=='larger':
            with disk.open('r+b') as f:f.truncate(32*1024*1024)
        if boot_hd:
            # Local test fixture only: normal firmware boot publishes storage
            # protocols before the unchanged diagnostic begins. No app connect.
            with PyFatFS(str(disk),utc=True) as fs:
                fs.makedirs('/EFI/BOOT',recreate=True);fs.writebytes('/EFI/BOOT/BOOTX64.EFI',(OUT/'BOOTX64.EFI').read_bytes())
        disks[str(disk)]=sha(disk)
        args+=['-drive','if=none,id=data,format=raw,file='+str(disk)+(',readonly=on' if mode=='readonly' else '')]
        bootprop=',bootindex=1' if boot_hd else ''
        if mode=='non_usb':args+=['-device','virtio-blk-pci,drive=data'+bootprop]
        else:args+=['-device','usb-storage,bus=xhci.0,drive=data,port=2,removable=on'+bootprop]
    save(folder/'command.json',args)
    result={'status':'FAIL','case':identity,'hardware_tested':False,'efi_sha256':sha(OUT/'BOOTX64.EFI'),'iso_sha256':sha(ISO),'ovmf_code_sha256':sha(CODE)}
    proc=None;start=time.monotonic()
    try:
        with (folder/'stderr.log').open('wb') as err:
            proc=subprocess.Popen(args,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=err,text=True,encoding='utf8',creationflags=subprocess.CREATE_NO_WINDOW)
            qmp=QMP(proc,folder);qmp.command('qmp_capabilities',timeout=15)
            def serial():return (folder/'serial.log').read_bytes() if (folder/'serial.log').exists() else b''
            def wait(token,after=0):
                end=time.monotonic()+50
                while time.monotonic()<end:
                    if token in serial()[after:]:return
                    if proc.poll() is not None:raise RuntimeError('QEMU exited')
                    time.sleep(.1)
                raise TimeoutError(repr(token))
            def key(k):qmp.command('send-key',{'keys':[{'type':'qcode','data':k}],'hold-time':20});time.sleep(.15)
            def capture(page,name):
                end=time.monotonic()+8
                while time.monotonic()<end:
                    time.sleep(.15);ppm=folder/(name+'.ppm');png=folder/(name+'.png');qmp.command('screendump',{'filename':str(ppm)});ppm_to_png(ppm,png)
                    try:
                        frame=read_image(png)
                        if parse_frame(frame)['page']==page:return frame
                    except ValueError:pass
                raise TimeoutError('QR capture '+name)
            wait(b'QR PAGE 1/');first=capture(1,'qr-1');pages=parse_frame(first)['pages'];frames=[first]
            for page in range(2,pages+1):key('n');frames.append(capture(page,f'qr-{page}'))
            log,meta=assemble(frames,require_inventory=False);(folder/'RESTORED-LOG.TXT').write_bytes(log)
            expected=serial().split(b'KVM_LOG_BEGIN\r\n',1)[1].split(b'KVM_LOG_END\r\n',1)[0];assert log==expected
            parsed=parse(log);save(folder/'parsed_inventory.json',parsed)
            assert parsed['complete'] and parsed['test_status']=='0000000000000000',log.decode()
            hs=parsed['handles'];usb=[r for r in hs if r.get('USB_DEVICE_VALID')=='1'];bios=[r for r in hs if r.get('BLOCK_IO_STATUS')=='0000000000000000']
            if not boot_hd:assert usb and any(r.get('MEDIA_BLOCK_BYTES')=='00000800' for r in bios),'read-only boot CD metadata'
            # QEMU VID/PID differs from the vendor gadget. Test generic metadata,
            # never spoof physical vendor-device success.
            target=[r for r in bios if r.get('MEDIA_BLOCK_BYTES')=='00000200' and r.get('MEDIA_LAST_BLOCK')==('000000000000FFFF' if mode=='larger' else '0000000000007FFF')]
            if boot_hd:
                assert target,(identity,'no requested geometry in existing BlockIO',hs)
                if mode=='non_usb':assert any(r.get('DP_USB_NODE')=='0' for r in target)
                else:assert any(r.get('DP_USB_NODE')=='1' for r in target)
                if mode=='readonly':assert all(r.get('MEDIA_READ_ONLY')=='01' for r in target)
            elif mode in ['usb','readonly','larger']:
                # Observed OVMF BDS connects the CD boot path only. The useful
                # result is precisely USB_IO present but BlockIO/SFS absent.
                assert len(usb)==2 and not target
                assert any(r.get('BLOCK_IO_STATUS')=='8000000000000003' and r.get('SFS_PUBLISHED')=='0' for r in usb)
            elif mode in ['absent','non_usb']:assert len(usb)==1 and not target
            assert b'FILE_OPS=0 BLOCK_DATA_OPS=0 RAW_USB_OPS=0 CONNECT_OPS=0' in log
            key('home');assert capture(1,'home')==first
            before=len(serial());key('t');wait(b'TEXT PAGE 1/',before);key('q');assert capture(1,'return-qr')==first
            before=len(serial());key('esc');wait(b'USB inventory ended.',before)
            qmp.command('quit');assert proc.wait(timeout=10)==0;qmp.thread.join(timeout=2)
            assert sha(ISO)==result['iso_sha256'] and sha(pristine)=='df7fa016a0f4be496d3d446db558e8de15f537aa9953faff20b4ae0c6132b4b6'
            for disk,baseline in disks.items():assert sha(Path(disk))==baseline,'data image changed'
            result.update(status='PASS_LOCAL_OVMF_ONLY',boot_fixture='normal firmware data-disk boot' if boot_hd else 'read-only CD boot',qr_pages=pages,qr_metadata=meta,qr_matches_console=True,usb_io_records=len(usb),block_io_records=len(bios),handle_records=len(hs),all_data_and_iso_images_unchanged=True,restored_log_sha256=sha(folder/'RESTORED-LOG.TXT'))
    except Exception as ex:
        import traceback
        result.update(error=str(ex),traceback=traceback.format_exc())
    finally:
        if proc and proc.poll() is None:
            proc.terminate()
            try:proc.wait(timeout=5)
            except subprocess.TimeoutExpired:proc.kill();proc.wait(timeout=5)
        result.update(seconds=round(time.monotonic()-start,2),owned_process_finished=bool(proc and proc.poll() is not None),folder=str(folder.relative_to(HERE)));save(folder/'result.json',result)
    print(json.dumps({'case':identity,'status':result['status'],'error':result.get('error'),'seconds':result['seconds']}),flush=True);return result
cases=[run(s) for s in (sys.argv[1:] or ['usb','readonly','absent','larger','non_usb','boot_usb','boot_readonly','boot_larger','boot_non_usb'])]
result={'status':'PASS_LOCAL_OVMF_ONLY' if all(c['status']=='PASS_LOCAL_OVMF_ONLY' for c in cases) else 'FAIL','hardware_tested':False,'efi_sha256':sha(OUT/'BOOTX64.EFI'),'iso_sha256':sha(ISO),'test_sha256':sha(Path(__file__)),'cases':cases,'scope':__doc__}
save(OUT/'ovmf_verification.json',result);assert result['status']=='PASS_LOCAL_OVMF_ONLY'
