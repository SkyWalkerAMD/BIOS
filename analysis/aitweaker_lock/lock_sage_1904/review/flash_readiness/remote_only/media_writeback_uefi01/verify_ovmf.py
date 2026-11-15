"""Actual OVMF file operations on disposable local USB IMG copies; no hardware or network.
Complete QR roundtrip, refusal cases and local image reopening are checked.
"""
from pathlib import Path
import datetime,hashlib,json,shutil,subprocess,sys,time
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[6];OUT=HERE/'build'
sys.path[:0]=[str(ROOT/'analysis/aitweaker_lock/uefi_vm_20261015'),str(ROOT/'analysis/aitweaker_lock/probe_p3_kvm')]
from run_vm_tests import QMP,ppm_to_png,QEMU,SHARE,CODE,VARS
from decode_captures import read_image,parse_frame,assemble
sys.path[:0]=[str(ROOT/'tools/pydeps'),str(ROOT/'tools/vm-pydeps')]
from pyfatfs.PyFatFS import PyFatFS
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
def save(p,x):p.write_text(json.dumps(x,indent=2)+'\n',encoding='utf8')
ISO=OUT/'SAGE1904-MEDIA-WRITEBACK01.iso'

def run(identity):
    folder=HERE/'vm'/(datetime.datetime.now().strftime('%Y%m%d_%H%M%S')+'_'+identity)
    folder.mkdir(parents=True);shutil.copyfile(VARS,folder/'vars.fd')
    args=[str(QEMU),'-L',str(SHARE),'-machine','q35,accel=tcg','-cpu','max','-m','512','-smp','1','-nic','none','-display','none','-monitor','none','-qmp','stdio','-vga','none','-device','VGA,xres=1280,yres=800','-serial','file:'+str(folder/'serial.log'),'-drive','if=pflash,format=raw,unit=0,readonly=on,file='+str(CODE),'-drive','if=pflash,format=raw,unit=1,file='+str(folder/'vars.fd'),'-drive','if=none,id=cd,format=raw,media=cdrom,readonly=on,file='+str(ISO),'-device','qemu-xhci,id=xhci','-device','usb-storage,bus=xhci.0,drive=cd,bootindex=1']
    pristine=HERE.parent/'media_writeback_review/blank_test/WRITEBACK02.img'
    assert sha(pristine)=='df7fa016a0f4be496d3d446db558e8de15f537aa9953faff20b4ae0c6132b4b6'
    datafiles=[];before_hashes={}
    if identity!='absent':
        for index in range(2 if identity=='duplicate' else 1):
            disk=folder/f'data-{index}.img';shutil.copyfile(pristine,disk)
            if identity in ['wrong_marker','existing_result']:
                with PyFatFS(str(disk),utc=True) as fs:
                    if identity=='wrong_marker':fs.writebytes('/IDENTIFY.TXT',b'WRONG TEST MARKER')
                    else:fs.writebytes('/WRBACK.TXT',b'EXISTING CONTENT MUST SURVIVE')
            before_hashes[str(disk)]=sha(disk);datafiles.append(disk)
            args+=['-drive',f'if=none,id=wb{index},format=raw,file='+str(disk)+(',readonly=on' if identity=='readonly' else '')]
            if identity=='non_usb':args+=['-device',f'virtio-blk-pci,drive=wb{index}']
            else:
                args+=['-device',f'usb-storage,bus=xhci.0,drive=wb{index}']
    save(folder/'command.json',args)
    result={'status':'FAIL','case':identity,'hardware_tested':False,'efi_sha256':sha(OUT/'BOOTX64.EFI'),'iso_sha256':sha(ISO),'ovmf_code_sha256':sha(CODE)}
    proc=None;start=time.monotonic()
    try:
        with (folder/'stderr.log').open('wb') as err:
            proc=subprocess.Popen(args,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=err,text=True,encoding='utf8',creationflags=subprocess.CREATE_NO_WINDOW)
            qmp=QMP(proc,folder);qmp.command('qmp_capabilities',timeout=15)
            def serial():return (folder/'serial.log').read_bytes() if (folder/'serial.log').exists() else b''
            def wait(token,after=0):
                end=time.monotonic()+40
                while time.monotonic()<end:
                    if token in serial()[after:]:return
                    if proc.poll() is not None:raise RuntimeError('QEMU exited')
                    time.sleep(.1)
                raise TimeoutError(repr(token))
            def key(code):qmp.command('send-key',{'keys':[{'type':'qcode','data':code}],'hold-time':20});time.sleep(.15)
            def capture(page,name):
                end=time.monotonic()+8
                while time.monotonic()<end:
                    time.sleep(.2);ppm=folder/(name+'.ppm');png=folder/(name+'.png')
                    qmp.command('screendump',{'filename':str(ppm)});ppm_to_png(ppm,png)
                    try:
                        frame=read_image(png)
                        if parse_frame(frame)['page']==page:return frame
                    except ValueError:pass
                raise TimeoutError('QR capture '+name)
            wait(b'QR PAGE 1/')
            first=capture(1,'qr-1');pages=parse_frame(first)['pages'];frames=[first]
            for page in range(2,pages+1):key('n');frames.append(capture(page,f'qr-{page}'))
            log,meta=assemble(frames,require_inventory=False);(folder/'RESTORED-LOG.TXT').write_bytes(log)
            expected=serial().split(b'KVM_LOG_BEGIN\r\n',1)[1].split(b'KVM_LOG_END\r\n',1)[0];assert log==expected
            assert b'Watchdog.disable=0x0000000000000000\r\n' in log
            expected_success=identity=='positive'
            assert (b'TEST_STATUS=0x0000000000000000' in log)==expected_success,log.decode('ascii')
            if expected_success:
                assert b'UEFI_FILE_READBACK_STATUS=0x0000000000000000' in log
                assert b'EXACT_MATCHES=0x0000000000000001' in log
            else:assert b'FILE_WRITE_STATUS' not in log
            key('home');assert capture(1,'home')==first
            before=len(serial());key('t');wait(b'TEXT PAGE 1/',before)
            key('q');assert capture(1,'return-qr')==first
            before=len(serial());key('esc');wait(b'File test ended.',before)
            qmp.command('quit');assert proc.wait(timeout=10)==0;qmp.thread.join(timeout=2)
            assert sha(ISO)==result['iso_sha256']
            for disk in datafiles:
                assert disk.stat().st_size==16777216
                with PyFatFS(str(disk),read_only=True,utc=True) as fs:
                    if identity=='positive':
                        assert fs.readbytes('/WRBACK.TXT')==(HERE/'expected-result.bin').read_bytes()
                        assert hashlib.sha256(fs.readbytes('/IDENTIFY.TXT')).hexdigest()=='cf23bdeea12a51328c1589210a11591a249964372d7aac3da93de75fbae5230a'
                        assert set(fs.listdir('/'))=={'IDENTIFY.TXT','WRBACK.TXT'}
                    else:assert sha(disk)==before_hashes[str(disk)],'Noneligible image changed'
            result['disposable_image_paths']=[str(p) for p in datafiles]
            result['positive_disk_reopened_read_only_and_exact_file_verified']=expected_success
            result['noneligible_images_unchanged']=not expected_success

            result.update(status='PASS_LOCAL_OVMF_ONLY',qr_pages=pages,qr_metadata=meta,qr_matches_console=True,checks=['read_only_cd_boot','watchdog_disable_success','USB_geometry_label_marker_unique_selection_and_bounded_file_readback','QR_CRC_and_exact_log_roundtrip','QR_home','text_mode','QR_return','Escape_returns','ISO_unchanged'],restored_log_sha256=sha(folder/'RESTORED-LOG.TXT'),only_disposable_regular_file_drives=True)
    except Exception as ex:
        import traceback
        result.update(error=str(ex),traceback=traceback.format_exc())
    finally:
        if proc and proc.poll() is None:
            proc.terminate()
            try:proc.wait(timeout=5)
            except subprocess.TimeoutExpired:proc.kill();proc.wait(timeout=5)
        result.update(seconds=round(time.monotonic()-start,2),owned_process_finished=bool(proc and proc.poll() is not None),folder=str(folder.relative_to(HERE)))
        save(folder/'result.json',result)
    print(json.dumps({'case':identity,'status':result['status'],'error':result.get('error'),'seconds':result['seconds']},indent=2),flush=True)
    return result

cases=[run(name) for name in (sys.argv[1:] or ['positive','absent','wrong_marker','existing_result','readonly','duplicate','non_usb'])]
report={'status':'PASS_LOCAL_OVMF_ONLY' if all(c['status']=='PASS_LOCAL_OVMF_ONLY' for c in cases) else 'FAIL','hardware_tested':False,'efi_sha256':sha(OUT/'BOOTX64.EFI'),'iso_sha256':sha(ISO),'test_source_sha256':sha(Path(__file__)),'cases':cases,'scope':__doc__}
save(OUT/'ovmf_verification.json',report)
assert report['status']=='PASS_LOCAL_OVMF_ONLY'
