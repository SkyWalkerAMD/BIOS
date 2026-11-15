"""Actual QEMU TCG/OVMF boot, residency, read-only ISO, and NVRAM tests.

No network, host disk, host NVRAM, physical device, or firmware flashing.
Fixtures deliberately contain no ASUS HII and make no password-lock claim.
"""
from pathlib import Path
import datetime,hashlib,json,shutil,subprocess,sys,time,traceback
OUT=Path(__file__).resolve().parent;ROOT=OUT.parents[3]
sys.path.insert(0,str(OUT.parent.parent/'uefi_vm_20261015'))
sys.path.insert(0,str(ROOT/'tools/kvm-pydeps'))
import disk_images,pycdlib
from inject_ovmf import inject
disk_images.OUT=OUT
Q=ROOT/'tools/qemu-11.1.0';SHARE=Q/'share'
def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def save(p,o):p.write_text(json.dumps(o,indent=2),encoding='utf8')
def make_iso(folder,files):
    disk_images.VOLUME_SIZE=16*1024*1024
    img=folder/'eltorito.img';meta=disk_images.create(img,'superfloppy',16,files)
    iso=pycdlib.PyCdlib();iso.new(interchange_level=3,vol_ident='VM_LAB_ONLY',joliet=3)
    iso.add_file(str(img),iso_path='/EFIBOOT.IMG;1',joliet_path='/EFIBOOT.IMG')
    iso.add_eltorito('/EFIBOOT.IMG;1',bootcatfile='/BOOT.CAT;1',boot_load_size=img.stat().st_size//512,platform_id=0xef,efi=True,media_name='noemul')
    target=folder/'lab.iso';iso.write(str(target));iso.close();return target,meta
def boot(folder,code,varsfile,medium,cd=False):
    folder.mkdir();args=[str(Q/'qemu-system-x86_64.exe'),'-L',str(SHARE),'-machine','q35,accel=tcg','-cpu','max','-m','512','-smp','1','-nic','none','-display','none','-monitor','none','-serial','file:'+str(folder/'serial.log'),'-debugcon','file:'+str(folder/'debug.log'),'-global','isa-debugcon.iobase=0x402','-device','isa-debug-exit,iobase=0xf4,iosize=0x4',
        '-drive','if=pflash,format=raw,unit=0,readonly=on,file='+str(code),'-drive','if=pflash,format=raw,unit=1,file='+str(varsfile),
        '-drive','if=none,id=boot,format=raw,file='+str(medium)+(',media=cdrom,readonly=on' if cd else ''),'-device',('ide-cd' if cd else 'ide-hd')+',drive=boot,bus=ide.0,bootindex=1']
    save(folder/'command.json',args);start=time.monotonic()
    with (folder/'stderr.log').open('wb') as err,(folder/'stdout.log').open('wb') as out:
        proc=subprocess.Popen(args,stdin=subprocess.DEVNULL,stdout=out,stderr=err,creationflags=subprocess.CREATE_NO_WINDOW)
        try:code_exit=proc.wait(timeout=90)
        except subprocess.TimeoutExpired:
            proc.terminate();proc.wait(timeout=5);raise TimeoutError('UEFI fixture did not finish within 90 s')
    log=(folder/'debug.log').read_text(encoding='ascii',errors='replace');result={'exit_code':code_exit,'seconds':round(time.monotonic()-start,2),'log_sha256':sha(folder/'debug.log')}
    assert code_exit==33 and 'LAB_PASS\n' in log and 'LAB_FAIL' not in log,(result,log[-4000:])
    result['passed']=True;save(folder/'result.json',result);return result,log
def main():
    tag=datetime.datetime.now().strftime('%Y%m%d_%H%M%S');folder=OUT/'runs'/tag;folder.mkdir(parents=True)
    build=OUT/'build';custom=build/'OVMF-LAB.fd';inject(build/'RESIDENT.EFI',custom)
    report={'purpose':'Real UEFI execution of VM-only lifecycle fixtures, not ASUS firmware navigation.','started_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'groups':[],'ovmf_source_sha256':sha(SHARE/'edk2-x86_64-code.fd'),'ovmf_injected_sha256':sha(custom),'all_passed':False}
    try:
        for name,auto,cd in [('external_fat',False,False),('external_readonly_iso',False,True),('embedded_dxe_fat',True,False)]:
            case=folder/name;case.mkdir();varsfile=case/'vars.fd';shutil.copyfile(SHARE/'edk2-i386-vars.fd',varsfile)
            files={'/EFI/BOOT/BOOTX64.EFI':(build/('AUTOBOOT.EFI' if auto else 'BOOTX64.EFI')).read_bytes(),'/CHECKER.EFI':(build/'CHECKER.EFI').read_bytes()}
            if not auto:files.update({'/LOADER.EFI':(build/'LOADER.EFI').read_bytes(),'/RESIDENT.EFI':(build/'RESIDENT.EFI').read_bytes()})
            if cd:medium,meta=make_iso(case,files)
            else:
                disk_images.VOLUME_SIZE=64*1024*1024;medium=case/'disk.img';meta=disk_images.create(medium,files=files)
            group={'name':name,'automatic_fv_dispatch':auto,'readonly_iso':cd,'medium_before_sha256':sha(medium),'boots':[]}
            report['groups'].append(group)
            for phase in range(2):
                result,log=boot(case/('boot'+str(phase)),custom if auto else SHARE/'edk2-x86_64-code.fd',varsfile,medium,cd)
                assert f'BOOT_PHASE={phase:016x}' in log
                if auto:assert log.index('RESIDENT_ENTRY')<log.index('BOOT_FIXTURE_BEGIN')
                else:assert log.index('BOOT_FIXTURE_BEGIN')<log.index('RESIDENT_ENTRY')
                if cd:assert 'BOOT_FILE_WRITE_OPEN=8000000000000008' in log
                else:assert 'BOOT_FILE_WRITE_OPEN=0000000000000000' in log
                result['vars_sha256_after']=sha(varsfile);group['boots'].append(result);print(name,'cold boot',phase,'PASS',flush=True)
            group['medium_after_sha256']=sha(medium)
            if cd:assert group['medium_before_sha256']==group['medium_after_sha256']
            else:
                result=disk_images.inspect(medium,meta['offset']);assert '/LAB-LOG.TXT' in result['files'];group['fat_copies_identical']=result['fat_copies_identical']
        report['all_passed']=True
    except Exception as exc:report['error']=str(exc);report['traceback']=traceback.format_exc();raise
    finally:
        report['finished_utc']=datetime.datetime.now(datetime.timezone.utc).isoformat();save(folder/'result.json',report);save(OUT/'latest_vm_result.json',report)
    print('All 6 cold boots PASS; evidence:',folder)
if __name__=='__main__':main()
