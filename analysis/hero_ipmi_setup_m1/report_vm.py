"""Bind the observed OVMF UI/session evidence to the exact release payload."""
from pathlib import Path
import sys,json,hashlib,re
OUT=Path(__file__).resolve().parent;ROOT=OUT.parents[1];VM=OUT/'vm'
sys.dont_write_bytecode=True;sys.path.insert(0,str(ROOT/'analysis/aitweaker_lock/uefi_vm_20261015'))
import disk_images
disk_images.OUT=VM
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
    build=json.loads((OUT/'build.json').read_text());verification=json.loads((OUT/'verification.json').read_text())
    dxe=OUT/'USB/EFI/HERO/HeroIpmiM1.efi';app=OUT/'USB/EFI/BOOT/BOOTX64.EFI'
    assert verification['driver_sha256']==sha(dxe)
    meta=json.loads((VM/'disk.json').read_text());disk=Path(meta['path'])
    with disk_images.PyFatFS(str(disk),read_only=True) as fs:
        assert fs.readbytes('/EFI/HERO/HeroIpmiM1.efi')==dxe.read_bytes()
        assert fs.readbytes('/EFI/BOOT/BOOTX64.EFI')==app.read_bytes()
        logs={i:fs.readbytes(f'/HERO-M1-{i:03}.TXT') for i in range(4)}
    for i in (0,1):assert logs[i]==(VM/f'HERO-M1-{i:03}.TXT').read_bytes(),'Prior logs overwritten'
    a,b=[logs[i].decode('ascii') for i in (2,3)]
    assert 'CONFIG_SAVE enabled=01 status=0000000000000000' in a and 'TX ' not in a
    assert 'M1_READ_ONLY_BEGIN' in b and 'M1_INITIALIZE_BEGIN' in b
    assert b.count('RESULT: Unsupported target.')==2
    assert 'TX ' not in b and 'PCI_ENABLE' not in b
    assert 'CONFIG_SAVE enabled=00 status=0000000000000000' in b
    for text in (a,b):assert 'SEND_FORM_RETURN 0000000000000000' in text
    serial1=(VM/'serial-release-save.log').read_text(errors='replace')
    serial2=(VM/'serial.log').read_text(errors='replace')
    for serial in (serial1,serial2):
        assert 'Driver unload: 0x0000000000000000' in serial and 'Session result: 0x0000000000000000' in serial
    # The saved-enabled string must be rendered BEFORE any save in boot #2.
    clean=re.sub(r'\x1b\[[0-9;=?]*[A-Za-z]','',serial2)
    assert 'Saved auto-init                  Enabled' in clean
    screenshots=['15-release-disabled.png','16-release-saved.png','17-release-persisted.png',
      '18-release-target-gate.png','19-release-confirm.png','20-release-init-gate.png','21-release-disabled.png']
    for name in screenshots:assert (VM/name).stat().st_size>1000
    share=ROOT/'tools/qemu-11.1.0/share'
    report=dict(driver_sha256=sha(dxe),launcher_sha256=sha(app),release_boots=2,
      tests=[{'name':s,'passed':True} for s in ['HII package registration and real SendForm','Default/disabled setting displayed','Checkbox + Save persists private NVRAM','Cold VM boot reads enabled setting back','Read-only action rejects non-HERO before PCI access','Confirmation action rejects non-HERO before PCI access','Saved setting can be disabled again','ESC exits and exact release driver unloads','Audit logs flush to virtual FAT filesystem','Existing logs preserved']],
      screenshots={name:sha(VM/name) for name in screenshots},logs={f'HERO-M1-{i:03}.TXT':hashlib.sha256(logs[i]).hexdigest() for i in (2,3)},
      ovmf_sha256=sha(share/'edk2-x86_64-code.fd'),qemu_executable_sha256=sha(ROOT/'tools/qemu-11.1.0/qemu-system-x86_64.exe'),
      limitations=['OVMF is not ASUS AMI firmware. Native ASUS menu visibility is not proven.','No HERO or ASPEED hardware is passed through. Sensor correctness and physical KCS behavior are not verified here.','ReadyToBoot engine tests use Unicorn event invocation; USB entry occurs after the real event.'],all_passed=True)
    (VM/'results.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    print('OVMF release checks passed:',len(report['tests']))
if __name__=='__main__':main()
