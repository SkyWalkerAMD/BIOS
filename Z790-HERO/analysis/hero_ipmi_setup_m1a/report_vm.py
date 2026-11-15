"""Summarize actual QEMU/OVMF observations; never equate them with HERO."""
from pathlib import Path
import hashlib,json,re,sys
sys.dont_write_bytecode=True
OUT=Path(__file__).resolve().parent;VM=OUT/'vm';ROOT=OUT.parents[1]
sys.path.insert(0,str(ROOT/'analysis/aitweaker_lock/uefi_vm_20261015'))
import disk_images
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def run():
    logs=[(VM/f'HERO-M1A-{i:03}.TXT').read_text() for i in range(3)]
    rows=[]
    def check(name,condition):
        assert condition,name
        rows.append(dict(case=name,passed=True))
    first,second,interrupted=logs
    check('text_gate_precedes_driver_and_hii',first.index('TEXT_READY_NO_DRIVER_NO_HII')<first.index('LOAD_IMAGE_BEFORE')<first.index('MINIMAL_NEW_PACKAGES_BEFORE'))
    check('driver_entry_does_not_register_hii_or_access_bmc',not re.search('NEW_PACKAGES|M1_READ_ONLY_BEGIN|M1_INITIALIZE_BEGIN|TX netfn=',first.split('START_IMAGE_BEFORE')[1].split('START_IMAGE_AFTER')[0]))
    check('simple_page_returns_success', 'MINIMAL_SEND_FORM_AFTER status=0000000000000000' in first)
    check('full_page_returns_success', 'FULL_SEND_FORM_AFTER status=0000000000000000' in first)
    check('string_updates_outside_browser',all('HII_SET_STRING' not in part.split('FULL_SEND_FORM_AFTER')[0] for log in logs for part in log.split('FULL_SEND_FORM_BEFORE')[1:]))
    check('read_only_wrong_target_rejected_before_hardware', 'M1_READ_ONLY_BEGIN' in first and 'Unsupported target' in first and 'TX netfn=' not in first)
    check('save_enabled_then_disabled_succeeds','CONFIG_SAVE enabled=01 status=0000000000000000' in first and 'CONFIG_SAVE enabled=00 status=0000000000000000' in second)
    serial=(VM/'serial-second-boot.log').read_text(encoding='utf-8')
    check('saved_enabled_visible_next_boot','Enabled (USB auto-run' in serial and 'suppressed)' in serial)
    check('no_auto_initialization_with_enabled_variable','M1_INITIALIZE_BEGIN' not in second and 'M1_READ_ONLY_BEGIN' not in second and 'TX netfn=' not in second)
    check('clean_session_unloads_successfully',all('UNLOAD_IMAGE_AFTER status=0x0000000000000000' in log and 'SESSION_END status=0x0000000000000000' in log for log in (first,second)))
    check('interrupted_browser_checkpoint_on_disk','MINIMAL_SEND_FORM_BEFORE' in interrupted and 'MINIMAL_SEND_FORM_AFTER' not in interrupted and 'SESSION_END' not in interrupted)
    check('earlier_logs_preserved',all((VM/f'HERO-M1A-{i:03}.TXT').stat().st_size>500 for i in range(3)))
    command=json.loads((VM/'command.json').read_text())
    disk=next(x.split('file=',1)[1] for x in command if x.startswith('if=none,id=boot,'))
    with disk_images.PyFatFS(disk,read_only=True) as fs:
        for p in sorted((OUT/'USB').rglob('*')):
            if p.is_file():assert fs.readbytes('/'+p.relative_to(OUT/'USB').as_posix())==p.read_bytes()
        for i in range(3):assert fs.readbytes(f'/HERO-M1A-{i:03}.TXT')==(VM/f'HERO-M1A-{i:03}.TXT').read_bytes()
    check('actual_release_payload_and_logs_match_fat_disk',True)
    screens=['01-text-start','02-driver-only','03-simple-hii','04-full-settings','05-text-read-return','08-full-disabled-final','09-interrupted-simple']
    assert all((VM/(p+'.png')).is_file() for p in screens)
    report=dict(driver_sha256=sha(OUT/'USB/EFI/HERO/HeroIpmiM1a.efi'),launcher_sha256=sha(OUT/'USB/EFI/BOOT/BOOTX64.EFI'),all_passed=True,count=len(rows),checks=rows,
        boots=3,firmware='OVMF edk2-stable202408-prebuilt.qemu.org',logs={f'HERO-M1A-{i:03}.TXT':sha(VM/f'HERO-M1A-{i:03}.TXT') for i in range(3)},
        screenshots={p+'.png':sha(VM/(p+'.png')) for p in screens},interruption='QEMU quit while simple page remained open; no guest Exit/UnloadImage. Log already contained pre-SendForm checkpoint.',
        limitations=['Not ASUS AMI firmware, HERO or BMC hardware.','Does not reproduce or prove the cause of the reported real black screen.','An interrupted virtual machine is not proof against every physical USB/power-loss failure.'])
    (VM/'results.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8');print('VM checks PASS',len(rows))
if __name__=='__main__':run()
