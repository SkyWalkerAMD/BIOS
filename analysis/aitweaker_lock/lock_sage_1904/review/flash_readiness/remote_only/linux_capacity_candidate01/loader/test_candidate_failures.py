"""Reject tampered media using the exact final candidate EFI binary under OVMF.
Only isolated copies below loader/tests are changed. Original artifacts untouched.
"""
import datetime,json
from pathlib import Path
from build_loader import OUT,sha
from run_tests import iso_for,run_vm,save

def main():
    manifest=json.loads((OUT/'candidate/media_manifest.json').read_text());contract=manifest['contract'];boot=OUT/'candidate/build/BOOTX64.EFI'
    assert sha(boot)==manifest['efi_sha256'];assert sha(manifest['iso'])==manifest['iso_sha256']
    kernel=Path(contract['kernel']['path']).read_bytes();initrd=Path(contract['initrd']['path']).read_bytes()
    folder=OUT/'tests/candidate-failures'/datetime.datetime.now().strftime('%Y%m%d_%H%M%S');folder.mkdir(parents=True)
    report={'scope':'Exact final EFI binary with missing/short/corrupt payload copies in isolated readonly ISO; no kernel execution expected','efi_sha256':sha(boot),'original_iso_sha256':manifest['iso_sha256'],'cases':[],'all_passed':False}
    for label,payload in [('kernel',kernel),('initrd',initrd)]:
        for mode in ['missing','short','changed']:
            name=mode+'_'+label;dest=folder/name;dest.mkdir();files={'/EFI/BOOT/BOOTX64.EFI':boot.read_bytes(),'/LINUX/VMLINUX.EFI':kernel,'/LINUX/CAPACITY01.IMG':initrd}
            target='/LINUX/VMLINUX.EFI' if label=='kernel' else '/LINUX/CAPACITY01.IMG'
            if mode=='missing':del files[target];reason=('kernel' if label=='kernel' else 'custom_initrd')+' status='
            elif mode=='short':files[target]=payload[:-1];reason='payload_length_or_info'
            else:files[target]=payload[:-1]+bytes([payload[-1]^1]);reason='payload_sha256'
            iso=iso_for(dest,files);r=run_vm(dest,iso,'LC01_BOOT_STOP '+reason,timeout=60,wait_seconds=2)
            r['case']=name;r['evidence']=str(dest.relative_to(OUT))
            if r['passed']:
                debug=(dest/'debug.log').read_text();assert 'LC01_START_PINNED_KERNEL' not in debug and 'LC01_INITRD_DELIVERED' not in debug
            report['cases'].append(r);save(folder/'summary.json',report);print(name,'PASS' if r['passed'] else 'FAIL',flush=True)
            assert r['passed'],r
    assert sha(manifest['iso'])==manifest['iso_sha256'] and sha(boot)==manifest['efi_sha256']
    report['all_passed']=True;report['original_candidate_unchanged']=True;save(folder/'summary.json',report);save(OUT/'tests/latest_candidate_failure_results.json',report)
if __name__=='__main__':main()
