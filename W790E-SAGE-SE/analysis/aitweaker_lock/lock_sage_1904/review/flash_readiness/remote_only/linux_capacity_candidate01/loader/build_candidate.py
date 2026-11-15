"""Assemble only the pinned bootstrap/kernel/custom-initrd into local media."""
from pathlib import Path
import argparse,json
from build_loader import OUT,build,sha
from run_tests import iso_for,save,disk_images
def main():
    p=argparse.ArgumentParser();p.add_argument('contract',type=Path);p.add_argument('--folder',type=Path,default=OUT/'candidate');a=p.parse_args()
    folder=a.folder.resolve();assert folder.is_relative_to(OUT);folder.mkdir(parents=True,exist_ok=True)
    contract=json.loads(a.contract.read_text(encoding='utf8'));assert contract.get('status')=='FROZEN_LOCAL_REVIEW','Only a jointly frozen local review contract may produce candidate media'
    build_report=build(a.contract,folder/'build');boot=Path(build_report['binary'])
    files={'/EFI/BOOT/BOOTX64.EFI':boot.read_bytes(),'/LINUX/VMLINUX.EFI':Path(contract['kernel']['path']).read_bytes(),'/LINUX/CAPACITY01.IMG':Path(contract['initrd']['path']).read_bytes()}
    assert sum(map(len,files.values()))<28*1024*1024,'The fixed 31 MiB FAT image does not fit these payloads safely'
    media=folder/'media';media.mkdir(exist_ok=True);iso=iso_for(media,files)
    filesystem=disk_images.inspect(media/'eltorito.img',0)
    assert set(filesystem['files'])==set(files)
    for name,data in files.items():
        import hashlib
        assert filesystem['files'][name]['sha256']==hashlib.sha256(data).hexdigest()
    report={'status':'LOCAL REVIEW CANDIDATE; no hardware deployment authorization','iso':str(iso),'iso_sha256':sha(iso),'iso_bytes':iso.stat().st_size,'efi_sha256':sha(boot),'kernel_sha256':contract['kernel']['sha256'],'initrd_sha256':contract['initrd']['sha256'],'contract':contract,'contract_file_sha256':sha(a.contract),'fat_files':filesystem['files'],'only_three_payload_files':True,'test_fixture_included':False,'stock_initramfs_included':False,'boot_image_bytes':(media/'eltorito.img').stat().st_size,'boot_transport':'UEFI El Torito FAT16 full extent <=65535 sectors','hardware_pass':False}
    save(folder/'media_manifest.json',report);print(json.dumps(report,indent=2))
if __name__=='__main__':main()
