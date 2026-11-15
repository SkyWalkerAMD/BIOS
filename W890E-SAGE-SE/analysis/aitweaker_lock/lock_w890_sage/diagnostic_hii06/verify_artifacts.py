"""Read-only checks of the final ISO, embedded FAT/EFI and retained old output tools."""
from pathlib import Path
import hashlib,io,json,sys
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[3];OUT=HERE/'build';BASE=ROOT/'analysis/aitweaker_lock'
for part in ('pydeps','vm-pydeps','kvm-pydeps'):sys.path.insert(0,str(ROOT/'tools'/part))
import pefile,pycdlib
from pyfatfs.PyFatFS import PyFatFS
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 efi=OUT/'BOOTX64.EFI';iso_path=OUT/'W890-HII06-FINGERPRINT-NOFLASH.iso';expected=efi.read_bytes();pe=pefile.PE(data=expected)
 assert pe.verify_checksum() and pe.OPTIONAL_HEADER.Subsystem==10 and not hasattr(pe,'DIRECTORY_ENTRY_IMPORT')
 assert pe.OPTIONAL_HEADER.DATA_DIRECTORY[5].Size and pe.OPTIONAL_HEADER.DATA_DIRECTORY[4].Size==0
 iso=pycdlib.PyCdlib();iso.open(str(iso_path));fat=io.BytesIO();iso.get_file_from_iso_fp(fat,iso_path='/EFIBOOT.IMG;1');assert fat.getvalue()==(OUT/'efiboot.img').read_bytes()
 direct=io.BytesIO();iso.get_file_from_iso_fp(direct,iso_path='/EFI/BOOT/BOOTX64.EFI;1');assert direct.getvalue()==expected
 assert iso.eltorito_boot_catalog.validation_entry.platform_id==0xef;iso.close()
 with PyFatFS(str(OUT/'efiboot.img'),read_only=True,utc=True) as fs:assert fs.readbytes('/EFI/BOOT/BOOTX64.EFI')==expected
 frozen=json.loads((HERE.parent/'collector_review06/review.json').read_text());unchanged=[]
 for record in frozen['sources']:
  path=ROOT/record['path'];assert sha(path)==record['sha256'],path;unchanged.append(record)
 old_file=BASE/'probe_p2/USB/EFI/BOOT/BOOTX64.EFI';assert sha(old_file)=='a16b2e7e0af6aa48cd375a3a3fbd77e58f60a50edd929751fcfe6951d6df64b5'
 report={'passed':True,'efi_sha256':sha(efi),'iso_sha256':sha(iso_path),'pe_valid':True,'iso_and_el_torito_fat_embedded_efi_equal':True,'efi_boot_platform_ef':True,'old_sources_and_artifacts_unchanged':len(unchanged),'old_file_output_efi_sha256':sha(old_file),'notes':['No legacy builder or packaging tool executed.','No new file-output collector claimed; old P2 file collector remains available unchanged.']}
 (OUT/'artifact_tests.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
if __name__=='__main__':main()
