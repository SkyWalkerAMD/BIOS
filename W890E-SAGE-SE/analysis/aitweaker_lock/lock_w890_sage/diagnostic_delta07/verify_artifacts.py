"""Final optical image, reproducible EFI, fixed inputs and legacy retention."""
from pathlib import Path
import hashlib,io,json,sys
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[3];OUT=HERE/'build';SAGE=HERE.parent
for part in ('pydeps','vm-pydeps','kvm-pydeps'):sys.path.insert(0,str(ROOT/'tools'/part))
import pefile,pycdlib
from pyfatfs.PyFatFS import PyFatFS
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 efi=OUT/'BOOTX64.EFI';image=OUT/'W890-DELTA07-STRUCTURE-NOFLASH.iso';expected=efi.read_bytes();pe=pefile.PE(data=expected)
 assert pe.verify_checksum() and pe.OPTIONAL_HEADER.Subsystem==10 and not hasattr(pe,'DIRECTORY_ENTRY_IMPORT')
 assert pe.OPTIONAL_HEADER.DATA_DIRECTORY[5].Size and not pe.OPTIONAL_HEADER.DATA_DIRECTORY[4].Size
 iso=pycdlib.PyCdlib();iso.open(str(image));fat=io.BytesIO();iso.get_file_from_iso_fp(fat,iso_path='/EFIBOOT.IMG;1');assert fat.getvalue()==(OUT/'efiboot.img').read_bytes();direct=io.BytesIO();iso.get_file_from_iso_fp(direct,iso_path='/EFI/BOOT/BOOTX64.EFI;1');assert direct.getvalue()==expected;assert iso.eltorito_boot_catalog.validation_entry.platform_id==0xef;iso.close()
 with PyFatFS(str(OUT/'efiboot.img'),read_only=True,utc=True) as fs:assert fs.readbytes('/EFI/BOOT/BOOTX64.EFI')==expected
 assert (OUT/'rebuilt/BOOTX64.EFI').read_bytes()==expected
 checks={}
 for name,key in (('diagnostic_hii06/component_manifest.json','files'),('spf_sampler06/component_manifest.json','files'),('collector_review06/review.json','sources')):
  entries=json.loads((SAGE/name).read_text())[key]
  for record in entries:assert sha(ROOT/record['path'])==record['sha256'],record['path']
  checks[name]=len(entries)
 for record in json.loads((OUT/'build.json').read_text())['inputs']:assert sha(Path(record['path']))==record['sha256']
 for record in json.loads((OUT/'rebuilt/build.json').read_text())['inputs']:assert sha(Path(record['path']))==record['sha256']
 old=ROOT/'analysis/aitweaker_lock/probe_p2/USB/EFI/BOOT/BOOTX64.EFI';assert sha(old)=='a16b2e7e0af6aa48cd375a3a3fbd77e58f60a50edd929751fcfe6951d6df64b5'
 ovmf=json.loads((OUT/'ovmf_tests.json').read_text());assert ovmf['passed']
 for run in ovmf['results']:assert run['efi_sha256']==sha(efi) and run['iso_sha256_before']==run['iso_sha256_after']==sha(image)
 report={'passed':True,'efi_sha256':sha(efi),'efi_bytes':len(expected),'iso_sha256':sha(image),'el_torito_and_direct_efi_equal':True,'rebuild_efi_identical':True,'all_frozen_bindings_unchanged':checks,'old_file_output_efi_sha256':sha(old),'no_hardware_operations':True,'note':'New read-only display collector; original file-output collector and existing QR tools are retained byte-for-byte.'}
 (OUT/'artifact_tests.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
if __name__=='__main__':main()
