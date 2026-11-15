"""Package one hash-bound RAM_TEST09 EFI for optical boot; never access a device."""
from pathlib import Path
import argparse,hashlib,io,json,sys
HERE=Path(__file__).resolve().parent;D04=HERE.parent;ROOT=HERE.parents[7]
sys.path[:0]=[str(ROOT/'tools/pydeps'),str(ROOT/'tools/vm-pydeps'),str(ROOT/'tools/kvm-pydeps')]
import pefile,pycdlib
from pyfatfs.PyFat import PyFat
from pyfatfs.PyFatFS import PyFatFS
sha=lambda data:hashlib.sha256(data).hexdigest()

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--efi',required=True);parser.add_argument('--sha256',required=True);args=parser.parse_args()
    source=Path(args.efi).resolve();build=(D04/'ram_transaction09/app_build').resolve()
    if source.parent!=build or source.name!='SageNative13RamTest09.efi':raise ValueError('Only the owned RAM_TEST09 application build is accepted')
    raw=source.read_bytes()
    if sha(raw)!=args.sha256 or not 4096<=len(raw)<=8*1024*1024:raise ValueError('EFI identity or size mismatch')
    pe=pefile.PE(data=raw)
    assert pe.FILE_HEADER.Machine==0x8664 and pe.OPTIONAL_HEADER.Subsystem==10
    assert not hasattr(pe,'DIRECTORY_ENTRY_IMPORT')
    assert pe.OPTIONAL_HEADER.DATA_DIRECTORY[5].Size>0,'ASLR relocations required'
    assert pe.OPTIONAL_HEADER.DATA_DIRECTORY[4].Size==0,'Internal unsigned test application expected'
    assert all((s.Characteristics&0xA0000000)!=0xA0000000 for s in pe.sections),'RWX PE section rejected'
    entry=pe.OPTIONAL_HEADER.AddressOfEntryPoint
    assert any(s.VirtualAddress<=entry<s.VirtualAddress+max(s.Misc_VirtualSize,s.SizeOfRawData) and s.Characteristics&0x20000000 for s in pe.sections)
    out=HERE/'packages'/args.sha256[:16];out.mkdir(parents=True,exist_ok=False)
    (out/'packager-snapshot.py').write_bytes(Path(__file__).read_bytes())
    efi=out/'SageNative13RamTest09.efi';efi.write_bytes(raw)
    fatfile=out/'readonly-efiboot.img';fatfile.write_bytes(b'')
    fat=PyFat();fat.mkfs(str(fatfile),fat_type=16,size=16*1024*1024,label='SAGERAM09');fat.close()
    with PyFatFS(str(fatfile)) as fs:
        fs.makedirs('/EFI/BOOT',recreate=True);fs.writebytes('/EFI/BOOT/BOOTX64.EFI',raw)
    with PyFatFS(str(fatfile),read_only=True) as fs:
        assert list(fs.walk.files('/'))==['/EFI/BOOT/BOOTX64.EFI']
        assert fs.readbytes('/EFI/BOOT/BOOTX64.EFI')==raw
    iso=out/'SAGE-N13-RAMTEST09-NOFLASH.iso'
    cd=pycdlib.PyCdlib();cd.new(interchange_level=3,vol_ident='SAGE_N13_RAM09',joliet=3)
    cd.add_file(str(fatfile),iso_path='/EFIBOOT.IMG;1',joliet_path='/EFIBOOT.IMG')
    cd.add_eltorito('/EFIBOOT.IMG;1',bootcatfile='/BOOT.CAT;1',boot_load_size=fatfile.stat().st_size//512,platform_id=0xef,efi=True,media_name='noemul',bootable=True)
    cd.write(str(iso));cd.close()
    cd=pycdlib.PyCdlib();cd.open(str(iso));extracted=io.BytesIO();cd.get_file_from_iso_fp(extracted,iso_path='/EFIBOOT.IMG;1');cd.close()
    assert extracted.getvalue()==fatfile.read_bytes(),'ISO embedded FAT must match the verified boot image exactly'
    assert source.read_bytes()==raw,'Compiler output changed during packaging'
    report={'status':'PACKAGED_AND_ROUNDTRIP_VERIFIED_NOT_HARDWARE_APPROVAL','source_efi':str(source),'source_efi_sha256':sha(raw),'compiler_output_unchanged':True,'efi':str(efi),'efi_bytes':len(raw),'efi_sha256':sha(raw),'iso':str(iso),'iso_bytes':iso.stat().st_size,'iso_sha256':sha(iso.read_bytes()),'boot_image':str(fatfile),'boot_image_sha256':sha(fatfile.read_bytes()),'only_fat_file':'/EFI/BOOT/BOOTX64.EFI','fat_file_equals_compiled_efi':True,'iso_fat_roundtrip_exact':True,'packager_sha256':sha(Path(__file__).read_bytes()),'template_layout':'16MiB FAT16 in UEFI ElTorito optical image; same layout as physically executed prerequisite04','hardware_execution':False,'firmware_release_ready':False}
    (out/'package.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report))

if __name__=='__main__':main()
