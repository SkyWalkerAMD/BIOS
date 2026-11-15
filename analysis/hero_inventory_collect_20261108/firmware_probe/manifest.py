"""Reference hashes and offline PE fingerprints for comparison with FV output."""
from pathlib import Path
import hashlib,json,zlib
P=Path(__file__).resolve().parent;ROOT=P.parents[2]
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 base='https://raw.githubusercontent.com/tianocore/edk2/edk2-stable202502/MdePkg/Include/'
 refs=[]
 for name,remote in [('FirmwareVolume2.h','Protocol/FirmwareVolume2.h'),('DevicePath.h','Protocol/DevicePath.h'),
  ('PiFirmwareFile.h','Pi/PiFirmwareFile.h'),('PiFirmwareVolume.h','Pi/PiFirmwareVolume.h')]:
  path=P/'reference'/name
  refs.append({'path':str(path.relative_to(ROOT)),'url':base+remote,'bytes':path.stat().st_size,'sha256':sha(path)})
 for name,remote in [('LoadedImage.h','Protocol/LoadedImage.h'),('UefiSpec.h','Uefi/UefiSpec.h')]:
  path=ROOT/'analysis/hero_ipmi_r2/reference/edk2'/name
  refs.append({'path':str(path.relative_to(ROOT)),'url':base+remote,'bytes':path.stat().st_size,'sha256':sha(path)})
 (P/'provenance.json').write_text(json.dumps({'references':refs,'definitions':{
  'FirmwareVolume2.h':'Protocol GUID; ReadFile/ReadSection signatures; metadata-only Buffer==NULL; caller-owned ReadSection buffer and EFI_WARN_BUFFER_TOO_SMALL; structure ordering.',
  'DevicePath.h':'MEDIA_PIWG_FW_FILE_DP=6 and MEDIA_FW_VOL_FILEPATH_DEVICE_PATH Header+GUID; End Entire=7F/FF.',
  'PiFirmwareVolume.h':'EFI_FV_FILE_ATTRIBUTES is UINT32.',
  'PiFirmwareFile.h':'EFI_FV_FILETYPE UINT8 and EFI_SECTION_PE32=0x10.',
  'LoadedImage.h':'FilePath, ImageBase, ImageSize ABI and protocol GUID.',
  'UefiSpec.h':'EFI memory descriptors, GetMemoryMap and Boot Services layout.'},
  'no_network_or_hardware_access_by_this_module_development':True},indent=2)+'\n')
 meta=json.loads((ROOT/'analysis/hero_ipmi_rc3_20261104/runtime-verification.json').read_text())
 p6=json.loads((ROOT/'analysis/hero_ipmi_p6_20261104/runtime-build.json').read_text())
 images=[]
 for label,path,digest in [
  ('R2 extracted from RC3','analysis/hero_ipmi_rc3_20261104/runtime-input/USB/EFI/HERO/HeroIpmiR2.efi',meta['r2_sha256']),
  ('P5 extracted from RC3; RC2/RC3 share P5','analysis/hero_ipmi_rc3_20261104/runtime-input/HeroIpmiP5.efi',meta['p5_sha256']),
  ('P6 RC4 candidate','analysis/hero_ipmi_p6_20261104/HeroIpmiP6.efi',p6['driver_sha256'])]:
  p=ROOT/path;assert sha(p)==digest;data=p.read_bytes()
  images.append({'label':label,'path':path,'bytes':len(data),'crc32':f'{zlib.crc32(data):08X}','sha256':digest})
 (P/'known-pe-images.json').write_text(json.dumps({'scope':'Compare only FP_FV_PE_BYTES/CRC32, never relocated FP_LOADED_MEMORY_CRC32. CRC32+size are diagnostic fingerprints, not cryptographic attestation. These hashes describe local archived images, not current hardware.',
  'images':images},indent=2)+'\n')
 print(json.dumps(images,indent=2))
if __name__=='__main__':main()
