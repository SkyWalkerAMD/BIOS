"""Prepare ONLY a RAM-load SNP driver; preserve the variable read failure gate."""
from pathlib import Path
import hashlib,json,sys,zlib
OUT=Path(__file__).resolve().parent;ROOT=OUT.parents[1]
sys.path.insert(0,str(ROOT/'tools/pydeps'))
import pefile
src=OUT/'reference/SnpDxe.efi';raw=src.read_bytes()
assert hashlib.sha256(raw).hexdigest()=='b186518817547c71ab0818f1bc0872c2d21e7f78ec42028498fba4247a263474'
p=pefile.PE(data=raw);off=p.get_offset_from_rva(0x613);old=bytes.fromhex('384424607462')
assert raw[off:off+6]==old
data=bytearray(raw);data[off:off+6]=b'\x90'*6
p=pefile.PE(data=bytes(data));p.OPTIONAL_HEADER.CheckSum=p.generate_checksum();data=p.write()
name='I3ASNP.EFI';(OUT/'staged-drivers'/name).write_bytes(data)
patches=[{'rva':'0x613','file_offset':off,'old':old.hex(),'new':'90'*6,'purpose':'Explicit per-session RAM load after exact .71 identity and internal NII matching; bypass only NetworkStackVar[0] flag, retain GetVariable failure branch.'},{'field':'PE.OptionalHeader.CheckSum','purpose':'Update checksum after six-byte instruction patch.'}]
entry={'name':name,'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest(),'source_sha256':hashlib.sha256(raw).hexdigest(),'crc32':f'{zlib.crc32(data):08X}','patches':patches}
mp=OUT/'staged-drivers/manifest.json';rows=json.loads(mp.read_text());rows=[r for r in rows if r['name']!=name];rows.append(entry);mp.write_text(json.dumps(rows,indent=2)+'\n')
(OUT/'source/snp_image.h').write_text(f'#define I3A_SNP_BYTES {len(data)}u\n#define I3A_SNP_CRC32 0x{zlib.crc32(data):08x}u\n')
print(json.dumps(entry,indent=2))
