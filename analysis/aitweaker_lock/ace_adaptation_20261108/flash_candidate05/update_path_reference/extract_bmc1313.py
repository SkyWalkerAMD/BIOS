"""Read a fixed official-image whitelist; never execute BMC code or access hardware."""
from pathlib import Path
import gzip, hashlib, json, sys, zipfile

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
sys.path.insert(0, str(ROOT / 'tools/PySquashfsImage-0.9.0'))
from PySquashfsImage import SquashFsImage

IMAGE = ROOT / 'analysis/bmc_1_3_13_official/KODO1313.ima'
ZIP = IMAGE.with_name('IPMI_EXPANSION_CARD-1.3.13.zip')
OUT = HERE / 'bmc1313_inputs'
NAMES = [
 '/etc/core_features', '/usr/local/lib/hpm.conf',
 '/usr/local/lib/libcompamibios.so.6.12.0', '/usr/local/lib/libflash.so.13.3.0',
 '/usr/local/lib/libpdkapp.so.13.2.0', '/usr/local/lib/libipmihpm.so.13.6.0',
 '/usr/local/lib/libspx_restservice.so.13.1.0', '/usr/local/bin/spx_restservice',
 '/usr/local/bin/flasher', '/etc/init.d/flasher.sh',
 '/usr/local/redfish/redfish/update-service.lua',
 '/usr/local/redfish/update-service/update-service.lua',
 '/usr/local/redfish/oem/ami/query/update-service.lua',
 '/usr/local/redfish/oem/ami/update-service_AmiOem.lua',
 '/usr/local/sync-agent/extensions/ami/sync-helpers_ami/bios_update.lua',
]

def sha(data): return hashlib.sha256(data).hexdigest()
def write_verified(path, data):
 assert path.resolve().is_relative_to(HERE)
 path.parent.mkdir(parents=True, exist_ok=True)
 if path.exists(): assert path.read_bytes() == data, str(path)
 else: path.write_bytes(data)

files = []
for offset, names in [(0x520000, NAMES), (0x3240000, ['/source.min.js'])]:
 with SquashFsImage.from_file(str(IMAGE), offset=offset) as fs:
  for name in names:
   item = fs.root.select(name)
   assert item.is_file and 0 <= item.size <= 2000000
   data = item.read_bytes()
   path = OUT / name.lstrip('/')
   write_verified(path, data)
   files.append(dict(image_offset=hex(offset), member=name,
                     output=path.relative_to(ROOT).as_posix(), bytes=len(data), sha256=sha(data)))
packed = (OUT / 'source.min.js').read_bytes()
decoded = gzip.decompress(packed)
write_verified(OUT / 'source.decoded.js', decoded)
current = HERE.parent / 'bmc_static_readonly/source.min.js'
with zipfile.ZipFile(ZIP) as z:
 zip_members=[dict(name=x.filename, bytes=x.file_size, crc32=f'{x.CRC:08x}') for x in z.infolist()]
 exact=[x for x in z.infolist() if Path(x.filename).name=='KODO1313.ima']
 assert len(exact)==1
 image_equals_official_zip_member = z.read(exact[0]) == IMAGE.read_bytes()
report = dict(
 source_image=dict(path=IMAGE.relative_to(ROOT).as_posix(), bytes=IMAGE.stat().st_size, sha256=sha(IMAGE.read_bytes())),
 source_zip=dict(path=ZIP.relative_to(ROOT).as_posix(), bytes=ZIP.stat().st_size, sha256=sha(ZIP.read_bytes()),members=zip_members),
 image_equals_official_zip_member=image_equals_official_zip_member,
 source_provenance=json.loads((IMAGE.parent/'source.json').read_text(encoding='utf8')),
 files=files,
 frontend=dict(packed_sha256=sha(packed),packed_bytes=len(packed),decoded_sha256=sha(decoded),decoded_bytes=len(decoded),
               live_capture=current.relative_to(ROOT).as_posix(), live_sha256=sha(current.read_bytes()),
               live_and_official_decoded_bytes_identical=(current.read_bytes()==decoded)),
 limits=['Matching official version and byte-identical public frontend do not independently attest every executable byte currently running on the BMC.',
         'This extraction reads an archived vendor image only; no BMC request, firmware upload, or firmware code execution.'])
(HERE/'bmc1313_extraction_manifest.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf8')
print(json.dumps(dict(image=report['source_image'],frontend=report['frontend'],files=len(files))))
