"""Extract a fixed read-only source whitelist from the already verified vendor image."""
from pathlib import Path
import hashlib,json,sys

OUT=Path(__file__).resolve().parent
ROOT=OUT.parents[2]
sys.path.insert(0,str(ROOT/'tools/PySquashfsImage-0.9.0'))
from PySquashfsImage import SquashFsImage

image=ROOT/'analysis/bmc_1_3_13_official/KODO1313.ima'
names=[
 '/usr/local/redfish/redfish-handler.lua',
 '/usr/local/redfish/utils.lua',
 '/usr/local/redfish/redfish/global-lua-tables.lua',
 '/usr/local/redfish/server.lua',
 '/usr/local/redfish/default_route.lua',
 '/usr/local/redfish/redfish-resource/redfish-resource-handler.lua',
 '/usr/local/redfish/redfish-resource/redfish-resource-URI_pattern.lua',
 '/usr/local/redfish/redfish-resource/redfish-resource-allow_method.lua',
 '/usr/local/redfish/redfish/system/processor-collection.lua',
 '/usr/local/redfish/redfish/system/processor-instance.lua',
 '/usr/local/redfish/redfish/system/memory.lua',
 '/usr/local/redfish/extensions/host-interface/hi-handlers/processor-collection-hi.lua',
 '/usr/local/redfish/extensions/host-interface/hi-handlers/processor-instance-hi.lua',
 '/usr/local/redfish/extensions/host-interface/hi-handlers/memory-collection-hi.lua',
 '/usr/local/redfish/extensions/host-interface/hi-handlers/system.lua',
 '/usr/local/redfish/extensions/host-interface/hi_utils.lua',
 '/usr/local/redfish/oem/ami_hi/hi-inventory-data.lua',
 '/usr/local/sync-agent/extensions/host-interface/hi-inventory-helper.lua',
]
manifest=[]
with SquashFsImage.from_file(str(image),offset=0x520000) as fs:
 for name in names:
  entry=fs.root.select(name)
  assert entry.is_file and 0<=entry.size<=200000
  data=entry.read_bytes()
  dest=OUT/'sources'/name.lstrip('/')
  assert dest.resolve().is_relative_to((OUT/'sources').resolve())
  dest.parent.mkdir(parents=True,exist_ok=True)
  if dest.exists(): assert dest.read_bytes()==data
  else: dest.write_bytes(data)
  manifest.append(dict(path=name,bytes=len(data),sha256=hashlib.sha256(data).hexdigest()))
result=dict(source_image=image.relative_to(ROOT).as_posix(),source_sha256=hashlib.sha256(image.read_bytes()).hexdigest(),squashfs_offset='0x520000',files=manifest)
(OUT/'source-manifest.json').write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps(dict(extracted=len(manifest),bytes=sum(x['bytes'] for x in manifest))))
