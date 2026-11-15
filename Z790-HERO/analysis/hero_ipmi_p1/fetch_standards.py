"""Fetch pinned, official protocol definitions for source review only."""
from pathlib import Path
import urllib.request, hashlib, json
out = Path(__file__).resolve().parent / 'reference'
sources = {}
for name, folder in [('IpmiNetFnApp.h','MdePkg/Include/IndustryStandard'),
                     ('IpmiNetFnTransport.h','MdePkg/Include/IndustryStandard'),
                     ('IpmiNetFnStorage.h','MdePkg/Include/IndustryStandard'),
                     ('MdeModuleHii.h','MdeModulePkg/Include/Guid')]:
    url = 'https://raw.githubusercontent.com/tianocore/edk2/edk2-stable202502/' + folder + '/' + name
    data = urllib.request.urlopen(url, timeout=20).read()
    (out / name).write_bytes(data)
    sources[name] = {'url': url, 'sha256': hashlib.sha256(data).hexdigest()}
(out / 'standards-sources.json').write_text(json.dumps(sources, indent=2) + '\n')
print('Saved', len(sources), 'pinned protocol headers.')
