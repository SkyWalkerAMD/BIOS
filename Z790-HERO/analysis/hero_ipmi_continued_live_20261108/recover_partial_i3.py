"""Preserve a contiguous, page-verified incomplete snapshot without claiming full CRC."""
from pathlib import Path
import hashlib, importlib.util, json
OUT=Path(__file__).resolve().parent
path=OUT.parent/'hero_inventory_publish_20261108/decode_captures.py'
spec=importlib.util.spec_from_file_location('i3decode',path)
decoder=importlib.util.module_from_spec(spec);spec.loader.exec_module(decoder)
folder=OUT/'captures/hero71-internal-i3-native-stack'
frames=[decoder.parse_frame(p.read_bytes()) for p in sorted(folder.glob('*.qr.bin'))]
assert frames and [f['page'] for f in frames]==list(range(1,len(frames)+1))
assert len({(f['total'],f['crc'],f['pages']) for f in frames})==1
data=b''.join(f['data'] for f in frames)
dest=OUT/'hero71-internal-i3-native-stack.PARTIAL.TXT'
assert not dest.exists() or dest.read_bytes()==data
dest.write_bytes(data)
meta=dict(status='INCOMPLETE_PAGE_CRC_ONLY',pages_captured=len(frames),pages_expected=frames[0]['pages'],
          bytes_captured=len(data),bytes_expected=frames[0]['total'],whole_crc_not_verified=f'{frames[0]["crc"]:08X}',
          partial_sha256=hashlib.sha256(data).hexdigest(),reason='KVM showed Powered Off during page transition')
(folder/'partial-manifest.json').write_text(json.dumps(meta,indent=2)+'\n')
print(json.dumps(meta,indent=2))
