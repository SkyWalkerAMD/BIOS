"""Find original executable references to the LZMA GUID, without execution."""
from pathlib import Path
import hashlib,json,uuid
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[3]
BASE=ROOT/'analysis/workstation_20261008/W890_SAGE_0603'
guid=uuid.UUID('ee4e5898-3914-4259-9d6e-dc7bd79403cf').bytes_le
found=[];examined=0
for p in BASE.rglob('body.bin'):
    if 'PE32 image section' not in p.parent.name and 'TE image section' not in p.parent.name:continue
    raw=p.read_bytes();examined+=1
    if guid not in raw:continue
    offsets=[];pos=raw.find(guid)
    while pos>=0:offsets.append(pos);pos=raw.find(guid,pos+1)
    found.append(dict(path=str(p),bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest(),guid_offsets=offsets))
out=dict(status='ORIGINAL_STATIC_CANDIDATES_ONLY',guid=str(uuid.UUID(bytes_le=guid)),executables_examined=examined,matches=found)
(HERE/'lzma_native_candidates.json').write_text(json.dumps(out,indent=2)+'\n',encoding='utf-8')
print(json.dumps(out))
