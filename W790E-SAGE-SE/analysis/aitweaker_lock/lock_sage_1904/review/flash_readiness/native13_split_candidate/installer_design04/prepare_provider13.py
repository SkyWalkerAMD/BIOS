"""Create isolated P13 sources once; preserve frozen P12 verbatim."""
from pathlib import Path
import hashlib,json
HERE=Path(__file__).resolve().parent;OLD=HERE.parents[1]/'native_provider12_candidate'
# installer_design04 parent is native13_split_candidate; sibling P12 is under FR.
OLD=HERE.parent.parent/'native_provider12_candidate'
DEST=HERE/'provider13';SRC=DEST/'source'
assert not SRC.exists(),'Do not overwrite a reviewed/work-in-progress provider'
SRC.mkdir(parents=True)
names=['provider.c','provider.h','password_core.c','password_core.h','password_crypto.c','services.c','ui.c','cpu_entropy.c','efi.h']
rows={}
for name in names:
 data=(OLD/'source'/name).read_bytes();(SRC/name).write_bytes(data)
 rows[name]=hashlib.sha256(data).hexdigest()
(DEST/'copied_p12_sources.json').write_text(json.dumps({'status':'BYTE_IDENTICAL_P12_BASE_SOURCES','source_root':str(OLD/'source'),'files':rows},indent=2)+'\n')
print(json.dumps({'copied':len(rows),'destination':str(SRC)}))
