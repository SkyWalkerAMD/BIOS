"""Seed app common declarations/transport from frozen audited inputs once."""
from pathlib import Path
import hashlib,json
HERE=Path(__file__).resolve().parent;D04=HERE.parent;SRC=HERE/'source';P04=D04/'prerequisite_probe04/source';P13=D04/'provider13/source'
assert not(SRC/'efi.h').exists()
rows={}
for name in ['efi.h','provider.h','password_core.h','password_crypto.c','split_owner.h']:
 data=(P13/name).read_bytes();(SRC/name).write_bytes(data);rows[name]={'from':str(P13/name),'sha256':hashlib.sha256(data).hexdigest()}
for name in ['targets.h','context_binding.h','launch_binding.h']:
 if(P04/name).exists():
  data=(P04/name).read_bytes();(SRC/name).write_bytes(data);rows[name]={'from':str(P04/name),'sha256':hashlib.sha256(data).hexdigest()}
for old in (P04/'transport').rglob('*'):
 if old.is_file():
  dest=SRC/'transport'/old.relative_to(P04/'transport');dest.parent.mkdir(parents=True,exist_ok=True);dest.write_bytes(old.read_bytes())
entry=(P04/'entry.S').read_text();(SRC/'entry.S').write_text(entry.replace('probe_main','app_main'))
(HERE/'app_source_seed.json').write_text(json.dumps(rows,indent=2)+'\n')
print(json.dumps({'copied_common_files':len(rows),'transport_copied':True}))
