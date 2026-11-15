"""Create isolated native12 source/test baseline; never alter frozen native11."""
from pathlib import Path
import shutil,json,hashlib
HERE=Path(__file__).resolve().parent
OLD=HERE.parent/'cold_entry_candidate/implementation';OUT=HERE/'implementation'
assert not OUT.exists(),'Only create this isolated baseline once'
OUT.mkdir();(OUT/'source').mkdir();(OUT/'build').mkdir()
files=['build_guard.py','verify_guard.py','verify_structure.py','verify_memory.py','verify_native_save.py','verify_native_commit.py','verify_hotkeys.py','verify_defaults.py','verify_native_history.py','verify_defaults_entries.py','verify_exit_counterexample.py']
files += ['source/'+n for n in ['gate.c','gate.h','efi.h','policy_data.h']]
files += ['build/'+n for n in ['OriginalHiiDatabase.efi','OriginalHiiDatabase.json','OriginalAMITSESetupData.bin','OriginalAMITSESetupData.json']]
for name in files:shutil.copy2(OLD/name,OUT/name)
r={'frozen_native11_build_sha256':hashlib.sha256((OLD/'build/build.json').read_bytes()).hexdigest(),
 'copied':{n:hashlib.sha256((OLD/n).read_bytes()).hexdigest()for n in files},
 'scope':'New private save scope and ACCESS_DENIED feedback only; no initialization/missing-variable creation exception; no public provider/frame ABI change; no CAP/device operation.'}
(HERE/'implementation_baseline.json').write_text(json.dumps(r,indent=2)+'\n')
print(str(OUT))
