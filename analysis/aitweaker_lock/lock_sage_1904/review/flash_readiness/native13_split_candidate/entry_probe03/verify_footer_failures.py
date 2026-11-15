"""Early refusal paths still state that browser absence is not proved."""
from pathlib import Path
import hashlib,json,sys
sys.dont_write_bytecode=True
import verify_context_probe as f
HERE=Path(__file__).resolve().parent
v=f.VM();v.map_fail=True;v.run('early_map_failure_explicit_no_absence_proof',lambda s:'BROWSER_ABSENCE_PROOF=NO'in s and not v.stack_reads)
v=f.VM();v.w(v.st+0x60,f.f.q(0));v.run('invalid_services_explicit_no_absence_proof',lambda s:'INVALID_BOOT_SERVICES'in s and'BROWSER_ABSENCE_PROOF=NO'in s and not v.stack_reads)
report={'status':'PASS_ACTUAL_EFI_EARLY_REFUSAL_FOOTER','cases':f.ROWS,'case_count':2,'efi_sha256':hashlib.sha256(f.f.EFI.read_bytes()).hexdigest(),'source_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'fixture_sha256':hashlib.sha256((HERE/'verify_context_probe.py').read_bytes()).hexdigest()}
(HERE/'tests/footer_failure_verification.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({'status':report['status'],'cases':2}))
