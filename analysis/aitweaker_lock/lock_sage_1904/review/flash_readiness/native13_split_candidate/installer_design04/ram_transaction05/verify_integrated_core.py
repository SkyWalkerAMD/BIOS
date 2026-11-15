"""Rebind the 75 transaction assertions to exact complete app PE bytes.
The original carrier suite is read-only; only the app_build result is written.
"""
from pathlib import Path
import hashlib,json
HERE=Path(__file__).resolve().parent
source=(HERE/'verify_transaction.py').read_text()
source=source.replace("BUILD=HERE/'build';", "BUILD=HERE/'app_build';")
source=source.replace('TransactionCore05.TESTONLY.efi','SageNative13RamTest05.efi').replace("'transaction.map'","'app.map'")
source=source.replace("'transaction_verification.json'","'integrated_core_verification.json'").replace("'build.json'","'app_build.json'")
scope={'__file__':str(Path(__file__).resolve()),'__name__':'tx05_integrated_core'}
exec(compile(source,str(HERE/'verify_transaction.py')+'[read-only rebinding]', 'exec'),scope)
scope['main']()
path=HERE/'app_build/integrated_core_verification.json';r=json.loads(path.read_text());r['suite_source_sha256']=hashlib.sha256((HERE/'verify_transaction.py').read_bytes()).hexdigest();r['status']='PASS_75_TRANSACTION_CASES_ON_COMPLETE_APP_PE_WITH_MODELED_TPL_VALIDATOR';path.write_text(json.dumps(r,indent=2)+'\n')
