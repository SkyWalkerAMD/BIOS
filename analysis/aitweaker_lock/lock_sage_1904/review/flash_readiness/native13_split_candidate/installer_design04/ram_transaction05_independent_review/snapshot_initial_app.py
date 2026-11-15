"""Preserve the intermediate source findings before author changes."""
from pathlib import Path
from datetime import datetime,timezone
import hashlib,json
HERE=Path(__file__).resolve().parent
SOURCE=HERE.parent/'ram_transaction05/source/app.c'
def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def main():
    source=SOURCE.read_text(encoding='utf8')
    assert 'ES status=st->bs->create_event(0x201,16,ending,0,&exit_event);if(FAILED(status))return ERR(7);' in source
    dest=HERE/'initial_app_snapshot';dest.mkdir(exist_ok=True)
    copied=dest/'app.c';copied.write_bytes(SOURCE.read_bytes())
    result={
      'status':'INTERMEDIATE_APP_SOURCE_FINDINGS_PENDING_AUTHOR_FIX_AND_COMPILED_REPLAY',
      'generated_utc':datetime.now(timezone.utc).isoformat(),
      'source':{'path':str(SOURCE),'sha256':sha(SOURCE),'snapshot':str(copied.relative_to(HERE))},
      'findings':[
        {'id':'APP01','priority':'must_fix_for_declared_EBS_boundary_contract','line':111,
         'condition':'The initial CreateEvent callback boundary marks app_ended and also returns an error in the ending fault model.',
         'actual_source_result':'FAILED(status) returns before app_require_services; application residency/termination invariant is not enforced on that branch.',
         'required_change':'Check ending immediately after the service returns, before the ordinary failure return. Treat failure with a nonzero event handle as potentially published and remain resident.',
         'scope':'Source-order counterexample for the explicitly required injected-ending model. Not evidence that ASUS naturally performs this sequence, and not yet an actual compiled app replay.'},
        {'id':'APP02','priority':'required_before_long_running_hardware_trial','line':114,
         'condition':'SetWatchdogTimer is absent or its disable call reports failure.',
         'actual_source_result':'Application continues into potentially long native UI/QR operation; the existing watchdog may still fire.',
         'required_change':'Refuse installation and keep an explicit bounded diagnostic result, or enter a deliberate hold. Do not report watchdog disable merely because its numeric status was logged.',
         'scope':'Source-level maintenance timing risk; no physical watchdog failure was observed.'},
      ],
      'remaining_read_dependencies':['platform_inventory/prepare/install/start_provider/remove adapter',
                                     'session_ui credential restore and native SendForm code',
                                     'actual transport ending checks and final EFI/ISO'],
      'hardware_ready':False,'author_sources_modified':False,'device_actions':False,
    }
    out=HERE/'initial_app_findings.json';out.write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n',encoding='utf8')
    print(json.dumps({'source_sha256':sha(SOURCE),'report_sha256':sha(out),'status':result['status']}))
if __name__=='__main__':main()
