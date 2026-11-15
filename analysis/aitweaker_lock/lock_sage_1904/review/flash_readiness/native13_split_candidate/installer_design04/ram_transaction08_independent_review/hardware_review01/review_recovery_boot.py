"""New-boot TX08 initial-only recovery observations; no retry authorization."""
from pathlib import Path
from datetime import datetime,timezone
import hashlib,importlib.util,json,sys
HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('tx08_frozen_qr_review',HERE/'review_snapshot.py')
R=importlib.util.module_from_spec(spec);sys.modules[spec.name]=R;spec.loader.exec_module(R)
def main():
 if len(sys.argv)!=3:raise SystemExit('review_recovery_boot.py CAPTURE_DIR ORIGINAL_BIOS_SCREEN_PNG')
 capture=Path(sys.argv[1]).resolve();bios=Path(sys.argv[2]).resolve()
 assert bios.parent==R.HW.resolve() and bios.suffix=='.png'
 raw,meta,snapshot,pages,attempts=R.transport(capture);lines=raw.decode('ascii').splitlines()
 def value(name):
  rows=[s.split('=',1)[1]for s in lines if s.startswith(name+'=')];assert len(rows)==1;return rows[0]
 assert snapshot=='0000000000000001' and value('MODE')==value('OPERATION_ID')==value('Warnings')=='0000000000000000'
 assert not any(s.startswith('ACTION=')or s.startswith('FAIL ')for s in lines)
 for line in ['WatchdogDisableStatus=0000000000000000','PASS exact SAGE SE 1904 SMBIOS',
  'AMITSECount=0000000000000001','SetupCount=0000000000000001','ENTRY_BOUND=EXACT_CORE_AMITSE_BOOT_CALL_RETURN',
  'OriginalSetupHiiMatches=0000000000000001','OriginalWritableSupervisorCodePages=0000000000000008',
  'PASS complete initial original identity and boot context','PASS initial private credential absent',
  'PASS initial complete OCMR snapshot read only','PASS initial complete memory snapshot read only','LOG_OVERFLOW=NO','LOG_COMPLETE=YES']:
  assert lines.count(line)==1,line
 assert int(value('EntryOuterReturnRVA'),16)in [0x2d7d,0x960c]
 prior=HERE/'initial_hardware-native13-ram-test08-1793715405937-cb989a98_review.json';oldreview=json.loads(prior.read_text())
 oldpath=Path(oldreview['capture'])/'hardware-log.txt';old=oldpath.read_bytes();assert hashlib.sha256(old).hexdigest()==oldreview['sha256']
 incident=HERE/'management_first_attempt_incident_review.json'
 result={'status':'NEW_BOOT_RECOVERY_ORIGINAL_IDENTITY_AND_CURRENT_PRIVATE_ABSENCE_REPORTED_PASS','utc':datetime.now(timezone.utc).isoformat(),
  'device_calls_by_reviewer':0,'capture':str(capture),'snapshot_id':snapshot,**meta,'candidate_efi_sha256':R.EFI,'candidate_iso_sha256':R.ISO,
  'boot_scope':'A new application boot after the failed first management call and observed ForceOff. Snapshot counter1 and operation0 are local to this new boot, not a continuation of the earlier journal.',
  'observed_recovery':{'current_original_identity_and_twelve_sites':True,'current_private_variable_absent':True,'fresh_two_protected_store_read_success':True,'no_transaction_or_management_action_in_this_boot_journal':True,'warnings':0,
   'log_bytes_equal_first_initial':raw==old,'bios_screenshot':R.bound(bios),
   'bios_visual_scope':'The separately supplied screenshot must be directly inspected by the reviewer; the QR identity independently reports exact board/version and original module checks.'},
  'limits':[
   'Current private absence is demonstrated by a size-only query returning NOT_FOUND, not inferred from the prior lack of password typing.',
   'New-boot original text/header/sites identity demonstrates currently loaded original module state; this is not an in-place RAM rollback record from the interrupted first boot.',
   'Initial store logs contain no store contents/digest. Even identical text logs across boots do not prove cross-boot OC/MEM equality or absence of every historical OEM NVRAM write.',
   'No transaction/provider/management action was requested in this recovery boot journal. It does not accept retry of the unchanged failed management path.',
   'This report does not itself establish final power/media/session cleanup; those need subsequent timestamped readbacks.',
   'No permanent lock, firmware signing, update/flash or full backup/recovery readiness is accepted.'
  ],'accepted_pages':pages,'attempt_images':attempts,
  'bindings':[R.bound(capture/'manifest.json'),R.bound(capture/'hardware-log.txt'),R.bound(prior),R.bound(oldpath),R.bound(incident),R.bound(R.DECODER),R.bound(R.WRAPPER),R.bound(HERE/'review_snapshot.py'),R.bound(Path(__file__))]}
 out=HERE/('recovery_'+capture.name+'_review.json');assert not out.exists();out.write_text(json.dumps(result,indent=2,ensure_ascii=False)+'\n',encoding='utf-8')
 print(json.dumps({'status':result['status'],'report':str(out),'sha256':R.sha(out),'pages':meta['pages'],'bytes':meta['bytes'],'crc32':meta['crc32'],'initial_log_equal':raw==old}))
if __name__=='__main__':main()
