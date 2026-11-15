"""Offline TX08 PNG/frame/CRC and staged-journal audit. Never sends device input."""
from pathlib import Path
from datetime import datetime,timezone
import hashlib,importlib.util,json,re,sys
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent;OWN=HERE.parent;D04=OWN.parent;CASE=OWN.parents[4]
ROOT=next(p for p in HERE.parents if(p/'tools/kvm-pydeps').is_dir())
HW=CASE/'remote_172_20_2_162'
DECODER=ROOT/'analysis/aitweaker_lock/probe_p3_kvm/decode_captures.py'
WRAPPER=HW/'read_native13_ram_test08_qr.py'
EFI='e0793175f78b6488c8222b65f0d5321d97e881bd06dca033a314d3fa8d307486'
ISO='44aa175e37bc367da4ded343df814ca0f3271391bc03cc53fc73371ebfd61dfe'
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
bound=lambda p:{'path':str(p),'bytes':p.stat().st_size,'sha256':sha(p)}
def module(name,path):
 spec=importlib.util.spec_from_file_location(name,path);obj=importlib.util.module_from_spec(spec);sys.modules[name]=obj;spec.loader.exec_module(obj);return obj
def journal(raw):
 start=raw.index(b'WatchdogDisableStatus=');end=raw.index(b'LOG_OVERFLOW=')
 return raw[start:end]
def transport(capture):
 assert capture.is_relative_to(HW.resolve()) and capture.parent==HW.resolve()
 assert sha(DECODER)=='f1ad8dc74f62136ce06a1b1cdb18df24de3bcaae0acdd1d388a769d31c128283'
 assert sha(WRAPPER)=='6fc2a6797fb4493b904b20933c6a1a3ee1771da400e1f765686fcdb5e435421f'
 dec=module('independent_tx08_transport',DECODER);wrapper=module('independent_tx08_wrapper',WRAPPER)
 manifest=json.loads((capture/'manifest.json').read_text())
 for name,digest in manifest['files'].items():
  p=(capture/name).resolve();assert p.parent==capture and sha(p)==digest
 pngs=sorted(capture.glob('page-[0-9][0-9].png'));assert len(pngs)==manifest['pages']
 frames=[];pages=[];attempts=[]
 for expected,p in enumerate(pngs,1):
  frame=dec.read_image(p);assert frame==p.with_suffix('.frame').read_bytes()
  info=dec.parse_frame(frame);assert info['page']==expected
  frames.append(frame);pages.append({**bound(p),'frame':bound(p.with_suffix('.frame')),'page':info['page'],'offset':info['offset'],'payload_bytes':len(info['data']),'png_exact_frame':True,'page_crc_checked':True})
 for p in sorted((capture/'attempts').glob('*.png')):
  saved=p.with_suffix('.frame');row=bound(p)
  try:frame=dec.read_image(p)
  except Exception as error:
   assert not saved.exists(),('Undecodable attempt unexpectedly has a saved frame',p)
   row.update(accepted=False,independently_decodable=False,reason=type(error).__name__)
  else:
   info=dec.parse_frame(frame);assert saved.exists() and frame==saved.read_bytes()
   same=any(frame==accepted for accepted in frames)
   row.update(independently_decodable=True,frame=bound(saved),decoded_page=info['page'],decoded_crc=info['crc'],equals_one_accepted_page=same)
  attempts.append(row)
 raw,meta=dec.assemble(frames,require_inventory=False);snapshot=wrapper.validate(raw)
 assert raw==(capture/'hardware-log.txt').read_bytes()
 for key in ['pages','bytes','crc32','sha256']:assert meta[key]==manifest[key],key
 assert snapshot==manifest['snapshot_id']
 return raw,meta,snapshot,pages,attempts
def main():
 if len(sys.argv)not in [3,4] or sys.argv[1]not in ['initial','mode1','mode2','management_return']:
  raise SystemExit('review_snapshot.py initial|mode1|mode2|management_return CAPTURE_DIRECTORY [PRIOR_REVIEW_JSON]')
 stage=sys.argv[1];capture=Path(sys.argv[2]).resolve();raw,meta,snapshot,pages,attempts=transport(capture)
 lines=raw.decode('ascii').splitlines()
 def values(name):return [s.split('=',1)[1]for s in lines if s.startswith(name+'=')]
 def value(name):
  rows=values(name);assert len(rows)==1,(name,rows);return rows[0]
 for key in ['SNAPSHOT_ID','MODE','OPERATION_ID','Warnings','LOG_OVERFLOW','LOG_COMPLETE']:value(key)
 assert value('Warnings')=='0000000000000000' and not any(s.startswith('FAIL ')for s in lines)
 initial_required=['WatchdogDisableStatus=0000000000000000','PASS exact SAGE SE 1904 SMBIOS','AMITSECount=0000000000000001','SetupCount=0000000000000001',
  'ENTRY_BOUND=EXACT_CORE_AMITSE_BOOT_CALL_RETURN','OriginalSetupHiiMatches=0000000000000001','OriginalWritableSupervisorCodePages=0000000000000008',
  'PASS complete initial original identity and boot context','PASS initial private credential absent','PASS initial complete OCMR snapshot read only','PASS initial complete memory snapshot read only',
  'LOG_OVERFLOW=NO','LOG_COMPLETE=YES','BROWSER_ABSENCE_PROOF=NO','BSP_TPL_TRANSACTION_PREMISE=YES']
 assert all(s in lines for s in initial_required)
 assert int(value('EntryOuterReturnRVA'),16) in [0x2d7d,0x960c]
 for key in ['AMITSEBase','SetupBase']:
  v=int(value(key),16);assert 4096<=v<(1<<47) and v%4096==0
 previous=None;new=journal(raw);bindings=[]
 if stage!='initial':
  assert len(sys.argv)==4;previous_path=Path(sys.argv[3]).resolve();assert previous_path.parent==HERE
  previous=json.loads(previous_path.read_text());assert previous['candidate_efi_sha256']==EFI and previous['candidate_iso_sha256']==ISO
  expected_prior={'mode1':'initial','mode2':'mode1','management_return':'mode2'}[stage];assert previous['stage']==expected_prior
  previous_capture=Path(previous['capture']);old=(previous_capture/'hardware-log.txt').read_bytes()
  assert hashlib.sha256(old).hexdigest()==previous['sha256'];old_journal=journal(old)
  assert new.startswith(old_journal) and int(snapshot,16)>int(previous['snapshot_id'],16)
  new=new[len(old_journal):];bindings.extend([bound(previous_path),bound(previous_capture/'hardware-log.txt')])
 new_lines=new.decode('ascii').splitlines();globals_result=None
 if stage=='initial':
  assert snapshot=='0000000000000001' and value('MODE')==value('OPERATION_ID')=='0000000000000000'
  assert not values('ACTION') and not values('InstallResult')
  verdict='INITIAL_PHYSICAL_PREFLIGHT_REPORTED_PASS_MODE1_PREREQUISITES'
  scope='Only the reviewed mode1 transaction/rollback may be attempted; no transaction or password UI success appears in this snapshot.'
 elif stage=='mode1':
  assert value('MODE')==value('OPERATION_ID')=='0000000000000001'
  required=['Operation=0000000000000001','ACTION=INSTALL_CHECK_ROLLBACK','PrepareResult=0000000000000000','InstallResult=0000000000000000',
   'ALL_12_ORIGINAL_SITES_RESTORED','ALL_PUBLISHED_ALLOCATION_LIFETIMES=UNTIL_POWER_OFF','PASS mode1 exact twelve-site restoration',
   'MODE1_PROVIDER_STARTED=NO','MODE1_PASSWORD_WRITES=NO','MODE1_RESULT_DOES_NOT_ACCEPT_MODE2']
  assert new_lines==required,(stage,new_lines)
  verdict='MODE1_PHYSICAL_EXACT_TWELVE_SITE_RESTORATION_REPORTED_PASS'
  scope='Prerequisites for one mode2 attach attempt are satisfied. Fresh complete protected-store comparison and exact provider READY checks still occur in the application; no password or native UI result is inferred.'
 elif stage=='mode2':
  assert value('MODE')==value('OPERATION_ID')=='0000000000000002'
  required=['Operation=0000000000000002','ACTION=START_PASSWORD_NATIVE_TEST','PASS complete OCMR values and attributes unchanged','PASS complete memory values and attributes unchanged',
   'ProviderLoadImageStatus=0000000000000000','PrepareResult=0000000000000000','InstallResult=0000000000000000','ProviderStartImageStatus=0000000000000000','ProviderInitialFlags=0000000000000001','PASS single resident provider attach']
  assert new_lines==required,(stage,new_lines)
  verdict='MODE2_PHYSICAL_PROVIDER_ATTACH_READY_REPORTED_PASS'
  scope='Only first M display -> one native ESC -> Q without password input is the next reviewed stage. Attach success does not accept management rendering, native return, password writes or B/original Setup.'
 else:
  assert value('MODE')=='0000000000000002' and value('OPERATION_ID')=='0000000000000003'
  assert new_lines[:2]==['Operation=0000000000000003','ACTION=PASSWORD_MANAGEMENT']
  assert values('ACTION')==['INSTALL_CHECK_ROLLBACK','START_PASSWORD_NATIVE_TEST','PASSWORD_MANAGEMENT']
  for s in ['PASS unique exact independent P14 HII package','UI_NATIVE_GLOBALS_BEFORE_SENDFORM','UI_NATIVE_GLOBALS_AFTER_SENDFORM','PASS SendForm returned with both owned chains empty',
    'PASS private record observed only in RAM without contents or digest','UiSendFormStatus=0000000000000000','UiActionRequest=0000000000000000','PASS original FormBrowser2 interface unchanged','UI_RETURN_IS_NOT_DIRECT_DEL_OR_PERMANENT_SECURITY_MENU_ACCEPTANCE']:
   assert new_lines.count(s)==1,s
  assert len(values('UiProviderFlags'))==4 and set(values('UiProviderFlags'))=={'0000000000000001'}
  assert new_lines.count('PASS complete OCMR values and attributes unchanged')==4
  assert new_lines.count('PASS complete memory values and attributes unchanged')==4
  names=['NativeAppPtr','NativeStage','NativePagesPtr','NativeRecordsPtr','NativeExternalPtr','NativePendingReset']
  observations=[]
  for label in ['UI_NATIVE_GLOBALS_BEFORE_SENDFORM','UI_NATIVE_GLOBALS_AFTER_SENDFORM']:
   at=new_lines.index(label);part=new_lines[at+1:at+8]
   assert part[-1]=='NATIVE_GLOBALS_OBSERVATION_NOT_IDLE_PROOF'
   assert [s.split('=')[0]for s in part[:-1]]==names
   assert all(re.fullmatch('[0-9A-F]{16}',s.split('=')[1])for s in part[:-1])
   observations.append({k:int(s.split('=')[1],16)for k,s in zip(names,part)})
  globals_result={'before':observations[0],'after':observations[1],'differences':{k:[observations[0][k],observations[1][k]]for k in names if observations[0][k]!=observations[1][k]},'observational_only_not_idle_or_safe_exit_proof':True}
  verdict='MANAGEMENT_CALL_RETURN_REPORTED_PASS_VISUAL_AND_PASSWORD_ACCEPTANCE_SEPARATE'
  scope='The complete log supports successful synchronous return with empty owned chains and matching protected stores. Review actual display/ESC input evidence separately before password or original-Setup operations.'
 local=json.loads((OWN/'independent_review.json').read_text());assert local['efi_sha256']==EFI and local['iso_sha256']==ISO
 result={'status':verdict,'utc':datetime.now(timezone.utc).isoformat(),'stage':stage,'capture':str(capture),'snapshot_id':snapshot,**meta,
  'device_calls_by_reviewer':0,'candidate_efi_sha256':EFI,'candidate_iso_sha256':ISO,
  'candidate_identity_scope':'Parent-controlled package selection/boot chain plus frozen local review. The QR payload does not self-measure the EFI/ISO hash.',
  'journal_extends_prior_without_changes':previous is not None,'new_operation_lines':new_lines,'raw_global_observations':globals_result,
  'next_action_scope':scope,'password_ui_accepted':False,'permanent_direct_del_lock_accepted':False,'firmware_flash_approved':False,
  'limits':[
   'This reconstructs captured firmware output; it is not an independent physical memory/register read.',
   'Recognized Core/AMITSE caller, eight RWX pages and raw globals do not prove absent outer browser or AP/SMM quiescence.',
   'A successful generic post-UI private-record observation means absent or valid owned record, not specifically private absence; only a dedicated absence check establishes that state.',
   'No-password operator actions and visual display must be tied to separate session/screenshots. QR values alone do not prove exact rendered UI, zero OEM variable writes, or hardware password acceptance.',
   'Unknown page/no verified safe Main can still deny input. Black pixels do not diagnose CPU hold. Power-off is not private credential cleanup.',
   'No BIOS flashing, permanent-lock or backup/recovery readiness is accepted by any of these diagnostic stages.'
  ],'accepted_pages':pages,'attempt_images':attempts,'bindings':bindings+[bound(capture/'manifest.json'),bound(capture/'hardware-log.txt'),bound(DECODER),bound(WRAPPER),bound(OWN/'independent_review.json'),bound(Path(__file__))]}
 out=HERE/(stage+'_'+capture.name+'_review.json');assert not out.exists();out.write_text(json.dumps(result,indent=2,ensure_ascii=False)+'\n',encoding='utf-8')
 print(json.dumps({'status':verdict,'report':str(out),'sha256':sha(out),'pages':meta['pages'],'bytes':meta['bytes'],'crc32':meta['crc32']}))
if __name__=='__main__':main()
