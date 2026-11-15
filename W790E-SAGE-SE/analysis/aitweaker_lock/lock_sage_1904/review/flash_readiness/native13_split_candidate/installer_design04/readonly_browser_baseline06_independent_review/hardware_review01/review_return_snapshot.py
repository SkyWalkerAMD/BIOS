"""Read-only independent audit of baseline06 native form return and QR recovery."""
from pathlib import Path
from datetime import datetime,timezone
import hashlib,importlib.util,json,re,sys
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent;OWN=HERE.parent
ROOT=next(p for p in HERE.parents if(p/'tools/kvm-pydeps').is_dir())
HW=ROOT/'analysis/aitweaker_lock/lock_sage_1904/remote_172_20_2_162'
C10=ROOT/'analysis/aitweaker_lock/lock_sage_1904/review/flash_readiness/remote_only/continuation10'
FINAL=HW/'hardware-native13-browser-baseline06-1793713512938-ce806332'
REJECTED=HW/'hardware-native13-browser-baseline06-1793713452913-bbc77732'
INITIAL=HW/'hardware-native13-browser-baseline06-1793713331040-a1540dce'
P3=ROOT/'analysis/aitweaker_lock/probe_p3_kvm/decode_captures.py';WRAPPER=HW/'read_native13_browser_baseline06_qr.py'
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
bindings={}
def bind(p):
 p=Path(p).resolve();r={'path':str(p.relative_to(ROOT)).replace('\\','/'),'bytes':p.stat().st_size,'sha256':sha(p)};bindings[r['path']]=r;return r
def load(name,p):
 s=importlib.util.spec_from_file_location(name,p);m=importlib.util.module_from_spec(s);sys.modules[name]=m;s.loader.exec_module(m);return m
def main():
 out=HERE/'returned_snapshot2_review.json';assert not out.exists()
 assert sha(P3)=='f1ad8dc74f62136ce06a1b1cdb18df24de3bcaae0acdd1d388a769d31c128283'
 assert sha(WRAPPER)=='abdcad40b3fc79443ab6b0933a488c850cfeefb31645ef6081a3b39169d7c240'
 d=load('baseline06_return_p3',P3);w=load('baseline06_return_wrapper',WRAPPER)
 manifest=json.loads((FINAL/'manifest.json').read_text());frames=[];accepted=[];attempts=[]
 for n,h in manifest['files'].items():assert sha(FINAL/n)==h;bind(FINAL/n)
 pngs=sorted(FINAL.glob('page-[0-9][0-9].png'));assert len(pngs)==manifest['pages']==7
 for p in pngs:
  frame=d.read_image(p);assert frame==p.with_suffix('.frame').read_bytes();part=d.parse_frame(frame)
  assert part['page']==len(frames)+1;frames.append(frame);accepted.append({'page':part['page'],'png':bind(p),'frame':bind(p.with_suffix('.frame')),'page_crc_verified':True})
 raw,meta=d.assemble(frames,require_inventory=False);snapshot=w.validate(raw)
 assert raw==(FINAL/'hardware-log.txt').read_bytes()and snapshot==manifest['snapshot_id']=='0000000000000002'
 for k in ['pages','bytes','crc32','sha256']:assert meta[k]==manifest[k]
 assert meta=={'pages':7,'bytes':4911,'crc32':'CCF8A98C','sha256':'520ea66fc0965f1268df8b0a7ca8f9d4a4d1bc6119676814092e79643e962cee'}
 for folder in [REJECTED,FINAL]:
  for p in sorted((folder/'attempts').glob('*.png')):
   requested=int(re.search(r'page-(\d+)-attempt-',p.name).group(1));record={'capture':folder.name,'requested_page':requested,'png':bind(p)}
   try:frame=d.read_image(p)
   except ValueError as exc:
    assert not p.with_suffix('.frame').exists();record.update(status='REJECTED_UNDECODABLE_PNG',error=str(exc),accepted_frame_present=False)
   else:
    assert frame==p.with_suffix('.frame').read_bytes();part=d.parse_frame(frame);assert frame==frames[part['page']-1]
    record.update(status='MATCHED_ACCEPTED_PAGE'if requested==part['page']else'REJECTED_STALE_DIFFERENT_PAGE',actual_page=part['page'],frame=bind(p.with_suffix('.frame')))
   attempts.append(record)
 assert sum(x['status']=='REJECTED_UNDECODABLE_PNG'for x in attempts)==6
 stale=[x for x in attempts if x['status']=='REJECTED_STALE_DIFFERENT_PAGE'];assert len(stale)==1 and stale[0]['requested_page']==4 and stale[0]['actual_page']==3
 manual=[]
 for page in range(4,8):
  note_path=FINAL/f'manual-page-{page:02d}.json';note=json.loads(note_path.read_text());source=HW/note['source']
  assert source.parent==HW and source.name==f'screen-{342+page}-current.png'and note['page']==page
  assert source.read_bytes()==(FINAL/f'page-{page:02d}.png').read_bytes()and sha(source)==note['sha256']
  info=d.parse_frame(d.read_image(source));assert(info['page'],info['total'],info['crc'],info['pages'])==(page,4911,0xccf8a98c,7)
  manual.append({'page':page,'note':bind(note_path),'source':bind(source),'exact_png_copy':True,'same_snapshot_total_crc_page_count':True});bind(source.with_suffix('.json'))
 completion=bind(C10/'complete_snapshot_pages.py')
 # Exact initial journal must be retained; the only extension begins at one B.
 initial=(INITIAL/'hardware-log.txt').read_bytes();assert hashlib.sha256(initial).hexdigest()=='483a3a0cb5d0e029d560dde14eec9e048b15b06f2a5165a05eac47c3b0a36337'
 old=initial.split(b'WatchdogDisableStatus=',1)[1].split(b'LOG_OVERFLOW=',1)[0]
 journal=raw.split(b'WatchdogDisableStatus=',1)[1].split(b'LOG_OVERFLOW=',1)[0];assert journal.startswith(old)
 lines=raw.decode('ascii').splitlines()
 def value(name,seq=lines):
  x=[s.split('=',1)[1]for s in seq if s.startswith(name+'=')];assert len(x)==1,name;return x[0]
 for name in ['BROWSER_ATTEMPTED','BASELINE_RETURN_ACCEPTED']:assert value(name)=='0000000000000001'
 for name in ['Warnings','NativeSendFormStatus','NativeActionRequest','ConfigAccessCallOverflow']:assert value(name)=='0000000000000000'
 assert value('ConfigAccessCallCount')=='0000000000000009'and value('LOG_COMPLETE')=='YES'and value('LOG_OVERFLOW')=='NO'
 for text in ['ACTION=ORIGINAL_SEND_FORM_BASELINE','NATIVE_SEND_FORM_BEGIN','NATIVE_SEND_FORM_RETURNED','PASS original text header snapshots and twelve sites unchanged','PASS private credential still absent; no content read','PASS native browser returned and readonly checks passed']:
  assert lines.count(text)==1
 assert not any(s.startswith('FAIL ')for s in lines)
 private=[x.split('=',1)[1]for x in lines if x.startswith('PrivateSizeOnlyQueryStatus=')];assert len(private)==4 and set(private)=={'800000000000000E'}
 assert lines.count('PASS complete OCMR values and attributes unchanged')==lines.count('PASS complete memory values and attributes unchanged')==3
 start=lines.index('ConfigAccessCallOverflow=0000000000000000')+1;end=lines.index('CONFIG_ACCESS_REJECTS_ALL_ACTIONS_INCLUDING_LIFECYCLE');cb=lines[start:end]
 assert len(cb)==45;callbacks=[]
 for i in range(0,45,5):
  block=cb[i:i+5];names=['CallbackKind','CallbackAction','CallbackQuestionId','CallbackType','CallbackStatus'];record={n:int(value(n,block),16)for n in names}
  assert record['CallbackKind']==3 and record['CallbackStatus']==0x8000000000000003;callbacks.append(record)
 assert [(r['CallbackAction'],r['CallbackQuestionId'],r['CallbackType'])for r in callbacks]==[(a,q,t)for a,t in [(3,9),(2,10),(4,10)]for q in range(0xffe0,0xffe3)]
 def section(begin,end):return lines[lines.index(begin)+1:lines.index(end)]
 before=section('BEFORE_NATIVE_SEND_FORM_GLOBALS','BEFORE_NATIVE_SEND_FORM_DISPLAY');after=section('AFTER_NATIVE_SEND_FORM_GLOBALS','AFTER_NATIVE_SEND_FORM_DISPLAY');assert before==after
 native={s.split('=',1)[0]:s.split('=',1)[1]for s in before};assert native['NativeStage']=='0000000000000007'and native['NativePendingReset']=='0000000000000000'
 display_before=section('BEFORE_NATIVE_SEND_FORM_DISPLAY','NATIVE_SEND_FORM_BEGIN')
 display_after=lines[lines.index('AFTER_NATIVE_SEND_FORM_DISPLAY')+1:lines.index('AFTER_NATIVE_SEND_FORM_DISPLAY')+8]
 db={x.split('=',1)[0]:x.split('=',1)[1]for x in display_before};da={x.split('=',1)[0]:x.split('=',1)[1]for x in display_after}
 assert db.keys()==da.keys();assert {k:(db[k],da[k])for k in db if db[k]!=da[k]}=={'ConsoleRowsCursor':('000000000000000A','0000000000000000')}
 bkey=HW/'browser-baseline06-key-1793713398527-fc74e951-result.json';bk=json.loads(bkey.read_text());assert bk['key']=='b'and bk['key_sent']is True and bk['automatic_retry']is False and sha(HW/bk['evidence'])==bk['evidence_sha256']
 qkey=HW/'browser-baseline06-key-1793713449416-d80f3183-result.json';qk=json.loads(qkey.read_text());assert qk['key']=='q'and qk['key_sent']is True and qk['automatic_retry']is False and sha(HW/qk['evidence'])==qk['evidence_sha256']
 for p in [bkey,qkey,HW/bk['evidence'],HW/qk['evidence'],HW/'screen-342-current.png',HW/'screen-342-current.json',HW/'screen-343-current.png',HW/'screen-343-current.json',INITIAL/'manifest.json',INITIAL/'hardware-log.txt',FINAL/'manifest.json',P3,WRAPPER,OWN/'independent_review.json',Path(__file__)]:bind(p)
 report={'status':'PHYSICAL_ORIGINAL_BROWSER_BASELINE_OPEN_AND_RETURN_OBSERVED_WITH_LIMITED_CHECKS_PASS','utc':datetime.now(timezone.utc).isoformat(),'candidate_efi_sha256':'2092c11abfc1cc9271357277aaac030424f8dd99c342ae1612f4c0cd3d82e169','candidate_iso_sha256':'1841d9a227f11ca7cce4270b75a32213a37e4b772f9040f293133554516db5f8','snapshot_id':snapshot,**meta,'device_operations_by_reviewer':0,'original_evidence_modified':False,'transport':{'accepted_png_pages':accepted,'capture_attempts':attempts,'undecodable_attempts_preserved':6,'stale_page_rejected':stale,'manual_completion':manual,'completion_script':completion,'completion_source_review':'Pinned decoder, fixed existing snapshot directory and first-fragment SNAPSHOT_ID=2; exact total4911/CRC/pagecount; pages4..7 only; open xb/x prevents replacing existing accepted files; local file decoding/copy only, no viewer/BMC/key call. All output/source PNG hashes were checked independently.','no_new_snapshot_required':'Seven final payload fragments share the same total/CRC/pagecount and assemble to one complete snapshot2. The manual completion script cannot request Q or B.','accepted_pages_crc_length_sha_all_checked':True},'semantics':{'initial_journal_preserved_exactly':True,'browser_attempts_in_log':1,'native_sendform_status':0,'native_action_request':0,'app_return_accepted':True,'warnings':0,'callbacks':callbacks,'all_callback_status':'EFI_UNSUPPORTED 0x8000000000000003','no_callback_action_0_or_1_observed':True,'private_size_only_queries':4,'private_absent_before_and_after':True,'complete_oc_and_memory_comparison_reports':3,'original_text_header_and_twelve_sites_check_passed':True,'fixed_native_globals_before_after_equal':native,'display_before':db,'display_after':da},'visual_evidence':{'screen342':'Directly inspected PNG: original Aptio Setup/AMI frame visibly renders explanatory text and Set or change password, Clear password, Verify password labels. No password operation is thereby accepted; the baseline callbacks reject everything.','screen343':'Directly inspected PNG: application text says Native browser returned and exposes Q; a previous QR background remains visible around the text. This is a display-cleanup limitation, not a clean full-frame restoration result.','escape':'One Escape and no password/action selection reported by parent; image343 plus subsequent log establishes return. This audit does not reconstruct all keyboard input from pixels.'},'conclusion':'This exact no-detour/no-provider baseline successfully rendered its standalone form with the original ASUS browser and returned, while the logged selected identity/private/two-store checks passed. It narrows the preceding TX05 black-screen investigation; it does not by itself attribute a unique root cause or accept the guard/password implementation.','limitations':['No password set/change/clear/verify or guard enforcement was exercised; lifecycle-style callback groups3/2/4 were rejected.','The native stage is a raw observed qword7, not proof that the OEM browser was inactive or safe for an installer.','The two stores are compared to this same boot initial snapshot in own RAM. No cross-boot complete NVRAM, SPI or filesystem equality is established.','Source has no direct variable setter, but OEM internal writes are not globally excluded; apparent unchanged selected values do not prove no write occurred.','Full mutable image/data equality, complete visual restoration, keyboard behavior for other actions, cold entry, persistence and firmware flashing/recovery remain unaccepted.','Power-off and media/session cleanup are separately owned by parent and not established by this return snapshot.'],'baseline_form_render_and_return_observed':True,'password_or_guard_accepted':False,'firmware_release_ready':False,'bindings':list(bindings.values())}
 out.write_text(json.dumps(report,indent=2)+'\n',encoding='utf8');print(json.dumps({'status':report['status'],'sha256':sha(out),'path':str(out),'bindings':len(bindings)}))
if __name__=='__main__':main()
