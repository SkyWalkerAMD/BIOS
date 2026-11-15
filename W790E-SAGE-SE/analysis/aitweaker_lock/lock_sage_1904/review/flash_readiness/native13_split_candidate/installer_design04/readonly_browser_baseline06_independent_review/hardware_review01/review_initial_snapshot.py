"""Independently reconstruct one baseline06 initial QR snapshot from PNGs."""
from pathlib import Path
from datetime import datetime,timezone
import hashlib,importlib.util,json,sys
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent;OWN=HERE.parent
ROOT=next(p for p in HERE.parents if(p/'tools/kvm-pydeps').is_dir())
HW=ROOT/'analysis/aitweaker_lock/lock_sage_1904/remote_172_20_2_162'
P3=ROOT/'analysis/aitweaker_lock/probe_p3_kvm/decode_captures.py'
WRAPPER=HW/'read_native13_browser_baseline06_qr.py'
EFI='2092c11abfc1cc9271357277aaac030424f8dd99c342ae1612f4c0cd3d82e169'
ISO='1841d9a227f11ca7cce4270b75a32213a37e4b772f9040f293133554516db5f8'
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
def bound(p):return {'path':str(p.relative_to(ROOT)).replace('\\','/'),'bytes':p.stat().st_size,'sha256':sha(p)}
def load(name,p):
 s=importlib.util.spec_from_file_location(name,p);m=importlib.util.module_from_spec(s);sys.modules[name]=m;s.loader.exec_module(m);return m
def main():
 assert len(sys.argv)==2;capture=Path(sys.argv[1]).resolve();assert capture.is_relative_to(HW)
 assert sha(P3)=='f1ad8dc74f62136ce06a1b1cdb18df24de3bcaae0acdd1d388a769d31c128283'
 assert sha(WRAPPER)=='abdcad40b3fc79443ab6b0933a488c850cfeefb31645ef6081a3b39169d7c240'
 d=load('baseline06_independent_p3',P3);w=load('baseline06_independent_wrapper',WRAPPER)
 manifest=json.loads((capture/'manifest.json').read_text());bindings=[]
 for n,h in manifest['files'].items():assert sha(capture/n)==h;bindings.append(bound(capture/n))
 pngs=sorted(capture.glob('page-[0-9][0-9].png'));assert len(pngs)==manifest['pages'];frames=[];pages=[];attempts=[]
 for p in pngs:
  frame=d.read_image(p);assert frame==p.with_suffix('.frame').read_bytes();part=d.parse_frame(frame);frames.append(frame)
  pages.append({'png':bound(p),'frame':bound(p.with_suffix('.frame')),'page':part['page'],'offset':part['offset'],'payload_bytes':len(part['data']),'page_crc_verified':True})
 for p in sorted((capture/'attempts').glob('*.png')):
  try:frame=d.read_image(p)
  except ValueError as exc:
   assert not p.with_suffix('.frame').exists(),'Undecodable attempt must not have an accepted frame'
   attempts.append({'png':bound(p),'status':'REJECTED_UNDECODABLE_ATTEMPT_RETAINED','decode_error':str(exc),'accepted_frame_present':False});continue
  assert frame==p.with_suffix('.frame').read_bytes();part=d.parse_frame(frame);assert frame==frames[part['page']-1]
  attempts.append({'png':bound(p),'frame':bound(p.with_suffix('.frame')),'status':'DECODED_MATCHES_ACCEPTED_PAGE','equals_accepted_page':part['page']})
 raw,meta=d.assemble(frames,require_inventory=False);snapshot=w.validate(raw)
 assert raw==(capture/'hardware-log.txt').read_bytes()
 for key in ['pages','bytes','crc32','sha256']:assert meta[key]==manifest[key]
 assert snapshot==manifest['snapshot_id']=='0000000000000001'
 lines=raw.decode('ascii').splitlines()
 def val(name):
  x=[l.split('=',1)[1]for l in lines if l.startswith(name+'=')];assert len(x)==1,name;return x[0]
 for k in ['BROWSER_ATTEMPTED','BASELINE_RETURN_ACCEPTED','Warnings']:assert val(k)=='0000000000000000'
 required=['WatchdogDisableStatus=0000000000000000','TOOL_SCOPE=ORIGINAL_BROWSER_BASELINE_ONLY','NO_DETOURS_NO_PROVIDER_NO_PASSWORD_OPERATIONS','NO_DIRECT_VARIABLE_DISK_FLASH_OR_RT_TABLE_WRITES','STANDARD_VOLATILE_EVENT_HII_PROTOCOL_PUBLICATION','OEM_INTERNAL_SEND_FORM_EFFECTS_NOT_ZERO','PASS exact SAGE SE 1904 SMBIOS','AMITSECount=0000000000000001','SetupCount=0000000000000001','ENTRY_BOUND=EXACT_CORE_AMITSE_BOOT_CALL_RETURN','BROWSER_ABSENCE_PROOF=NO','BROWSER_BASELINE_NO_TRANSACTION=YES','OriginalSetupHiiMatches=0000000000000001','PASS complete initial original identity and boot context','PASS initial private credential absent','PASS initial complete OCMR snapshot read only','PASS initial complete memory snapshot read only','PASS initial private absence and complete OC memory snapshots','PASS complete OCMR values and attributes unchanged','PASS complete memory values and attributes unchanged','ConfigAccessInstallStatus=0000000000000000','NewPackageListStatus=0000000000000000','PASS unique exact frozen P13 package published without provider','PASS static independent baseline HII publication','LOG_OVERFLOW=NO','LOG_COMPLETE=YES']
 assert all(x in lines for x in required)
 assert not any(x.startswith('FAIL ')or x.startswith('ACTION=')or x.startswith('NATIVE_SEND_FORM_')for x in lines)
 private_queries=[x.split('=',1)[1]for x in lines if x.startswith('PrivateSizeOnlyQueryStatus=')];assert private_queries and all(x=='800000000000000E'for x in private_queries)
 assert int(val('EntryOuterReturnRVA'),16)in [0x2d7d,0x960c]
 for name in ['AMITSEBase','SetupBase']:
  v=int(val(name),16);assert 0<v<(1<<47)and v%4096==0
 local=json.loads((OWN/'independent_review.json').read_text());assert local['efi_sha256']==EFI and local['iso_sha256']==ISO
 result={'status':'INITIAL_BASELINE06_PHYSICAL_PREFLIGHT_AND_VOLATILE_PUBLICATION_REPORTED_PASS','utc':datetime.now(timezone.utc).isoformat(),'capture':str(capture.relative_to(ROOT)).replace('\\','/'),'snapshot_id':snapshot,**meta,'candidate_efi_sha256':EFI,'candidate_iso_sha256':ISO,'candidate_identity_scope':'The QR does not self-measure the full EFI or ISO. Exact selection/boot provenance belongs to the parent controlled-session chain and frozen package.','independent_checks':['All accepted PNGs decoded again to exact saved frames; page/whole CRC, total bytes, complete snapshot and hash agree. Every attempt is either independently decoded and matched, or explicitly preserved as undecodable with no accepted frame.','Original identity/launch caller and exact native interfaces reported accepted; source-bound checks do not prove the browser is inactive.','Only size-zero private queries returned NOT_FOUND, initial protected-store snapshots and pre-publication comparisons passed.','Own standard ConfigAccess and exact frozen991B HII publication reported success; no browser attempt appears and warnings=0.'],'next_action_scope':'Prerequisites are satisfied for the single reviewed B original SendForm baseline attempt, followed by ESC and new QR if responsive. No password, saving or resetting action is authorized by this result.','native_browser_return_accepted':False,'password_or_guard_accepted':False,'firmware_release_ready':False,'device_calls_by_reviewer':0,'source_evidence_modified':False,'limits':['This is independent reconstruction of recorded output, not a second physical memory read.','Own events/HII/protocol publication already occurred; read-only refers to original modules and variables, not zero volatile firmware state changes.','No direct SetVariable code is linked, but standard OEM browser internals may write other state and lifecycle callback rejection may affect rendering.','Full text/header/12-window identity is not equality of all runtime data, every variable or SPI contents.','A black display after B would not by itself establish CPU hold, absence of writes, or any password-lock outcome.'],'accepted_pages':pages,'attempts':attempts,'bindings':bindings+[bound(capture/'manifest.json'),bound(capture/'hardware-log.txt'),bound(P3),bound(WRAPPER),bound(OWN/'independent_review.json'),bound(Path(__file__))]}
 out=HERE/('initial_'+capture.name+'_review.json');assert not out.exists();out.write_text(json.dumps(result,indent=2)+'\n',encoding='utf8');print(json.dumps({'status':result['status'],'sha256':sha(out),'path':str(out),'pages':meta['pages'],'bytes':meta['bytes'],'crc32':meta['crc32']}))
if __name__=='__main__':main()
