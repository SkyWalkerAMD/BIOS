"""Local source/report binding review; does not execute remote operations."""
from pathlib import Path
import difflib,hashlib,json
HERE=Path(__file__).resolve().parent;D04=HERE.parent;READY=HERE.parents[2];CASE=READY.parents[1]
C12=READY/'remote_only/continuation12';HW=CASE/'remote_172_20_2_162'
ROOT=next(p for p in HERE.parents if(p/'tools/pydeps').is_dir())
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
files={Path(__file__)}
derivation=C12/'delivery09_derivation.json';d=json.loads(derivation.read_text());files.add(derivation)
assert len(d['bindings'])==15 and d['device_calls']==0
for row in d['bindings']:
 for kind in ['source','output']:
  p=Path(row[kind]);assert p.resolve().is_relative_to(ROOT)and sha(p)==row[kind+'_sha256'];files.add(p)
local=C12/'delivery09_local_checks.json';r=json.loads(local.read_text());files.add(local)
assert r['derivation_sha256']==sha(derivation)and r['device_calls']==0
reports=[]
for name,row in r['reports'].items():
 p=C12/name;test=json.loads(p.read_text());assert sha(p)==row['sha256']and test['status']==row['status']and test['status'].startswith('PASS')
 count=len(test.get('checks',test.get('cases',[])));assert count==row['checks'];files.add(p)
 reports.append({'path':str(p.relative_to(ROOT)),'sha256':sha(p),'checks':count})
diag=C12/'diagnostic09_decoder_tests.json';dr=json.loads(diag.read_text());files.add(diag)
assert dr['decoder_sha256']==sha(C12/'decode_diagnostic09.py')and len(dr['checks'])==10 and not dr['actual_provider_output_tested']
files.update([C12/'decode_diagnostic09.py',C12/'test_diagnostic09_decoder.py',C12/'diagnostic09_synthetic_display.txt'])
# The author hashes the LF Python string, then Windows write_text emits CRLF.
# Preserve both identities instead of treating that field as a raw-file hash.
assert dr['sample_sha256']==hashlib.sha256((C12/'diagnostic09_synthetic_display.txt').read_text(encoding='ascii').encode('ascii')).hexdigest()
comparisons=[('read_native13_ram_test08_qr.py','read_native13_ram_test09_qr.py'),('operations/capture_native13_ram_test08.mjs','operations/capture_native13_ram_test09.mjs'),('operations/native_test_keys11.mjs','operations/native_test_keys12.mjs'),('operations/power_off_ram_test11.mjs','operations/power_off_ram_test12.mjs')]
diff=''.join(''.join(difflib.unified_diff((HW/a).read_text().splitlines(True),(HW/b).read_text().splitlines(True),fromfile=a,tofile=b))for a,b in comparisons)
(HERE/'operations_delta.patch').write_text(diff);files.add(HERE/'operations_delta.patch')
for a,b in comparisons:files.update([HW/a,HW/b])
snapshot=HERE/'operations_snapshot';snapshot.mkdir(exist_ok=True)
bindings=[]
for p in sorted(files):
 rel=p.resolve().relative_to(ROOT);bindings.append({'path':rel.as_posix(),'bytes':p.stat().st_size,'sha256':sha(p)})
 if p.parent==HERE:continue
 target=snapshot/(sha(p)[:12]+'--'+p.name)
 if target.exists():assert target.read_bytes()==p.read_bytes()
 else:target.write_bytes(p.read_bytes())
review={'status':'PASS_TX09_DELIVERY_OPERATIONS_SOURCE_AND_LOCAL_REPORT_BINDING','new_test_executions':0,'device_calls':0,'derived_files':15,'reviewed_local_reports':reports,'display_decoder_checks':10,'sample_identity_note':'Author sample_sha256 identifies LF string bytes; the saved sample has Windows CRLF. Normalized string hash checked separately and actual file hash retained in bindings.',
 'observations':['QR parser pins the preexisting P3 decoder hash; exact09 prefix/uniqueEND/single first-page snapshot ID/size/completeness markers are mandatory. QR payload is handled only as data.','Capture advances only one n after an accepted nonfinal page; stale immediately previous page with exact total/CRC/pages is retried without another key. Foreign identity/CRC is refused. All attempted images and frames are retained.','Menu tool performs one permitted key after recent screenshot SHA/focus checks and durable intent; it does not perform OCR or automatic UI-state recognition. It never emits Enter or a password.','Power-off tool retains standard advertised ForceOff plus On/native/Bios1904 checks and durable intent; HTTP success still requires independent Off readback. It does not delete a private credential.','Six-line decoder accepts fixed widths/labels/uppercase ASCII only, no OCR substitutions; CRC is exactly100 displayed scalars, not a full256-byte memory record or proof of a fresh request.'],
 'scope_restrictions':['This exact binary and family menu tool still contain normal M/B/password functionality. The current diagnostic PROCEDURE is narrower: initialQ,mode1,mode2 attach,M,limitedESC/read screenshot; noB,noEnter,nofixture/no password entry. This is an operator constraint, not a newly compiled hard restriction.','Existing source/mock results do not establish real KVM focus or internal firmware state; uncertain outcomes need observation, not blind retry.','The no-safe-page exit gap remains. Power-off may be needed; this diagnostic does not claim a native unwind repair.','No codec/journal/recovery work authorizes a password-writing test yet.'],
 'confirmed_new_blockers':[],'bindings':bindings}
out=HERE/'operations_review.json';out.write_text(json.dumps(review,indent=2)+'\n')
print(json.dumps({'status':review['status'],'bindings':len(bindings),'sha256':sha(out)}))
