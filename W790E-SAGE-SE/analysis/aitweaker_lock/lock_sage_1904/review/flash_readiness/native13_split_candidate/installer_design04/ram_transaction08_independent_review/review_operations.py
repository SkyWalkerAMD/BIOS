"""Read-only TX08 control/decoder source and local-test binding review."""
from pathlib import Path
import difflib,hashlib,json
HERE=Path(__file__).resolve().parent;READY=HERE.parents[2];CASE=READY.parents[1]
HW=CASE/'remote_172_20_2_162';C11=READY/'remote_only/continuation11'
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
EXPECTED={
 'read_native13_ram_test08_qr.py':'6fc2a6797fb4493b904b20933c6a1a3ee1771da400e1f765686fcdb5e435421f',
 'operations/capture_native13_ram_test08.mjs':'1cfd1646247389f976f06afa6621e9e613e77d47cc1ec8eb7b4994fdd09b3e88',
 'operations/native_test_keys11.mjs':'1f36efde2f9130c4de7b4e9ab10a43b90adc3bda87d9187e13f6c446e4a798a0',
 'operations/power_off_ram_test11.mjs':'cfebee9ba5d76e4ce908ad3c41fad8a6c02415d21c1e6743cb3548bc9b07f42c',
 'operations/kvm_password_fixture11.mjs':'26cd9c79e23fa379f3156f92b60c949410e56c471724660eb00d4ebc63a89b16',
}
def main():
 for name,digest in EXPECTED.items():assert sha(HW/name)==digest
 derivation=C11/'ram08_delivery_derivation.json';derived=json.loads(derivation.read_text())
 assert derived['device_calls']is False
 files={derivation,C11/'prepare_ram08_delivery.py',Path(__file__)}
 for row in derived['bindings']:
  assert sha(Path(row['source']))==row['source_sha256'];assert sha(Path(row['output']))==row['output_sha256']
  files.update([Path(row['source']),Path(row['output'])])
 specs=[('decoder08_tests.json','source_sha256','read_native13_ram_test08_qr.py',14,'checks'),
        ('capture08_tests.json','capture_sha256','operations/capture_native13_ram_test08.mjs',4,'checks'),
        ('capture08_stale_tests.json','capture_sha256','operations/capture_native13_ram_test08.mjs',3,'checks'),
        ('native11_key_tests.json','source_sha256','operations/native_test_keys11.mjs',6,'cases'),
        ('poweroff_ram11_tests.json','source_sha256','operations/power_off_ram_test11.mjs',4,'checks'),
        ('kvm_password_fixture11_tests.json','source_sha256','operations/kvm_password_fixture11.mjs',5,'cases')]
 summaries=[]
 for name,key,tool,count,collection in specs:
  p=C11/name;obj=json.loads(p.read_text());assert obj['status'].startswith('PASS')
  assert obj[key]==EXPECTED[tool] and len(obj[collection])==count
  if 'capture' in name:assert obj['decoder_sha256']==EXPECTED['read_native13_ram_test08_qr.py']
  files.add(p);summaries.append({'path':str(p),'sha256':sha(p),'checks':count,'status':obj['status']})
 for name in ['test_capture08_stale.mjs']:
  files.add(C11/name)
 for p in (C11/'capture08-qr-fixtures').glob('*'):
  if p.is_file():files.add(p)
 files.update(HW/name for name in EXPECTED)
 files.add(CASE.parent/'probe_p3_kvm/decode_captures.py')
 comparisons=[('read_native13_ram_test05_qr.py','read_native13_ram_test08_qr.py'),
  ('operations/capture_native13_ram_test05.mjs','operations/capture_native13_ram_test08.mjs'),
  ('operations/native_test_keys09.mjs','operations/native_test_keys11.mjs'),
  ('operations/power_off_ram_test09.mjs','operations/power_off_ram_test11.mjs'),
  ('operations/kvm_password_fixture09.mjs','operations/kvm_password_fixture11.mjs')]
 diff=HERE/'operations05_to08.diff.txt'
 diff.write_text(''.join(''.join(difflib.unified_diff((HW/a).read_text().splitlines(True),(HW/b).read_text().splitlines(True),fromfile=a,tofile=b))for a,b in comparisons))
 files.add(diff)
 # Preserve exact operation and test files without changing parent artifacts.
 snap=HERE/'operations_snapshot';snap.mkdir(exist_ok=True)
 records=[]
 root=next(p for p in HERE.parents if(p/'tools/pydeps').is_dir())
 for p in sorted(files):
  p=p.resolve();assert p.is_relative_to(root)
  records.append({'path':str(p.relative_to(root)).replace('\\','/'),'bytes':p.stat().st_size,'sha256':sha(p)})
  if p==Path(__file__).resolve() or p==diff.resolve():continue
  target=snap/('HW' if p.is_relative_to(HW) else 'C11' if p.is_relative_to(C11) else 'other')/(sha(p)[:12]+'--'+p.name)
  target.parent.mkdir(exist_ok=True)
  if target.exists():assert target.read_bytes()==p.read_bytes()
  else:target.write_bytes(p.read_bytes())
 result={'status':'PASS_TX08_OPERATION_SOURCE_AND_LOCAL_TEST_BINDING_REVIEW','device_calls':0,'new_test_execution_by_reviewer':0,
  'confirmed_blockers':[],'reviewed_existing_tests':summaries,'derived_files_verified':len(derived['bindings']),
  'findings':[
   'Decoder accepts only RAM_TEST08 identity and exact complete immutable snapshots; pinned P3 CRC parser is retained. QR bytes are data, never commands.',
   'The only new capture behavior waits up to eight screenshots for the immediately preceding page with identical whole CRC, total bytes and page count. It does not send an additional key during retries. A foreign CRC or other page is refused.',
   'Capture preserves all attempted screenshots/decoded frames and copies accepted pages exclusively. One n is sent only after an accepted nonfinal page; assembly still checks exact page and whole CRC/length/snapshot completeness.',
   'Menu tool permits only MAIN 1/2/q or SESSION m/b/r/q, one key after recent local screenshot hash and focus checks, with intent before input and no retry. Manual stage attribution is not automatic screen recognition.',
   'ForceOff retains fixed standard advertised ComputerSystem.Reset/ForceOff, current Redfish/native On plus BIOS1904, recent screen binding, durable intent and no retry. Revised comment and intent distinguish an unresponsive browser from proven CPU hold.',
   'Password fixture values stay in owned controller buffers, are not returned or logged, and are sent one character at a time with no Enter. Clear zeroes those local buffers only; it does not remove a firmware credential.',
   'Physical protocol target/session ownership and operation serialization remain parent-controller duties. No operation was run against the device by this review.'
  ],'limits':[
   'Inspected local mock tests are source/hash-bound, not reexecuted by this reviewer. No physical permission or success is inferred from mocks.',
   'Screenshot/metadata checks are not atomic and do not prove the application has reached a precise internal state. Ambiguous key or power outcomes require observation, never blind retry.',
   'The currently approved diagnostic progression begins with initial Q, mode1 restoration, mode2 attach, then M/ESC/Q without password input. Password tools existing in the family do not prove those actions accepted.',
   'A ForceOff HTTP acknowledgment is not an Off readback and does not itself clean a private NVRAM credential.'
  ],'bindings':records}
 out=HERE/'operations_review.json';assert not out.exists();out.write_text(json.dumps(result,indent=2)+'\n')
 print(json.dumps({'status':result['status'],'bindings':len(records),'sha256':sha(out)}))
if __name__=='__main__':main()
