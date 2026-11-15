from pathlib import Path
import hashlib
import json
H=Path(__file__).resolve().parent;B=H.parent;R=H.parents[3]
C=H/'capture_6e7a57f9729b082c'
L=B/'remote_172_20_2_245/hardware-inventory01-1794118383562-7cf167e2'
def bind(p):
 d=p.read_bytes();return {'path':p.relative_to(R).as_posix(),'bytes':len(d),'sha256':hashlib.sha256(d).hexdigest()}
report=json.loads((C/'reconciled.json').read_text())
assert report['complete_selected_objects'] and len(report['objects'])==5 and not report['omitted'] and not report['refused']
assert report['spf']['observations_equal'] and report['spf']['both_reads_complete']
assert bind(L/'hardware-log.txt')['sha256']=='6e7a57f9729b082ce15931a063d94a32a56f51d78c9dc8097a80984e9487aa00'
capture=json.loads((L/'manifest.json').read_text())
for item in capture['screenshots']:assert bind(L/item['file'])['sha256']==item['sha256']
local=[H/'freeze.py',H/'reconcile.py']+sorted(C.glob('*'))
external=[L/'hardware-log.txt',L/'manifest.json',L/'decoded.json']+[L/x['file'] for x in capture['screenshots']]
external += [B/x for x in (
 'diagnostic_delta07/component_manifest.json','diagnostic_delta07/build/build.json',
 'diagnostic_delta07/selection_hardware02.json','diagnostic_delta07/transport.py',
 'diagnostic_delta07/decode_packet.py','spf_sampler06/component_manifest.json','spf_sampler06/decode.py',
 'spf_sampler06_review/final_review.json','foreign_hii05/catalog.json',
 'foreign_hii05/scan_sources.py','foreign_hii05/build_catalog.py',
 'remote_172_20_2_245/screen-93-current.png','remote_172_20_2_245/screen-94-current.png',
 'remote_172_20_2_245/screen-95-current.png','remote_172_20_2_245/screen-96-current.png',
 'remote_172_20_2_245/collection-state07-1794118563252.json',
 'remote_172_20_2_245/inventory-session-logout-1794118592059.json')]
manifest={'status':'FROZEN_PHYSICAL_STRUCTURE_EVIDENCE_NOT_PASSWORD_OR_FLASH_QUALIFICATION',
 'log_pages':17,'log_bytes':12989,'log_crc32':'ABFB51BC','restored_instances':5,
 'environment':report['environment'],'spf_complete_stable':True,
 'post_setup_observations_only':True,'pool_ownership_proven':False,
 'remote_session_closed':True,'media_detached':True,'original_main_observed':True,
 'password_operations':0,'firmware_flash_requests':0,
 'files':[bind(p) for p in local if p.is_file()],
 'external_bindings':[bind(p) for p in external]}
p=H/'component_manifest.json';p.write_text(json.dumps(manifest,indent=2)+'\n')
print(json.dumps({'manifest':bind(p),'files':len(manifest['files']),'external_bindings':len(manifest['external_bindings'])}))
