"""Preserve findings against frozen revision01 before a separate fix exists."""
from pathlib import Path
import hashlib,json,difflib
H=Path(__file__).resolve().parent;B=H.parent;R=B.parents[2];O=B/'observer_generation08'
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def bind(p):return {'path':p.relative_to(R).as_posix(),'bytes':p.stat().st_size,'sha256':sha(p)}
def load(p):return json.loads(p.read_text())
m=load(O/'component_manifest.json');assert sha(O/'component_manifest.json')=='4fc68d969c583e39cf1bfbf798dcf52c5bcc6a7fe4e00e8616eb168b9e778d30'
for key in ('files','external_bindings'):
 for x in m[key]:assert bind(R/x['path'])==x
build=load(O/'build/build.json')
for p,h in build['sources'].items():assert sha(R/p)==h
t=load(O/'generation_tests.json');assert t['checks']==len(t['cases'])==9 and all(x['passed'] for x in t['cases'])
assert t['component_sha256']==sha(O/'build/W890ObserverGeneration08.TESTONLY.dll') and t['source_sha256']==sha(O/'verify_generation.py')
old=B/'navigation05/visit/observer_visit05.c';new=O/'visit/observer08.c'
diff=''.join(difflib.unified_diff(old.read_text().splitlines(True),new.read_text().splitlines(True),fromfile=str(old.relative_to(R)),tofile=str(new.relative_to(R))))
(H/'revision01.diff.txt').write_text(diff)
repro=load(H/'revalidation_repro.json');assert repro['source']==bind(H/'reproduce_revalidation.py')
report={
 'status':'REVISION01_REVALIDATION_FINDINGS_REPRODUCED_FIX_REQUIRED_BEFORE_INTEGRATION',
 'manifest':bind(O/'component_manifest.json'),'component':bind(O/'build/W890ObserverGeneration08.TESTONLY.dll'),
 'source_delta':bind(H/'revision01.diff.txt'),'verified_bindings':{'files':15,'external':26},
 'existing_tests':{'cases':9,'bindings_match':True,'limits':'Effect-ticket fixture and original private loop execute; BrowserLoop body/UEFI/page objects/scheduling remain models. No full-GUI or management/lease invalidation coverage is inferred.'},
 'good_properties':[
  'Separate64-bit catalog_generation starts1, advances only matching FORMS event types, and saturating-next-event revokes instead of wrapping.',
  'Foreign FORMS branch preserves epoch, private native frame/visit and active occupancy, while shared ticket_valid compares captured catalog_generation.',
  'String-only notifications do not invalidate FORMS tickets. Unknown Setup/NULL/exhausted-generation paths retain the identity revocation policy.',
  'no_scope_validate performs cached validation after identity services; no_read_variable checks again after its variable service.',
  'The new query creates no ticket or provider grant. Twoog08_test exports and their call windows are explicitly fixture-only and must be removed during integration.'
 ],
 'findings':[
  {'id':'OG08-01','severity':'FIX_BEFORE_INTEGRATION','function':'no_management_valid',
   'finding':'ticket_valid checks generation only before identity_live. A real registered foreign notify during a modeled identity-service return advances generation without faulting the private loop. Subsequent page/control checks remain valid, so the expired ticket validates once.',
   'actual_pe_result':'Enter/valid-before/valid-during/valid-after = [1,1,1,0], fault=0.',
   'minimal_fix':'Recheck ticket_valid and frame_active after potentially notifying services and at the final management-object acceptance.'},
  {'id':'OG08-02','severity':'FIX_BEFORE_INTEGRATION','functions':['no_catalog_generation','no_native_visit_identity','no_scope_enter'],
   'finding':'frame_active is evaluated before identity_live. A registered Setup notification during its service calls revokes the epoch but identity_live itself has no final fault/ended rejection. New queries report success or scope_enter mints an immediately invalid ticket.',
   'actual_pe_result':'Each readonly query returns[1,0] across the during/after calls with fault1. Real registered consumer scope_enter reports entered1/before_valid0/after_valid0; no variable service or credential write executes.',
   'minimal_fix':'Post-service frame checks before output or mint. identity_live final fault/ended rejection is an additional defense, not a replacement for ticket-generation comparison.'},
  {'id':'OG08-03','severity':'RELATED_SOURCE_REVIEW','functions':['no_management_enter','no_lease_begin','no_publication_validate'],
   'finding':'These paths also test active frame/cold state before identity services. Their post-service guard pattern deserves the same bounded correction; this report does not claim independent PE reproduction for all three.',
   'minimal_fix':'Recheck unchanged occupied-slot state plus live frame/cold state before mint/accept; retain old occupancy until the legitimate owner leaves.'}
 ],
 'actual_instruction_reproduction':bind(H/'revalidation_repro.json'),
 'scope_limits':[
  'Notification timing at modeled RestoreTPL is explicit; no physical scheduling or deployed exploit is claimed.',
  'Management fixture runs actual cold publication/privateLoop/control checks but supplies the enter caller ABI value; original ConfigAccess CALL is not executed in this case.',
  'No private observer state, owner boolean, original PE, frozen source or hardware state was modified.',
  'Preserved occupancy assumes trusted paired API use; this report does not claim arbitrary ring0 memory-writer resistance.'
 ],
 'pending_hii08':'Dependency identity is bound by the reviewed observer manifest. Its separate10 original-instruction/REA cases are not independently rerun by this narrow review.',
 'revision01_left_frozen':True,'hardware_actions':0,'runtime_authorized':False
}
(H/'initial_review.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps({'initial_review':bind(H/'initial_review.json')}))
