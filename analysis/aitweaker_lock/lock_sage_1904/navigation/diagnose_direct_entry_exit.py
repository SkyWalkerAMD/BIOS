"""Read-only diagnostic of legitimate native empty-history entry conditions.

No candidate/production source, object, binary or existing test report is edited.
"""
from pathlib import Path
import hashlib,json
NAV=Path(__file__).resolve().parent
fixture=NAV/'history_candidate/verify_history.py'
source=fixture.read_text(encoding='utf8').split('\nv=NativeHistoryVM();v.poll()',1)[0]
ns={'__file__':str(fixture)};exec(compile(source,str(fixture),'exec'),ns)
VM=ns['NativeHistoryVM'];TSE=ns['TSE'];q=ns['q'];d=ns['d'];w=ns['w']
results=[]
for name,index,form,parent in [
 ('initial page index zero',0,0x2712,0),
 ('initial protected child with static parent',3,0x272c,1),
]:
 v=VM();page=v.pages[index]
 v.u.mem_write(page+0x20,q(v.handle));v.u.mem_write(page+0x2a,w(form))
 v.u.mem_write(page+0x32,w(parent));v.u.mem_write(v.records+index*64+10,w(form))
 v.u.mem_write(TSE+0x835a0,q(0));v.u.mem_write(TSE+0x835b8,d(0));v.u.mem_write(TSE+0x83594,d(0))
 v.current(index)
 status=v.call(TSE+0x10220,0,index)
 assert status==0 and v.getq(TSE+0x835a0)==0 and v.getd(TSE+0x835b8)==0
 prompts=v.calls['ui'];v.poll()
 assert v.calls['ui']==prompts+1
 assert v.u.mem_read(v.app+0x5a,1)==b'\1' and v.getd(v.app+0x28)==index
 assert v.getq(TSE+0x835a0)==0 and v.getd(TSE+0x835b8)==0
 results.append({'case':name,'fixture_form':hex(form),'initial_index':index,'native_page_parent':parent,
                 'original_history_initializer_status':hex(status),'history_after_native_initializer':'NULL / count 0',
                 'candidate_password_prompt':True,'candidate_exit_requested':True,'native_history_ownership_preserved':True})

v=VM();v.u.mem_write(v.pages[2]+0x2a,w(0x2712));v.u.mem_write(v.records+2*64+10,w(0x2712))
v.poll()
assert v.getd(v.app+0x28)==1 and v.u.mem_read(v.app+0x5a,1)==b'\0'
results.append({'case':'Favorites policy with valid native history','candidate_redirects_to_Main':True,'candidate_exit_requested':False})

report={
 'status':'NATIVE_EMPTY_HISTORY_PATHS_AND_CANDIDATE_FAIL_CLOSED_CONFIRMED',
 'candidate_driver_sha256':hashlib.sha256((NAV/'history_candidate/build/AiTweakerLock1904.efi').read_bytes()).hexdigest(),
 'cases':results,
 'observed_hardware':'Parent reports HISTORY01 screen155 password prompt, screen156 returns to P5 menu after cancel, screen157 remains responsive.',
 'assessment':'Compatible with the intentional conservative exit path; cancellation does not grant entry. It is acceptable for the current no-flash diagnostic invocation, with a documented cancellation-return difference. These fixtures do not establish which specific runtime branch Favorites took.',
 'unknowns':['Actual Favorites global page index and native parent are not in current logs.','Actual history pointer/count/capacity/search start and safe-root selection are not in current logs.','A repeated Escape event or OEM early-return path is not excluded by screenshots alone.'],
 'minimum_future_diagnostics':['redirect reason enum (no-safe-root vs invalid-history vs unavailable-write-range)','app.current and app.page_count','current/target native page index, page ID, static parent, form ID and flags','history pointer presence/alignment, capacity, used count and search lower bound','selected safe-root index; before/after app.exit','existing SendForm.status and request'],
 'recommendation':'Keep HISTORY01 unchanged while completing authorized tests. Do not relax history checks based only on this UI difference. If every cancel must remain inside Setup, design and validate an explicit empty-history allocation/ownership path as a separate change after collecting reason fields.',
 'limits':'Only original AMITSE helper and compiled candidate run inside Unicorn with synthetic data. No live state dump, BMC call, candidate source/binary modification or new hardware claim.'
}
(NAV/'direct_entry_exit_diagnosis.json').write_text(json.dumps(report,indent=2),encoding='utf8')
print(json.dumps(report,indent=2))
