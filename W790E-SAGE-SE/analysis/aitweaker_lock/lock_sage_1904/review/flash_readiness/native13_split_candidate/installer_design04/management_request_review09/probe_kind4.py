"""Bounded original kind4 frame construction and frozen07 classification.

Explicit HII/allocator/memory/provider endpoints remain models. No hardware,
no provider source changes, no new allow rule or full native browser claim.
"""
from pathlib import Path
import hashlib,json,sys,traceback
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent;D04=HERE.parent;C07=D04/'static_chrome_candidate07'
source=(C07/'verify_chrome.py').read_text(encoding='utf8').split('\nchecks=[];observations=[]',1)[0]
ns={'__file__':str(C07/'verify_chrome.py')}
exec(compile(source,str(C07/'verify_chrome.py')+' [prefix only; no report-writing tests]','exec'),ns)
ChromeVM=ns['ChromeVM'];S=ns['S'];q=ns['q'];TSE=ns['TSE']
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
assert sha(C07/'build/guard_template.bin')=='2aef4bfca4ecb31631c60f9ee01cc2480a5782169524620a502ae0cf2e295efa'
v=ChromeVM(4)
v.u.mem_write(v.page+0x20,q(0x99998888))
state={
 'page_source_hii':hex(v.getq(v.page+0x20)),
 'page_owner_result':hex(v.call(S['AMITSE']['gate_owner'],v.getq(v.page+0x20),0)),
 'frame_kind':v.getd(v.frame+0x20),'frame_vtable_rva':hex(v.getq(v.frame)-TSE),
 'control_count':v.getd(v.frame+0x3c),'control_vtable_rva':hex(v.getq(v.control)-TSE),
 'control_hii':hex(v.getq(v.control+0x20)),'expected_amitse_string_hii':hex(v.amih),
 'descriptor_hex':bytes(v.u.mem_read(v.control+0x20,64)).hex(),
 'ifr_rva':hex(v.ifr-TSE),'ifr_first_16_hex':bytes(v.u.mem_read(v.ifr,16)).hex(),
 'gate_owner_result':hex(v.call(S['AMITSE']['gate_owner'],v.amih,0)),
 'native_chrome_exported':False,
 'native_chrome_scope':'Compiler inlined this helper; actual complete frame_protected is executed below.',
 'frame_protected_result':hex(v.call(S['AMITSE']['frame_protected'],v.frame)),
 'page_protected_result':hex(v.call(S['AMITSE']['page_protected'],v.page)),
 'actual_native_counts':v.native_counts,'explicit_construction_models':v.models
}
v.provider_present=True;v.provider_bits=3;v.request_accept=False
v.u.mem_write(TSE+0x83468,q(5))
for _ in range(2):v.call(S['AMITSE']['gate_poll'])
state['after_two_polls']={'provider_calls':v.provider_calls,'native_endpoint_calls':v.calls,
 'exit_flag':bytes(v.u.mem_read(v.app+0x5a,1)).hex(),'current_page_index':v.getd(v.app+0x28)}
report={'status':'OBSERVED_SYNTHETIC_NATIVE_KIND4_WITH_EXPLICIT_BOUNDARY_MODELS',
 'guard_template_sha256':sha(C07/'build/guard_template.bin'),
 'source_sha256':sha(Path(__file__)),
 'observation':state,
 'limits':['This creates a native kind4 frame using original machine code, but its page and HII/service associations are controlled models.',
 'No actual TX08 hardware page/control snapshot exists here. Matching the observed Request symptom is not proof of the physical cause.',
 'The provider Request endpoint is a denial-count model; physical P14 UI is source-mapped separately.']}
(HERE/'kind4_observation.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf8')
print(json.dumps(report,indent=2))
