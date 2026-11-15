"""Hash-check the root operator's bounded read-only diagnostic session close."""
from pathlib import Path
import hashlib,json
HERE=Path(__file__).resolve().parent;BOARD=HERE.parent;REMOTE=BOARD/'remote_172_20_2_245'
def read(p):return json.loads(p.read_text(encoding='utf-8'))
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def binding(p):return dict(path=str(p.resolve()),size=p.stat().st_size,sha256=sha(p))
p=REMOTE/'collection-close-20261108.json';close=read(p);checked=[]
assert len(close['evidence'])==12
for e in close['evidence']:
    path=(BOARD/e['path']).resolve();assert path.is_relative_to(REMOTE.resolve())
    assert sha(path)==e['sha256'] and path.stat().st_size==e['bytes'];checked.append(binding(path))
state=read(REMOTE/'maintenance-state-1794101474523.json')
system=next(x for x in state['reads'] if x['uri']=='/redfish/v1/Systems/Self')
assert system['status']==200 and system['data']['PowerState']=='On' and system['data']['BiosVersion']=='0603'
assert system['data']['Boot']['BootNext'] is None and system['data']['Boot']['BootSourceOverrideEnabled']=='Disabled'
assert close['password_record_writes']==close['oc_variable_writes_by_diagnostics']==close['firmware_write_actions']==0
assert close['virtual_media_detached'] and close['browser_session_logout_http']==200 and close['controller_exit_code_observed']==0
assert not close['bios_configuration_save_requested']
out=dict(status='PASS_BOUND_SESSION_CLOSE_OBSERVATIONS',release_ready=False,
    close_record=binding(p),checked_evidence_count=12,bindings=checked,
    visual_review='Reviewer independently viewed screen-38-current.png: original Main tab, BIOS 0603 X64; virtual media bar shows Browse File, 0 KB and Start Media.',
    verified_readback=dict(power='On',bios='0603',boot_next=None,override='Disabled'),
    root_operator_report=dict(no_requested_BIOS_save=True,password_record_writes=0,OC_writes_by_diagnostic=0,
        firmware_update_actions=0,keepalive_stopped=close['owned_keepalive_stopped'],
        redfish_client_disposed=close['owned_redfish_client_disposed'],logout_http=200,controller_exit=0),
    scope_limit='No blanket claim of zero firmware-internal writes during ordinary boot enumeration, reboots, or application launch. No password/gate/flash acceptance is inferred.',
    reviewer_network_or_device_actions=False)
(HERE/'remote_session_close_review.json').write_text(json.dumps(out,indent=2)+'\n',encoding='utf-8')
print(json.dumps(dict(status=out['status'],sha256=sha(HERE/'remote_session_close_review.json'))))
