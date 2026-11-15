"""Offline evidence binding for interrupted post-restart capacity attempt."""
from pathlib import Path
from datetime import datetime
import hashlib,json
HERE=Path(__file__).resolve().parent
REMOTE=HERE.parents[1]
CASE=REMOTE.parents[2]
HW=CASE/'remote_172_20_2_162'
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def ref(p):return {'path':str(p),'bytes':p.stat().st_size,'sha256':sha(p)}
def read(p):return json.loads(p.read_text(encoding='utf-8-sig'))
def dt(x):return datetime.fromisoformat(x)
def write(p,x):p.write_text(json.dumps(x,ensure_ascii=False,indent=2)+'\n',encoding='utf8')
def main():
    paths={
        'manager_after_restart':HW/'manager-restart08-capability-1793701071459.json',
        'boot_once':HW/'boot-once-1793701152945.json',
        'power_on':HW/'power-on-1793701155865.json',
        'helper_result':REMOTE/'media_writeback_client01/runs/20261103_101847/result.json',
        'native_401':HW/'browser-read-258.json',
        'manager_during_failure':HW/'manager-restart08-capability-1793701287308.json',
        'screenshot':HW/'screen-262-current.png',
        'screenshot_metadata':HW/'screen-262-current.json',
        'shutdown':HW/'power-1793701397438.json',
        'native_off':HW/'browser-read-263.json',
        'media_cleanup':HW/'media-cleanup-1793701437159.json',
        'boot_options_before':HW/'boot-options-1793666634014.json',
        'sd_after':HW/'system-1793701458552.json',
        'boot_options_after':HW/'boot-options08-1793701530248.json'}
    data={k:read(p) for k,p in paths.items() if p.suffix=='.json'}
    a=data['manager_after_restart'];b=data['manager_during_failure'];h=data['helper_result']
    elapsed=(dt(b['utc'])-dt(a['utc'])).total_seconds()
    clock_elapsed=(dt(b['managers'][0]['DateTime'])-dt(a['managers'][0]['DateTime'])).total_seconds()
    old_entries={r['data']['BootOptionReference']:r['data'] for r in data['boot_options_before']['members']}
    new_entries={r['BootOptionReference']:r for r in data['boot_options_after']['entries']}
    before_order=data['boot_once']['before']['BootOrder'];after_order=data['boot_options_after']['Boot']['BootOrder']
    identity_fields=['Id','BootOptionReference','DisplayName','BootOptionEnabled','UefiDevicePath']
    comparisons=[]
    for key in after_order:
        comparisons.append({'reference':key,'fields':{f:old_entries[key][f]==new_entries[key][f] for f in identity_fields}})
    removed=set(old_entries)-set(new_entries);added=set(new_entries)-set(old_entries)
    assert removed=={'Boot0007'} and not added
    removed_entry={f:old_entries['Boot0007'][f] for f in identity_fields}
    assert removed_entry['DisplayName']=='UEFI: AMI Virtual CDROM0 1.00'
    assert removed_entry['UefiDevicePath']=='PciRoot(0x0)/Pci(0x14,0x0)/USB(0xC,0x0)/USB(0x0,0x0)/CDROM(0x0,0x20,0x8000)'
    assert after_order==[x for x in before_order if x!='Boot0007']
    assert all(all(x['fields'].values()) for x in comparisons)
    assert data['native_401']['status']==401 and data['native_401']['data']['code']==1303
    assert b['power']['status']==401 and b['media']['status']==401
    assert b['system']['status']==200 and b['managers'][0]['status']==200
    assert h['end_reason']=='peer_closed' and h['status']=='SESSION_ENDED_WITHOUT_PROTOCOL_ERROR'
    assert h['backend_read_calls']==h['backend_write_calls']==h['backend_flush_calls']==h['backend_written_bytes']==0
    assert h['final_image_bytes']==16777216 and h['final_image_sha256']=='df7fa016a0f4be496d3d446db558e8de15f537aa9953faff20b4ae0c6132b4b6'
    assert len(h['capacity_sends'])==1 and h['capacity_sends'][0]['capacity8_hex']=='00007fff00000200'
    assert h['capacity_sends'][0]['sendall_returned'] is True
    assert data['native_off']['status']==200 and data['native_off']['data']['power_status']==0
    assert all(data['media_cleanup']['verified'].values())
    assert data['shutdown']['command']==5 and data['shutdown']['result']['status']==200
    frozen=REMOTE/'bmc_restart_review01'
    assert sha(frozen/'restart_review.json')=='b5e1d402175335e529f1f9e19900d1325a4468ae2350166770c2b54d3c7456a0'
    assert sha(frozen/'manifest.json')=='54ae46b12553581889780b69f8a44b71f11c327cbb1f9c0040ec081bbfed846c'
    assert sha(frozen/'physical_outcome_review.json')=='0c3905dad2c93f5c0e0da7d7035ab749ccc4d70ddebc7a8bde121890100a2c92'
    report={
        'status':'INTERRUPTED_ATTEMPT_NO_POST_RESTART_CAPACITY_RESULT',
        'scope':'Independent offline review of parent-collected files and direct visual inspection of screen262. No device connection, mutation or firmware operation.',
        'inputs':{k:ref(p) for k,p in paths.items()},
        'timeline':[
            {'utc':a['utc'],'event':'After BMC restart: healthy manager, host Off, native API authenticated.'},
            {'utc':h['started_utc'],'event':'Same disposable image opened; helper authenticated.'},
            {'utc':h['capacity_sends'][0]['utc'],'event':'Client sendall returned for101-byte opcode25 response00007fff00000200; not a server apply acknowledgement.'},
            {'utc':data['boot_once']['utc'],'event':'Requested one-time UEFI CD override; SD readback verified.'},
            {'utc':data['power_on']['utc'],'event':'Host On request accepted202.'},
            {'utc':h['finished_utc'],'event':'Helper peer_closed; no backend data read/write/flush calls; image digest unchanged.'},
            {'utc':b['utc'],'event':'Native APIs401; Redfish system/manager still200; host On. Manager DateTime now about4hours ahead of local elapsed progression.'},
            {'utc':data['shutdown']['utc'],'event':'Parent requested ACPI orderly shutdown (command5), accepted200.'},
            {'utc':data['media_cleanup']['utc'],'event':'Host Off, helper reaped, virtualCD detached and media idle read back.'},
            {'utc':data['boot_options_after']['utc'],'event':'Six remaining boot-option identities and their relative order match original non-CD entries.'}],
        'clock_and_authentication':{
            'before_manager_datetime':a['managers'][0]['DateTime'],
            'after_manager_datetime':b['managers'][0]['DateTime'],
            'local_elapsed_seconds':elapsed,'manager_datetime_elapsed_seconds':clock_elapsed,
            'excess_manager_datetime_advance_seconds':clock_elapsed-elapsed,
            'native_401':data['native_401'],
            'independent_redfish_still_200':True,
            'conclusion':'Large reported Manager DateTime jump, native session rejection and media peer closure occurred during the same bounded attempt.',
            'not_proven':['Exact time/source of clock adjustment','Actual BMC kernel clock versus presentation-layer correction','Which peer closed the media connection internally','Clock jump caused session expiry or media loss','Whether this is a second manager reboot']},
        'capacity_and_writeback':{
            'client_capacity_response':h['capacity_sends'][0],
            'backend_calls':{k:h[k] for k in ['backend_read_calls','backend_write_calls','backend_flush_calls','backend_written_bytes']},
            'final_image_sha256':h['final_image_sha256'],
            'no_valid_post_restart_host_capacity_result':True,
            'conclusion':'This interrupted run cannot determine whether the BMC restart fixed the geometry mismatch; it supplies no successful file writeback result.',
            'scope_limit':'Zero calls describe this controlled image helper only, not all host-OS storage activity.'},
        'visual_observation':{
            'source':ref(paths['screenshot']),
            'method':'Direct visual inspection of the original PNG with view_image.',
            'visible':['Rocky Linux8.10 (Green Obsidian)','Kernel4.18.0-553.el8_10.x86_64','K6D-008 login prompt','sr0 and sdb READ/media I/O errors','Virtual CD UI shows Browse File0KB / Start Media'],
            'not_claimed':['Custom frozen Linux PID1 ran','sdb is conclusively identified from this screenshot','Local disk damage or successful storage writes','Precise cause of fallback to regular installed OS']},
        'boot_option_change':{
            'old_order':before_order,'current_order':after_order,
            'removed':[removed_entry],'added':[],
            'remaining_identity_checks':comparisons,
            'relative_order_preserved':True,
            'conclusion':'Only the previously identified virtual-CD Boot0007 is absent; the six current non-CD entries retain identity and order.',
            'scope_limit':'Observed option lifecycle is consistent with media disconnect; this review does not prove the firmware code that removed it.',
            'restore_rule':'Restore only BootSourceOverrideEnabled/Target/Mode to Disabled/None/Legacy after fresh safety checks. Do not recreate Boot0007, patch BootOrder, or restore stale BootOptions.',
            'state_before_restore':{k:data['boot_options_after']['Boot'][k] for k in ['BootSourceOverrideEnabled','BootSourceOverrideTarget','BootSourceOverrideMode','BootNext']},
            'restoration_not_yet_verified_here':True},
        'cleanup_readback':data['media_cleanup']['verified'],
        'prior_frozen_restart_review_unchanged':[ref(frozen/'restart_review.json'),ref(frozen/'manifest.json'),ref(frozen/'physical_outcome_review.json')]}
    write(HERE/'interruption_review.json',report)
    write(HERE/'interruption_manifest.json',{'files':[ref(HERE/'review_interruption.py'),ref(HERE/'interruption_review.json')],
          'inputs':{k:ref(p) for k,p in paths.items()}})
    print(json.dumps({'report':ref(HERE/'interruption_review.json'),'manifest':ref(HERE/'interruption_manifest.json'),
                      'local_elapsed':elapsed,'clock_excess':clock_elapsed-elapsed},indent=2))
if __name__=='__main__':main()
