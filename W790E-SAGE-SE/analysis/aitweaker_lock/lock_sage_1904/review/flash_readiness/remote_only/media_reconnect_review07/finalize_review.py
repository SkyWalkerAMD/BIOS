"""Freeze bounded normal-stop versus transport-close evidence, no network."""
from pathlib import Path
import hashlib,json,struct,sys
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent;REMOTE=HERE.parent;HW=HERE.parents[3]/'remote_172_20_2_162'
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def ref(p):return {'path':str(p),'bytes':p.stat().st_size,'sha256':sha(p)}
def read(p):return json.loads(p.read_text(encoding='utf-8-sig'))
def write(p,d):p.write_text(json.dumps(d,indent=2,ensure_ascii=False)+'\n',encoding='utf8')
def main():
    replay=read(HERE/'disconnect_replay.json');assert replay['status']=='PASS' and replay['case_count']==7
    native=read(HERE/'native_analysis.json');frontend=read(HERE/'frontend_evidence.json')
    for row in native.values():assert sha(Path(row['path']))==row['sha256']
    for row in frontend['inputs']:assert sha(Path(row['path']))==row['sha256']
    helper=REMOTE/'media_writeback_client01/runs/20261103_103442/result.json'
    h=read(helper);assert h['script_sha256']=='1f83f12403636e9764f3cc90350880b6bfa7b15ea0610e220a1106b5e0bd4f43'
    assert h['opcode_counts']=={'F1':1,'F3':17} and h['capacity_sends']==[] and h['end_reason']=='parent_stop'
    assert h['backend_read_calls']==h['backend_write_calls']==h['backend_flush_calls']==h['backend_written_bytes']==0
    assert h['final_image_sha256']=='df7fa016a0f4be496d3d446db558e8de15f537aa9953faff20b4ae0c6132b4b6'
    iso=HW/'browser-selected-iso08-1793702316238.json';im=read(iso)
    assert im['files_count']==1 and im['files'][0]['size']==im['files'][0]['array_buffer_bytes']==32571392
    assert im['files'][0]['sha256']=='4e70bb0abfc285849301a6829b1ac51cae914d65025e135b971b06dd47d25d18'
    prior=[(REMOTE/'media_geometry_review06/geometry_review.json','df07bf5c111f3c207b382c91196170df87baffc64500303b214ba6e4f99e698f'),
           (REMOTE/'media_geometry_review06/manifest.json','27fbd86cf9bb31f1f38c653cd0732d339e41a96cbb7dee10277c5aa64d0af71d'),
           (REMOTE/'bmc_restart_review01/restart_review.json','b5e1d402175335e529f1f9e19900d1325a4468ae2350166770c2b54d3c7456a0'),
           (REMOTE/'bmc_restart_review01/manifest.json','54ae46b12553581889780b69f8a44b71f11c327cbb1f9c0040ec081bbfed846c')]
    for p,pin in prior:assert sha(p)==pin
    # Distinct original dataflow paths, not a general binary-string inference.
    hdloop=(HERE/'disassembly/hdserver/hdserver_loop.txt').read_text()
    cdloop=(HERE/'disassembly/cdserver/cdserver_loop.txt').read_text()
    assert '00015868' in hdloop and '#0xf7' in hdloop and '00015e68' in hdloop and '; nbd_disconnect' in hdloop
    assert '00014ffc' in cdloop and '#0x15254' in cdloop and '00015010' in cdloop and '#0x158e4' in cdloop
    report={
        'status':'BOUNDED_OFFLINE_RECONNECT_DIFFERENCE_CONFIRMED_PHYSICAL_CAUSE_UNPROVEN',
        'scope':'Pinned official BMC1.1.57 ARM/Lua-independent native/client evidence and7synthetic original-instruction cases only. No device contact, client connection, service mutation, sysfs command, image write or firmware operation.',
        'inputs':{'official_image':ref(REMOTE/'official_bmc/W7901157.ima'),
                  'native_analysis':ref(HERE/'native_analysis.json'),'frontend_evidence':ref(HERE/'frontend_evidence.json'),
                  'actual_arm_replay':ref(HERE/'disconnect_replay.json'),
                  'parent_latest_helper_result':ref(helper),'browser_selected_iso':ref(iso)},
        'protocol_correction':{'F3':'KEEP_ALIVE, not disconnect','F6':'KILL_REDIR','F7':'MEDIA_SESSION_DISCONNECT'},
        'normal_client_stop':{
            'java':'Original HarddiskRedir.stopRedirection sendsF7 at bytecode37..40 before closing at72..78; abnormal stop closes withoutF7.',
            'h5':'Stop Media invokes CDROM.sendstopcommandtoserver, which sendsF7. The UI clears the selected image and reports stopped without waiting for a server clear-slot acknowledgement.',
            'errors':'H5 sendPacket catches exceptions; Java normal-stop also logs send failure and proceeds to close. Visible stopped status does not prove F7 delivery.',
            'helper04_difference':'Current helper04 parent STOP closes the socket in finally without first sending F7. This matches transport-close semantics, not the normal Java stop protocol.',
            'not_a_patch':'This report did not change or run any helper. Any new normal-stop implementation would need isolated serialization/lifecycle/error tests before use.'},
        'hdserver_paths':{
            'source_sha256':native['hdserver']['sha256'],
            'receiver':'0x17054 returns1 for recv<=0 or read/format failure.',
            'common_dispatch':'0x15850..0x1586C separates receive error, F3 andF7.',
            'F3':'0x15A78 records heartbeat response and maintains/reset its state machine; no explicit stop or NBD disconnect.',
            'F7':'0x15E08..0x15E74 calls hdisk_stop0x180B4 for active gadget, clears gadget slot; calls nbd_disconnect for active NBD, clears NBDslot; then0x15B28→0x149E4.',
            'EOF':'0x15B04→0x13770 writes a NoMedia response to the last packet buffer,0x15C98→0x12E68 dispatches that response, then common session cleanup0x149E4.',
            'normal_stop_body':'0x180B4 cancels eject monitor and asks the existing vendor helper to clear only hddisk/lun.N/file; on failure it attempts the legacy USBHD disconnect.0x17DE0 is conditional UDC unbind.',
            'session_cleanup':'0x149E4 clears socket/active-session records, cancels/joins owned worker, resets media-token/session records and may unbind hddisk UDC. It contains no unconditional NBD disconnect.',
            'conditional_EOF_cleanup':'If last pending READ response reaches nbd_write_res and fails, that branch does explicitly stop/disconnect. Do not generalize every EOF as a leak.',
            'state_scope':'The recorded slot/NBD/gadget state is synthetic in the replay, not read back from the target.'},
        'native_replay':{
            'cases':7,'status':'PASS','executed_original_code':['receive_packet','NoMedia response','response dispatch','F3/F7/EOF branch','common session cleanup'],
            'stubbed_boundaries':['network recv/select','NBD operations','gadget stop','session configuration/database','thread management','safe_system command execution'],
            'results':[
                'F3 leaves session/socket and slots intact.',
                'F7 clears gadget/NBD slots before session cleanup.',
                'EOF with a lastF3 packet clears session/socket but retains slot values, both with and without a synthetic GetVMediaCfg setting that requests UDC unbind.',
                'EOF with a pending READ and injected NBD response failure clears both slots.'],
            'limit':'No kernel/configfs/NBD driver action or actual server memory was executed/observed.'},
        'cdserver_paths':{
            'source_sha256':native['cdserver']['sha256'],
            'EOF':'0x14FF0 receiver0x167E0 returns1;0x14FFC branches0x15254, sets NoMedia and joins0x15264.',
            'F7':'0x1500C..0x15010 branches0x158E4, logs normal session disconnect and joins the same0x15264 cleanup flow.',
            'common_cleanup':'0x152EC calls0x13F58; clears media/session/socket records, joins worker, resets CD token/session and conditionally unbinds cdrom UDC at0x17564.',
            'scope':'Different initial NoMedia action, then shared conditional cleanup. No proof that every backend backing slot is purged merely because UI/session state is idle.'},
        'HD_vs_CD':{
            'verified_distinction':'Selected native calls use separate hddisk and cdrom configfs gadget paths, UDC port2 andport1 respectively, and distinct device-type/session records4 versus1.',
            'shared_NBD_claim':'Not established. HD has explicit libnbd/nbd_disconnect path; this review did not establish that the browser CD session shares the same selected NBDslot.',
            'remaining_shared_context':'Common BMC process infrastructure, USB virtual hub and authentication/session services can still couple behavior; separate paths do not prove complete independence.',
            'supported_stop_limit':'Stopping the browser CD is not established as an HD-slot flush. Current GET media idle values are session observations, not NBD/gadget-slot readback.'},
        'latest_physical_evidence_scope':{
            'helper_start':h['started_utc'],'helper_finish':h['finished_utc'],'opcodes':h['opcode_counts'],
            'capacity_sends':0,'controlled_image_rw_flush_calls':0,'image_sha256':h['final_image_sha256'],
            'browser_file_sha256':im['files'][0]['sha256'],
            'conclusion':'F1 plus17F3 shows authentication and heartbeat traffic only. It does not prove image capacity negotiation or optical boot delivery. No new post-restart custom Linux capacity result is available.',
            'helper_start_info':'Bound source emits F2 then F8 before the receive loop; lack of incoming25 is not evidence of missing outgoingF8.'},
        'bounded_hypothesis':{
            'supported_by_code':'An abnormal HD socket close can leave more backend attachment state than an explicit normalF7 stop, even after session-idle readback. This is a concrete candidate explanation for different reconnect behavior.',
            'not_proven_on_target':['Retained NBD/gadget slot values','Why opcode25 was absent on latest session','Why the selected optical ISO did not boot','HD client disturbed CD backing storage','Exact cache origin of the earlier capacity mismatch'],
            'next_discriminating_test':'Parent-planned CD-only boot with HD helper absent tests optical boot independently. A later isolated helper change may emulate the documented normalF7 stop, but should not be substituted into the current frozen helper without review.',
            'no_blind_operations':'Do not issue shell/sysfs/ioctl/service-control commands from these disassembly strings. No validated generic force-clear API has been established by this bounded review.'},
        'frozen_prior_reports_unchanged':[ref(p) for p,_ in prior]}
    write(HERE/'reconnect_review.json',report)
    artifacts=[]
    for p in sorted(HERE.rglob('*')):
        if not p.is_file() or p.name=='manifest.json' or any(x.startswith('ghidra-') or x=='__pycache__' for x in p.relative_to(HERE).parts):continue
        artifacts.append({'path':str(p.relative_to(HERE)),'bytes':p.stat().st_size,'sha256':sha(p)})
    write(HERE/'manifest.json',{'scope':'Source, static decompilation/disassembly and in-memory replay only; Ghidra project/cache excluded.','files':artifacts})
    print(json.dumps({'report':ref(HERE/'reconnect_review.json'),'manifest':ref(HERE/'manifest.json'),'artifacts':len(artifacts)},indent=2))
if __name__=='__main__':main()
