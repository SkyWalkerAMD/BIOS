"""Freeze a bounded, offline review of the advertised standard BMC restart.

No target bytecode/native function is executed; no network module is imported.
"""
from pathlib import Path
import hashlib, importlib.util, json, struct, sys
sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
REMOTE = HERE.parent
CASE = HERE.parents[3]
HW = CASE / 'remote_172_20_2_162'

def sha(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()

def file_ref(p):
    return {'path': str(p), 'bytes': p.stat().st_size, 'sha256': sha(p)}

def write(name, value):
    (HERE/name).write_text(json.dumps(value, indent=2, ensure_ascii=False)+'\n', encoding='utf8')

def main():
    spec = importlib.util.spec_from_file_location('restart_native_reader', HERE/'inspect_native.py')
    reader = importlib.util.module_from_spec(spec); spec.loader.exec_module(reader)
    base = HERE/'official_inputs/5308416/usr/local'
    stack = reader.m.Elf32(base/'lib/libipmistack.so.13.13.12')
    pdk = reader.m.Elf32(base/'lib/libipmipdk.so.13.8.7')
    handler = reader.m.Elf32(base/'lib/libipmimsghndlr.so.13.22.37')
    hooks = []
    expected = {19: 'PDK_BeforeBMCColdReset', 58: 'PDK_ColdResetBMC', 189: 'PDK_SetRebootCause'}
    for n in range(282):
        va = 0x34374+n*0x102
        off = stack.offset(va, 258)
        data = stack.data[off:off+258]
        index = struct.unpack_from('<H', data)[0]
        if index not in expected: continue
        name = data[2:].split(b'\0', 1)[0].decode('ascii')
        assert name == expected[index]
        matches = [s for s in pdk.symbols if s.get('name') == name and s.get('va', 0)]
        hooks.append({'record_elf_va': hex(va), 'index': index, 'handle_offset': hex(index*4),
                      'name': name, 'defined_in_shipped_default_pdk': bool(matches),
                      'matching_symbols': matches})
    assert len(hooks) == 3
    assert not next(x for x in hooks if x['index'] == 189)['defined_in_shipped_default_pdk']
    off = handler.offset(0xA09DC, 8)
    pending_id, callback = struct.unpack_from('<II', handler.data, off)
    assert (pending_id, callback) == (5, 0x7C58C)
    raw_symbol = {'name': 'PendColdReset5', 'va': 0x7C58C, 'size': 0x88}
    native_row, disasm = reader.m.disassemble(handler, raw_symbol)
    (HERE/'native/handler/PendColdReset5.txt').write_text(disasm, encoding='utf8')
    assert '; reboot' in disasm and '0x1234567' in disasm and '0x4c4b40' in disasm
    before = (HERE/'native/pdk/PDK_BeforeBMCColdReset.txt').read_text()
    assert 'mov r0, #0' in before and 'bx lr' in before
    msg = (HERE/'native/handler/MsgHndlr.txt').read_text()
    assert '0001c968' in msg and '; Platform_ColdReset' in msg
    native = {'scope': 'Static original ELF instructions, data tables and relocations; no target execution.',
              'sources': [file_ref(base/'lib'/n) for n in ['libipmistack.so.13.13.12','libipmipdk.so.13.8.7','libipmimsghndlr.so.13.22.37']],
              'hook_table': {'elf_va': '0x34374', 'stride': 258, 'index_width': 2, 'name_bytes': 256,
                             'loader_function': 'InitPDKHooks 0xB30C',
                             'loader_store_instruction': '0xB3A8: store dlsym result at g_PDKHandle[index*4]',
                             'default_library': '/usr/local/lib/libipmipdk.so', 'selected_records': hooks,
                             'limitation': 'Default shipped library inspected. No live hook addresses or live native library hash obtained.'},
              'pending_id5': {'table': 'm_CorePendCmdHndlrTbl', 'entry_elf_va': '0xA09DC',
                              'callback_relocation_elf_va': '0xA09E0', 'id': pending_id,
                              'callback_elf_va': hex(callback), 'decoded': native_row},
              'selected_chain': [
                  'ColdReset 0x4788C sets per-instance g_BMCInfo+0x4E74B=1 and returns completion code zero.',
                  'MsgHndlr 0x1C65C..0x1C668 checks that flag; 0x1C95C..0x1C968 clears it and calls Platform_ColdReset.',
                  'Platform_ColdReset 0x7B54 calls inform_platform_reset (HostDisplayLock(0)), optional PDK_BeforeBMCColdReset, then PDK_ColdResetBMC.',
                  'Shipped PDK_BeforeBMCColdReset 0x91DC consists of mov r0,0; bx lr.',
                  'PDK_ColdResetBMC 0x99F8 queues pending ID5 if not already pending.',
                  'Pending ID5 handler 0x7C58C calls select_sleep(0,5000000), optional PDK_SetRebootCause(11,instance), then reboot(0x01234567).'],
              'reset_cause_hook': {'offset': '0x2F4', 'name': 'PDK_SetRebootCause',
                                   'calls': [{'elf_va':'0x478D8','reason':6},{'elf_va':'0x7C5B8','reason':11}],
                                   'shipped_default_export_absent': True,
                                   'statement': 'Do not confuse this optional hook with chassis power control.'},
              'excluded_paths': ['RestartBMC is an update-related restart helper, not the selected ordinary ColdReset path.',
                                 'Platform_HostColdReset/PDK_ResetChassis are separate functions; not the selected flag branch.']}
    write('native_reset_chain.json', native)
    op = HW/'operations/restart_manager08.mjs'
    op_pin = '44b652117f516d3c77c77c1769b57894d0af5e66f3c08a9fa3f2eec1d7841fbe'
    assert sha(op) == op_pin
    src = op.read_text(encoding='utf8')
    assert src.count('rf.client.post(') == 1
    assert "request:{ResetType:'ForceRestart'}" in src
    assert "globalThis.managerRestart08Attempted=true;" in src
    tests = REMOTE/'continuation08/restart_operation_tests.json'
    t = json.loads(tests.read_text())
    assert t['source']['sha256'] == op_pin and t['status'] == 'PASS' and len(t['cases']) == 11
    assert all(x['status'] == 'PASS' and x['posts'] <= 1 for x in t['cases'])
    for n in ['transport_ambiguous','success']:
        assert next(x for x in t['cases'] if x['name'] == n)['posts'] == 1
    (HERE/'reviewed_operation.mjs').write_bytes(op.read_bytes())
    write('operation_review.json', {
        'status': 'NO_BLOCKING_DEFECT_IDENTIFIED_IN_SCOPED_REVIEW', 'source': file_ref(op),
        'review_type': 'Independent source review and input/hash verification of parent mocked test report; tests not rerun here.',
        'parent_mock_tests': file_ref(tests), 'parent_mock_test_cases': 11,
        'verified_properties': [
            'Single fixed relative standard Manager.Reset endpoint; body contains only ResetType ForceRestart.',
            'Manager type/version, advertised exact target/ActionInfo and required allowable ResetType checked freshly.',
            'Before POST: host Off, BIOS1904, SD override Disabled/BootNext null, native power Off, expected media-idle sentinel and owned helper absent.',
            'Local intent is exclusively created before mutation; attempted latch set immediately before the sole POST.',
            'GET and POST use maxRetries0; transport ambiguity recorded without retry.',
            'Only 200/202/204 are accepted HTTP responses, explicitly not declared restart completion.',
            'Returned task Location is recorded only if matching the fixed local TaskService path pattern.',
            'No host-power, factory-reset, firmware-update, file-upload, shell or hidden-service request in operation source.'],
        'scope_limits': [
            'Owned client base URL/TLS/authentication correctness is established by parent session, not re-proven by this function.',
            'The in-memory attempted flag is a per-process guard; intent files support audit but are not a global cross-process lock. Parent must not rerun the mutation after a process reset.',
            'Expected active_sessions=128 is the observed idle sentinel; it is not a count of128 concurrent sessions.',
            'The operation checks SD Enabled and BootNext; Mode/Target/BootOrder/UUID/network preservation are readback requirements, not conditions enforced by this function.',
            'Checks and action are sequential remote requests and cannot provide an atomic guarantee against an unrelated operator.']})
    capability = HW/'manager-restart08-capability-1793700497217.json'
    uptime = HW/'browser-read-255.json'
    u = json.loads(uptime.read_text(encoding='utf-8-sig'))
    assert u['path'] == '/api/status/uptime' and u['status'] == 200
    assert u['data'] == {'minutes_per_count':60,'poh_counter_reading':111}
    geometry = REMOTE/'media_geometry_review06/geometry_review.json'
    geo_manifest = REMOTE/'media_geometry_review06/manifest.json'
    assert sha(geometry) == 'df07bf5c111f3c207b382c91196170df87baffc64500303b214ba6e4f99e698f'
    assert sha(geo_manifest) == '27fbd86cf9bb31f1f38c653cd0732d339e41a96cbb7dee10277c5aa64d0af71d'
    chain = REMOTE/'update_chain_review05/update_chain_review.json'
    chain_manifest = REMOTE/'update_chain_review05/evidence_manifest.json'
    assert sha(chain) == 'f77dd07ddf85309ab4eb2c4ad8ae4dbd2a0f258e00faa021685655b1f158822c'
    assert sha(chain_manifest) == '70f183d372c6afade794f1c81a4ebe14b5d74d20b3439b4d2d8fc195b54bde46'
    report = {
        'status': 'SUPPORTED_STANDARD_BMC_COLD_RESTART_PATH_CONFIRMED_STATICALLY',
        'scope': 'Offline source/bytecode/native review only. No BMC contact, restart, firmware upload/flash, configuration change or native target execution by this reviewer.',
        'hardware_completion': 'NOT_EVALUATED_IN_THIS_REPORT',
        'official_image': file_ref(REMOTE/'official_bmc/W7901157.ima'),
        'live_capability_read_by_parent': file_ref(capability),
        'request': {'method':'POST','target':'/redfish/v1/Managers/Self/Actions/Manager.Reset',
                    'minimal_json_body':{'ResetType':'ForceRestart'},
                    'allowable_values':['ForceRestart'],
                    'operation_apply_time':'Omit for immediate execution; Immediate is also implemented. Do not schedule this diagnostic restart.',
                    'not_offered':['GracefulRestart','WarmReset'],
                    'excluded_oem_action':'AMIManager.BMCReset is the separate factory-reset route; never substitute it.'},
        'evidence': {
            'action_info':['lua/actioninfo.asm.txt','lua/actioninfo.lua'],
            'request_validation':['lua/manager_metadata.asm.txt','lua/manager_metadata.lua'],
            'reset_dispatch':['lua/BMC.asm.txt','lua/BMC.lua'],
            'ipmi_packed_netfn_and_command':['lua/ipmi_general.asm.txt','lua/ipmi_general.lua'],
            'native':'native_reset_chain.json','operation':'operation_review.json',
            'decoder_caution':'Lua files are static decompiler pseudo-code and may contain invalid or undefined slot syntax. Critical constants/branches/argument calls were cross-checked against saved original LuaJIT instruction listing; no decompiled script was executed.'},
        'actual_dispatch': {'cold_reset':{'packed_netfn_lun':'0x18','netfn':'0x06','command':'0x02','request_data_bytes':0},
                            'warm_reset_helper_only':{'packed_netfn_lun':'0x18','command':'0x03'},
                            'factory_reset_separate':{'packed_netfn_lun':'0xC8','command':'0x66'},
                            'terminal_native_call':'reboot(0x01234567) from pending ID5; normal BMC Linux restart'},
        'effects_found': [
            'Redfish manager reset action key consumed; audit event created.',
            'SSE subscription keys removed and Redis BGSAVE requested before BMC ColdReset.',
            'BMC cold-reset flag is set and consumed; display-lock helper called; pending restart queued.',
            'BMC services, authenticated connections, virtual media and volatile driver/cache state can be interrupted/recreated during restart.',
            'These are real BMC state effects; this is not a zero-write or configuration-immutable operation.'],
        'effects_not_found_in_selected_path': [
            'No factory/default configuration restore or network-settings erase call.',
            'No chassis power on/off/reset command in selected ColdReset chain.',
            'No BIOS/BMC firmware update, image upload, SPI ownership transition or flash erase/program request.'],
        'limits_on_host_and_network_claims': [
            'A supported BMC-only cold restart is distinct from a host restart, but static selected-path review cannot guarantee all board-level reboot behavior or configuration health.',
            'Live backend ELF hashes and optional hook pointers are not available; exact frontend binding and parent live version/action advertisement corroborate the pinned official implementation.',
            'After reboot, require fresh native and Redfish host Off readback, same Manager identity/version, network reachability/configuration, boot settings/order and media state. Failure to read back is incomplete, not a success.',
            'Existing KVM/media sessions will not be assumed reusable; parent must reconnect deliberately.'] ,
        'completion_evidence': {
            'task_completed_not_sufficient':'ResetManager marks an existing task Completed before calling doBMCColdReset; the actual operation can still fail or be interrupted.',
            'http_response_not_sufficient':'200/202/204 or transport closure shows request handling/delivery uncertainty, not reboot completion.',
            'supported_uptime_candidate_rejected':{'frontend_url':'/api/status/uptime','parent_readback':file_ref(uptime),
                                                   'observed_fields':u['data'],
                                                   'reason':'POH counter in60-minute units is not established BMC boot uptime; do not expect zero/decrease or use it to prove manager reset.'},
            'reliable_boot_counter_api':'Not established by this bounded review; do not invent one.',
            'bounded_readback_plan':[
                'Observe authenticated action result/transport and independent read-only pinned-identity HTTPS down/up if visible.',
                'Establish a fresh connection after services return; re-read Manager/Self identity/version/status and native chassis status.',
                'Re-read Systems/Self and SD boot state/order, manager network settings and virtual-media state; compare with saved baseline.',
                'If no outage is observed, retain that limitation rather than infer reboot from task completion alone.',
                'Do not retry the restart POST when response delivery is ambiguous.']},
        'geometry_experiment': {
            'frozen_input_evidence':file_ref(geometry),
            'meaningful':True,
            'basis':'Original native/kernel evidence permits stale opened-LUN metadata while later NBD capacity changes. A BMC kernel restart recreates volatile gadget/NBD state and can test that class of explanation using the identical client/image/ISO.',
            'controlled_inputs':['Same pristine16MiB image and digest','Same helper04 wire capacity response00007fff00000200','Same frozen Linux capacity ISO and device identity/UA handling'],
            'positive_result':'If host now reports expected32768blocks of512bytes, supports an earlier BMC/session/cache-state influence; does not identify the exact stale object or prove all writeback safe.',
            'unchanged_result':'If raw0004000000000400 persists, restart did not resolve the mismatch; deterministic firmware/protocol/configuration causes remain. It does not prove cache was never involved.',
            'no_hidden_change':'No BMC defaults, service shell, sysfs manipulation, arbitrary ioctls or firmware updates needed for this controlled reset test.',
            'writeback_gate':'Continue to reject file writes while actual geometry differs; restart alone does not establish storage correctness.'},
        'frozen_prior_reports_unchanged':[file_ref(geometry),file_ref(geo_manifest),file_ref(chain),file_ref(chain_manifest)]}
    write('restart_review.json', report)
    entries=[]
    for p in sorted(HERE.rglob('*')):
        if not p.is_file() or p.name=='manifest.json' or '__pycache__' in p.parts: continue
        entries.append({'path':str(p.relative_to(HERE)), 'bytes':p.stat().st_size,'sha256':sha(p)})
    write('manifest.json',{'scope':'New isolated BMC restart static review; no credentials, live sessions or target execution.','files':entries})
    print(json.dumps({'report':file_ref(HERE/'restart_review.json'),'manifest':file_ref(HERE/'manifest.json'),'artifacts':len(entries)},indent=2))

if __name__ == '__main__': main()
