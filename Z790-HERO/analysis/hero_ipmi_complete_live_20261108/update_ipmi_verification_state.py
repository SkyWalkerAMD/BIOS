"""Reconcile saved evidence only; never accesses BMC or firmware services."""
from pathlib import Path
import hashlib
import json

HERE = Path(__file__).resolve().parent
file = HERE / 'verification-state.json'
state = json.loads(file.read_text(encoding='utf-8'))
pins = {
    'r4-fresh-hardware-verification.json': 'd0f967170dd055300647d6813d4e7004890176da85aa9e06dd77cf4e7c708600',
    'p6s21r-ram-failure.json': '17c325a1907decf9022ddba0f1b2909313631dee56dcf1794530388fd82245dc',
}
for name, expected in pins.items():
    data = (HERE / name).read_bytes()
    if hashlib.sha256(data).hexdigest() != expected:
        raise ValueError('Evidence hash mismatch: ' + name)
    json.loads(data)

state['last_reconciled_utc'] = '2026-11-08T07:20:00Z'
state['active_scope'] = 'IPMI BMC status, sensors and native settings; PCIe/storage/inventory paused'
state['verified'].update({
    'r4_pe_sha256': 'a3036261c18bd66b158844a6818cf828b54af002dbb9ecf45d8dbc97a5317b2f',
    'r4_ram_actual_ready_to_boot_fresh_bmc': True,
    'r4_ram_actual_ready_to_boot_warm': True,
    'r4_fresh_target_sdr_before': 0,
    'r4_fresh_target_sdr_after': 16,
    'r4_initial_target_readable_count': 5,
    'r4_settled_web_normal_sensor_count': 20,
    'r4_cha1_samples_rpm': [2640, 2640, 2640],
    'r4_warm_query_count_no_configuration_sets': 127,
    'r4_config_map_before_sensor_enable': True,
    'native_current_bmc_fields': 'Not queried; verified again after host reset at 07:14',
    'p6_s21r_ram_load': True,
    'p6_s21r_return_to_setup': False,
    'p6_s21r_native_bmc_display': False,
    'host_recovered_after_s21r_test': True,
})
state['delivery'] = {
    'candidate': 'RC5-IPMI-ONLY-R4-S21R-CANDIDATE02',
    'sha256': 'a10c22412e0f1388915b14c3c297121cc9d9b976ce10143652b4b15b9cc4f5c1',
    'status': 'WITHHELD: exact P6 RAM core failed return-to-Setup validation',
    'flash_performed': False,
    'old_candidate01_is_not_a_validated_fallback': True,
}
state['pending'] = [
    'Isolate and fix native BMC query/publish path; separate application-stage diagnostics first',
    'Prove actual native BMC status rendering and responsive return',
    'Rebuild and independently review final IPMI-only CAP only after runtime fix',
    'Onsite native FlashBack/boot/config-save validation',
]
known = {e['path'] for e in state.get('evidence', [])}
for name, sha in pins.items():
    if name not in known:
        state.setdefault('evidence', []).append({'path': name, 'sha256': sha})
file.write_text(json.dumps(state, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
print(json.dumps({'path': str(file), 'sha256': hashlib.sha256(file.read_bytes()).hexdigest()}))
