"""Reconcile independently checked A1 evidence; no device access."""
from pathlib import Path
import hashlib
import json

HERE = Path(__file__).resolve().parent
EVIDENCE = HERE.parent / 'hero_p6_afterboot_hang_review_20261108/a1-hardware-independent.json'
EXPECTED = 'aa38cafcbd76534afe3a2b800eaa8964a53eec51b1e811d977fe7994b1606f1b'
raw = EVIDENCE.read_bytes()
if hashlib.sha256(raw).hexdigest() != EXPECTED:
    raise ValueError('Independent A1 evidence changed; re-review before reconciliation')
e = json.loads(raw)
if not e['passed_for_captured_stages'] or len(e['latest_completed_stages']) != 4:
    raise ValueError('Not all explicit application stages passed')
if e['native_automatic_refresh_verified'] or e['configuration_setters_verified']:
    raise ValueError('Unexpected evidence scope')
if len(e['native_menu_after_explicit_app_publication']) != 6:
    raise ValueError('Missing native menu visual evidence')
for item in e['photos']:
    path = HERE.parents[1] / item['path']
    data = path.read_bytes()
    if len(data) != item['bytes'] or hashlib.sha256(data).hexdigest() != item['sha256']:
        raise ValueError('Changed screenshot: ' + str(path))

p = HERE / 'verification-state.json'
s = json.loads(p.read_text(encoding='utf-8'))
if s['native_flash_performed_this_run'] or s['delivery']['candidate'] != 'RC5-IPMI-ONLY-R4-S21R-CANDIDATE02':
    raise ValueError('State moved past this reconciliation; do not overwrite newer work')
last = e['rows'][-1]
s['verified'].update({
    'a1_explicit_application_stages': e['latest_completed_stages'],
    'a1_native_menu_after_application_publication': True,
    'a1_standard_get_count': last['standard_get_count'],
    'a1_hii_set_count': last['hii_calls']['HII_SET_STRING']['after'],
    'a1_return_to_setup_and_navigation': True,
    'a1_settings_width_preserved': last['settings_bytes'],
    'a1_state_absent_all_snapshots': last['state_absent_all_snapshots'],
    'native_current_bmc_fields': 'Real BMC values displayed after A1 explicit RAM publication at 07:48–07:54; not native automatic refresh',
    'sel_entries_current': int(last['display_values']['13']),
    'native_automatic_refresh_verified': False,
    'native_f10_settings_application_verified': False,
})
s['pending'] = [
    'Validate synchronous AfterBoot hypothesis using exact new resident PE in RAM',
    'Resolve and verify early native SetupEnter path; A1 application pass does not cover it',
    'Rebuild and independently review final IPMI-only CAP only after runtime validation',
    'Onsite native FlashBack/boot/config-save validation',
]
s['last_reconciled_utc'] = '2026-11-08T07:59:00Z'
relative = '../hero_p6_afterboot_hang_review_20261108/a1-hardware-independent.json'
s['evidence'] = [item for item in s['evidence'] if item['path'] != relative]
s['evidence'].append({'path': relative, 'sha256': EXPECTED})
p.write_text(json.dumps(s, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
print(json.dumps({'path': str(p), 'sha256': hashlib.sha256(p.read_bytes()).hexdigest()}))
