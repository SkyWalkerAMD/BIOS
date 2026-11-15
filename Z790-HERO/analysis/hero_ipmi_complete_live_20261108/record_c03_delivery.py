"""Reconcile completed runtime evidence and the locally verified field package."""
from pathlib import Path
from datetime import datetime, timezone
import hashlib
import json

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
RELEASE = ROOT/'analysis/hero_ipmi_rc5_s21s_20261108'
CAP_SHA = '7a21f28c5a805ea29d651524b2ec2e05925252ff0799b71251583d99e1d53624'
ZIP_SHA = 'f1b5e247609219e9626c1c6777c972bd6e0758241904a9d786ce53d7f68d9a8e'
pins = {
    'analysis/hero_p6_s21s_independent_review_20261108/hardware-verification.json':'7133485ca073e689322ca48b2af887e4fc0ed7b7f8353212e224dcf0f1f1c591',
    'analysis/hero_rc5_r4_s21s_independent_review_20261108/final-review.json':'a79ff878194b87f5272517b3c3262f4d8a41efa968a6ad4dcaada1bd5f932e4c',
    'analysis/hero15_ipmi_validation_20261108/two-host-comparison.json':'0adf0fb57a147873508be09c25f3b16afc0c0db6110d537e6a8bca08f17af038',
    'analysis/hero_rc5_r4_s21s_independent_review_20261108/delivery-review.json':'734e9fbbe96842025284ae417e388af05020a5189d0fe1395435be8ff3874eaf',
}
for path, expected in pins.items():
    if hashlib.sha256((ROOT/path).read_bytes()).hexdigest() != expected:
        raise ValueError('Changed evidence: '+path)
delivery = json.loads((RELEASE/'delivery/DELIVERY.json').read_text(encoding='utf-8'))
if delivery['cap_sha256'] != CAP_SHA or delivery['sha256'] != ZIP_SHA or delivery['native_flash_performed']:
    raise ValueError('Unexpected delivery identity or scope')
zip_path=Path(delivery['package'])
if not zip_path.resolve().is_relative_to(RELEASE.resolve()) or hashlib.sha256(zip_path.read_bytes()).hexdigest()!=ZIP_SHA:
    raise ValueError('Packaged ZIP changed')
state_file=HERE/'verification-state.json'
s=json.loads(state_file.read_text(encoding='utf-8'))
prior=s['delivery']
if prior['candidate'] not in ('RC5-IPMI-ONLY-R4-S21R-CANDIDATE02','RC5-IPMI-ONLY-R4-S21S-CANDIDATE03'):
    raise ValueError('State moved past this reconciliation')
if prior['candidate']=='RC5-IPMI-ONLY-R4-S21R-CANDIDATE02':
    s['historical_withheld_delivery']=prior
elif prior['sha256']!=CAP_SHA:
    raise ValueError('Unexpected Candidate03 core changed')
s['verified'].update({
    's21s_exact_pe_sha256':'401a61dbf60f128a1f0aba86462aa90ce6e69a95f4266c64876072a841672b66',
    's21s_ram_real_afterboot_native_menu':True,
    's21s_repeated_real_afterboot_no_replay':True,
    's21s_standard_get_count':28,
    's21s_no_bmc_configuration_writes_in_real_test':True,
    's21s_original_21_byte_settings_preserved':True,
    's21s_state_absent_all_snapshots':True,
    's21s_same_boot_centos_login_confirmed':True,
    's21s_virtual_media_unmounted':True,
    'private_test_browser_closed':True,
    'server_logout_not_confirmed':True,
    'native_current_bmc_fields':'At 08:06–08:07, exact RAM S21S real AfterBoot displayed BMC identity/watchdog/LAN/SEL correctly; final CAP not flashed',
    'native_automatic_refresh_verified':False,
    'native_first_setupenter_verified':False,
    'native_f10_settings_application_verified':False,
    'last_observed_normal_sensors':20,
    'last_observed_cha1_rpm':3120,
    'psu2_discrete_alarm_remains':True,
})
s['delivery']={
    'candidate':'RC5-IPMI-ONLY-R4-S21S-CANDIDATE03','sha256':CAP_SHA,
    'status':'PACKAGED_FIELD_CANDIDATE; exact RAM drivers verified, native flash acceptance and first SetupEnter pending',
    'package':str(zip_path.relative_to(ROOT)).replace('\\','/'),'package_sha256':ZIP_SHA,
    'files':delivery['files'],'all_zip_members_read_back_equal':True,
    'independent_delivery_content_review_passed':True,
    'flash_performed':False,'first_native_setupenter_verified':False,
    'F10_configuration_writes_verified':False,'official_restore_verified':False,
    'old_candidate02_stays_withheld':True,
}
s['pending']=[
    'Onsite exact Candidate03 FlashBack acceptance and native DXE/first SetupEnter cold boot',
    'Native F10 save/reboot/BMC readback for LAN, watchdog and SEL configurations',
    'Official3107 recovery from exact Candidate03',
    'Further fan channels and Creator parity remain outside this validated scope',
]
s['last_reconciled_utc']=datetime.now(timezone.utc).isoformat()
for path,digest in pins.items():
    relative='../'+path.removeprefix('analysis/')
    s['evidence']=[e for e in s['evidence'] if e['path']!=relative]
    s['evidence'].append({'path':relative,'sha256':digest})
state_file.write_text(json.dumps(s,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
print(json.dumps({'state':str(state_file),'sha256':hashlib.sha256(state_file.read_bytes()).hexdigest(),
                  'field_candidate_packaged':True,'native_flash_performed':False},ensure_ascii=False))
