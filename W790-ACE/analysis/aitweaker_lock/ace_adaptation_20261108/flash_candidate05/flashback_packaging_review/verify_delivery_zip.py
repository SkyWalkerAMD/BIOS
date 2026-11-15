"""Independent complete ZIP/manifest/sums check; does not rebuild or extract."""
import ast
import hashlib
import json
from pathlib import Path
import re
import sys
import zipfile

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
FC = HERE.parent
ROOT = next(p for p in HERE.parents if (p / 'tools/pydeps').is_dir())
DELIVERY = FC / 'flashback_delivery'
ARCHIVE = DELIVERY / 'W790-ACE-1904-AI-TWEAKER-C05-FLASHBACK-ONLY.zip'
ZIP_SHA = 'ee3157797f71453690da4d9ef704b9925d131a8d878e3afffbbcc274ce36ee1b'
BUILDER_SHA = 'ac48c260f22793e6e9e17aa29cc93f2627a292fefef7b8683c675b168f632da4'
CANDIDATE = '01-CANDIDATE05-USB/PWW790A.CAP'
RECOVERY = '02-OFFICIAL1904-RECOVERY/PWW790A.CAP'
EXPECTED_NAMES = {
    CANDIDATE, RECOVERY, '03-EVIDENCE/flashback-selection-review.json',
    '03-EVIDENCE/format-and-name-review.json', '03-EVIDENCE/official-instruction-sources.json',
    '03-EVIDENCE/validation-summary.json', 'POSTFLASH-CHECKS.txt', 'README-USB-FlashBack.txt',
    'Verify-Package.ps1', 'manifest.json', 'SHA256SUMS.txt',
}
CHECKS = []


def sha(data):
    return hashlib.sha256(data).hexdigest()


def check(condition, label):
    if not condition:
        raise ValueError(label)
    CHECKS.append(label)


def record(path):
    return {'path': path.relative_to(ROOT).as_posix(), 'bytes': path.stat().st_size, 'sha256': sha(path.read_bytes())}


archive_bytes = ARCHIVE.read_bytes()
check(len(archive_bytes) == 31218704 and sha(archive_bytes) == ZIP_SHA, 'fixed final archive size and SHA256')
with zipfile.ZipFile(ARCHIVE) as archive:
    names = archive.namelist()
    check(set(names) == EXPECTED_NAMES and len(names) == len(EXPECTED_NAMES), 'exactly eleven approved unique members')
    # zipfile.read also checks each member CRC, including the two full CAPs.
    members = {name: archive.read(name) for name in names}
rows = [{'path': name, 'bytes': len(members[name]), 'sha256': sha(members[name])} for name in sorted(names)]
manifest = json.loads(members['manifest.json'])
check(manifest['schema'] == 'ace1904_flashback_field_package_v1', 'manifest schema')
check(manifest['status'] == 'PREPARED_FOR_PHYSICAL_USB_FLASHBACK_FIELD_VALIDATION', 'manifest status remains preparation only')
listed = {entry['path']: entry for entry in manifest['files']}
check(len(listed) == len(manifest['files']) == 9, 'manifest contains nine unique content files')
check(set(listed) == EXPECTED_NAMES - {'manifest.json', 'SHA256SUMS.txt'}, 'manifest coverage exact, no missing content files')
for name, entry in listed.items():
    check(entry['bytes'] == len(members[name]) and entry['sha256'] == sha(members[name]), 'manifest length/hash: ' + name)
sum_rows = [re.fullmatch(r'([0-9a-f]{64})  (.+)', line) for line in members['SHA256SUMS.txt'].decode('ascii').splitlines()]
check(all(sum_rows), 'SHA256SUMS format')
hashes = {match.group(2): match.group(1) for match in sum_rows}
check(len(hashes) == len(sum_rows) == 10, 'SHA256SUMS ten unique entries')
check(set(hashes) == EXPECTED_NAMES - {'SHA256SUMS.txt'}, 'SHA256SUMS covers manifest and all content without self-reference')
for name, expected in hashes.items():
    check(sha(members[name]) == expected, 'SHA256SUMS identity: ' + name)
package = DELIVERY / 'package'
unpacked = {p.relative_to(package).as_posix(): p for p in package.rglob('*') if p.is_file()}
check(set(unpacked) == EXPECTED_NAMES, 'unpacked package contains same exact files')
for name, path in unpacked.items():
    check(path.read_bytes() == members[name], 'unpacked/ZIP byte equality: ' + name)
builder_bytes = (DELIVERY / 'build_package.py').read_bytes()
check(sha(builder_bytes) == BUILDER_SHA, 'reviewed builder unchanged')
tree = ast.parse(builder_bytes)
literals = {node.targets[0].id: ast.literal_eval(node.value) for node in tree.body
            if isinstance(node, ast.Assign) and isinstance(node.targets[0], ast.Name) and node.targets[0].id in {'VERIFY', 'README', 'POSTFLASH'}}
for literal, name, encoding in [('VERIFY', 'Verify-Package.ps1', 'ascii'), ('README', 'README-USB-FlashBack.txt', 'utf8'), ('POSTFLASH', 'POSTFLASH-CHECKS.txt', 'utf8')]:
    check(literals[literal].encode(encoding) == members[name], 'reviewed builder literal matches packaged ' + name)
identity = json.loads((HERE / 'final_package_identity.json').read_text('utf8'))
check(identity['container']['sha256'] == ZIP_SHA and identity['status'] == 'PASS_FILE_IDENTITY_ONLY', 'independent CAP identity report binds this actual ZIP')
check([row['sha256'] for row in identity['capsules']] == [manifest['candidate_CAP_sha256'], manifest['official_CAP_sha256']], 'candidate/recovery CAP roles match independent file validation')
check(members[CANDIDATE][:4096] == members[RECOVERY][:4096], 'complete original 4096-byte CAP header retained')
check(manifest['candidate_file'] == CANDIDATE and manifest['official_recovery_file'] == RECOVERY, 'selected and recovery paths explicit and separate')
check(manifest['full_CAP_bytes'] == 67112960 and manifest['header_bytes'] == 4096, 'manifest full CAP dimensions')
for field in ['modified_payload_OEM_signature_valid', 'engineering_resigned_CAP_included', 'hardware_flashback_acceptance_verified',
              'permanent_DXE_native_password_UI_verified', 'firmware_flash_performed', 'complete_current_SPI_backup_included']:
    check(manifest[field] is False, 'accurate unproven boundary: ' + field)
check(sha(members['03-EVIDENCE/flashback-selection-review.json']) == '8079150cd4f641c241563b4eac35c519671ee6bf7c1659231f042adc1803b997', 'final REA selection report exact')
check(sha(members['03-EVIDENCE/format-and-name-review.json']) == '90afbaeda71ec23188f4778c9c6e4ad2b986bc7722342dd2443929c57642db36', 'independent Renamer/static format evidence exact')
check(sha(members['03-EVIDENCE/official-instruction-sources.json']) == '19108fdd37d909a619ad000e9dfc392cd24c18a9f12c1ad1b7aedce4b6eea991', 'official procedure evidence exact')
receipt = json.loads((DELIVERY / 'build-receipt.json').read_text('utf8'))
check(receipt['sha256'] == ZIP_SHA and receipt['bytes'] == len(archive_bytes) and receipt['files'] == 11 and receipt['builder_sha256'] == BUILDER_SHA, 'build receipt binds actual archive and builder')
check((DELIVERY / (ARCHIVE.name + '.sha256')).read_text('ascii') == ZIP_SHA + '  ' + ARCHIVE.name + '\n', 'external archive checksum text exact')
old_zip = ROOT / 'analysis/aitweaker_lock/ace_adaptation_20261108/flash_candidate05/delivery_review/archives/W790-ACE-1904-AI-TWEAKER-CANDIDATE05-ENGINEERING.zip'
check(sha(old_zip.read_bytes()) == 'd285cbd90fce3d66d683932a1e7c31fba47cf803eeb212fa2ab5acf746d87304', 'old engineering ZIP remains byte-identical')
nv_path = FC / 'nv_persistence_review/independent_review/hardware_nv_summary.json'
nv_data = nv_path.read_bytes()
nv = json.loads(nv_data)
summary = json.loads(members['03-EVIDENCE/validation-summary.json'])
check(summary['hardware_nv_summary_sha256'] == sha(nv_data) == 'f797d759e331e7343f65c1c727c0b096eb04cbe19a891f546bca0ebde9372040' and nv['status'] == 'PASS' and all(nv['observations'].values()) and nv['ac_power_removed'] is False, 'isolation/NVRAM summary binds actual Off/On evidence without AC-loss claim')
layout = json.loads((FC / 'lock_1904_candidate05/lab/asus_review/W790-ACE-1904-lock.review.json').read_text('utf8'))
check(layout['original_inner_ffs_count_unchanged'] == 423 and layout['original_inner_ffs_offsets_preserved'] and layout['original_inner_ffs_bytes_preserved'], '423 inner original FFS preservation statement matches actual builder report')
report = {
    'schema': 'ace1904_flashback_final_package_review_v1', 'status': 'PASS_FILE_PACKAGE_AND_DOCUMENTS_ONLY',
    'archive': record(ARCHIVE), 'builder': record(DELIVERY / 'build_package.py'), 'check_count': len(CHECKS), 'checks': CHECKS,
    'members': rows, 'manifest_entries_verified': len(listed), 'SHA256SUMS_entries_verified': len(hashes), 'all_member_CRCs_verified': True,
    'independent_CAP_identity_report': record(HERE / 'final_package_identity.json'),
    'windows_verifier_execution': {
        'tool_chunk': 'f80af4', 'host': 'Actual Windows PowerShell5.1.26100.9711', 'exit_code': 0,
        'script_member_sha256': sha(members['Verify-Package.ps1']),
        'invocation': 'powershell.exe -NoProfile -ExecutionPolicy Bypass -File <unpacked-package>/Verify-Package.ps1',
        'stdout': 'PASS: 9 manifest files and both exact CAP identities verified.\nFile verification is complete. Physical FlashBack acceptance and post-flash boot are not yet tested.',
        'execution_count_on_actual_package': 1, 'no_Codex_or_Python_dependency_for_end_user': True,
    },
    'Windows_PS51_parser_and_negative_fixture': record(HERE / 'builder_review.json'),
    'document_review': {
        'README_manually_read': True, 'POSTFLASH_CHECKS_manually_read': True,
        'consistent_selected_file_and_full_CAP': True, 'separate_official_recovery': True,
        'proper_FlashBack_port_manual_reference_and_LED_boundaries': True,
        'contains_working_process_scoped_PowerShell_command': True,
        'same_version_is_not_feature_acceptance': True,
        'native_UI_full_flash_and_recovery_not_misrepresented_as_completed': True,
    },
    'inputs_or_package_modified_by_this_review': False, 'builder_executed_by_this_review': False,
    'core_tests_repeated': False, 'network_or_hardware_access': False,
    'hardware_acceptance_not_proven': ['USB FlashBack controller acceptance', 'physical write completion', 'permanent DXE/native Setup password behavior', 'complete current-unit SPI recovery'],
    'FLASH_READY': False,
}
output = HERE / 'final_delivery_review.json'
output.write_text(json.dumps(report, indent=2, ensure_ascii=False) + '\n', encoding='utf8')
print(json.dumps({'status': report['status'], 'checks': len(CHECKS), 'files': len(rows), 'zip_sha256': ZIP_SHA, 'review_sha256': sha(output.read_bytes())}))
