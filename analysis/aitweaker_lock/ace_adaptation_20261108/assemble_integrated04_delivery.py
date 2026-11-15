"""Fail-closed, local-only INTEGRATED04 evidence packaging.

Use --write-template once to describe the final validation index. The parent
freezes that index and the hardware evidence index after collecting results.
--check-only verifies every dependency without creating a report or archive.
--check-pending verifies local candidate inputs while leaving both freeze gates
untouched; a finalized RAM hardware addendum is checked when present, but the
in-progress overall hardware collection is not inspected and no output is made.
No networking, process launch, firmware mutation or automatic rebuilding occurs.
"""
from pathlib import Path
import argparse
import datetime
import hashlib
import json
import re
import sys
import zipfile

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
ROOT = next(p for p in HERE.parents if (p/'tools/pydeps').is_dir())
CASE = HERE/'lock_1904_integrated04'
BUILD = CASE/'driver/build'
SHA = re.compile(r'^[0-9a-f]{64}$')
REQUIRED_ROLES = {'core', 'adapter', 'history', 'policy', 'entropy', 'hii_abi',
                  'owner', 'discovery', 'ebs', 'entry', 'save', 'ovmf'}
FORBIDDEN_PARTS = {'__pycache__', 'runtime-temp', '.zig-global', '.zig-local',
                   'operations', 'sessions', 'session', 'credentials', '.git',
                   'ghidra', 'ghidra-project', 'node_modules'}
FORBIDDEN_NAME = re.compile(r'(?i)(?:^|[._-])(?:cookie|cookies|token|secret|credential|session|process|pid|endpoint)(?:[._-]|$)')
SECRET_TEXT = re.compile(r'(?i)(?:\bBearer\s+[A-Za-z0-9._~+/-]{24,}|\bBasic\s+[A-Za-z0-9+/]{16,}={0,2}|-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----)')
HASH_MAP_KEYS = {'sources', 'source_sha256', 'compiled_source_sha256', 'external_source_sha256',
                 'external_sources', 'verification_source_sha256', 'verification_inputs',
                 'driver_source_sha256', 'driver_external_source_sha256', 'input_files',
                 'source_and_fixture_sha256', 'identities', 'test_sources'}
SCALAR_INPUT_HASHES = {'build_manifest_sha256', 'driver_build_manifest_sha256', 'linker_map_sha256',
                       'driver_map_sha256', 'fixture_sha256', 'firmware_sha256', 'services_obj_sha256',
                       'verification_source_sha256', 'test_source_sha256', 'source_ifr_sha256',
                       'amitse_sha256', 'original_amitse_sha256', 'original_setup_sha256',
                       'baseline_driver_sha256', 'baseline_efi_sha256', 'entry_source_sha256',
                       'script_sha256', 'fixture_source_sha256', 'map_sha256',
                       'source_capsule_sha256', 'original_builder_sha256', 'exact_builder_input_sha256',
                       'independent_uefiextract_full_decoded_sha256'}
MAX_FILE = 128*1024*1024
MAX_PACKAGE = 512*1024*1024


class DeliveryError(RuntimeError):
    pass


def require(value, message):
    if not value:
        raise DeliveryError(message)


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def workspace_path(value, base=ROOT, must_exist=True):
    require(isinstance(value, (str, Path)), 'file reference must be a path')
    path = Path(value)
    if not path.is_absolute():
        path = base/path
    path = path.resolve()
    require(path.is_relative_to(ROOT.resolve()), 'file reference escapes workspace')
    if must_exist:
        require(path.is_file(), 'required file missing: '+str(path.relative_to(ROOT)))
    return path


def relative(path):
    return path.relative_to(ROOT).as_posix()


def package_safe(path):
    parts = [part.lower() for part in path.relative_to(ROOT).parts]
    require(not set(parts) & FORBIDDEN_PARTS, 'excluded directory: '+relative(path))
    require(not FORBIDDEN_NAME.search(path.name), 'excluded process/session/credential artifact: '+relative(path))
    require(path.suffix.lower() not in {'.fd', '.img', '.obj', '.pyc', '.gpr', '.rep', '.mjs'},
            'excluded intermediate/runtime artifact: '+relative(path))
    require(path.stat().st_size <= MAX_FILE, 'artifact exceeds individual size bound: '+relative(path))


def scan_public_text(path):
    if path.suffix.lower() not in {'.json', '.txt', '.log', '.py', '.c', '.h', '.diff', '.tsv', '.md', '.frame'}:
        return
    raw = path.read_text(encoding='utf8')
    require(not SECRET_TEXT.search(raw), 'credential-like content in selected artifact: '+relative(path))
    if path.suffix.lower() == '.json':
        def walk(value):
            if isinstance(value, dict):
                for key, child in value.items():
                    normalized = re.sub(r'[-_]', '', key.lower())
                    if normalized in {'authorization', 'xauthtoken', 'cookie', 'setcookie', 'password', 'secret', 'sessionid', 'accesstoken', 'refreshtoken'}:
                        require(not isinstance(child, str) or child.lower() in {'', 'redacted', '[redacted]', 'none'},
                                'secret/session field in selected JSON: '+relative(path))
                    walk(child)
            elif isinstance(value, list):
                for child in value:
                    walk(child)
        walk(json.loads(raw))


class Evidence:
    def __init__(self):
        self.inputs = {}
        self.selected = set()
        self.derived_hashes = set()

    def bind(self, value, expected=None, base=ROOT, include=False):
        path = workspace_path(value, base)
        actual = digest(path)
        if expected is not None:
            require(isinstance(expected, str) and SHA.fullmatch(expected), 'invalid SHA256 for '+relative(path))
            require(actual == expected, 'hash mismatch: '+relative(path))
        require(path not in self.inputs or self.inputs[path] == actual, 'input changed during validation: '+relative(path))
        self.inputs[path] = actual
        if include:
            package_safe(path)
            scan_public_text(path)
            self.selected.add(path)
        return path

    def read(self, value, expected=None, base=ROOT, include=False):
        path = self.bind(value, expected, base, include)
        return json.loads(path.read_text(encoding='utf8'))

    def reference(self, value, base=ROOT, include=True):
        require(isinstance(value, dict) and {'path', 'sha256'} <= set(value), 'expected path/sha256 reference')
        return self.bind(value['path'], value['sha256'], base, include)

    def unchanged(self):
        for path, expected in self.inputs.items():
            require(path.is_file() and digest(path) == expected, 'input changed before publication: '+relative(path))


def verify_map(evidence, mapping, bases):
    require(isinstance(mapping, dict) and mapping, 'empty or invalid input hash map')
    for name, expected in mapping.items():
        require(isinstance(expected, str) and SHA.fullmatch(expected), 'invalid input hash in map')
        possibilities = set()
        for base in bases:
            path = workspace_path(name, base, must_exist=False)
            if path.is_file():
                possibilities.add(path)
        matches = [p for p in possibilities if digest(p) == expected]
        require(matches, 'mapped input missing or changed: '+str(name))
        for path in matches:
            evidence.bind(path, expected)


def embedded_bindings(evidence, value, bases):
    """Verify path-bearing hashes actually present in a validation summary."""
    if isinstance(value, dict):
        for name, child in value.items():
            if name in HASH_MAP_KEYS and isinstance(child, dict) and child and all(isinstance(h, str) and SHA.fullmatch(h) for h in child.values()):
                path_keys = {p: h for p, h in child.items() if Path(p).suffix or '/' in p or '\\' in p}
                if path_keys:
                    verify_map(evidence, path_keys, bases)
        for path_key, hash_key in [('path', 'sha256'), ('file', 'sha256'), ('report', 'report_sha256'),
                                   ('response', 'response_sha256'), ('source', 'source_sha256')]:
            if isinstance(value.get(path_key), str) and isinstance(value.get(hash_key), str) and SHA.fullmatch(value[hash_key]):
                verify_map(evidence, {value[path_key]: value[hash_key]}, bases)
        for child in value.values():
            embedded_bindings(evidence, child, bases)
    elif isinstance(value, list):
        for child in value:
            embedded_bindings(evidence, child, bases)


def dotted(value, field):
    for part in field.split('.'):
        require(isinstance(value, dict) and part in value, 'missing report binding field: '+field)
        value = value[part]
    return value


def scalar_input_bindings(evidence, value):
    if isinstance(value, dict):
        for key, child in value.items():
            if key in SCALAR_INPUT_HASHES and isinstance(child, str) and SHA.fullmatch(child):
                require(child in evidence.inputs.values() or child in evidence.derived_hashes,
                        'report input hash lacks a checked file/byte range in input_files: '+key)
            scalar_input_bindings(evidence, child)
    elif isinstance(value, list):
        for child in value:
            scalar_input_bindings(evidence, child)


def passed(report):
    return report.get('passed') is True or report.get('all_passed') is True or str(report.get('status', '')).startswith('PASS')


def verify_final_build(evidence, expected):
    require(SHA.fullmatch(expected), 'expected driver SHA256 must be the frozen 64-character lowercase digest')
    build = evidence.read(BUILD/'build.json', include=True)
    require(build['revision'] == 'ACE1904_INTEGRATED04', 'build revision is not INTEGRATED04')
    require(build['efi_sha256'] == expected, 'build manifest is not the requested final candidate')
    evidence.bind(BUILD/'AiTweakerLock1904.efi', expected, include=True)
    evidence.bind(BUILD/'driver.map', include=True)
    verify_map(evidence, build['sources'], [CASE])
    verify_map(evidence, build['external_sources'], [ROOT])
    return build


def verify_regressions(evidence, index, expected, require_frozen=True):
    require(index.get('driver_sha256') == expected, 'final validation index belongs to another candidate')
    require(index.get('frozen') is (True if require_frozen else False),
            'final validation index freeze state is incompatible with requested validation mode')
    reports = index.get('reports', [])
    roles = [item.get('role') for item in reports]
    require(len(set(roles)) == len(roles) and REQUIRED_ROLES <= set(roles), 'final validation index lacks required roles or duplicates them')
    results = []
    for item in reports:
        path = evidence.reference(item)
        require(path.is_relative_to(CASE) or
                (item['role'] in {'save', 'notice_ui'} and path.is_relative_to(HERE/'integration03_rea_review/save_wrapper_experiment')),
                'final regression report is outside the explicit review locations: '+item['role'])
        data = evidence.read(path)
        require(passed(data), 'regression is not passing: '+item['role'])
        inputs = item.get('input_files', {})
        require(inputs and all(Path(p).is_absolute() or str(p).replace('\\', '/').startswith(('analysis/', 'tools/')) for p in inputs),
                'regression input_files must be nonempty workspace-relative or absolute paths: '+item['role'])
        verify_map(evidence, inputs, [ROOT])
        for derived in item.get('derived_inputs', []):
            source = evidence.bind(derived['source_path'], derived['source_sha256'])
            start, length = derived['offset'], derived['length']
            require(isinstance(start, int) and isinstance(length, int) and start >= 0 and length > 0 and start+length <= source.stat().st_size,
                    'invalid derived-input byte range')
            with source.open('rb') as stream:
                stream.seek(start); raw = stream.read(length)
            value = hashlib.sha256(raw).hexdigest()
            require(value == derived['sha256'] == dotted(data, derived['report_field']), 'derived input bytes do not match report')
            evidence.derived_hashes.add(value)
        require(relative(BUILD/'build.json') in {str(p).replace('\\', '/') for p in inputs} or str(BUILD/'build.json') in inputs,
                'each regression needs the final build manifest in input_files: '+item['role'])
        if item.get('binding') == 'source':
            require(item['role'] in {'core', 'entry'}, 'only core/entry may use explicitly source-scoped evidence')
            if item.get('driver_hash_field'):
                require(dotted(data, item['driver_hash_field']) == expected, 'source binding report belongs to another candidate')
            if item['role'] == 'core':
                verify_map(evidence, data['sources'], [CASE/'core'])
                evidence.bind(CASE/'core/verify_core.py', data['test_source_sha256'])
            else:
                evidence.bind(CASE/'driver/entry.c', data['entry_source_sha256'])
        else:
            require(dotted(data, item['driver_hash_field']) == expected, 'regression belongs to another driver: '+item['role'])
        bases = [path.parent, CASE, CASE/'driver', CASE/'core', ROOT, HERE]
        embedded_bindings(evidence, data, bases)
        scalar_input_bindings(evidence, data)
        if item['role'] == 'ovmf':
            boots = [b for group in data['groups'] for b in group['boots']]
            require(data['all_passed'] and len(boots) == 6 and all(b['passed'] for b in boots), 'six passing OVMF boots required')
        count = data.get('checks', data.get('assertions', data.get('cases', data.get('case_groups'))))
        if isinstance(count, list):
            count = len(count)
        row = {'role': item['role'], 'binding': item.get('binding', 'candidate'), 'count': count,
               'path': relative(path), 'sha256': digest(path), 'status': data.get('status', 'PASS')}
        if item['role'] == 'ovmf':
            row.update(count=sum(b['checks'] for b in boots), cold_boots=len(boots))
        results.append(row)
    return results


def verify_structure(evidence, index, expected, expected_image=None):
    candidate = evidence.reference(index['review_image'])
    require(candidate.is_relative_to(CASE/'lab') and candidate.suffix.lower() == '.bin', 'review image must be a local lab BIN')
    if expected_image:
        evidence.bind(candidate, expected_image)
    verification = evidence.reference(index['structural_verification'])
    data = evidence.read(verification)
    require(data['status'] == 'PASS' and data['driver_sha256'] == expected and data['candidate_sha256'] == digest(candidate), 'structural verification identity mismatch')
    require(data['uefiextract_exit_code'] == 0 and data['inserted_driver_pe32_exact_match'] and
            data['inserted_driver_ffs_checksums_valid'] and data['source_capsule_unchanged'], 'structural checks incomplete')
    require(data['contains_original_signature_without_resigning'] and not data['hardware_boot_and_capsule_acceptance_verified'],
            'review BIN must remain explicitly unsigned/unaccepted for deployment')
    return {'path': relative(candidate), 'sha256': digest(candidate), 'verification': relative(verification)}


def verify_ram(evidence, expected, summary_reference):
    directory = CASE/'ram_validation'
    summary_path = evidence.reference(summary_reference)
    require(summary_path == directory/'delivery_summary.json', 'RAM summary reference is not the current revision delivery manifest')
    summary = evidence.read(summary_path, include=True)
    require(summary['production_driver_sha256'] == expected and summary['binding']['production_object_relink_exact_match'], 'RAM medium is not bound to final production objects')
    for kind in ['iso', 'efi', 'build_manifest']:
        path = evidence.bind(summary[kind+'_path'], summary[kind+'_sha256'], include=True)
        require(path.is_relative_to(directory), 'RAM artifact escapes its revision')
    build = evidence.read(summary['build_manifest_path'])
    require(build['production_driver_sha256'] == expected and build['production_object_relink_exact_match'], 'RAM build identity mismatch')
    require(build['iso_sha256'] == summary['iso_sha256'] and build['efi_sha256'] == summary['efi_sha256'], 'RAM build/summary disagreement')
    evidence.bind(directory/'build/PRODUCTION-RELINK-CHECK.EFI', expected)
    evidence.bind(BUILD/'build.json', build['production_manifest_sha256'])
    verify_map(evidence, build['production_sources'], [CASE])
    verify_map(evidence, build['production_external_sources'], [ROOT])
    verify_map(evidence, build['external_source_tree_sha256'], [ROOT])
    verify_map(evidence, build['local_source_sha256'], [directory])
    verify_map(evidence, build['generated_source_sha256'], [directory/'build/source'])
    for name, value in build['all_production_object_hashes'].items():
        evidence.bind(BUILD/name, value)
    for name, value in build['linked_objects'].items():
        evidence.bind(BUILD/(name+'.obj'), value)
    for kind in ['non_target_board_check', 'compiled_fixture_checks']:
        proof = summary[kind]
        report = evidence.read(proof['report_path'], proof['report_sha256'], include=True)
        require(passed(report), 'RAM validation incomplete: '+kind)
        require(report['production_driver_sha256'] == expected and report['efi_sha256'] == summary['efi_sha256'] and report['iso_sha256'] == summary['iso_sha256'], 'RAM test identity mismatch: '+kind)
        embedded_bindings(evidence, report, [directory/'build', directory, CASE, ROOT])
    non_target = summary['non_target_board_check']
    require(all(non_target.get(k) for k in ['passed', 'refusal_verified', 'exit_verified', 'medium_unchanged']), 'RAM non-target refusal/QR/exit checks incomplete')
    for name, value in summary['recommended_package_files'].items():
        path = workspace_path(name)
        require(path.is_relative_to(directory), 'RAM package recommendation escapes revision')
        evidence.bind(path, value, include=True)
    if summary.get('hardware_tested') is True:
        proof = summary['hardware_validation']
        observation = evidence.read(evidence.reference(proof['observation_summary']))
        require(observation.get('finalized') is True and observation['driver_sha256'] == expected and
                observation['iso_sha256'] == summary['iso_sha256'], 'RAM hardware addendum lacks finalized exact-candidate observations')
        log = evidence.reference(proof['final_log'])
        hardware_log_identity(log.read_text(encoding='utf8'), 'INTEGRATED04', expected)
        require(proof['final_log'] == observation['final_hardware_QR']['decoded_log'], 'RAM hardware log reference disagrees with independent review')
        for key in ['checks', 'failures', 'blocked_SetVariable_calls']:
            require(proof[key] == observation['final_hardware_QR'][key], 'RAM hardware counters disagree with reviewed QR')
        evidence.reference(proof['decoded_manifest'])
        evidence.reference(summary['media_build_record'])
        evidence.reference(summary['media_build_readme'])
    return summary


def verify_rea(evidence, summaries):
    sys.path.insert(0, str(ROOT/'tools/pydeps'))
    import pefile
    results = []
    for reference in summaries:
        path = evidence.reference(reference)
        data = evidence.read(path)
        require(str(data.get('status', '')).startswith('PASS'), 'REA summary not passing')
        embedded_bindings(evidence, data, [path.parent, HERE, ROOT])
        if 'accepted_efi_sha256' in data:
            evidence.bind(BUILD/'AiTweakerLock1904.efi', data['accepted_efi_sha256'])
        sessions = [data[k] for k in ['amitse_session', 'dxe_core_session', 'cache_state_REA'] if k in data]
        if not sessions:
            sessions = [data]
        for session in sessions:
            target = evidence.reference(session['target'])
            pe = pefile.PE(str(target)); mapped = pe.get_memory_mapped_image(); pe.close()
            for function in session['functions']:
                require(function.get('evidence_id'), 'REA function missing evidence id')
                evidence.bind(function['response'], function['response_sha256'], path.parent, include=True)
            for item in session.get('read_bytes_verified', []):
                start = int(item['rva'], 16); raw = mapped[start:start+item['bytes']]
                require(len(raw) == item['bytes'] and hashlib.sha256(raw).hexdigest() == item['sha256'] and item['equals_original_mapped_PE'], 'REA original mapped bytes changed')
                evidence.bind(item['response'], base=path.parent, include=True)
            for item in session.get('analysis_bytes_checked_against_original', []):
                require(item['complete'] and item['equals_original_mapped_file_bytes'], 'REA history byte verification incomplete')
            close = session['close']
            require(close['result'] == {'result': None}, 'REA analysis was not closed cleanly')
            evidence.bind(close['response'], close['response_sha256'], path.parent, include=True)
        for key in ['entry_review', 'core_support', 'save_design', 'original_byte_comparison']:
            item = data.get(key)
            if isinstance(item, dict) and {'path', 'sha256'} <= set(item):
                evidence.reference(item, path.parent)
        if 'source_integration_contract' in data:
            evidence.reference(data['source_integration_contract'], path.parent)
        for item in data.get('verification_reports', []):
            evidence.reference(item, path.parent)
        # Static decompilations and seeds are evidence; runtime/request scripts,
        # session endpoints and Ghidra databases are never directory-swept.
        for file in path.parent.glob('*.c'):
            evidence.bind(file, include=True)
        for file in path.parent.rglob('seeds.tsv'):
            evidence.bind(file, include=True)
        results.append({'path': relative(path), 'sha256': digest(path), 'classification': 'ORIGINAL_FIRMWARE_STATIC_EVIDENCE_NOT_FINAL_HARDWARE_ACCEPTANCE'})
    require(results, 'REA evidence list is empty')
    return results


def hardware_log_identity(text, revision, expected):
    require('ACE1904-'+revision+'-RAM' in text, 'hardware log revision mismatch')
    require(re.search(r'^DriverSHA256='+re.escape(expected)+r'\r?$', text, re.M), 'hardware log driver mismatch')
    require('PROBE_COMPLETE' in text, 'hardware QR log is incomplete')


def verify_hardware(evidence, index_path, expected, ram):
    data = evidence.read(index_path, include=True)
    require(data.get('collection_closed') is True, 'hardware evidence collection remains open; parent must close it after final review/cleanup')
    rows = []
    seen = set()
    for run in data['runs']:
        revision = run['revision']; require(revision in {'HISTORY02', 'INTEGRATED03', 'INTEGRATED04'} and revision not in seen, 'invalid/duplicate hardware revision')
        seen.add(revision)
        observed = run['status'] == 'OBSERVED'
        if observed:
            require(run['logs'] and run['screenshots'], 'observed hardware run lacks QR logs or screens')
            delivery = evidence.read(evidence.reference(run['ram_delivery_summary'], include=False))
            require(delivery['production_driver_sha256'] == run['driver_sha256'] and delivery['iso_sha256'] == run['iso_sha256'], 'hardware run does not match its own RAM medium')
            if revision == 'INTEGRATED04':
                require(run['driver_sha256'] == expected and run['iso_sha256'] == ram['iso_sha256'], 'INTEGRATED04 hardware observations belong to an older candidate')
            for record in run['logs']:
                path = evidence.reference(record)
                require(path.name == 'hardware-log.txt', 'only decoded hardware-log.txt is admitted as QR text')
                hardware_log_identity(path.read_text(encoding='utf8'), revision, run['driver_sha256'])
                manifest_path = evidence.reference(record['decoded_manifest'])
                manifest = evidence.read(manifest_path)
                require(manifest['sha256'] == digest(path) and manifest['bytes'] == path.stat().st_size, 'decoded QR manifest mismatch')
                for name, value in manifest['files'].items():
                    require(Path(name).name == name and (name == 'hardware-log.txt' or name.endswith('.frame')), 'unexpected QR manifest member')
                    evidence.bind(name, value, manifest_path.parent, include=True)
            for screen in run['screenshots']:
                path = evidence.reference(screen)
                require(path.suffix.lower() == '.png' and screen.get('visually_reviewed') is True, 'hardware screenshot not explicitly reviewed')
            if run.get('observation_source'):
                evidence.reference(run['observation_source'])
        else:
            require(not run.get('logs') and not run.get('screenshots') and not run.get('observations'), 'unobserved version contains attributed hardware pass evidence')
        rows.append({'revision': revision, 'status': run['status'], 'driver_sha256': run.get('driver_sha256'),
                     'iso_sha256': run.get('iso_sha256'), 'observed': observed,
                     'observations': run.get('observations', []), 'final_counters': run.get('final_counters'), 'notes': run.get('notes', [])})
    require(seen == {'HISTORY02', 'INTEGRATED03', 'INTEGRATED04'}, 'hardware index must distinguish all three revisions')
    cleanup = data.get('cleanup', {})
    require(cleanup.get('status') in {'COMPLETED', 'NOT_VERIFIED'}, 'cleanup status must be explicit')
    if cleanup['status'] == 'COMPLETED':
        require(cleanup.get('evidence'), 'completed cleanup lacks evidence')
    for reference in cleanup.get('evidence', []):
        path = evidence.reference(reference)
        allowed = path.suffix.lower() == '.png' or (path.suffix.lower() in {'.json', '.txt'} and not path.name.startswith('screen-'))
        require(allowed, 'cleanup admits curated summaries/screens only')
    return {'runs': rows, 'cleanup': cleanup, 'index_path': relative(workspace_path(index_path))}


def collect_sources(evidence):
    for sub in ['core', 'driver', 'lab', 'ram_validation']:
        directory = CASE/sub
        require(directory.is_dir(), 'required source directory missing: '+sub)
        for path in directory.iterdir():
            if path.is_file() and path.suffix.lower() in {'.c', '.h', '.py', '.json', '.txt', '.diff'}:
                evidence.bind(path, include=True)
    for sub in ['entry_review', 'owner_review', 'ebs_review', 'save_review', 'integration_review', 'compression_review']:
        directory = CASE/sub
        if directory.is_dir():
            # Top-level review material only; recursive candidate builds,
            # transient runs and large provider databases stay outside.
            for path in directory.iterdir():
                if path.is_file() and path.suffix.lower() in {'.c', '.h', '.py', '.txt', '.diff'}:
                    evidence.bind(path, include=True)
    evidence.bind(Path(__file__), include=True)
    evidence.bind(HERE/'README-integrated04-delivery.txt', include=True)


def write_report(expected, structure, ram, regressions, hardware):
    rows = []
    for run in hardware['runs']:
        identity = run['driver_sha256'] or (expected if run['revision'] == 'INTEGRATED04' else '尚未绑定')
        rows.append(run['revision']+'：'+run['status']+'；驱动 '+identity+'。')
        if run['observed']:
            rows.extend('  - '+str(o.get('case', o)) for o in run['observations'])
            if run.get('final_counters'):
                rows.append('  QR 计数：'+json.dumps(run['final_counters'], ensure_ascii=False))
        rows.extend('  说明：'+note for note in run['notes'])
    tests = '\n'.join('  '+item['role']+'：'+item['status']+'；证据范围 '+item['binding']+
                      ('；计数 '+str(item['count']) if item['count'] is not None else '')+
                      ('；冷启动 '+str(item['cold_boots'])+' 次' if 'cold_boots' in item else '') for item in regressions)
    return f'''W790-ACE 1904 / AI Tweaker 独立密码 — INTEGRATED04 离线审查交付

最终候选与证据范围
本报告绑定驱动 SHA256：{expected}
离线 BIOS 审查映像 SHA256：{structure['sha256']}
RAM 测试 ISO SHA256：{ram['iso_sha256']}
RAM 测试 EFI SHA256：{ram['efi_sha256']}
打包前已核对最终生产源、构建清单、回归输入、RAM 原对象重链接、介质校验和以及所收录的原厂 REA 证据。
这是一份审查包；没有签名发布，也没有以本脚本执行带外、启动或刷写操作。

本轮工程覆盖
适配范围为 ACE 1904：安全历史根、原生浏览器会话归属、HII 管理与导航授权、EBS 恢复、发现重试与退役边界，以及本次保存路径修订。
实际组成以 core/driver 源快照和逐项回归为准；组件测试不扩大为整机通过。

离线验证（计数单位不同，不合并成一种总测试数）
{tests}
RAM 介质另有非目标板拒绝、QR 恢复与编译代码检查。原生产对象的重链接输出必须逐字节等于最终候选。
REA 内容是原厂 AMITSE / DXE Core 的静态及有界指令证据，不是最终固件在实体主板运行的证明。

实机证据按版本区分
{chr(10).join(rows)}
上列旧版本观察不会计入 INTEGRATED04 的实机通过项。
清理状态：{hardware['cleanup']['status']}。
清理详情：{hardware['cleanup'].get('note', '')}

未证明项
1. 冷启动 Del/F2 自动生效、第一轮原生 Setup 加载次序和完整平台路径。
2. 实体 NVRAM 跨重启的密码持久化、默认值/训练等行为。
3. 真实 Save / Save & Reset 成功与失败反馈、全部设置保存和重启兼容性。
4. 新 OEM 签名、更新器接受性、实际刷写和可恢复部署路径。
5. RAM 表拦截不涵盖 SMM、缓存指针或直接硬件写入；三个命名变量不代表全 NVRAM/SPI 审计。
6. EBS 异常终止及外部恢复仍须实机验证；维护期介质必须复位后退出，不用于正常 OS handoff。
审查 BIN 保留原 Capsule 签名结构但负载已改，不构成新的有效厂商签名，不能视为正式可刷文件。

交付与复现
ZIP 内保留工作区相对目录，package-manifest.json 和 SHA256SUMS.txt 提供逐文件哈希。
工具链、官方输入固件及未收录的测试依赖仍按原工作区使用；本包不是独立安装程序。
保留 README、构建脚本、回归 JSON、REA 响应、经人工核对的 KVM PNG 与完整 QR 日志。
缓存、会话/凭据、BMC 网络请求与进程脚本、临时 NVRAM 镜像和 Ghidra 数据库未收录。
'''


def template():
    prefix = relative(CASE)
    names = {'core': 'core/test_report.json', 'adapter': 'driver/build/adapter_emulation.json',
             'history': 'driver/build/history_regression.json', 'policy': 'driver/build/policy_test.json',
             'entropy': 'driver/build/entropy_test.json', 'hii_abi': 'driver/build/hii_abi_test.json',
             'owner': 'owner_review/integrated_owner_regression.json', 'discovery': 'driver/build/discovery_regression.json',
             'ebs': 'ebs_review/integrated_ebs_regression.json', 'entry': 'entry_review/retirement_regression.json',
             'save': 'save_review/integrated_save_regression.json', 'ovmf': 'driver/build/vm_integration.json'}
    return {'schema': 1, 'frozen': False, 'driver_sha256': 'REPLACE_WITH_FINAL_DRIVER_SHA256',
            'review_image': {'path': prefix+'/lab/asus_review/W790-ACE-1904-lock.review.bin', 'sha256': 'REPLACE'},
            'structural_verification': {'path': prefix+'/lab/asus_review/verification.json', 'sha256': 'REPLACE'},
            'ram_delivery_summary': {'path': prefix+'/ram_validation/delivery_summary.json', 'sha256': 'REPLACE'},
            'rea_summaries': [{'path': relative(HERE/'integration03_rea_review/integration03_review_summary.json'), 'sha256': 'REPLACE'}],
            'reports': [{'role': role, 'path': prefix+'/'+names[role], 'sha256': 'REPLACE',
                         'binding': 'source' if role in {'core', 'entry'} else 'candidate',
                         'driver_hash_field': 'driver_efi_sha256' if role == 'policy' else 'driver_sha256',
                         'input_files': {prefix+'/driver/build/build.json': 'REPLACE',
                                         'REPLACE_WITH_EXACT_TEST_SCRIPT_AND_INPUT_PATHS': 'REPLACE'}} for role in sorted(REQUIRED_ROLES)],
            'instructions': ['Paths are workspace-relative; fill exact report and input hashes after final validation.',
                             'Every report input_files must include its actual test script, final build.json, native inputs and any linked fixture artifacts used.',
                             'Only core and entry allow source-scoped evidence; all other required regressions must embed the exact final EFI SHA.',
                             'No old hardware PASS may be assigned to INTEGRATED04. Close the separate hardware index only after parent review.']}


def self_test():
    checks = 0
    def rejects(callback):
        nonlocal checks
        try:
            callback()
        except DeliveryError:
            checks += 1
            return
        raise DeliveryError('negative self-test unexpectedly accepted')
    rejects(lambda: workspace_path(ROOT.parent/'escape.bin', must_exist=False))
    rejects(lambda: Evidence().bind(Path(__file__), '0'*64))
    rejects(lambda: verify_regressions(Evidence(), {'frozen': False, 'driver_sha256': 'a'*64}, 'a'*64))
    rejects(lambda: hardware_log_identity('ACE1904-HISTORY02-RAM\nDriverSHA256='+'a'*64+'\nPROBE_COMPLETE', 'INTEGRATED04', 'a'*64))
    rejects(lambda: hardware_log_identity('ACE1904-INTEGRATED04-RAM\nDriverSHA256='+'b'*64+'\nPROBE_COMPLETE', 'INTEGRATED04', 'a'*64))
    require(SECRET_TEXT.search('Bearer '+'A'*32), 'secret recognizer self-test failed')
    require(FORBIDDEN_NAME.search('session-state.json') and 'operations' in FORBIDDEN_PARTS, 'runtime exclusion self-test failed')
    require(not passed({'status': 'FAIL'}) and passed({'status': 'PASS_COMPILED'}), 'status self-test failed')
    return {'status': 'PASS_PACKAGER_STATIC_GUARDS', 'negative_checks': checks, 'positive_checks': 3, 'final_candidate_packaged': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--expected-driver-sha')
    parser.add_argument('--expected-review-sha')
    parser.add_argument('--validation-index', default=str(CASE/'final_validation_index.json'))
    parser.add_argument('--hardware-index', default=str(HERE/'bmc_hardware03/hardware_evidence_index.json'))
    parser.add_argument('--output-dir')
    parser.add_argument('--check-only', action='store_true')
    parser.add_argument('--check-pending', action='store_true')
    parser.add_argument('--self-test', action='store_true')
    parser.add_argument('--write-template', action='store_true')
    args = parser.parse_args()
    if args.self_test:
        print(json.dumps(self_test(), indent=2)); return
    if args.write_template:
        path = HERE/'integrated04_delivery_inputs.example.json'
        require(not path.exists(), 'template already exists; refusing to overwrite')
        path.write_text(json.dumps(template(), ensure_ascii=False, indent=2)+'\n', encoding='utf8')
        print(json.dumps({'template': str(path), 'final_candidate_packaged': False})); return
    require(args.expected_driver_sha, '--expected-driver-sha is required; never infer the final candidate from a stale build')
    require(not (args.check_only and args.check_pending), '--check-only and --check-pending are separate validation modes')
    evidence = Evidence()
    build = verify_final_build(evidence, args.expected_driver_sha)
    index = evidence.read(args.validation_index, include=True)
    regressions = verify_regressions(evidence, index, args.expected_driver_sha, require_frozen=not args.check_pending)
    structure = verify_structure(evidence, index, args.expected_driver_sha, args.expected_review_sha)
    ram = verify_ram(evidence, args.expected_driver_sha, index['ram_delivery_summary'])
    rea = verify_rea(evidence, index['rea_summaries'])
    for reference in index.get('supporting_evidence', []):
        evidence.reference(reference)
    if args.check_pending:
        collect_sources(evidence)
        evidence.unchanged()
        require(sum(p.stat().st_size for p in evidence.selected) <= MAX_PACKAGE, 'selected package exceeds total size bound')
        print(json.dumps({'status': 'PASS_PENDING_LOCAL_INPUTS_NOT_FROZEN',
                          'driver_sha256': args.expected_driver_sha, 'review_image': structure,
                          'ram_iso_sha256': ram['iso_sha256'], 'regressions': regressions,
                          'checked_input_files': len(evidence.inputs), 'selected_files': len(evidence.selected),
                          'selected_bytes': sum(p.stat().st_size for p in evidence.selected),
                          'hardware_collection_index_inspected': False,
                          'ram_hardware_addendum_checked': ram.get('hardware_tested') is True, 'final_index_frozen': False,
                          'hardware_collection_closed_by_this_check': False, 'candidate_packaged': False}, indent=2)); return
    hardware = verify_hardware(evidence, args.hardware_index, args.expected_driver_sha, ram)
    collect_sources(evidence)
    evidence.unchanged()
    require(sum(p.stat().st_size for p in evidence.selected) <= MAX_PACKAGE, 'selected package exceeds total size bound')
    if args.check_only:
        print(json.dumps({'status': 'PASS_FINAL_INPUTS_ONLY', 'driver_sha256': args.expected_driver_sha,
                          'files': len(evidence.selected), 'candidate_packaged': False}, indent=2)); return
    output = workspace_path(args.output_dir or HERE/('delivery_integrated04_'+args.expected_driver_sha[:12]), must_exist=False)
    require(output.is_relative_to(HERE) and not output.exists(), 'output must be a new directory inside the adaptation workspace')
    output.mkdir(parents=True)
    report_path = output/'W790-ACE-1904-INTEGRATED04-适配报告.txt'
    report_path.write_text(write_report(args.expected_driver_sha, structure, ram, regressions, hardware), encoding='utf8')
    evidence.bind(report_path, include=True)
    files = {relative(p): {'sha256': digest(p), 'bytes': p.stat().st_size} for p in sorted(evidence.selected)}
    manifest = {'schema': 1, 'generated_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
                'revision': 'W790-ACE-1904-INTEGRATED04', 'status': 'REVIEW_PACKAGE_NOT_SIGNED_OR_FLASH_APPROVED',
                'driver_sha256': args.expected_driver_sha, 'review_image': structure,
                'ram_iso_sha256': ram['iso_sha256'], 'regressions': regressions, 'rea': rea, 'hardware': hardware,
                'ready_for_permanent_deployment': False, 'workspace_dependencies_required': True,
                'verified_input_files': {relative(p): h for p, h in sorted(evidence.inputs.items())}, 'files': files}
    manifest_text = json.dumps(manifest, ensure_ascii=False, indent=2)+'\n'
    checksum_text = ''.join(v['sha256']+'  '+name+'\n' for name, v in files.items())
    (output/'package-manifest.json').write_text(manifest_text, encoding='utf8')
    (output/'SHA256SUMS.txt').write_text(checksum_text, encoding='utf8')
    archive_path = output/'W790-ACE-1904-INTEGRATED04-离线审查包.zip'
    evidence.unchanged()
    with zipfile.ZipFile(archive_path, 'x', compression=zipfile.ZIP_DEFLATED, compresslevel=6) as archive:
        for p in sorted(evidence.selected):
            archive.write(p, relative(p))
        archive.writestr('package-manifest.json', manifest_text)
        archive.writestr('SHA256SUMS.txt', checksum_text)
    with zipfile.ZipFile(archive_path) as archive:
        require(archive.testzip() is None, 'ZIP CRC verification failed')
        require(archive.read('package-manifest.json') == manifest_text.encode('utf8') and
                archive.read('SHA256SUMS.txt') == checksum_text.encode('utf8'), 'ZIP manifest/checksum text mismatch')
        for name, item in files.items():
            with archive.open(name) as stream:
                actual = hashlib.file_digest(stream, 'sha256').hexdigest()
            require(actual == item['sha256'] and archive.getinfo(name).file_size == item['bytes'], 'ZIP member hash/size mismatch')
    evidence.unchanged()
    delivery = {'status': manifest['status'], 'driver_sha256': args.expected_driver_sha,
                'archive': relative(archive_path), 'archive_sha256': digest(archive_path), 'archive_bytes': archive_path.stat().st_size,
                'report': relative(report_path), 'manifest': relative(output/'package-manifest.json'), 'verified_members': len(files)}
    (output/'delivery.json').write_text(json.dumps(delivery, ensure_ascii=False, indent=2)+'\n', encoding='utf8')
    archive_path.with_suffix('.zip.sha256').write_text(delivery['archive_sha256']+'  '+archive_path.name+'\n', encoding='utf8')
    print(json.dumps(delivery, ensure_ascii=True, indent=2))


if __name__ == '__main__':
    try:
        main()
    except (DeliveryError, KeyError, ValueError, OSError) as error:
        print(json.dumps({'status': 'DELIVERY_NOT_CREATED', 'reason': str(error)}, ensure_ascii=True), file=sys.stderr)
        raise SystemExit(2)
