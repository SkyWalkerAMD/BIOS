"""Package reviewed RC2 bytes; never accesses hardware or credentials."""
from pathlib import Path, PurePosixPath
import hashlib, json, zipfile

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
P5 = ROOT / 'analysis/hero_ipmi_p5'
DEST = ROOT / 'analysis/HERO-3107-IPMI-P5-RC2-REA-REVIEWED-FLASHBACK.zip'
RC2_SHA = '5906d1bca3dbaa1157ecf36ecff1a1123bfe4b6fb896aeb33d354ab4ef21b521'
ORIGINAL_SHA = 'e900f164cbabec0088ea8f1dd3c0ad932f32a5e14412be814d06cce3a4210f6a'
DRIVER_SHA = 'bfdf3ae73fee0492ae664f0925ae86a26607aafa00c0c41d3fd32a1257383a71'

def sha(data):
    return hashlib.sha256(data).hexdigest()

def read_json(path):
    return json.loads(Path(path).read_text(encoding='utf-8'))

def main():
    independent = read_json(HERE/'rc2-container-review.json')
    assert independent['passed'] and independent['target_sha256'] == RC2_SHA
    assert independent['driver_only_in_inner_fv'] and independent['driver_ffs_identical_to_rc1']
    assert read_json(HERE/'menu-spf-independent.json')['passed']
    assert not read_json(HERE/'menu-review.json')['confirmed_blocking_defects']
    for name in ('native-verification.json', 'publisher-tests.json', 'policy-tests.json'):
        assert read_json(P5/name)['passed'], name
    index = read_json(HERE/'review-index.json')
    assert index['candidate_sha256'] == RC2_SHA and len(index['records']) == 18
    for record in index['records']:
        assert sha((HERE/record['response']).read_bytes()) == record['response_sha256']
    files = {}

    def add(name, path):
        name = str(PurePosixPath(name))
        assert not name.startswith('/') and '..' not in PurePosixPath(name).parts
        data = Path(path).read_bytes()
        if name in files:
            assert files[name] == data, name
        files[name] = data

    def tree(prefix, folder, suffixes=None):
        folder = Path(folder)
        for path in sorted(folder.rglob('*')):
            if path.is_file() and (suffixes is None or path.suffix in suffixes):
                add(prefix+'/'+path.relative_to(folder).as_posix(), path)

    add('01-TEST-USB/MZ790H.CAP', HERE/'rc2/HERO-3107-IPMI-P5-RC2-UNSIGNED.CAP')
    official = ROOT/'analysis/hero_3107_official'
    add('02-RECOVERY-USB/MZ790H.CAP', official/'ROG-MAXIMUS-Z790-HERO-ASUS-3107.CAP')
    assert sha(files['01-TEST-USB/MZ790H.CAP']) == RC2_SHA
    assert sha(files['02-RECOVERY-USB/MZ790H.CAP']) == ORIGINAL_SHA
    add('02-RECOVERY-USB/source.json', official/'source.json')
    add('03-DIAGNOSTIC/HERO-IPMI-P5-PREFLIGHT.iso', P5/'HERO-IPMI-P5-PREFLIGHT.iso')
    tree('03-DIAGNOSTIC/USB', P5/'USB')
    assert sha(files['03-DIAGNOSTIC/USB/EFI/HERO/HeroIpmiP5.efi']) == DRIVER_SHA
    assert sha(files['03-DIAGNOSTIC/HERO-IPMI-P5-PREFLIGHT.iso']) == 'ad74780b427bf68400d13f376d89d53dde27a90b9d472ee91425a97ef3e0c32f'

    tree('04-SOURCE/hero_ipmi_p5/source', P5/'source')
    for path in sorted(P5.glob('*.py')):
        # Exclude the superseded RC1 delivery/media packagers from this delivery.
        if path.name not in ('package_candidate.py', 'build_review_media.py'):
            add('04-SOURCE/hero_ipmi_p5/'+path.name, path)
    for path in sorted(P5.glob('*.map')):
        add('04-SOURCE/hero_ipmi_p5/'+path.name, path)
    for path in sorted((P5/'host-lzma').iterdir()):
        if path.suffix in ('.c', '.h', '.json'):
            add('04-SOURCE/hero_ipmi_p5/host-lzma/'+path.name, path)
    for name in ('build_rc2.py','container_review_rc2.py','menu_independent_audit.py',
                 'menu_spf_independent.py','session.py','write_review.py','package_rc2.py'):
        add('04-SOURCE/rc2-review/'+name, HERE/name)
    for name in ('hero_ipmi_p3/generate_forms.py','aitweaker_lock/uefi_vm_20261015/disk_images.py'):
        add('04-SOURCE/workspace-dependencies/'+name, ROOT/'analysis'/name)

    review_names = ('review-index.json','rc2-container-review.json','menu-review.json',
                    'menu-spf-independent.json','menu-pe-independent.json',
                    'setupenter-guid-findings.json','amitse-setupenter-imm.json',
                    'dxe-entry-stub.json','retained-menu-rea-index.json')
    for name in review_names:
        add('05-REVIEW/'+name, HERE/name)
    add('05-REVIEW/rc2/build.json', HERE/'rc2/build.json')
    add('05-REVIEW/rc2/parser-output.txt', HERE/'rc2/parser-output.txt')
    for name in ('HERO-3107-IPMI-P5-RC2-UNSIGNED.CAP.report.txt',
                 'HERO-3107-IPMI-P5-RC2-UNSIGNED.CAP.guids.csv'):
        add('05-REVIEW/rc2/'+name, HERE/'rc2'/name)
    for session in ('driver-loopback','driver-seeded','dxe','amitse'):
        prefix = '05-REVIEW/REA/'+session
        add(prefix+'/evidence.json', HERE/session/'evidence.json')
        tree(prefix+'/commands', HERE/session/'commands', {'.json'})
        tree(prefix+'/responses', HERE/session/'responses', {'.json'})
        for path in sorted((HERE/session).iterdir()):
            if path.suffix in ('.c','.tsv'):
                add(prefix+'/'+path.name, path)
    tree('05-REVIEW/retained-menu-rea', HERE/'retained-menu-rea', {'.txt'})
    for source in sorted({x['source'] for x in read_json(HERE/'retained-menu-rea-index.json')}):
        path = ROOT/source
        add('05-REVIEW/prior-REA/'+path.relative_to(ROOT/'analysis/hero_rea_20261102').as_posix(), path)
    add('05-REVIEW/targets/HERO-3107-DxeCore.efi', HERE/'HERO-3107-DxeCore.efi')
    add('05-REVIEW/targets/HERO-3107-AMITSE.efi', ROOT/'analysis/hero_rea_20261102/HERO-3107-AMITSE.efi')
    skill = ROOT/'tools/rea-runtime/node_modules/rea-agents/skills/reverse-engineer-anything'
    assert sha((skill/'SKILL.md').read_bytes()) == index['skill']['sha256']
    for name in ('SKILL.md','references/connection-and-recovery.md','references/native-and-artifacts.md'):
        add('05-REVIEW/REA-SKILL/'+name, skill/name)

    for name in ('native-payload.json','native-verification.json','build.json',
                 'publisher-tests.json','policy-tests.json'):
        add('06-PRIOR-EVIDENCE/unchanged-p5-inputs/'+name, P5/name)
    live = ROOT/'analysis/hero_ipmi_p5_live_20261103'
    preflight = read_json(live/'preflight-result.json')
    assert preflight['probe_returned_success'] and preflight['pci_memory_bit_restored']
    assert sha((live/'P5-preflight.txt').read_bytes()) == preflight['log_sha256']
    for name in ('preflight-result.json','P5-preflight.txt'):
        add('06-PRIOR-EVIDENCE/RAM-preflight/'+name, live/name)
    for name in preflight['screens']:
        add('06-PRIOR-EVIDENCE/RAM-preflight/screens/'+name, live/'screens'/name)
    check_dir = ROOT/'analysis/hero_ipmi_p5_review_live_20261103'
    check = read_json(check_dir/'image-check-result.json')
    add('06-PRIOR-EVIDENCE/RC1-EZFlash-control/image-check-result.json', check_dir/'image-check-result.json')
    for name in check['screens']:
        add('06-PRIOR-EVIDENCE/RC1-EZFlash-control/screens/'+name, check_dir/'screens'/name)
    for name in ('现场刷写说明-P5-RC2.txt','REA复核结论-RC2.txt'):
        add(name, HERE/name)

    assert sorted(x for x in files if x.lower().endswith('.cap')) == ['01-TEST-USB/MZ790H.CAP','02-RECOVERY-USB/MZ790H.CAP']
    manifest = {name:dict(bytes=len(data),sha256=sha(data)) for name,data in sorted(files.items())}
    files['SHA256-MANIFEST.json'] = (json.dumps(manifest,indent=2,ensure_ascii=False)+'\n').encode('utf-8')
    for name, data in files.items():
        if name.endswith(('.txt','.json','.py','.c','.h','.md','.tsv')):
            for line in data.splitlines():
                assert not line.strip().lower().startswith((b'authorization: basic ',b'x-auth-token:')), name
    with zipfile.ZipFile(DEST, 'w', zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for name,data in sorted(files.items()):
            archive.writestr(name,data)
    with zipfile.ZipFile(DEST) as archive:
        assert archive.testzip() is None
        assert len(archive.namelist()) == len(files) == len(set(archive.namelist()))
        for name, item in manifest.items():
            data = archive.read(name)
            assert len(data) == item['bytes'] and sha(data) == item['sha256'], name
    report = dict(package=str(DEST),bytes=DEST.stat().st_size,sha256=sha(DEST.read_bytes()),
                  files=len(files),manifest_files=len(manifest),archive_crc_passed=True,
                  all_manifest_hashes_passed=True,candidate_sha256=RC2_SHA,original_sha256=ORIGINAL_SHA,
                  real_rea_records=len(index['records']),independent_static_container_passed=True,
                  unchanged_driver_ram_preflight_passed=True,
                  flashback_acceptance_verified=False,native_menu_hardware_verified=False,
                  official_release=False,configuration_setters_implemented=False)
    (HERE/'delivery.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(report,indent=2))

if __name__ == '__main__':
    main()
