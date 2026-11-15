"""Derive a new pinned C05 workspace, preserving every C04 artifact."""
from pathlib import Path
import hashlib
import json
import re

if not __debug__:
    raise RuntimeError('Run with assertions enabled')
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
OLD = ROOT / 'analysis/hero_ipmi_rc5_s22_20261108'
PINS = {
    'build_candidate.py': '74bb4ede6a7c5c50d36883b813966bd421306bf9afe7ee0d24a26ab439793de4',
    'verify_candidate.py': 'af4e5f57178777f9f1d60555374655644019785a4e36d8a983182e2edf53b052',
    'test_builder_guards.py': '0843c283f1a0021e0fe729874567f7a58df2f34aa72d429a4fdb1980dbc6ff96',
    'audit_inventory_exclusion.py': 'b8a0f38e283c2d79c4e5a5a0fcc8f4bfd73c61da49b00a7da073f6d16b8bca96',
}
REPLACEMENTS = {
    '554e210cca3de3bc337f944e7126f244d1ffcd67bb81089662f6d3ae78f2ad1b':
        '15c1e38b0693105a3f2abad917f375cc0d36285d9e4d8402013e5088244766fa',
    'abe692ebc1c80fe86b1e319b30fca300a11638845da4c3be7b0c81bd85423d75':
        '1536d23d32c5787820bf61749df1a16bba7e99b755854f2cd4114f7e62e390cc',
    'analysis/hero_p6_s22_20261108/HeroIpmiNativeP6.ffs':
        'analysis/hero_p6_s23_20261108/HeroIpmiNativeP6.ffs',
    'RC5-IPMI-ONLY-R5-S22-CANDIDATE04': 'RC5-IPMI-ONLY-R5-S23-CANDIDATE05',
    'candidate04': 'candidate05',
    'CANDIDATE03': 'CANDIDATE05',
    'builder-guard-tests-ipmi-only-s22.json': 'builder-guard-tests-ipmi-only-s23.json',
    '# S22 preserves S21S lifecycle; adds unique PCI bus discovery. Hardware evidence is separate.':
        '# S23 preserves S22 PCI/settings/lifecycle and accepts exact known P5/P6 Forms. Hardware evidence is separate.',
    'R4_FFS_SHA': 'R5_FFS_SHA', 'R4_PE_SHA': 'R5_PE_SHA', 'frozen_r4': 'frozen_r5',
    '8adf138c82c71d8d599b625fa5776bcd201096f59d6f357fd2ef75251efdf70f':
        'C05_PENDING_PIN',
}


def sha(data):
    return hashlib.sha256(data).hexdigest()


def main():
    for name, pin in PINS.items():
        assert sha((OLD / name).read_bytes()) == pin
        assert not (HERE / name).exists(), 'Do not overwrite existing C05 work'
    manifest = json.loads((OLD / 'integration-manifest.json').read_text(encoding='utf8'))
    manifest['build_id'] = 'RC5-IPMI-ONLY-R5-S23-CANDIDATE05'
    native = next(x for x in manifest['modules'] if x['role'] == 'native_ipmi')
    native.update(path='analysis/hero_p6_s23_20261108/HeroIpmiNativeP6.ffs',
                  sha256='15c1e38b0693105a3f2abad917f375cc0d36285d9e4d8402013e5088244766fa',
                  pe_sha256='1536d23d32c5787820bf61749df1a16bba7e99b755854f2cd4114f7e62e390cc')
    for mod in manifest['modules']:
        assert sha((ROOT / mod['path']).read_bytes()) == mod['sha256']
    assert sha((ROOT / 'analysis/hero_p6_s23_20261108/HeroIpmiP6.efi').read_bytes()) == native['pe_sha256']
    rows = []
    for name, pin in PINS.items():
        source = OLD / name
        text = source.read_text(encoding='utf8')
        for before, after in REPLACEMENTS.items():
            text = text.replace(before, after)
        text = re.sub(r'\bR4\b', 'R5', text)
        target = HERE / name
        target.write_text(text, encoding='utf8', newline='\n')
        rows.append(dict(source=source.relative_to(ROOT).as_posix(), source_sha256=pin,
                         output=target.relative_to(ROOT).as_posix(), initial_sha256=sha(target.read_bytes())))
    (HERE / 'integration-manifest.json').write_text(json.dumps(manifest, indent=2) + '\n', encoding='utf8')
    (HERE / 'builder-source-provenance-initial.json').write_text(json.dumps(dict(
        base='C04 pinned source files; unchanged input artifacts', files=rows,
        replacements=REPLACEMENTS, additional_lexical_replacement='word R4 to R5 (correct inherited variable labels)',
        pending='New C05 negative guards, independently pinned official input and final CAP pin are recorded in final provenance.'
    ), indent=2) + '\n', encoding='utf8')
    print('C05 sources prepared; no firmware generated or hardware validation claimed.')


if __name__ == '__main__':
    main()
