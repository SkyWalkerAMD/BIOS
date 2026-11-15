from pathlib import Path
import hashlib
import json
import zipfile

root = Path(__file__).resolve().parent
bundle = root / 'porting_bundle'
archive = root / 'Z790_HERO_IPMI_analysis_only.zip'
extras = ['IPMI移植分析.md', 'module_comparison.tsv', 'module_details.txt',
          'setup_layout.json', 'hero_official_verification.json']
with zipfile.ZipFile(archive, 'w', zipfile.ZIP_DEFLATED) as z:
    for p in bundle.rglob('*'):
        if p.is_file():
            z.write(p, p.relative_to(bundle).as_posix())
    for name in extras:
        z.write(root / name, name)
    for p in (root / 'structures').glob('*_setup.h'):
        z.write(p, 'structures/' + p.name)
with zipfile.ZipFile(archive) as z:
    assert z.testzip() is None
    assert not any(n.lower().endswith('.cap') for n in z.namelist())
    m = json.loads(z.read('manifest.json'))
    assert len(m['modules']) == 52
    for module in m['modules']:
        assert hashlib.sha256(z.read(module['file'])).hexdigest() == module['sha256']
    print('Archive verified:', len(z.namelist()), 'entries;', archive.stat().st_size, 'bytes')
    for name, expected in m['original_files'].items():
        assert hashlib.sha256((root.parent / name).read_bytes()).hexdigest() == expected['sha256']
    print('Both source capsules are unchanged.')
sha = hashlib.sha256(archive.read_bytes()).hexdigest()
archive.with_suffix('.zip.sha256').write_text(sha + '  ' + archive.name + '\n', encoding='ascii')
print('Archive SHA256:', sha)
