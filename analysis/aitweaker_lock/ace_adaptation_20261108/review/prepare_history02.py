"""Create an isolated ACE 1904 source snapshot; never overwrite a snapshot."""
from pathlib import Path
import difflib
import hashlib
import json
import shutil

HERE = Path(__file__).resolve().parent
ROOT = next(p for p in HERE.parents if (p / 'tools/pydeps').is_dir())
ORIGINAL = ROOT / 'analysis/aitweaker_lock/lock_1904'
SAGE = ROOT / 'analysis/aitweaker_lock/lock_sage_1904'
TARGET = HERE.parent / 'lock_1904_history02'
assert not TARGET.exists(), 'Existing snapshot must not be overwritten'

def sha(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()

baseline = {}
for folder in ['core', 'driver', 'navigation']:
    (TARGET / folder).mkdir(parents=True, exist_ok=False)
    endings = {'.c', '.h', '.py'} if folder != 'navigation' else {'.mjs', '.tsv', '.json'}
    for source in sorted((ORIGINAL / folder).iterdir()):
        if source.is_file() and source.suffix in endings:
            rel = source.relative_to(ORIGINAL)
            baseline[str(rel)] = sha(source)
            shutil.copyfile(source, TARGET / rel)

root_expression = "next(p for p in HERE.parents if (p/'tools/zig-x86_64-windows-0.14.1/zig.exe').is_file())"
for rel in ['driver/build.py', 'driver/generate_policy.py', 'driver/build_vm.py', 'core/build_core.py']:
    p = TARGET / rel
    text = p.read_text(encoding='utf8')
    text = text.replace('ROOT=HERE.parents[3]', 'ROOT=' + root_expression)
    text = text.replace('ROOT = HERE.parents[3]', 'ROOT = ' + root_expression)
    if rel.endswith('generate_policy.py'):
        text = text.replace("CASE=HERE.parent.parent/'hardware_20261102_W790_ACE_E9B906DF'", "ROOT=" + root_expression + "\nCASE=ROOT/'analysis/aitweaker_lock/hardware_20261102_W790_ACE_E9B906DF'")
    text = text.replace("HERE.parent.parent/'probe_p3_kvm/source", "ROOT/'analysis/aitweaker_lock/probe_p3_kvm/source")
    text = text.replace("HERE.parent.parent/'hardware_20261102_W790_ACE_E9B906DF'", "ROOT/'analysis/aitweaker_lock/hardware_20261102_W790_ACE_E9B906DF'")
    text = text.replace('sys.path.insert(0,str(HERE.parent.parent))', "sys.path.insert(0,str(ROOT/'analysis/aitweaker_lock'))")
    if rel == 'driver/build.py':
        text = text.replace("'board':'Pro WS W790-ACE'", "'revision':'ACE1904_HISTORY02','board':'Pro WS W790-ACE'")
    p.write_text(text, encoding='utf8')

p = TARGET / 'driver/platform.c'
text = p.read_text(encoding='utf8')
sage = (SAGE / 'driver/platform.c').read_text(encoding='utf8')
replacement = sage[sage.index('static int overlaps('):sage.index('static int gate(')]
for old, new in [('0x10220','0x10270'), ('0x1012c','0x1017c'), ('0x83594','0x82754'), ('0x83598','0x82758'), ('0x835a0','0x82760'), ('0x835b8','0x82778')]:
    replacement = replacement.replace(old, new)
text = text.replace('static UN setup_bytes;', 'static UN tse_bytes,setup_bytes;')
text = text[:text.index('static void redirect(')] + replacement + text[text.index('static int gate('):]
text = text.replace('tse_base=tse;setup_base=setup;', 'tse_base=tse;tse_bytes=tse_size;setup_base=setup;')
p.write_text(text, encoding='utf8')

production = [Path(rel) for rel in baseline if Path(rel).suffix in {'.c', '.h'}]
changed_production = [str(rel) for rel in production if sha(ORIGINAL / rel) != sha(TARGET / rel)]
assert changed_production == [str(Path('driver/platform.c'))]
diffs = []
for rel in baseline:
    if sha(ORIGINAL / rel) != sha(TARGET / rel):
        diffs.extend(difflib.unified_diff((ORIGINAL / rel).read_text(encoding='utf8').splitlines(True), (TARGET / rel).read_text(encoding='utf8').splitlines(True), fromfile='baseline/' + rel, tofile='HISTORY02/' + rel))
(HERE / 'history02_initial_source.diff').write_text(''.join(diffs), encoding='utf8')
report = {
    'baseline_directory': str(ORIGINAL),
    'target_directory': str(TARGET),
    'baseline_driver_sha256': sha(ORIGINAL / 'driver/build/AiTweakerLock1904.efi'),
    'baseline_source_sha256': baseline,
    'production_sources_changed': changed_production,
    'logic_source': str(SAGE / 'driver/platform.c'),
    'logic_source_sha256': sha(SAGE / 'driver/platform.c'),
    'change': 'Rebase native ACE navigation history to verified safe root when denying initial or stale protected page. Retain exact ACE 1904 module guards.',
    'originals_unchanged': all(sha(ORIGINAL / rel) == digest for rel, digest in baseline.items()),
    'test_scripts_copied_but_require_adaptation': 'verify_*.py and run_vm.py retain original paths/fixtures until parent adapts them; no old test results were copied.',
}
(HERE / 'history02_source_snapshot.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf8')
print(json.dumps({'copied_files': len(baseline), 'production_sources_changed': changed_production, 'originals_unchanged': report['originals_unchanged']}, indent=2))
