"""Same independent edge matrix on the exact final linked app, not a carrier.

The real inventory refuses absent modeled service methods before CPU discovery.
Only UEFI service calls are modeled. No app entry or target code runs natively.
"""
import hashlib
import importlib.util
import json
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
TX = HERE.parent / 'ram_transaction08'
BASE = 0x140000000

def sha(p): return hashlib.sha256(p.read_bytes()).hexdigest()

def main():
    if len(sys.argv) != 2 or not re.fullmatch('[0-9a-f]{64}', sys.argv[1]):
        raise SystemExit('Usage: verify_final_app_entry.py EXPECTED_FINAL_EFI_SHA256')
    expected = sys.argv[1]
    source = TX / 'app_build/SageNative13RamTest08.efi'
    assert sha(source) == expected
    dest = HERE / ('final_app_edges_' + expected[:16])
    dest.mkdir(exist_ok=True)
    efi = dest / source.name
    efi.write_bytes(source.read_bytes())
    linkmap = dest / 'app.map'
    linkmap.write_bytes((TX / 'app_build/app.map').read_bytes())
    buildpath = TX / 'app_build/app_build.json'
    build = json.loads(buildpath.read_text())
    assert build['efi_sha256'] == expected
    (dest / 'app_build.json').write_bytes(buildpath.read_bytes())
    for row in build['sources']:
        assert sha(TX / row['path']) == row['sha256'], row['path']
    for name, digest in build['objects'].items():
        assert sha(TX / 'app_build' / name) == digest, name
    harness = HERE / 'verify_app_entry_edges.py'
    spec = importlib.util.spec_from_file_location('independent_entry_fixture', harness)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    pe = module.pefile.PE(str(efi))
    symbols = {name: int(address, 16) - pe.OPTIONAL_HEADER.ImageBase + BASE
               for name, address in re.findall(r'^\s+[0-9A-Fa-f]{4}:[0-9A-Fa-f]+\s+(\S+)\s+([0-9A-Fa-f]{16})', linkmap.read_text(), re.M)}
    cases = []
    for ending in ['create', 'create_ex', 'watchdog', 'attribute', 'clear', 'output', 'input']:
        for failed in (False, True):
            vm = module.VM(efi, symbols, ending=ending, failed=ending if failed else None)
            result = vm.run()
            assert result == ('resident_hold', 0xe0000001) and not vm.after_end
            cases.append({'case': f'ending during {ending}, return ' + ('error' if failed else 'success'),
                          'status': 'PASS', 'result': result, 'firmware_calls': vm.calls,
                          'calls_after_ending': vm.after_end})
    for label, kwargs, expected_result in [
        ('normal create failure without event', {'failed': 'create'}, ('returned', module.ERR(7))),
        ('create failure with nonzero event', {'failed': 'create', 'failure_handle': True}, ('resident_hold', 0xe000000f)),
        ('create_ex failure after registered exit callback', {'failed': 'create_ex'}, ('resident_hold', 0xe0000010)),
        ('watchdog method missing', {'missing': 'watchdog'}, ('resident_hold', 0xe0000012)),
        ('watchdog disable failure', {'failed': 'watchdog'}, ('resident_hold', 0xe0000013)),
        ('actual platform refusal menu stays resident', {}, ('menu_reached', 0)),
    ]:
        vm = module.VM(efi, symbols, **kwargs)
        result = vm.run()
        assert result == expected_result, (label, result)
        cases.append({'case': label, 'status': 'PASS', 'result': result, 'firmware_calls': vm.calls})
    assert sha(source) == expected and sha(buildpath) == sha(dest / 'app_build.json')
    result = {
        'status': 'PASS_EXACT_LINKED_APP_ENTRY_AND_ENDING_PATHS_WITH_MODELED_UEFI',
        'efi_sha256': expected, 'build_sha256': sha(buildpath), 'map_sha256': sha(linkmap),
        'cases': len(cases), 'records': cases,
        'test_source_sha256': sha(Path(__file__)), 'fixture_source_sha256': sha(harness),
        'sources_and_objects_verified_against_build': True,
        'recompiled_or_relinked_app': False,
        'limits': [
            'Only PE bytes execute in Unicorn; UEFI methods/event delivery are explicit models.',
            'The exact original platform_inventory executes and refuses because fixture service pointers needed for discovery are absent. No adapter or inventory implementation is replaced.',
            'No original ASUS module patch, provider entry, UI password operation or QR presentation is performed in this matrix.',
            'These checks do not replace final ISO boot/refusal smoke, full adapter validation, or physical acceptance.',
        ],
    }
    out = dest / 'result.json'
    out.write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({'status': result['status'], 'efi_sha256': expected, 'cases': len(cases), 'report': str(out), 'sha256': sha(out)}))

if __name__ == '__main__': main()
