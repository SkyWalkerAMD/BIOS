"""Read builder literals without executing it; run its verifier under Windows PS5.1."""
import ast
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
FC = HERE.parent
BUILDER = FC / 'flashback_delivery/build_package.py'
POWERSHELL = Path('C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe')
code = BUILDER.read_bytes()
tree = ast.parse(code)
verify = next(ast.literal_eval(node.value) for node in tree.body if isinstance(node, ast.Assign)
              and any(isinstance(t, ast.Name) and t.id == 'VERIFY' for t in node.targets))
checks = []
ps_environment = os.environ.copy()
# The Codex app may pass its own PS7 module path through Python. Use the
# system PS5.1 module set, matching a normal Windows PowerShell launch.
ps_environment['PSModulePath'] = str(POWERSHELL.parent / 'Modules')


def sha(data):
    return hashlib.sha256(data).hexdigest()


with tempfile.TemporaryDirectory(prefix='ps51-review-', dir=HERE) as temp:
    base = Path(temp)
    verifier = base / 'Verify-Package.ps1'
    verifier.write_text(verify, encoding='ascii', newline='\n')
    parser = base / 'parse.ps1'
    parser.write_text("$tokens = $null\n$errors = $null\n"
                      "[void][System.Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot 'Verify-Package.ps1'), [ref]$tokens, [ref]$errors)\n"
                      "if ($errors.Count) { throw ($errors | Out-String) }\n"
                      "Write-Output ('PARSE_PASS_PS=' + $PSVersionTable.PSVersion.ToString())\n", encoding='ascii')
    run = subprocess.run([str(POWERSHELL), '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', str(parser)], capture_output=True, text=True, env=ps_environment)
    assert run.returncode == 0 and 'PARSE_PASS_PS=5.1' in run.stdout, (run.returncode, run.stdout, run.stderr)
    checks.append({'case': 'actual system Windows PowerShell5.1 parser', 'status': 'PASS', 'stdout': run.stdout.strip()})
    note = base / 'README.txt'
    note.write_text('实际 UTF-8 文本核对\n', encoding='utf8')
    normal = {'path': 'README.txt', 'bytes': note.stat().st_size, 'sha256': sha(note.read_bytes())}
    tests = [
        ('hash real UTF8 content then report missing CAP', [normal], 'Missing CAP:'),
        ('reject changed text hash', [{**normal, 'sha256': '0' * 64}], 'Hash mismatch:'),
        ('reject duplicate path', [normal, normal], 'Duplicate manifest path'),
        ('reject parent traversal', [{**normal, 'path': '../README.txt'}], 'Unsafe manifest path'),
        ('reject absolute drive path', [{**normal, 'path': 'C:/README.txt'}], 'Unsafe manifest path'),
    ]
    candidate = base / '01-CANDIDATE05-USB/PWW790A.CAP'
    candidate.parent.mkdir()
    candidate.write_bytes(b'short fixture, not firmware')
    tests.append(('reject short CAP even with internally correct listed SHA',
                  [{'path': '01-CANDIDATE05-USB/PWW790A.CAP', 'bytes': candidate.stat().st_size, 'sha256': sha(candidate.read_bytes())}],
                  'CAP identity mismatch:'))
    for name, files, expected in tests:
        (base / 'manifest.json').write_text(json.dumps({'schema': 'ace1904_flashback_field_package_v1', 'files': files}), encoding='utf8')
        run = subprocess.run([str(POWERSHELL), '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', str(verifier)], capture_output=True, text=True, env=ps_environment)
        assert run.returncode != 0 and expected in run.stderr, (name, run.returncode, run.stdout, run.stderr)
        checks.append({'case': name, 'status': 'PASS_REJECTED', 'error': expected})

report = {
    'status': 'PASS_STATIC_AND_WINDOWS_PS51_SMOKE', 'builder_sha256': sha(code),
    'builder_path': str(BUILDER), 'powershell_path': str(POWERSHELL), 'verifier_literal_sha256': sha(verify.encode('ascii')),
    'fixture_environment': 'PSModulePath set to system Windows PowerShell5.1 Modules; other environment inherited.',
    'initial_fixture_environment_failure': 'Codex PS7 ModulePath inherited through Python made Get-FileHash unavailable. A direct normal powershell.exe launch succeeded; verifier source unchanged.',
    'checks': checks, 'check_count': len(checks), 'builder_executed': False, 'actual_CAPs_copied': False,
    'full_valid_package_execution': 'Pending root package creation; will execute its actual verifier against all real members.',
    'boundary': 'This tests the ordinary Windows implementation and negative paths; it does not authenticate the independently distributed ZIP hash.',
    'static_findings': [
        'Pinned original-header candidate and official recovery remain in distinct directories with exact FlashBack names.',
        'Full 67112960-byte CAPs retained; engineering CAP used only for payload comparison.',
        'All package writes confined to fixed flashback_delivery output; existing package or ZIP rejected.',
        'Manifest lists content except itself and SHA256SUMS; SHA256SUMS includes manifest but not itself.',
        'README and manifest preserve untested physical FlashBack / permanent native DXE and original-signature limitations.',
    ],
}
output = HERE / 'builder_review.json'
output.write_text(json.dumps(report, indent=2, ensure_ascii=False) + '\n', encoding='utf8')
print(json.dumps({'status': report['status'], 'checks': len(checks), 'builder_sha256': sha(code), 'report_sha256': sha(output.read_bytes())}))
