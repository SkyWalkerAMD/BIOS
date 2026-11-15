"""Run installed Ghidra statically using argv (no shell/batch interpolation)."""
from pathlib import Path
import argparse
import json
import subprocess
import time

HERE = Path(__file__).resolve().parent
ROOT = next(p for p in HERE.parents if (p / 'tools/rea-runtime').is_dir())
GHIDRA = ROOT / 'tools/rea-runtime/ghidra_12.1.4_PUBLIC'
JAVA = Path('D:/JAVA/graalvm-jdk-21.0.9+7.1/bin/java.exe')

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('label')
    parser.add_argument('binary', type=Path)
    parser.add_argument('pattern_file', type=Path)
    parser.add_argument('--process', action='store_true')
    args = parser.parse_args()
    assert args.label.replace('_', '').replace('-', '').isalnum()
    base = HERE / ('ghidra-' + args.label)
    base.mkdir(exist_ok=True)
    props = ['-Djava.awt.headless=true']
    for key, folder in [('user.home', 'home'), ('application.settingsdir', 'settings'),
                        ('application.cachedir', 'cache'), ('application.tempdir', 'tmp'), ('java.io.tmpdir', 'tmp')]:
        p = base / folder
        p.mkdir(exist_ok=True)
        props.append('-D' + key + '=' + str(p))
    vm = subprocess.run([str(JAVA), *props, '-cp', str(GHIDRA/'support/LaunchSupport.jar'),
                         'LaunchSupport', str(GHIDRA), '-vmargs'], capture_output=True, text=True, check=True)
    project = base / 'project'
    project.mkdir(exist_ok=True)
    output = HERE / (args.label + '_decompile')
    action = ['-process', args.binary.name, '-noanalysis'] if args.process else ['-import', str(args.binary.resolve())]
    argv = [str(JAVA), *vm.stdout.splitlines(), '-Xmx2G', '-XX:ParallelGCThreads=2', '-XX:CICompilerCount=2', *props,
            '-cp', str(GHIDRA/'Ghidra/Framework/Utility/lib/Utility.jar'), 'ghidra.Ghidra',
            'ghidra.app.util.headless.AnalyzeHeadless', str(project), 'SageBmc', *action,
            '-scriptPath', str(HERE), '-postScript', 'BmcSelectedDecompile.java', str(output),
            str(args.pattern_file.resolve()), '-analysisTimeoutPerFile', '150', '-max-cpu', '2',
            '-log', str(base/'analysis.log'), '-scriptlog', str(base/'script.log')]
    stamp = str(time.time_ns())
    (base/(stamp+'.argv.json')).write_text(json.dumps(argv, indent=2), encoding='utf-8')
    print('STATIC_START', args.label, flush=True)
    with (base/(stamp+'.stdout.log')).open('wb') as out:
        proc = subprocess.run(argv, stdout=out, stderr=subprocess.STDOUT, timeout=420)
    print('STATIC_DONE', args.label, 'exit', proc.returncode, 'log', base/(stamp+'.stdout.log'), flush=True)
    raise SystemExit(proc.returncode)

if __name__ == '__main__':
    main()
