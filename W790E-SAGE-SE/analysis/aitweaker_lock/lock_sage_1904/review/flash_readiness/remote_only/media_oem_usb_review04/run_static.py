"""Installed Ghidra static analysis of one isolated original EFI only."""
from pathlib import Path
import argparse,json,subprocess,time
HERE=Path(__file__).resolve().parent;REMOTE=HERE.parent
ROOT=next(p for p in HERE.parents if (p/'tools/rea-runtime').is_dir())
GHIDRA=ROOT/'tools/rea-runtime/ghidra_12.1.4_PUBLIC'
JAVA=Path('D:/JAVA/graalvm-jdk-21.0.9+7.1/bin/java.exe')

def main():
    ap=argparse.ArgumentParser();ap.add_argument('regex');ap.add_argument('--process',action='store_true');ap.add_argument('--guid',default='580DD900-385D-11D7-883A-00500473D4EB');a=ap.parse_args()
    assert len(a.guid)==36 and all(c in '0123456789abcdefABCDEF-' for c in a.guid)
    binary=HERE/(a.guid+'.efi')
    label={'580DD900-385D-11D7-883A-00500473D4EB':'uhcd','171F43DC-C4D9-47A6-9641-65DDCDD5AA30':'usbrtdxe','04EAAAA1-29A1-11D7-8838-00500473D4EB':'usbrtsmm'}[a.guid]
    base=HERE/('ghidra' if label=='uhcd' else 'ghidra_'+label);base.mkdir(exist_ok=True);out=HERE/(label+'_decompile')
    pattern=base/'selection.txt';pattern.write_text(a.regex,encoding='utf8')
    props=['-Djava.awt.headless=true']
    for k,n in [('user.home','home'),('application.settingsdir','settings'),('application.cachedir','cache'),('application.tempdir','tmp'),('java.io.tmpdir','tmp')]:
        p=base/n;p.mkdir(exist_ok=True);props.append('-D'+k+'='+str(p))
    vm=subprocess.run([str(JAVA),*props,'-cp',str(GHIDRA/'support/LaunchSupport.jar'),'LaunchSupport',str(GHIDRA),'-vmargs'],capture_output=True,text=True,check=True)
    project=base/'project';project.mkdir(exist_ok=True)
    action=['-process',binary.name,'-noanalysis'] if a.process else ['-import',str(binary)]
    argv=[str(JAVA),*vm.stdout.splitlines(),'-Xmx2G','-XX:ParallelGCThreads=2','-XX:CICompilerCount=2',*props,
          '-cp',str(GHIDRA/'Ghidra/Framework/Utility/lib/Utility.jar'),'ghidra.Ghidra','ghidra.app.util.headless.AnalyzeHeadless',
          str(project),'OemUsb',*action,'-scriptPath',str(REMOTE),'-postScript','BmcSelectedDecompile.java',str(out),str(pattern),
          '-analysisTimeoutPerFile','120','-max-cpu','2','-log',str(base/'analysis.log'),'-scriptlog',str(base/'script.log')]
    stamp=str(time.time_ns());(base/(stamp+'.argv.json')).write_text(json.dumps(argv,indent=2),encoding='utf8')
    print('STATIC_START',flush=True)
    with (base/(stamp+'.stdout.log')).open('wb') as o:r=subprocess.run(argv,stdout=o,stderr=subprocess.STDOUT,timeout=240)
    print('STATIC_DONE',r.returncode,flush=True);raise SystemExit(r.returncode)
if __name__=='__main__':main()
