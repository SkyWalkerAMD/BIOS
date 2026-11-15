"""Run installed Ghidra only against extracted static ELF artifacts."""
from pathlib import Path
import argparse,hashlib,json,subprocess,time
HERE=Path(__file__).resolve().parent;REMOTE=HERE.parent
ROOT=next(p for p in HERE.parents if (p/'tools/rea-runtime').is_dir())
GHIDRA=ROOT/'tools/rea-runtime/ghidra_12.1.4_PUBLIC'
JAVA=Path('D:/JAVA/graalvm-jdk-21.0.9+7.1/bin/java.exe')
def main():
    ap=argparse.ArgumentParser();ap.add_argument('label');ap.add_argument('binary',type=Path);ap.add_argument('regex');ap.add_argument('--process',action='store_true');a=ap.parse_args()
    assert a.label.replace('_','').isalnum()
    binary=a.binary.resolve();assert binary.is_relative_to((HERE/'backend').resolve())
    base=HERE/('ghidra_'+a.label);base.mkdir(exist_ok=True);out=HERE/(a.label+'_decompile')
    pattern=base/'selection.txt';pattern.write_text(a.regex,encoding='utf8')
    props=['-Djava.awt.headless=true']
    for k,n in [('user.home','home'),('application.settingsdir','settings'),('application.cachedir','cache'),('application.tempdir','tmp'),('java.io.tmpdir','tmp')]:
        p=base/n;p.mkdir(exist_ok=True);props.append('-D'+k+'='+str(p))
    vm=subprocess.run([str(JAVA),*props,'-cp',str(GHIDRA/'support/LaunchSupport.jar'),'LaunchSupport',str(GHIDRA),'-vmargs'],capture_output=True,text=True,check=True)
    project=base/'project';project.mkdir(exist_ok=True)
    action=['-process',binary.name,'-noanalysis'] if a.process else ['-import',str(binary)]
    argv=[str(JAVA),*vm.stdout.splitlines(),'-Xmx2G','-XX:ParallelGCThreads=2','-XX:CICompilerCount=2',*props,
          '-cp',str(GHIDRA/'Ghidra/Framework/Utility/lib/Utility.jar'),'ghidra.Ghidra','ghidra.app.util.headless.AnalyzeHeadless',
          str(project),'MediaAttach',*action,'-scriptPath',str(REMOTE),'-postScript','BmcSelectedDecompile.java',str(out),str(pattern),
          '-analysisTimeoutPerFile','120','-max-cpu','2','-log',str(base/'analysis.log'),'-scriptlog',str(base/'script.log')]
    stamp=str(time.time_ns());(base/(stamp+'.argv.json')).write_text(json.dumps(argv,indent=2),encoding='utf8')
    print('STATIC_START',a.label,flush=True)
    with (base/(stamp+'.stdout.log')).open('wb') as o:r=subprocess.run(argv,stdout=o,stderr=subprocess.STDOUT,timeout=360)
    print('STATIC_DONE',a.label,r.returncode,flush=True);raise SystemExit(r.returncode)
if __name__=='__main__':main()
