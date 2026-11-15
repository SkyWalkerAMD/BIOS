"""Bounded direct-provider fallback after a cancelled REA bridge stall."""
from pathlib import Path
import hashlib,json,os,subprocess,sys
OUT=Path(__file__).resolve().parent;ROOT=OUT.parents[2]
pe=ROOT/'analysis/hero_remote_bios_r3/reference/AB78D6A5-7E2A-47AA-9F32-780793C0DADB.efi'
sha=hashlib.sha256(pe.read_bytes()).hexdigest()
assert sha=='e1fd4b36c4bf60386b06d1b8fbe8c323735f1c1c110c2cb6ac0bf6e75df7d4b4'
work=OUT/'ghidra-direct';work.mkdir(exist_ok=True)
env=os.environ.copy();env['JAVA_HOME']='D:/JAVA/jdk-27'
env['TEMP']=str(work);env['TMP']=str(work)
for name in ('user','settings','cache','temp'):(work/name).mkdir(exist_ok=True)
phase=sys.argv[1] if len(sys.argv)>1 else 'first'
assert phase in ('first','leaves2','leaves3')
mode=['-import',str(pe)] if phase=='first' else ['-process',pe.name,'-noanalysis']
out={'first':'export','leaves2':'export2','leaves3':'export3'}[phase]
more={'first':[],'leaves2':['0x710c,0xe374,0xe18c,0x51b4,0x54d0,0xb14c,0xb428'],
      'leaves3':['0x6e18,0xe078,0x96a8,0x95ac,0x492c,0x4af4,0x4d50']}[phase]
cmd=['D:/JAVA/jdk-27/bin/java.exe','-Xmx2G','-Djava.awt.headless=true','-Djava.system.class.loader=ghidra.GhidraClassLoader',
     '-Duser.home='+str(work/'user'),'-Dapplication.settingsdir='+str(work/'settings'),
     '-Dapplication.cachedir='+str(work/'cache'),'-Djava.io.tmpdir='+str(work/'temp'),
     '-cp',str(ROOT/'tools/rea-hero-12.1.4/ghidra_12.1.4_PUBLIC/Ghidra/Framework/Utility/lib/Utility.jar'),
     'ghidra.Ghidra','ghidra.app.util.headless.AnalyzeHeadless',str(work),'InventoryLeaves',
     *mode,'-scriptPath',str(OUT),'-postScript','ExportInventoryLeaves.java',str(work/out),*more,
     '-analysisTimeoutPerFile','120','-log',str(work/f'analysis-{phase}.log'),'-scriptlog',str(work/f'script-{phase}.log')]
(work/f'provenance-{phase}.json').write_text(json.dumps(dict(target=str(pe),sha256=sha,provider='Ghidra 12.1.4 direct headless; not REA MCP',command=cmd,timeout_seconds=240),indent=2)+'\n')
with (work/f'stdout-{phase}.log').open('wb') as log:
 try:
  p=subprocess.run(cmd,env=env,stdout=log,stderr=subprocess.STDOUT,timeout=240,creationflags=subprocess.CREATE_NO_WINDOW)
  print('Direct Ghidra exit:',p.returncode)
 except subprocess.TimeoutExpired:
  print('Direct Ghidra timed out; incomplete output is not completed evidence.')
  raise
