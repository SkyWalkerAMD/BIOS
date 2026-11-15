"""Replay selected frozen original OEM paths with the detached guard bytes.

Only bounded definition/assertion slices execute. Frozen report-writing tails
and recursive imports are excluded. All evidence is written in this directory.
"""
from pathlib import Path
import hashlib,json,sys
sys.dont_write_bytecode=True
from verify_split import make_namespace,HERE,OLD,BUILD,meta,sha

sources=set()
def piece(scope,path,start,finish,replace=None):
 text=path.read_text();at=text.index(start);end=text.index(finish,at)if finish else len(text)
 code=text[at:end]
 for a,b in (replace or {}).items():code=code.replace(a,b)
 sources.add(path)
 exec(compile(code,str(path)+' [bounded split fixture slice]','exec'),scope)

def setup_save(scope):
 piece(scope,OLD/'verify_native_save.py','HII_BASE=','\nchecks=[];v=SaveVM()',{'HII_BASE=0x30000000':'HII_BASE=0x38000000'})
def setup_commit(scope):
 setup_save(scope);piece(scope,OLD/'verify_native_commit.py','DATA=','\nchecks=[];v=CommitVM(True)')

def main():
 suites=[]
 for name,setup,start,finish in [
  ('verify_native_save.py',setup_save,'checks=[];v=SaveVM()','\nreport={'),
  ('verify_native_commit.py',setup_commit,'checks=[];v=CommitVM(True)','\nr={'),
  ('verify_hotkeys.py',lambda s:piece(s,OLD/'verify_hotkeys.py','class HotkeyVM','\nchecks=[]'),'checks=[]','\nr={'),
  ('verify_defaults_entries.py',lambda s:(piece(s,OLD/'verify_hotkeys.py','class HotkeyVM','\nchecks=[]'),piece(s,OLD/'verify_defaults_entries.py','class EntryVM','\nchecks=[];v=EntryVM()')),'checks=[];v=EntryVM()','\nr={'),
  ('verify_defaults.py',lambda s:piece(s,OLD/'verify_defaults.py','DATA=','\nchecks=[]'),'checks=[]','\nr={')]:
  scope=make_namespace();setup(scope);piece(scope,OLD/name,start,finish)
  suites.append({'source':str(OLD/name),'checks':len(scope['checks']),'check_names':scope['checks']})
  print(json.dumps({'suite':name,'checks':len(scope['checks'])}),flush=True)
 scope=make_namespace();setup_commit(scope)
 piece(scope,OLD.parent/'native_harness.py','COPY=',None)
 piece(scope,OLD.parent/'verify_save_scope.py','checks=[];cases=[]','\nr={')
 suites.append({'source':str(OLD.parent/'verify_save_scope.py'),'checks':len(scope['checks']),'check_names':scope['checks'],'cases':scope['cases']})
 report={'status':'PASS_SPLIT_GUARD_ORIGINAL_OEM_NATIVE_PATHS_WITH_SERVICE_MODELS','checks':sum(s['checks']for s in suites),'suites':suites,'split_build_sha256':sha(BUILD/'split_build.json'),'guard_sha256':{k:v['guard_sha256']for k,v in meta['module_fixtures'].items()},'test_source_sha256':sha(Path(__file__)),'fixture_adapter_sha256':sha(HERE/'verify_split.py'),'frozen_sources':{str(p):sha(p)for p in sorted(sources)},'fixture_adjustments':['HiiDatabase fixture mapping moved from 0x30000000 to 0x38000000 to avoid the detached guard allocation.','OEM original-sized headers/text and exact12 runtime detours replace old N12 memory images; old appended pages inaccessible.','Modeled frame-head lookup redirected to explicit detached state page. All original policy/assertion logic retained.'],'limits':['The original Setup routing/HiiDatabase parser, AMITSE direct commit, hotkey/default/event dispatch and save loop execute actual bytes in Unicorn.','Firmware services/variable persistence, provider/password acceptance, effect callbacks, some formatting/event/cache handlers and complete graphical browser remain explicit models.','Actual native save effects and feedback limits documented by the original tests still apply; original defaults can change RAM cache while later protected persistence is denied.','No physical hook transaction or ASUS UI acceptance; N12/P12 were not modified.']}
 (BUILD/'split_native_regression.json').write_text(json.dumps(report,indent=2)+'\n')
 print(json.dumps({'status':report['status'],'checks':report['checks']}))

if __name__=='__main__':main()
