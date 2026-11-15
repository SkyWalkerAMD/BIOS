"""Selected original native reset functions; no target code execution."""
from pathlib import Path
import hashlib,importlib.util,json,re,sys
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent;BASE=HERE.parent
spec=importlib.util.spec_from_file_location('native_reader',BASE/'update_chain_review05/inspect_chain.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
SOURCES={
 'handler':('lib/libipmimsghndlr.so.13.22.37',r'^(ColdReset|WarmReset|RestartBMC|PendCmdTask|InitPendCmdHndlrTable|MsgHndlr)$'),
 'pdk':('lib/libipmipdk.so.13.8.7',r'^(PDK_(BeforeBMCColdReset|BeforeBMCWarmReset|ColdResetBMC|WarmResetBMC|ResetChassis|BeforeResetChassis|AfterResetChassis))$'),
 'stack':('lib/libipmistack.so.13.13.12',r'^(Platform_ColdReset|Platform_WarmReset|Platform_HostColdReset|inform_reset_event_to_vmedia|inform_platform_reset|InitPDKHooks)$'),
 'main':('bin/IPMIMain',r'^(SwapWarmReset|Host_Reset_function)$')}
sha=lambda b:hashlib.sha256(b).hexdigest()
def main():
 result={}
 for label,(relative,pattern) in SOURCES.items():
  p=HERE/'official_inputs/5308416/usr/local'/relative;e=m.Elf32(p)
  outdir=HERE/'native'/label;outdir.mkdir(parents=True,exist_ok=True)
  rows={}
  for sym in m.functions(e,pattern):
   row,text=m.disassemble(e,sym);rows[sym['name']]=row
   (outdir/(sym['name']+'.txt')).write_text(text,encoding='utf8')
  result[label]={'path':str(p),'sha256':sha(e.data),'functions':rows}
  print(label,[(n,hex(v['symbol']['va'])) for n,v in rows.items()])
 (HERE/'native_analysis.json').write_text(json.dumps(result,indent=2),encoding='utf8')
if __name__=='__main__':main()
