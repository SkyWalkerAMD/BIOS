"""Run installed static LuaJIT decoder on selected pinned files, never Lua."""
from pathlib import Path
import hashlib,json,subprocess,sys
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent
ROOT=next(p for p in HERE.parents if (p/'tools/luajit-decompiler/main.py').is_file())
PREFIX=HERE/'official_inputs/5308416/usr/local'
SELECT={
 'manager':'redfish/redfish/manager.lua',
 'manager_metadata':'redfish/redfish/resource_metadata/ManagersInstance.lua',
 'actioninfo':'redfish/redfish/actioninfo/reset-actioninfo.lua',
 'BMC':'sync-agent/extensions/ipmi/sync-helpers/BMC.lua',
 'ipmi_general':'sync-agent/extensions/ipmi/libipmi/general.lua',
 'factory_reset':'redfish/oem/ami/factory-reset.lua',
 'factory_actioninfo':'redfish/oem/ami/actioninfo/factoryreset-actioninfo.lua',
 'intermediate_map':'sync-agent/extensions/ipmi/redfish_intermediate_map.lua'}
sha=lambda b:hashlib.sha256(b).hexdigest()
def main():
 out=HERE/'lua';out.mkdir(exist_ok=True);rows=[]
 for label,relative in SELECT.items():
  p=PREFIX/relative;dest=out/(label+'.lua')
  argv=[sys.executable,'-B','-X','utf8',str(ROOT/'tools/luajit-decompiler/main.py'),'-f',str(p),'-o',str(dest),'--unsafe','false']
  r=subprocess.run(argv,capture_output=True,text=True,encoding='utf8',errors='replace',timeout=90)
  (out/(label+'.decompile.log')).write_text(r.stdout+'\n'+r.stderr,encoding='utf8')
  asm_argv=[sys.executable,'-B','-X','utf8',str(ROOT/'tools/luajit-decompiler/main.py'),'-f',str(p),'--asm']
  a=subprocess.run(asm_argv,capture_output=True,text=True,encoding='utf8',errors='replace',timeout=90)
  (out/(label+'.asm.txt')).write_text(a.stdout,encoding='utf8')
  (out/(label+'.asm-errors.txt')).write_text(a.stderr,encoding='utf8')
  rows.append({'name':label,'input':str(p),'input_sha256':sha(p.read_bytes()),'decompile_return':r.returncode,'asm_return':a.returncode,
               'output':str(dest),'output_sha256':sha(dest.read_bytes()) if dest.exists() else None,
               'decompile_argv':argv,'asm_argv':asm_argv})
  print(label,r.returncode,a.returncode)
 (HERE/'lua_decode_manifest.json').write_text(json.dumps({'scope':'Static decode only; no BMC Lua code loaded or executed','tool':str(ROOT/'tools/luajit-decompiler/main.py'),'tool_sha256':sha((ROOT/'tools/luajit-decompiler/main.py').read_bytes()),'files':rows},indent=2),encoding='utf8')
if __name__=='__main__':main()
