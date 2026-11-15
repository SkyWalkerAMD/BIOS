"""One owned static REA session; never runs the selected firmware."""
from pathlib import Path
import json,os,queue,subprocess,threading,time
P=Path(__file__).resolve().parent;ROOT=P.parents[1];D=P/'rea-hwm';D.mkdir(exist_ok=True);T=D/'temp';T.mkdir(exist_ok=True)
NODE=ROOT/'tools/rea-runtime/node-v26.13.0-win-x64/node.exe';REA=ROOT/'tools/rea-runtime/node_modules/rea-agents/scripts/rea.mjs'
env=os.environ.copy();env.update(GHIDRA_INSTALL_DIR=str(ROOT/'tools/rea-hero-12.1.4/ghidra_12.1.4_PUBLIC'),JAVA_HOME='D:/JAVA/jdk-27',REA_ANALYSIS_PROVIDER='ghidra',TEMP=str(T),TMP=str(T),NO_COLOR='1')
proc=subprocess.Popen([str(NODE),str(REA),'mcp'],cwd=ROOT,env=env,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=(D/'stderr.txt').open('w'),text=True,encoding='utf-8',bufsize=1,creationflags=subprocess.CREATE_NO_WINDOW)
(D/'process.json').write_text(json.dumps(dict(controller_pid=os.getpid(),rea_pid=proc.pid))+'\n')
q=queue.Queue();counter=0
def reader():
 for line in proc.stdout:
  try:q.put(json.loads(line))
  except ValueError:q.put({'transport_text':line})
 q.put({'eof':True})
threading.Thread(target=reader,daemon=True).start()
def rpc(method,args,seconds=230):
 global counter
 counter+=1;i=counter;proc.stdin.write(json.dumps(dict(jsonrpc='2.0',id=i,method=method,params=args))+'\n');proc.stdin.flush();deadline=time.monotonic()+seconds;cancelled=False
 while time.monotonic()<deadline:
  if not cancelled and (D/'stop-session').exists() and args.get('name')!='close_binary':
   proc.stdin.write(json.dumps(dict(jsonrpc='2.0',method='notifications/cancelled',params=dict(requestId=i,reason='End owned bounded analysis')))+'\n');proc.stdin.flush();cancelled=True
  try:r=q.get(timeout=1)
  except queue.Empty:continue
  if r.get('id')==i:return r
  if r.get('eof'):raise RuntimeError('REA closed')
  with (D/'notifications.jsonl').open('a') as f:f.write(json.dumps(r)+'\n')
 raise TimeoutError(method)
try:
 r=rpc('initialize',dict(protocolVersion='2024-11-05',capabilities={},clientInfo=dict(name='hero-fan-static',version='1')),30);(D/'initialize.json').write_text(json.dumps(r,indent=2)+'\n')
 proc.stdin.write(json.dumps(dict(jsonrpc='2.0',method='notifications/initialized'))+'\n');proc.stdin.flush()
 r=rpc('tools/list',{},30);tools={x['name']:x for x in r['result']['tools']};(D/'used-tool-schemas.json').write_text(json.dumps({n:tools[n] for n in ('open_binary','batch_decompile','close_binary')},indent=2)+'\n')
 for name,args in [('open_binary',dict(provider_id='ghidra',path=str(P/'sources/HERO-3107-HWM.efi'))),('batch_decompile',dict(addresses=['0xe7c']))]:
  print('REA',name,flush=True);r=rpc('tools/call',dict(name=name,arguments=args));(D/(name+'.json')).write_text(json.dumps(r,indent=2)+'\n');print('saved',name,flush=True)
finally:
 if proc.poll() is None:
  try:r=rpc('tools/call',dict(name='close_binary',arguments={}),60);(D/'close.json').write_text(json.dumps(r,indent=2)+'\n')
  except Exception as e:(D/'close-error.txt').write_text(repr(e))
  proc.stdin.close()
  try:proc.wait(timeout=20)
  except subprocess.TimeoutExpired:proc.terminate();proc.wait(timeout=10)
 (D/'ended.json').write_text(json.dumps(dict(rea_exit_code=proc.poll(),completed_process=True))+'\n');print('REA owned session ended',flush=True)
