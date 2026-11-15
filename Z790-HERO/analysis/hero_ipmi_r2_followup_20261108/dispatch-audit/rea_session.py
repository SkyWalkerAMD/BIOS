"""Own one local REA stdio session; persist explicit request/response evidence.

Commands are files created by this investigation in commands/. No executable
target is launched: selected REA operations are static native analysis only.
"""
from pathlib import Path
import json, os, queue, subprocess, threading, time, traceback, sys
BASE = Path(__file__).resolve().parent; ROOT = BASE.parents[2]
OUT = BASE / sys.argv[1] if len(sys.argv)>1 else BASE
assert OUT.resolve().is_relative_to(BASE.resolve())
OUT.mkdir(exist_ok=True)
COMMANDS = OUT / 'commands'; COMMANDS.mkdir(exist_ok=True)
RESPONSES = OUT / 'responses'; RESPONSES.mkdir(exist_ok=True)
TEMP = OUT / 'runtime-temp'; TEMP.mkdir(exist_ok=True)
NODE = ROOT / 'tools/rea-runtime/node-v26.13.0-win-x64/node.exe'
REA = ROOT / 'tools/rea-runtime/node_modules/rea-agents/scripts/rea.mjs'
env = os.environ.copy()
env.update(GHIDRA_INSTALL_DIR=str(ROOT / 'tools/rea-hero-12.1.4/ghidra_12.1.4_PUBLIC'),
           JAVA_HOME='D:/JAVA/jdk-27', REA_ANALYSIS_PROVIDER='ghidra',
           TEMP=str(TEMP), TMP=str(TEMP), NO_COLOR='1')
if (OUT/'seeds.tsv').exists(): env['REA_GHIDRA_SEED_FILE'] = str(OUT/'seeds.tsv')
proc = subprocess.Popen([str(NODE), str(REA), 'mcp'], cwd=ROOT, env=env,
    stdin=subprocess.PIPE, stdout=subprocess.PIPE,
    stderr=(OUT / 'rea-stderr.log').open('w', encoding='utf-8'),
    text=True, encoding='utf-8', bufsize=1, creationflags=subprocess.CREATE_NO_WINDOW)
(OUT/'process.json').write_text(json.dumps({'controller_pid':os.getpid(),'rea_pid':proc.pid,
    'node':str(NODE),'entry':str(REA),'provider':env['GHIDRA_INSTALL_DIR'],'temp':str(TEMP)},indent=2)+'\n')
messages = queue.Queue()
def reader():
    for line in proc.stdout:
        try: messages.put(json.loads(line))
        except ValueError: messages.put({'transport_text': line})
    messages.put({'transport_eof': True})
threading.Thread(target=reader, daemon=True).start()
serial = 0
def rpc(method, params, timeout=900):
    global serial
    serial += 1; request = {'jsonrpc':'2.0','id':serial,'method':method,'params':params}
    proc.stdin.write(json.dumps(request) + '\n'); proc.stdin.flush()
    end = time.monotonic() + timeout; cancelled = False
    while time.monotonic() < end:
        if not cancelled and method=='tools/call' and params.get('name')!='close_binary' and (OUT/'stop-session').exists():
            proc.stdin.write(json.dumps({'jsonrpc':'2.0','method':'notifications/cancelled',
                'params':{'requestId':serial,'reason':'Caller requested owned-session shutdown.'}})+'\n')
            proc.stdin.flush(); cancelled=True
        try: value = messages.get(timeout=min(2, end-time.monotonic()))
        except queue.Empty: continue
        if value.get('id') == serial: return value
        with (OUT / 'notifications.jsonl').open('a', encoding='utf-8') as f:
            f.write(json.dumps(value) + '\n')
        if value.get('transport_eof'): raise RuntimeError('REA connection closed')
    raise TimeoutError(method)
try:
    init = rpc('initialize', {'protocolVersion':'2024-11-05','capabilities':{},
              'clientInfo':{'name':'hero-firmware-static-investigation','version':'1'}}, 30)
    (OUT / 'initialize.json').write_text(json.dumps(init,indent=2)+'\n')
    proc.stdin.write(json.dumps({'jsonrpc':'2.0','method':'notifications/initialized'})+'\n'); proc.stdin.flush()
    catalog = rpc('tools/list', {}, 30)
    (OUT / 'tool-catalog.json').write_text(json.dumps(catalog,indent=2)+'\n')
    print('REA session ready; canonical tool catalog saved.', flush=True)
    last = time.monotonic()
    while not (OUT / 'stop-session').exists() and time.monotonic()-last < 1800:
        pending = [p for p in sorted(COMMANDS.glob('*.json')) if not (RESPONSES/p.name).exists()]
        if not pending:
            time.sleep(.2); continue
        for path in pending:
            request = json.loads(path.read_text())
            started = time.monotonic()
            print('Running', path.name, request.get('name'), flush=True)
            assert request['name'] in ('list_procedures','binary_session','open_binary','batch_decompile','procedure_pseudo_code',
                'procedure_info','procedure_callers','procedure_callees','read_bytes','read_function_instructions',
                'procedure_references','resolve_containing_procedure','export_evidence_bundle','close_binary',
                'inspect_analysis_view','inspect_analysis_settings','update_analysis_settings')
            response = rpc('tools/call', request)
            elapsed = time.monotonic()-started
            (RESPONSES/path.name).write_text(json.dumps(response,indent=2)+'\n',encoding='utf-8')
            print('Saved', path.name, f'{elapsed:.1f}s', flush=True)
            last = time.monotonic()
finally:
    if proc.poll() is None:
        try:
            result = rpc('tools/call', {'name':'close_binary','arguments':{}}, 60)
            (OUT/'close-finally.json').write_text(json.dumps(result,indent=2)+'\n')
        except Exception: traceback.print_exc()
        try: proc.stdin.close()
        except OSError: pass
        try: proc.wait(timeout=45)
        except subprocess.TimeoutExpired: proc.terminate(); proc.wait(timeout=10)
    print('REA session stopped.', flush=True)
