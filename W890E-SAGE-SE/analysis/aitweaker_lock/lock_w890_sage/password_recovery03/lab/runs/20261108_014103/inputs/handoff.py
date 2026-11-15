"""Minimum working DPAPI-to-local-QEMU keyboard handoff; no BMC adapter.

Only encrypted journal data is read from disk. Passwords stay in this process
and individual local QMP keyboard events; requests are never logged. The caller
must have observed the isolated recovery carrier's ready marker before invoking
this API. A matching journal target is necessary, not a hardware identity proof.
"""
from pathlib import Path
import importlib.util,json,socket,sys,time
sys.dont_write_bytecode=True
SOURCE=Path(__file__).resolve().parent.parent/'password_runtime02/journal/durable_fixture.py'
spec=importlib.util.spec_from_file_location('w890_frozen_journal',SOURCE)
journal=importlib.util.module_from_spec(spec);spec.loader.exec_module(journal)

class LocalQmpKeyboard:
    def __init__(self,port,target):
        if not isinstance(port,int)or not 1<=port<=65535:raise ValueError('Invalid local test port')
        self.target=target;self.socket=socket.create_connection(('127.0.0.1',port),timeout=5)
        self.file=self.socket.makefile('rwb',buffering=0)
        if 'QMP'not in json.loads(self.file.readline()):raise RuntimeError('Local QMP greeting absent')
        self.command('qmp_capabilities')
    def command(self,name,arguments=None):
        message={'execute':name}
        if arguments is not None:message['arguments']=arguments
        self.file.write(json.dumps(message).encode('ascii')+b'\n')
        for _ in range(128):
            answer=json.loads(self.file.readline())
            if 'error'in answer:raise RuntimeError('Local keyboard command rejected; request not logged')
            if 'return'in answer:return answer['return']
        raise RuntimeError('Local keyboard response missing')
    def key(self,keys):
        self.command('send-key',{'keys':[{'type':'qcode','data':key}for key in keys],'hold-time':20})
        time.sleep(.055)
    def close(self):self.file.close();self.socket.close()

def deliver_candidate(path,target,candidate,keyboard):
    if type(keyboard)is not LocalQmpKeyboard or keyboard.target!=target or candidate not in ['before','after']:
        raise ValueError('Exact local test transport and journal target required')
    payload=journal.open_fixture(path,target)
    value=payload[candidate]
    # Validate the complete alphabet before sending any keystroke.
    if any(not(c.isascii()and(c.isalnum()or c in '-_'))for c in value):
        raise ValueError('Unsupported journal password alphabet; nothing typed')
    for char in value:
        if char.isupper():keys=['shift',char.lower()]
        elif char=='_':keys=['shift','minus']
        elif char=='-':keys=['minus']
        else:keys=[char]
        keyboard.key(keys)
    keyboard.key(['ret'])
    # No secret or secret digest is included in the result.
    return {'journal_id':payload['id'],'candidate':candidate,'status':'TYPED_IN_LOCAL_TEST_ONLY'}
