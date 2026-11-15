from pathlib import Path
import hashlib,json,shutil

HERE=Path(__file__).resolve().parent;TX=HERE.parent;D04=TX.parent
OLD=D04/'ram_test05_delivery_review/full_app_ui_9115f1afbab01b62'
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
APP_HASH='e0793175f78b6488c8222b65f0d5321d97e881bd06dca033a314d3fa8d307486'
source_app=TX/'app_build/SageNative13RamTest08.efi'
assert sha(source_app)==APP_HASH
IN=HERE/'inputs';IN.mkdir();(IN/'source').mkdir()
for p in (TX/'source').iterdir():
    if p.is_file():shutil.copyfile(p,IN/'source'/p.name)
for name in ['SageNative13RamTest08.efi','app.map','app_build.json']:
    shutil.copyfile(TX/'app_build'/name,IN/name)
for row in json.loads((IN/'app_build.json').read_text())['sources']:
    if (IN/row['path']).exists():assert sha(IN/row['path'])==row['sha256']
raw=(OLD/'test_full_app_ui.py').read_text(encoding='utf8')
raw=raw.replace('SageNative13RamTest05.efi','SageNative13RamTest08.efi')
raw=raw.replace("'app_hold_reason']:","'app_hold_reason','platform_native_globals']:")
raw=raw.replace("PE=HERE/'inputs/SageNative13RamTest08.efi';p=pefile.PE(str(PE))", "PE=HERE/'inputs/SageNative13RamTest08.efi';assert hashlib.sha256(PE.read_bytes()).hexdigest()=='"+APP_HASH+"';p=pefile.PE(str(PE))")
raw=raw.replace('self.query_tpl=None;self.query_tpl_at=1;self.query_count=0',
 '''self.query_tpl=None;self.query_tpl_at=1;self.query_count=0
        self.globals_fail_at=None;self.globals_count=0;self.on_globals=None''')
needle="        for address in set(self.handlers)|{STOP,EXPORT['app_hold'],EXPORT['app_log'],EXPORT['app_number'],EXPORT['app_result']}:"
assert needle in raw
raw=raw.replace(needle,"        self.handlers[EXPORT['platform_native_globals']]=self.fixture_globals\n"+needle)
needle='    def fixture_raise(self):'
assert needle in raw
raw=raw.replace(needle,'''    def fixture_globals(self):
        label=self.text(self.arg(1));self.globals_count+=1
        assert label==('UI_NATIVE_GLOBALS_BEFORE_SENDFORM' if self.globals_count%2 else 'UI_NATIVE_GLOBALS_AFTER_SENDFORM')
        self.boundary('NativeGlobalsModel:'+label)
        if self.on_globals:self.on_globals(self)
        self.ret(0 if self.globals_count==self.globals_fail_at else 1)
'''+needle)
raw=raw.replace("        self.putq(self.arg(7),self.send_action);self.ret(self.send_status)",
'''        assert self.q(self.arg(7))==0,'Caller must initialize ActionRequest NONE'
        if self.send_action is not None:self.putq(self.arg(7),self.send_action)
        self.ret(self.send_status)''')
raw=raw.replace('for when in [1,3]:','for when in [1,4]:')
marker='# Insert an actual app_ended transition at every mocked firmware boundary and'
extra='''# New08-specific boundaries. platform_native_globals itself is an explicit
# model here; its actual CPU/pagewalk/map implementation is tested separately.
def untouched_action():
    m=Model();m.prepare();m.send_action=None
    assert m.call('ui_open_management',m.session)==('RETURN',1)
    assert len(m.sent)==1 and m.globals_count==2 and not m.writes
case('ordinary native return leaving ActionRequest untouched accepts initialized NONE',untouched_action)

def globals_before_failure():
    m=Model();m.prepare();m.globals_fail_at=1
    assert m.call('ui_open_management',m.session)==('RETURN',0)
    assert not m.sent and not m.writes and m.globals_count==1
case('before native-globals read refusal does not enter SendForm',globals_before_failure)

def globals_after_failure():
    m=Model();m.prepare();m.globals_fail_at=2
    m.on_send=lambda x:x.vars.__setitem__(PRIVATE,(3,record()))
    assert m.call('ui_open_management',m.session)==('RETURN',0)
    assert len(m.sent)==1 and m.globals_count==2
    after=m.calls.index('NativeGlobalsModel:UI_NATIVE_GLOBALS_AFTER_SENDFORM')
    assert 'GetVariable:'+PRIVATE in m.calls[after+1:] and 'GetVariable:'+OC in m.calls[after+1:] and 'GetVariable:'+MEM in m.calls[after+1:]
    assert m.call('ui_restore_credential',m.session)==('RETURN',1) and len(m.writes)==1
case('post native-globals ordinary refusal still observes owned private record and stores for safe cleanup',globals_after_failure)

for kind in ['private','store','provider','ui_head','ended']:
    def check(kind=kind):
        m=Model();m.prepare()
        def changed(x):
            if x.globals_count!=1:return
            if kind=='private':x.vars[PRIVATE]=(3,record())
            if kind=='store':x.vars[OC]=(3,bytes(26681))
            if kind=='provider':x.putd(EXPORT['fixture_provider_flags'],32)
            if kind=='ui_head':x.putq(EXPORT['fixture_state'],1)
            if kind=='ended':x.putd(EXPORT['app_ended'],1)
        m.on_globals=changed
        result=m.call('ui_open_management',m.session)
        assert result[0]=='HOLD' if kind in ['ui_head','ended'] else result==('RETURN',0)
        assert not m.sent and not m.writes
    case('revalidation after before-globals detects '+kind+' before SendForm',check)

'''
assert marker in raw;raw=raw.replace(marker,extra+marker)
raw=raw.replace('UEFI/provider service endpoints and pure log sink are mocked.','UEFI/provider endpoints, platform_native_globals, and pure log sink are mocked.')
raw=raw.replace('The real P13 OVMF','The real P14 OVMF')
(HERE/'test_full_app_ui.py').write_text(raw,encoding='utf8',newline='\n')
build=HERE/'build';build.mkdir()
sources=[p for p in IN.rglob('*') if p.is_file()]
(build/'build.json').write_text(json.dumps({'no_app_recompilation':True,'actual_app_sha256':APP_HASH,'sources':[{'path':str(p),'bytes':p.stat().st_size,'sha256':sha(p)}for p in sources]},indent=2)+'\n')
(HERE/'origins.json').write_text(json.dumps({'reference':str(OLD/'test_full_app_ui.py'),'reference_sha256':sha(OLD/'test_full_app_ui.py'),'original_preserved':True,'actual_app_sha256':APP_HASH},indent=2)+'\n')
print('Actual TX08 app snapshotted; added explicit native-globals model and08 boundary cases')
