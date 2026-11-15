"""Read-only offline replay of the frozen TX08 credential ownership boundary.

This is not a recovery utility. All firmware services and persistent storage are
explicit memory models. No provider enrollment or real variable operation runs.
"""
from pathlib import Path
import hashlib,json,struct,sys
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent;D04=HERE.parent
SOURCE=D04/'ram_transaction08/ui_independent_review/test_full_app_ui.py'
PIN='e0793175f78b6488c8222b65f0d5321d97e881bd06dca033a314d3fa8d307486'
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
# Load only the frozen actual-PE model definitions, never its report-writing
# test driver. Keep its original __file__ so its pinned read-only inputs resolve.
definition=SOURCE.read_text().split('\nresults=[]\n',1)[0]
assert definition.endswith('Model=ActualFullAppModel\n')
ns={'__file__':str(SOURCE),'__name__':'frozen_tx08_model_definitions'}
exec(compile(definition,str(SOURCE),'exec'),ns)
Model=ns['Model'];record=ns['record'];PRIVATE=ns['PRIVATE'];EXPORT=ns['EXPORT']
assert sha(ns['PE'])==PIN
results=[]
def add(name,**facts):results.append({'case':name,'status':'PASS',**facts})

def fresh_boot(storage):
    fresh=Model();fresh.vars=dict(storage)
    assert fresh.call('ui_capture_initial')==('RETURN',0)
    assert fresh.call('ui_open_management',fresh.session)==('RETURN',0)
    assert fresh.call('ui_restore_credential',fresh.session)==('RETURN',0)
    assert not fresh.writes and not fresh.sent
    assert fresh.vars==storage
    assert fresh.calls.count('GetVariable:'+PRIVATE)==1
    assert len(fresh.owned_locations(storage[PRIVATE][1]))==0
    return fresh

for enabled in [True,False]:
    m=Model();m.vars[PRIVATE]=(3,record(enabled=enabled));fresh_boot(m.vars)
    add('fresh boot rejects '+('enabled' if enabled else 'disabled')+' record',
        capture_return=0,management_return=0,cleanup_return=0,
        private_queries=1,content_adopted=False,variable_writes=0)

class StoppedSendForm(Model):
    def fixture_send(self):
        # The browser/provider is intentionally NOT executed. Model the exact
        # adverse premise: a valid record is already committed, while the native
        # SendForm call has not returned. Stop at the external boundary.
        assert self.arg(3)==1 and self.arg(6)==0
        assert self.q(self.arg(2))==0x8888 and self.arg(5)==1
        assert self.q(self.arg(7))==0
        self.boundary('OriginalSendForm:not-returned-model')
        self.vars[PRIVATE]=(3,record())
        self.stopped_at_send=True;self.u.emu_stop()
    def stop_in_management(self):
        sp=ns['STACK']+0x1ef88
        self.u.mem_write(sp,b'\0'*256);self.putq(sp,ns['STOP'])
        self.u.reg_write(ns['UC_X86_REG_RSP'],sp)
        self.u.reg_write(ns['UC_X86_REG_EFLAGS'],0x202)
        self.u.reg_write(ns['UC_X86_REG_RCX'],self.session)
        self.u.emu_start(EXPORT['ui_open_management'],ns['STOP'],count=20000000)
        assert self.error is None and self.stopped_at_send
        assert self.u.reg_read(ns['UC_X86_REG_RIP'])==EXPORT['fixture_send']

m=StoppedSendForm();m.stopped_at_send=False;m.prepare();m.stop_in_management()
assert not m.writes and not m.owned_locations(record())
assert not any(label=='private record observed only in RAM without contents or digest' for label,_ in m.logs)
assert m.calls[-1]=='OriginalSendForm:not-returned-model'
fresh_boot(m.vars)
add('modeled persistence inside non-returning SendForm leaves no app receipt',
    actual_app_entry_executed='ui_open_management',native_browser_executed=False,
    storage_write='modeled external premise, not an executed provider write',
    stopped_before_SendForm_return=True,post_UI_observation_executed=False,
    app_owned_record_copies=0,fresh_boot_cleanup_return=0,app_variable_writes=0)

for condition in ['ui_head','save_head']:
    m=Model();m.prepare();m.on_send=lambda x:x.vars.__setitem__(PRIVATE,(3,record()))
    m.after_send_condition=condition
    result=m.call('ui_open_management',m.session)
    assert result==('HOLD',0x55350001)
    assert not m.writes and not m.owned_locations(record())
    fresh_boot(m.vars)
    add('returned browser with '+condition+' nonempty stops before receipt',
        app_result=list(result),owned_record_copies=0,fresh_boot_cleanup_return=0,
        services_and_native_browser='models',variable_writes=0)

for tpl in [8,16,31]:
    m=Model();m.prepare()
    def write_and_raise(x):x.vars[PRIVATE]=(3,record());x.tpl=tpl
    m.on_send=write_and_raise
    result=m.call('ui_open_management',m.session)
    assert result==('HOLD',0x55350003)
    assert not m.writes and not m.owned_locations(record())
    fresh_boot(m.vars)
    add('returned browser TPL '+str(tpl)+' stops before receipt',
        app_result=list(result),owned_record_copies=0,fresh_boot_cleanup_return=0,
        services_and_native_browser='models',variable_writes=0)

m=Model();m.prepare();m.enroll()
assert len(m.owned_locations(record()))==1
assert m.call('ui_restore_credential',m.session)==('RETURN',1)
assert m.writes==['DELETE_FIXED_PRIVATE'] and PRIVATE not in m.vars
add('normal browser return permits existing exact-owned cleanup',
    captured_record_copies_before_cleanup=1,cleanup_return=1,
    writes=['modeled one fixed private deletion'],absence_read_back=True)

m=Model();m.prepare();m.enroll();assert len(m.owned_locations(record()))==1
fresh_boot(m.vars)
add('even a previously captured receipt is lost across a fresh app instance',
    old_RAM_owned_copies=1,new_RAM_owned_copies=0,
    fresh_boot_cleanup_return=0,variable_writes=0)

m=Model();m.prepare();m.enroll();m.on_send=lambda x:x.vars.__setitem__(PRIVATE,(3,record(2,False)))
assert m.call('ui_open_management',m.session)==('RETURN',1)
assert m.vars[PRIVATE][1]==record(2,False)
assert m.call('ui_restore_credential',m.session)==('RETURN',1)
assert PRIVATE not in m.vars and m.writes==['DELETE_FIXED_PRIVATE']
add('disabled record is removable only after ordinary post-UI ownership observation',
    disabled_record_was_present=True,cleanup_return=1,
    writes=['modeled one fixed private deletion'])

report={'status':'PASS_FROZEN_ACTUAL_APP_COUNTEREXAMPLES_AND_POSITIVE_CONTROL',
 'cases':len(results),'results':results,
 'scope':[
  'Frozen exact TX08 e079 full PE machine code for UI entry, receipt, initial refusal and cleanup.',
  'UEFI services, HII, provider query, original SendForm and storage are explicit memory models.',
  'The non-returning browser case establishes a conditional gap; it does not prove a real password write or C11 failure cause.',
  'No recovery app, new credential behavior, live BMC, filesystem-on-host or real firmware setter is implemented or invoked.'
 ],'bindings':[{'path':str(p.relative_to(D04)),'sha256':sha(p)} for p in [SOURCE,ns['PE'],SOURCE.parent/'inputs/app.map',HERE/'replay_recovery_gap.py']]}
(HERE/'actual_app_recovery_gap.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps({'status':report['status'],'cases':len(results),'report_sha256':sha(HERE/'actual_app_recovery_gap.json')}))
