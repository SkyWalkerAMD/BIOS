"""Additional actual-PE cases, without rebuilding or modifying TX05.

Uses the author's explicit TPL/validator model, preserving those limitations.
Focus: removal/prepare termination, stale state, relocation boundaries and a
hardware permission-fault counterexample that cannot be inferred from status
return models. No target EFI is executed by Windows or a physical machine.
"""
from pathlib import Path
from datetime import datetime, timezone
import hashlib, importlib.util, json, struct, sys
sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
D04 = HERE.parent
TX = D04/'ram_transaction05'
BUILD = TX/'build'


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    expected = '3a04ddeca96cd62d4cbad9a453735cfb096f98f7e1731579c7ce938eaeb47767'
    assert sha(BUILD/'TransactionCore05.TESTONLY.efi') == expected
    spec = importlib.util.spec_from_file_location('tx05_author_model', TX/'verify_transaction.py')
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    model_sha = sha(TX/'verify_transaction.py')
    records = []

    def record(name, vm, returned, condition, detail):
        assert condition, name
        records.append({'case': name, 'status': 'PASS_EXPECTED_BOUNDARY', 'return': returned,
                        'TPL': vm.tpl, 'transaction_phase': vm.getd(m.CTX+8),
                        'ended': vm.getd(m.CTX+16), 'held': vm.getd(m.CTX+20),
                        'state_phase': vm.getd(m.STATE+24), 'target_stores': len(vm.writes),
                        'service_model_calls': vm.calls, 'meaning': detail})

    v=m.VM();v.ending='validate';out=v.prepare()
    record('EBS during prepare validation',v,out,out==5 and not v.writes and v.getd(m.CTX+16)==1,
           'No published target exists. State phase may remain armed because ownership was not yet committed; ended rejects later install.')
    before=list(v.calls);assert v.install()==5 and v.calls==before
    for where in ['raise','validate','restore']:
        v=m.VM();assert v.prepare()==0 and v.install()==0
        v.writes=[];v.calls=[];v.ending=where;out=v.remove()
        record('EBS during remove '+where,v,out,out==5 and v.getd(m.CTX+16)==1 and v.getd(m.STATE+24)==3,
               'Terminal outcome retains code/state. Restore-boundary case has restored originals; earlier cases keep installed sites.')
        assert v.exact(where!='restore')
        assert v.tpl==(4 if where=='restore' else 31)
        before=list(v.calls);assert v.install()==5 and v.remove()==5 and v.calls==before

    class NestedRemove(m.VM):
        def code(self,u,a,n,data):
            if a==m.VALIDATE and self.validations==3:
                self.validations+=1;self.calls.append(('validate',self.arg(1),self.tpl))
                self.callback_call('tx_remove',1);return
            super().code(u,a,n,data)
    v=NestedRemove();assert v.prepare()==0 and v.install()==0;out=v.remove()
    record('Remove reentry during removal prevalidation',v,out,
           out==2 and v.getq(m.RESULT)==3 and v.exact() and v.tpl==4,
           'Actual nested tx_remove returns BUSY; outer rollback completes.')

    for label, offset, data in [('retired state',24,m.d(2)),('ended state without tx_end',24,m.d(3)),
                               ('active UI head',0,m.q(0xdead0000)),('active save head',8,m.q(0xdead0000))]:
        v=m.VM();assert v.prepare()==0;v.u.mem_write(m.STATE+offset,data);out=v.install()
        record('Before install: '+label,v,out,out==1 and not v.writes and v.exact() and v.tpl==4,
               'Guard publication refuses stale/active private state without OEM writes.')

    for label, offset, data in [('bad magic',16,m.q(0)),('reserved bit',28,m.d(1))]:
        v=m.VM();assert v.prepare()==0 and v.install()==0
        v.writes=[];v.u.mem_write(m.STATE+offset,data);out=v.remove()
        record('Removal with '+label,v,out,out==3 and not v.writes and v.exact(True) and v.tpl==4,
               'Current API reports BUSY for malformed state as well as active heads. App must not treat BUSY as permission to free or return.')

    for label, offset, value in [('noncanonical module',0,1<<47),
                                ('unaligned guard',32,v.guard[0]+1),
                                ('guard overlap state',32,m.STATE),
                                ('rel32 guard too distant',32,0x900000000)]:
        v=m.VM();v.u.mem_write(m.PLAN+offset,m.q(value));out=v.prepare()
        record(label,v,out,out==1 and not v.writes and v.exact(),
               'No target stores; rel32 bound is checked independently of host validation.')

    v=m.VM();assert v.prepare()==0
    first=m.meta['patches'][0];address=int(first['address'],16)
    v.u.mem_protect(address&~4095,4096,m.U.UC_PROT_READ|m.U.UC_PROT_EXEC)
    caught=None
    try:v.install()
    except m.U.UcError as error:caught=error
    assert caught is not None and caught.errno==m.U.UC_ERR_WRITE_PROT
    assert v.tpl==31 and v.exact() and v.getd(m.CTX+12)==1
    records.append({'case':'Actual CPU write-protection exception at first target',
                    'status':'PASS_COUNTEREXAMPLE_SCOPE_CONFIRMED','unicorn_error':str(caught),
                    'TPL':v.tpl,'busy':v.getd(m.CTX+12),'attempted_mask':v.getd(m.CTX+28),
                    'original_bytes_unchanged':v.exact(),
                    'meaning':'A real protection fault does not return TX_HOLD/ROLLED_BACK. Adapter must prove effective writable supervisor mapping before transaction; no exception recovery is established.'})

    inputs=[TX/'source/transaction.c',TX/'source/transaction.h',TX/'source/transaction_plan.h',
            BUILD/'TransactionCore05.TESTONLY.efi',BUILD/'transaction.obj',BUILD/'transaction.map',
            BUILD/'build.json',TX/'verify_transaction.py',D04/'split_core/build/split_build.json',
            D04/'provider13/local_candidate_manifest.json']
    snapshot=HERE/'core_snapshot';snapshot.mkdir(exist_ok=True)
    for path in inputs:
        (snapshot/path.name).write_bytes(path.read_bytes())
    assert sha(BUILD/'TransactionCore05.TESTONLY.efi')==expected and sha(TX/'verify_transaction.py')==model_sha
    result={'status':'PASS_ADDITIONAL_ACTUAL_TX05_CORE_BOUNDARIES_NOT_ADAPTER_ACCEPTANCE',
            'generated_utc':datetime.now(timezone.utc).isoformat(),'cases':len(records),
            'transaction_efi_sha256':expected,'test_source_sha256':sha(Path(__file__)),
            'inputs':[{'path':str(path),'sha256':sha(path),'snapshot':str((snapshot/path.name).relative_to(HERE))}for path in inputs],
            'records':records,
            'limits':['TPL, validator and callback scheduling remain explicit models from the pinned author fixture.',
                      'This does not prove real EFI adapter identity, map permissions, ownership or image lifecycle.',
                      'No target EFI was launched by the host OS/firmware; Unicorn executed instructions on synthetic memory only.',
                      'No new hardware test, AP/SMM exclusion, automatic recovery or flash acceptance is claimed.']}
    (HERE/'core_edges_result.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n',encoding='utf8')
    print(json.dumps({'status':result['status'],'cases':len(records),'report_sha256':sha(HERE/'core_edges_result.json')}))


if __name__=='__main__':main()
