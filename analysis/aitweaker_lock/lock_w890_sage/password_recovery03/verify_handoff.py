from pathlib import Path
import hashlib,json,sys
sys.dont_write_bytecode=True
import handoff
HERE=Path(__file__).resolve().parent;target='QEMU-W890-RECOVERY03-ISOLATED';path=HERE/'lab/handoff-fixture.dpapi'
cases=[];typed=[]
keyboard=object.__new__(handoff.LocalQmpKeyboard);keyboard.target=target;keyboard.key=lambda chord:typed.append(chord)
def check(name,condition):assert condition,name;cases.append(name)
def rejects(name,function):
    before=len(typed)
    try:function()
    except (ValueError,handoff.journal.JournalError):check(name,len(typed)==before);return
    raise AssertionError(name)
rejects('wrong explicit target sends zero keys',lambda:handoff.deliver_candidate(path,target+'-OTHER','before',keyboard))
rejects('unknown candidate sends zero keys',lambda:handoff.deliver_candidate(path,target,'unknown',keyboard))
rejects('unknown transport sends zero keys',lambda:handoff.deliver_candidate(path,target,'before',object()))
original=path.read_bytes();temporary=HERE/'build/handoff-tampered.dpapi';damaged=bytearray(original);damaged[len(damaged)//2]^=1;temporary.write_bytes(damaged)
rejects('DPAPI ciphertext damage sends zero keys',lambda:handoff.deliver_candidate(temporary,target,'before',keyboard))
fixture=handoff.journal.open_fixture(path,target)
result=handoff.deliver_candidate(path,target,'before',keyboard)
check('result exposes neither password nor password hash',set(result)=={'journal_id','candidate','status'})
check('complete password maps to key events then Enter',len(typed)==len(fixture['before'])+1 and typed[-1]==['ret'])
check('plaintext candidates absent from encrypted journal',all(fixture[key].encode()not in original for key in ['before','after']))
check('journal ciphertext unchanged after handoff',path.read_bytes()==original)
report={'status':'PASS_ACTUAL_DPAPI_HANDOFF_VALIDATION_MODEL_KEY_SINK','case_count':len(cases),'cases':cases,
        'handoff_source_sha256':hashlib.sha256((HERE/'handoff.py').read_bytes()).hexdigest(),'physical_or_bmc_operations':0,
        'scope':'Actual DPAPI and strict request validation. Key sink modeled here; actual QEMU keyboard transport/UEFI input/NV deletion covered by separate OVMF run.'}
(HERE/'build/handoff_tests.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps({'status':report['status'],'cases':len(cases)}))
