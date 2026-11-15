"""Behavioral scenarios and randomized policy sequences for a host-only model.
These results do not count as tests of the P2 EFI or actual BIOS password code.
"""
from pathlib import Path
import hashlib
import json
import random
from password_flow_model import PasswordFlowModel,Credential,Verdict,Commit,Ticket

OUT=Path(__file__).resolve().parent


def opened(credential=Credential.VALID):
    m=PasswordFlowModel(credential);m.enter_setup();return m


def prompt(m,entry='ai_tweaker'):
    outcome,ticket=m.begin_access(entry);assert outcome=='PROMPT' and ticket is not None
    return ticket


def directed_scenarios():
    rows=[]
    def passed(name):rows.append({'name':name,'passed':True})
    m=opened();ticket=prompt(m)
    assert m.finish_access(ticket,Verdict.MATCH)=='UNLOCKED'
    for entry in m.PROTECTED_ENTRIES:assert m.begin_access(entry)==('ALLOW_SESSION',None)
    passed('first_correct_verification_unlocks_remaining_session')

    for verdict,result in ((Verdict.MISMATCH,'DENIED'),(Verdict.CANCEL,'CANCELLED'),(Verdict.ERROR,'VERIFIER_ERROR')):
        m=opened();ticket=prompt(m);assert m.finish_access(ticket,verdict)==result
        assert not m.unlocked and prompt(m)!=ticket
        passed('failed_access_'+verdict.value+'_remains_locked')

    m=opened();ticket=prompt(m);m.finish_access(ticket,Verdict.MATCH);m.exit_setup()
    assert m.begin_access()==('OUTSIDE_SETUP',None)
    m.enter_setup();new=prompt(m);assert new!=ticket
    assert m.finish_access(ticket,Verdict.MATCH)=='STALE_OR_WRONG_PURPOSE' and not m.unlocked
    assert m.finish_access(new,Verdict.MATCH)=='UNLOCKED'
    passed('exit_and_reenter_relock_and_reject_old_response')

    m=opened();ticket=prompt(m);m.reboot();m.enter_setup();new=prompt(m)
    assert m.finish_access(ticket,Verdict.MATCH)=='STALE_OR_WRONG_PURPOSE' and not m.unlocked
    assert m.finish_access(new,Verdict.MATCH)=='UNLOCKED'
    passed('reboot_invalidates_previous_prompt_even_if_session_number_repeats')

    m=opened();ticket=prompt(m);m.reload_credential(Credential.VALID);prompt(m)
    assert m.finish_access(ticket,Verdict.MATCH)=='STALE_OR_WRONG_PURPOSE' and not m.unlocked
    passed('credential_revision_change_invalidates_pending_response')

    a=opened();b=opened();ticket=prompt(a);prompt(b)
    assert b.finish_access(ticket,Verdict.MATCH)=='STALE_OR_WRONG_PURPOSE' and not b.unlocked
    passed('verification_from_another_model_instance_rejected')

    m=opened();ticket=prompt(m)
    for entry in m.PROTECTED_ENTRIES:assert m.begin_access(entry)==('PROMPT',ticket)
    assert m.begin_access('unclassified_oc_path')==('UNCLASSIFIED_ENTRY',None)
    assert not m.unlocked
    passed('classified_alternative_entries_require_same_gate')

    for state in (Credential.CORRUPT,Credential.UNREADABLE):
        m=opened(state)
        for entry in m.PROTECTED_ENTRIES:assert m.begin_access(entry)==('CREDENTIAL_ERROR',None)
        assert m.begin_change(Credential.ABSENT)==('CREDENTIAL_ERROR',None)
        m.load_defaults();assert m.credential==state and not m.unlocked
        passed(state.value+'_credential_is_not_treated_as_no_password')

    m=opened(Credential.ABSENT)
    assert m.begin_access()==('ALLOW_NO_PASSWORD',None)
    result,ticket=m.begin_change(Credential.VALID);assert result=='SET_NEW_PASSWORD'
    assert m.finish_change(ticket,Verdict.MATCH,Commit.OK)=='CREDENTIAL_CHANGED'
    prompt(m);assert m.credential==Credential.VALID and not m.unlocked
    passed('setting_first_password_activates_access_gate')

    for target in (Credential.VALID,Credential.ABSENT):
        m=opened();result,ticket=m.begin_change(target);assert result=='VERIFY_CURRENT_PASSWORD'
        assert m.finish_change(ticket,Verdict.MISMATCH,Commit.OK)=='DENIED'
        assert m.credential==Credential.VALID
        result,ticket=m.begin_change(target)
        assert m.finish_change(ticket,Verdict.MATCH,Commit.OK)=='CREDENTIAL_CHANGED'
        assert m.credential==target
        if target==Credential.ABSENT:assert m.begin_access()==('ALLOW_NO_PASSWORD',None)
        else:prompt(m)
        passed('change_to_'+target.value+'_requires_current_credential_verdict')

    m=opened();_,ticket=m.begin_change(Credential.ABSENT)
    assert m.finish_change(ticket,Verdict.CANCEL,Commit.OK)=='CANCELLED'
    assert m.credential==Credential.VALID;prompt(m)
    passed('cancelled_password_change_keeps_old_record')

    for commit in (Commit.FAILED_UNCHANGED,Commit.UNKNOWN):
        m=opened();ticket=prompt(m);m.finish_access(ticket,Verdict.MATCH)
        _,change=m.begin_change(Credential.ABSENT);m.finish_change(change,Verdict.MATCH,commit)
        assert not m.unlocked
        if commit==Commit.FAILED_UNCHANGED:
            assert m.credential==Credential.VALID;prompt(m)
        else:assert m.begin_access()==('CREDENTIAL_ERROR',None)
        passed('credential_write_'+commit.value+'_does_not_grant_access')

    m=opened();ticket=prompt(m);m.load_defaults()
    assert m.credential==Credential.VALID and m.begin_access()==('PROMPT',ticket)
    m.finish_access(ticket,Verdict.MATCH);m.load_defaults()
    assert m.credential==Credential.VALID and m.begin_access()==('ALLOW_SESSION',None)
    passed('ordinary_defaults_preserve_independent_credential')

    m=opened();_,ticket=m.begin_change(Credential.ABSENT)
    assert m.begin_access()==('BUSY',None)
    assert m.finish_access(ticket,Verdict.MATCH)=='STALE_OR_WRONG_PURPOSE' and not m.unlocked
    assert m.finish_change(ticket,Verdict.MATCH,Commit.OK)=='CREDENTIAL_CHANGED'
    assert m.finish_change(ticket,Verdict.MATCH,Commit.OK)=='STALE_OR_WRONG_PURPOSE'
    passed('management_result_cannot_unlock_access_and_cannot_be_replayed')

    m=opened();ticket=prompt(m)
    assert m.finish_change(ticket,Verdict.MATCH,Commit.OK)=='STALE_OR_WRONG_PURPOSE'
    assert m.credential==Credential.VALID and not m.unlocked
    m.finish_access(ticket,Verdict.MISMATCH)
    assert m.finish_access(ticket,Verdict.MATCH)=='STALE_OR_WRONG_PURPOSE'
    passed('access_result_cannot_clear_password_or_be_reused_after_failure')
    return rows


def random_sequences(steps=20000):
    rng=random.Random(0xA17EA315);m=PasswordFlowModel();tickets=[];stats={};successes=0
    for _ in range(steps):
        action=rng.choice(('enter','exit','reboot','request','verify','defaults','reload','begin_change','finish_change'))
        before=(m.credential,m.active,m.unlocked,m.pending,m.revision)
        stats[action]=stats.get(action,0)+1;legitimate_unlock=False
        if action=='enter':m.enter_setup();assert not m.unlocked and m.active
        elif action=='exit':m.exit_setup();assert not m.unlocked and not m.active
        elif action=='reboot':m.reboot();assert not m.unlocked and not m.active
        elif action=='defaults':
            m.load_defaults();assert before==(m.credential,m.active,m.unlocked,m.pending,m.revision)
        elif action=='reload':
            m.reload_credential(rng.choice(tuple(Credential)));assert not m.unlocked and m.pending is None
        elif action=='request':
            result,ticket=m.begin_access(rng.choice(m.PROTECTED_ENTRIES+('unknown',)))
            if ticket:tickets.append(ticket)
            if result=='ALLOW_SESSION':assert before[1] and before[2] and before[0]==Credential.VALID
            if result=='ALLOW_NO_PASSWORD':assert before[1] and before[0]==Credential.ABSENT
            if before[0] in (Credential.CORRUPT,Credential.UNREADABLE):assert not result.startswith('ALLOW')
        elif action=='verify':
            ticket=(m.pending if rng.random()<0.7 else rng.choice(tickets) if tickets else None)
            verdict=rng.choice(tuple(Verdict));result=m.finish_access(ticket,verdict)
            legitimate_unlock=(result=='UNLOCKED')
            if legitimate_unlock:
                successes+=1
                assert verdict==Verdict.MATCH and before[1] and before[0]==Credential.VALID
                assert ticket==before[3] and ticket.purpose=='access'
                assert ticket.instance==m.instance and ticket.boot==m.boot and ticket.session==m.session
                assert ticket.revision==before[4]
            else:assert m.unlocked==before[2] or not m.unlocked
        elif action=='begin_change':
            _,ticket=m.begin_change(rng.choice((Credential.ABSENT,Credential.VALID)))
            if ticket:tickets.append(ticket)
        elif action=='finish_change':
            ticket=m.pending if rng.random()<0.7 else rng.choice(tickets) if tickets else None
            verdict=rng.choice(tuple(Verdict));commit=rng.choice(tuple(Commit))
            result=m.finish_change(ticket,verdict,commit)
            if result=='CREDENTIAL_CHANGED':
                assert commit==Commit.OK and before[1] and ticket==before[3] and ticket.purpose=='change'
                if before[0]==Credential.VALID:assert verdict==Verdict.MATCH
                assert not m.unlocked
            elif result=='STORE_OUTCOME_UNKNOWN':assert m.credential==Credential.UNREADABLE and not m.unlocked
            else:assert m.credential==before[0]
        if not before[2] and m.unlocked:assert action=='verify' and legitimate_unlock
        if m.unlocked:assert m.active and m.credential==Credential.VALID
        if not m.active:assert m.pending is None and not m.unlocked
        if m.credential in (Credential.CORRUPT,Credential.UNREADABLE):assert not m.unlocked
    assert successes>0
    return {'steps':steps,'seed':'0xA17EA315','action_counts':stats,'legitimate_unlock_events':successes,'passed':True}


def main():
    cases=directed_scenarios();random_result=random_sequences()
    report={'status':'HOST_POLICY_MODEL_PASS_NOT_FIRMWARE_PASSWORD_VALIDATION',
            'directed_scenarios':cases,'directed_scenario_count':len(cases),'random_sequences':random_result,
            'model_sha256':hashlib.sha256((OUT/'password_flow_model.py').read_bytes()).hexdigest(),
            'implementation_level':'Host-only abstract state machine; synthetic authentication/storage outcomes.',
            'confirmed_requirements_modeled':['Prompt on first protected access per Setup session.',
              'Keep successful unlock only for that Setup session.',
              'Independent credential state and setup/change workflow, separate from other passwords.'],
            'proposed_policies_not_user_confirmed':['Clear/change requires a fresh current-password verification outcome.',
              'Uncertain/corrupt credential storage blocks protected access until a valid record can be established.',
              'Credential changes invalidate the existing access-unlock state.',
              'All classified alternative OC entries route through the same gate.'],
            'not_implemented':['Actual password hashing, comparison, secure randomness and secret erasure.',
              'Persistent/atomic NVRAM records and recovery, lockout/rate-limiting policy.',
              'BIOS dialogs, menu hooks, actual session lifecycle and classification of all alternative entries.',
              'A flashable firmware patch or changes to the diagnostic EFI.']}
    (OUT/'password_model_verification.json').write_text(json.dumps(report,indent=2),encoding='utf8')
    print('Host-only model PASS:',len(cases),'directed scenarios,',random_result['steps'],'random steps')


if __name__=='__main__':main()
