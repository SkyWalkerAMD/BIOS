"""Host-only policy prototype. NOT linked into the diagnostic EFI or BIOS.

No passwords, hashes, salts, NVRAM, menus, hardware or real authentication are
implemented here. MATCH / MISMATCH / ERROR are synthetic verifier outcomes.
The model assumes every protected entry is routed through begin_access; proving
that assumption on ASUS firmware remains a separate integration task.
"""
from dataclasses import dataclass
from enum import Enum
from itertools import count


class Credential(Enum):
    ABSENT='absent'
    VALID='valid'
    CORRUPT='corrupt'
    UNREADABLE='unreadable'


class Verdict(Enum):
    MATCH='match'
    MISMATCH='mismatch'
    CANCEL='cancel'
    ERROR='error'


class Commit(Enum):
    OK='committed'
    FAILED_UNCHANGED='failed_with_old_record_intact'
    UNKNOWN='storage_result_unknown'


@dataclass(frozen=True)
class Ticket:
    instance:int
    boot:int
    session:int
    revision:int
    sequence:int
    purpose:str
    target:Credential|None=None


class PasswordFlowModel:
    PROTECTED_ENTRIES=('ai_tweaker','oc_subpage','favorites_oc','search_oc','ez_mode_oc','profile_import_oc')
    _instances=count(1)

    def __init__(self,credential=Credential.VALID):
        self.instance=next(self._instances);self.boot=0;self.session=0;self.revision=0;self.sequence=0
        self.credential=credential;self.active=False;self.unlocked=False;self.pending=None

    def _invalidate(self):
        self.unlocked=False;self.pending=None

    def enter_setup(self):
        self.session+=1;self.active=True;self._invalidate()

    def exit_setup(self):
        self.active=False;self._invalidate()

    def reboot(self):
        self.boot+=1;self.session=0;self.sequence=0;self.active=False;self._invalidate()

    def reload_credential(self,credential):
        """Synthetic external record-read outcome, including corruption/I/O faults."""
        self.credential=credential;self.revision+=1;self._invalidate()

    def load_defaults(self):
        """Only models independent-credential preservation, not OC default writes."""
        return 'INDEPENDENT_CREDENTIAL_PRESERVED'

    def _ticket(self,purpose,target=None):
        self.sequence+=1
        self.pending=Ticket(self.instance,self.boot,self.session,self.revision,self.sequence,purpose,target)
        return self.pending

    def _current(self,ticket,purpose):
        return (self.active and isinstance(ticket,Ticket) and ticket==self.pending
                and ticket.purpose==purpose and ticket.instance==self.instance
                and ticket.boot==self.boot and ticket.session==self.session
                and ticket.revision==self.revision)

    def begin_access(self,entry='ai_tweaker'):
        if not self.active:return 'OUTSIDE_SETUP',None
        if entry not in self.PROTECTED_ENTRIES:return 'UNCLASSIFIED_ENTRY',None
        if self.credential in (Credential.CORRUPT,Credential.UNREADABLE):return 'CREDENTIAL_ERROR',None
        if self.pending and self.pending.purpose!='access':return 'BUSY',None
        if self.credential==Credential.ABSENT:return 'ALLOW_NO_PASSWORD',None
        if self.unlocked:return 'ALLOW_SESSION',None
        if self.pending:return 'PROMPT',self.pending
        return 'PROMPT',self._ticket('access')

    def finish_access(self,ticket,verdict):
        if not self._current(ticket,'access') or self.credential!=Credential.VALID:return 'STALE_OR_WRONG_PURPOSE'
        self.pending=None
        if verdict==Verdict.MATCH:
            self.unlocked=True;return 'UNLOCKED'
        self.unlocked=False
        return 'CANCELLED' if verdict==Verdict.CANCEL else 'VERIFIER_ERROR' if verdict==Verdict.ERROR else 'DENIED'

    def begin_change(self,target):
        if not self.active:return 'OUTSIDE_SETUP',None
        if target not in (Credential.ABSENT,Credential.VALID):return 'INVALID_TARGET',None
        if self.credential in (Credential.CORRUPT,Credential.UNREADABLE):return 'CREDENTIAL_ERROR',None
        if self.pending:return 'BUSY',None
        if self.credential==Credential.ABSENT and target==Credential.ABSENT:return 'ALREADY_ABSENT',None
        prompt='VERIFY_CURRENT_PASSWORD' if self.credential==Credential.VALID else 'SET_NEW_PASSWORD'
        return prompt,self._ticket('change',target)

    def finish_change(self,ticket,old_verdict,commit):
        if not self._current(ticket,'change'):return 'STALE_OR_WRONG_PURPOSE'
        self.pending=None
        if old_verdict==Verdict.CANCEL:return 'CANCELLED'
        if old_verdict==Verdict.ERROR:return 'VERIFIER_ERROR'
        if self.credential==Credential.VALID and old_verdict!=Verdict.MATCH:return 'DENIED'
        if commit==Commit.FAILED_UNCHANGED:
            self._invalidate();return 'STORE_FAILED_OLD_RECORD_RETAINED'
        if commit!=Commit.OK:
            self.reload_credential(Credential.UNREADABLE);return 'STORE_OUTCOME_UNKNOWN'
        self.credential=ticket.target;self.revision+=1;self._invalidate();return 'CREDENTIAL_CHANGED'
