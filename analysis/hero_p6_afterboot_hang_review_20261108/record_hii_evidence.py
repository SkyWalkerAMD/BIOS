"""Reproduce exact-PE HII observations; no target connection or PE execution.

These local instruction checks are evidence of possible synchronous callbacks,
not a reconstruction of the real machine's missing post-return call stack.
"""
from pathlib import Path
import hashlib, json, struct, sys
sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(ROOT / 'tools/pydeps'))
import capstone, pefile

PIN_HII = 'eb6c77a2a4a41e9434490eb52611239d39a65e47a28db6aed07a26ee5767003b'
PIN_TSE = 'f48b8729b53e1bcd196a533576d0b228d2df175c631f314d56623a5a88bcb02c'
def image(path, pin):
    raw = path.read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    if digest != pin: raise ValueError('Subject identity changed: '+str(path))
    pe = pefile.PE(data=raw)
    return pe.get_memory_mapped_image(), {'path':str(path),'bytes':len(raw),'sha256':digest,
        'preferred_base':pe.OPTIONAL_HEADER.ImageBase}

hii, hii_meta = image(HERE/'HiiDatabase.efi', PIN_HII)
tse, tse_meta = image(ROOT/'analysis/hero_rea_20261102/HERO-3107-AMITSE.efi', PIN_TSE)
cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
cs.detail = True
def instructions(blob, start, end):
    return [{'rva':hex(i.address),'bytes':i.bytes.hex(),'mnemonic':i.mnemonic,'operands':i.op_str}
            for i in cs.disasm(blob[start:end], start)]
def q(blob, off): return struct.unpack_from('<Q',blob,off)[0]
def must(ok, why):
    if not ok: raise ValueError(why)

db = [q(hii,0x16748+8*i) for i in range(7)]
strings = [q(hii,0x16720+8*i) for i in range(5)]
must(db == [0x13a44,0x13c08,0x13e58,0x140ac,0x14218,0x1433c,0x14434], 'HII DB table changed')
must(strings == [0x7818,0x8304,0x84b4,0x864c,0x8778], 'HII String table changed')
lock = list(cs.disasm(hii[0x16308:0x16333],0x16308))
must(q(hii,0x16848)==16, 'Unexpected lock TPL')
must(not any(i.mnemonic.startswith('j') or i.mnemonic in ('loop','pause') for i in lock), 'Lock now contains branching/spinning')
must(any(i.mnemonic=='call' and i.op_str=='qword ptr [rax + 0x18]' for i in lock), 'RaiseTPL call missing')
forms = list(cs.disasm(hii[0x11890:0x119c0],0x11890))
must(any(i.mnemonic=='mov' and i.op_str=='edx, 4' for i in forms), 'Export type4 missing')
must(any(i.mnemonic=='mov' and i.op_str=='r9b, 2' for i in forms), 'Forms type2 missing')
must(any(i.mnemonic=='call' and i.op_str=='0x107ec' for i in forms), 'Notification dispatcher missing')
notify = list(cs.disasm(hii[0x1089f:0x108e1],0x1089f))
must(any(i.address==0x108d6 and i.mnemonic=='call' and i.op_str=='qword ptr [rsi - 0x10]' for i in notify), 'Indirect notification callback changed')
regs=list(cs.disasm(tse[0x4af68:0x4b023],0x4af68))
register_calls=[i.address for i in regs if i.mnemonic=='call' and i.op_str=='qword ptr [rax + 0x28]']
must(len(register_calls)==3,'AMITSE registration call count changed')
types=[]
for addr in register_calls:
    prior=[i for i in regs if i.address<addr]
    stores=[i for i in prior if i.mnemonic=='mov' and i.op_str.startswith('qword ptr [rsp + 0x20], ')]
    must(bool(stores),'AMITSE notification type not reconstructed')
    types.append(int(stores[-1].op_str.split(', ')[-1],0))
must(types==[1,2,8], 'AMITSE observed notification types changed')
result = {
    'scope':'offline static instruction checks only; not a real-machine call stack',
    'subjects':{'hii':hii_meta,'amitse':tse_meta},
    'protocol_tables':{'database':list(map(hex,db)),'string':list(map(hex,strings))},
    'facts':{
        'set_string_acquire_rva':'0x16308','acquire_tpl':16,'acquire_has_spin_loop':False,
        'forms_export_notify_type':4,'forms_package_type':2,'notify_dispatcher_rva':'0x107ec',
        'notify_indirect_call_rva':'0x108d6',
        'observed_amitse_register_function':'0x4af68',
        'observed_amitse_notify_types':types,'observed_registers_export':False},
    'limits':[
        'The observed AMITSE registration function does not register EXPORT4. This is not proof that no aliased or other module registration exists.',
        'SetString conditionally reexports the database if byte 0x16fe0 is nonzero; its runtime value was not captured and must not be assumed.',
        'RaiseTPL16 without a spin loop does not prove every downstream synchronous callback returns.',
        'No post-return checkpoint or call stack exists for the actual S21R hang. The blocking call remains unknown.'
    ],
    'instruction_windows':{
        'lock':instructions(hii,0x16308,0x16333),
        'export_forms_notify':instructions(hii,0x118f1,0x11962),
        'notification_filter_and_call':instructions(hii,0x1089f,0x108e1),
        'set_string_unlock':instructions(hii,0x85d0,0x862a),
        'amitse_observed_registration':instructions(tse,0x4af68,0x4b023)}
}
(HERE/'hii-machinecode-evidence.json').write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8')
print(json.dumps({'result':'PASS','hii_sha256':PIN_HII,'observed_amitse_types':types,'register_calls':list(map(hex,register_calls))}))
