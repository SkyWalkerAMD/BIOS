"""Read-only SAGE 1904 PE scan; writes only this isolated review directory."""
import sys
sys.dont_write_bytecode = True
from pathlib import Path
ROOT = Path(__file__).resolve().parents[6]
sys.path.insert(0, str(ROOT / 'tools/pydeps'))
import pefile, capstone, json, hashlib
from capstone.x86 import X86_OP_MEM, X86_REG_RIP, X86_OP_IMM
HERE = Path(__file__).resolve().parent
BASE = HERE.parents[2]

def scan(name, targets):
    path = BASE / 'analysis/modules' / (name + '.efi')
    raw = path.read_bytes(); pe = pefile.PE(data=raw)
    mapped = pe.get_memory_mapped_image()
    sec = next(s for s in pe.sections if s.Name.rstrip(b'\0') == b'.text')
    cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    cs.detail = True; cs.skipdata = True
    ops = list(cs.disasm(mapped[sec.VirtualAddress:sec.VirtualAddress+sec.Misc_VirtualSize], sec.VirtualAddress))
    refs = []; calls = []
    for i, op in enumerate(ops):
        if op.id == 0: continue
        for arg in op.operands:
            if arg.type == X86_OP_MEM and arg.mem.base == X86_REG_RIP:
                address = op.address + op.size + arg.mem.disp
                if address in targets:
                    refs.append({'target':hex(address),'label':targets[address], 'instruction':f'{op.address:#x}: {op.mnemonic} {op.op_str}',
                                 'context':[f'{x.address:#x}: {x.mnemonic} {x.op_str}' for x in ops[max(0,i-5):i+15]]})
        if op.mnemonic == 'call' and len(op.operands) == 1 and op.operands[0].type == X86_OP_IMM:
            calls.append({'from':hex(op.address),'to':hex(op.operands[0].imm)})
    report={'file':str(path),'sha256':hashlib.sha256(raw).hexdigest(),'refs':refs,'direct_calls':calls,
            'limits':'Linear Capstone .text scan is a bounded static reference search, not exhaustive CFG/call graph or observed runtime.'}
    (HERE / (name+'_scan.json')).write_text(json.dumps(report,indent=2),encoding='utf-8')
    print(name, 'sha256',report['sha256'])
    for r in refs:
        print(r['label'],r['instruction'])
    return mapped, ops

if __name__ == '__main__':
    scan('AMITSE',{0x83318:'RT',0x83468:'stage',0x837d8:'poll slot',0x6b928:'render slot',0x6b930:'page input',0x6b840:'app input',0x7d4f8:'navigation',0x6b270:'FormBrowser2 GUID'})
    scan('Setup',{0x43620:'RT',0x280c0:'FormBrowser2 GUID'})
