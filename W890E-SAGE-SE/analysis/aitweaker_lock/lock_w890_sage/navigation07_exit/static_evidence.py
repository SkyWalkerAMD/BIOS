"""Exact original byte/branch evidence and bounded candidate hook contract."""
from pathlib import Path
import sys,json,hashlib
H=Path(__file__).resolve().parent;B=H.parent;R=H.parents[3];O=H/'build'
sys.path.insert(0,str(R/'tools/pydeps'))
import capstone,pefile
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
source=B/'navigation/modules/AMITSE.efi'
assert sha(source)=='43f80bf738e0b1101431b7319a8a9c0060655e708f22f5b6379620aee862e6fe'
for mn in [B/'exit_control07/component_manifest.json',B/'navigation06_actions/component_manifest.json']:
 d=json.loads(mn.read_text())
 for k in ['files','local_bindings','external_bindings']:
  for row in d.get(k,[]):assert sha(R/row['path'])==row['sha256'],row['path']
pe=pefile.PE(str(source));base=pe.OPTIONAL_HEADER.ImageBase;im=pe.get_memory_mapped_image()
md=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64);md.detail=True
ins=list(md.disasm(im[0x190f4:0x19a8f],0x190f4));assert ins[-1].mnemonic=='ret'
entry=im[0x190f4:0x1910d].hex();tail=im[0x1995f:0x1996f].hex()
assert entry=='40555356574154415541564157488d6c24e14881ec98000000'
assert tail=='488b056a64090038585a0f8490fdffff'
targets={0x1995f,0x1996f,0x19973,0x19994,0x199e6,0x19a76,0x196ff};edges=[]
for x in ins:
 if x.mnemonic.startswith('j')or x.mnemonic=='call':
  for op in x.operands:
   if op.type==capstone.x86.X86_OP_IMM and op.imm in targets:
    edges.append({'from_rva':x.address,'target_rva':op.imm,'bytes':x.bytes.hex(),'mnemonic':x.mnemonic,'operand':x.op_str})
assert any(e['from_rva']==0x196f7 and e['target_rva']==0x19973 for e in edges)
rea=B/'navigation/rea/W890-seeded-loop190f4.json';ev=json.loads(json.loads(rea.read_text())['content'][0]['text'])
windows=[]
for first,last,label in [(0x190f4,0x1910d,'original_prologue'),(0x196ec,0x19973,'input_loop_and_candidate'),(0x232dc,0x23398,'original_input_read_reset')]:
 text='\n'.join(f'{x.address:05x} {x.bytes.hex():28} {x.mnemonic} {x.op_str}'for x in md.disasm(im[first:last],first))+'\n'
 (H/(label+'.asm.txt')).write_text(text)
 windows.append({'label':label,'rva':first,'length':last-first,'sha256':hashlib.sha256(im[first:last]).hexdigest()})
report={'status':'PARTIAL_ESTABLISHED_LOOP_TAIL_CANCELLATION_ONLY','original_sha256':sha(source),'original_base':base,'rea_evidence_id':ev['evidence_id'],'rea_response_sha256':sha(rea),'rea_observation':'Existing seeded Ghidra dossier; no new REA session fabricated. Resolved edges only; indirect flows remain unknown.','stack':{'native_saved_gpr_bytes':64,'native_local_bytes':152,'body_return_offset':216,'rbp_minus_body_rsp':121,'anchor':'actual n07_loop_body_call CALL return while real private NO_LOOP frame exists'},'hook':{'rva':0x1995f,'length':16,'original':tail,'patch':'FF25 absolute indirect jump14 + NOP2','export':'n07_native_tail','resume_rva':0x196ff,'stolen_trampoline':False,'relocation':"Original RIP-relative load/conditional branch are replaced by proved App load plus exact CMP(0,0) flags; do not replay original bytes at a foreign PC."},'incoming_direct_edges':edges,'windows':windows,'uncovered':['196F7 directly reaches19973 without1995F','initialization error paths directly reach19994 or19A76','any unknown computed target or external intra-function entry','full cleanup/save/reset effects and persistence before exit flag','opaque nonempty history allocation ownership is preserved, not granted']}
(H/'hook_plan.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps({'edges':edges,'rea_evidence_id':ev['evidence_id'],'checks':'exact original windows/prologue, direct bypass and frozen bindings verified'},indent=2))
