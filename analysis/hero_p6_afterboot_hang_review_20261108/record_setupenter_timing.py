"""Exact HERO AMITSE SetupEnter timing, retaining existing REA evidence only."""
from pathlib import Path
import hashlib,json,sys
if not __debug__:raise RuntimeError('Run without -O')
sys.dont_write_bytecode=True
OUT=Path(__file__).resolve().parent;ROOT=OUT.parents[1]
sys.path.insert(0,str(ROOT/'tools/pydeps'))
import pefile,capstone
image=ROOT/'analysis/hero_rea_20261102/HERO-3107-AMITSE.efi';raw=image.read_bytes()
PIN='f48b8729b53e1bcd196a533576d0b228d2df175c631f314d56623a5a88bcb02c'
assert hashlib.sha256(raw).hexdigest()==PIN
pe=pefile.PE(data=raw);data=pe.get_memory_mapped_image()
cs=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64);cs.detail=True;cs.skipdata=True
def window(lo,hi):
 return [{'rva':hex(i.address),'bytes':i.bytes.hex(),'mnemonic':i.mnemonic,'operands':i.op_str} for i in cs.disasm(data[lo:hi],lo)]
known_calls={0x3d236:'0x176c',0x3d251:'0x3c38',0x3d270:'0x176c',0x7a1b:'0x3d204',0x6c710:'0x3d204',0x6c715:'0x325b4',0x3262c:'0x4af68',0x3263d:'0x33560'}
for address,target in known_calls.items():
 ins=next(cs.disasm(data[address:address+15],address));assert ins.mnemonic=='call' and ins.op_str==target,(hex(address),ins.op_str)
assert data[0x3d20d:0x3d214].hex()=='833d8c36150000'
assert data[0x3d242:0x3d24c].hex()=='c7055436150001000000'
refs=[];callers=[]
for section in pe.sections:
 if not section.Characteristics&0x20000000:continue
 for ins in cs.disasm(section.get_data(),section.VirtualAddress):
  if not ins.id:continue
  for op in ins.operands:
   if op.type==capstone.x86.X86_OP_MEM and op.mem.base==capstone.x86.X86_REG_RIP:
    pointer=ins.address+ins.size+op.mem.disp
    if pointer<=0x1908a0<pointer+op.size:refs.append({'rva':hex(ins.address),'mnemonic':ins.mnemonic,'operands':ins.op_str,'access':op.access})
  if ins.mnemonic=='call' and ins.operands[0].type==capstone.x86.X86_OP_IMM and ins.operands[0].imm==0x3d204:callers.append(hex(ins.address))
assert callers==['0x7a1b','0x6c710'] and len(refs)==2
def retained(path):
 p=ROOT/path;b=p.read_bytes();r=json.loads(b)['result'];structured=r.get('structuredContent') or json.loads(r['content'][0]['text'])
 assert structured['subject']['digest']['sha256']==PIN
 return {'path':path,'sha256':hashlib.sha256(b).hexdigest(),'evidence_id':structured.get('evidence_id'),'operation':structured['operation']}
rea=retained('analysis/hero_ipmi_p5_rea_review_20261103/amitse/responses/005-setupenter-signal.json')
spf_rea=retained('analysis/hero_rea_20261102/p3b-reuse/responses/008-native-spf-loader.json')
prior=ROOT/'analysis/hero_ipmi_p6_20261104/review-20261108/setupenter-lifecycle.json';prior_data=json.loads(prior.read_text())
assert prior_data['sha256']==PIN and len(prior_data['emulation']['first_call_publications'])==2 and prior_data['emulation']['first_call_publications']==prior_data['emulation']['total_publications_after_second_call']
report={
 'subject':{'path':str(image.relative_to(ROOT)),'sha256':PIN},
 'reused_rea':[rea,spf_rea],
 'reused_actual_helper_emulation':{'path':str(prior.relative_to(ROOT)),'sha256':hashlib.sha256(prior.read_bytes()).hexdigest(),'first_helper_call_publications':2,'total_after_second_helper_call':2,'not_reexecuted_for_this_static_review':True},
 'setupenter_guid':'71202eee-5f53-40d9-ab3d-9e0c26d96657','guard_rva':'0x1908a0','helper_rva':'0x3d204','direct_guard_refs':refs,'direct_helper_callers':callers,
 'first_helper_sequence':[
  {'rva':'0x3d20d','operation':'Read per-image guard; nonzero branches directly to return'},
  {'rva':'0x3d236','operation':'First transient publication through0x176c'},
  {'rva':'0x3d242','operation':'Set guard1'},
  {'rva':'0x3d251','operation':'AMI callback group FFFF0003; fallback0x4b2c8'},
  {'rva':'0x3d267','operation':'Conditional helper0xb467c for global mode4 or5'},
  {'rva':'0x3d270','operation':'Second transient publication through0x176c'},
  {'rva':'0x3d27f','operation':'Helper0xb1c80(1,0x3050007)'},
  {'rva':'0x3d284','operation':'Return path'}],
 'publication':{'helper':'0x176c','install_call':'0x1790','uninstall_call':'0x17a8','interface':'NULL','lifetime':'InstallProtocolInterface then immediately UninstallProtocolInterface before helper returns'},
 'ui_preparation_sequence':[
  {'rva':'0x6c710','operation':'SetupEnter helper before the following native SPF import call'},
  {'rva':'0x6c715','operation':'Native resource import/cache construction0x325b4'},
  {'rva':'0x3262c','operation':'Inside import: register native HII notifications0x4af68 (NEW1/REMOVE2/ADD8)'},
  {'rva':'0x3263d','operation':'Inside import: load native resource0x33560 before binding/importing fields'},
  {'rva':'0x6c73c','operation':'After native import: initialize/read native variable/default buffers0x1a61c'},
  {'rva':'0x6c993..0x6caca','operation':'Later UI object setup and virtual method calls; no proof of every global side effect'}],
 'other_path':{'entry':'0x7a04','setupenter_call':'0x7a1b','later_calls':['0x9184','0xcebc','0x1a3e4'],'nearby_variable':'BootNowCount','interpretation':'Boot-selection-related path inferred from BootNowCount; do not equate this marker with fully initialized graphical Setup.'},
 'conclusions':[
  'A late-loaded driver cannot rely on LocateProtocol returning a marker that was installed and removed earlier. The per-image helper guard prevents later calls from repeating its first-entry publication sequence.',
  'The main observed UI-preparation path publishes SetupEnter before native SPF/variable cache initialization, giving a static reason to consider synchronous work before later cache construction instead of delayed timer interruption.',
  'This ordering does not prove the exact target HII Forms package is already registered at the first notification. HII database protocol readiness and target package readiness are different predicates.',
  'Do not blindly copy the AfterBoot terminal bind-failure policy to earliest SetupEnter: consuming the boot attempt while the target package is absent could prevent a later valid refresh.',
  'Two InstallProtocol calls do not prove two separately delivered event callbacks. Delivery depends on current TPL, event coalescing and UEFI protocol-notify semantics, none reconstructed here.'],
 'limits':[
  'No new REA session or bulk operation, no firmware change and no hardware action.',
  'The guard scan covers direct RIP-relative references only. Computed/aliased writes and wholesale memory resetting are not excluded.',
  'The FFFF0003 callbacks and conditional mode helper can do opaque work; their effects and current mode are not assumed.',
  'Synchronous SetupEnter would still execute in the AMITSE/Boot Services notification context; this is not proof of no HII reentry or blocking.',
  'Original SetupEnter timer and proposed replacement have not been validated by this static review on a native cold-boot path.'],
 'windows':{'setupenter':window(0x3d204,0x3d28a),'publish_helper':window(0x176c,0x17b4),'ui_before_import':window(0x6c705,0x6c761),'import_begin':window(0x32627,0x3264e),'hii_register_notify':window(0x4af68,0x4b017),'other_entry':window(0x7a04,0x7a7b)}
}
(OUT/'setupenter-timing-evidence.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf8')
print(json.dumps({'passed':True,'first_helper_publications':2,'marker_transient':True,'before_native_cache_import':True,'synchronous_fix_proven':False}))
