from pathlib import Path
import sys,hashlib,json,struct
H=Path(__file__).resolve().parent;R=H.parents[3];sys.path[:0]=[str(R/'tools/pydeps'),str(R/'tools/kvm-pydeps')]
import pefile,capstone
specs=[
 ('AMITSE',0x1c958,'NativeCommit','EFI_STATUS(UINT32 native_index, VOID *data, UINTN size)','REQUIRES_GLOBAL_BATCH_BOUNDARY_AND_POST_PRECHECK_EXECUTION_LEASE','native_bridge04.c:ws04_native_commit'),
 ('AMITSE',0x1fcb4,'Save','UINT8(void); zero means failure','DENY_WHOLE_ACTION_NOTIFICATION_BOOT_DRIVER_SINKS_UNCLOSED','native_bridge04.c:ws04_native_save'),
 ('Setup',0x2248,'ConfigAccessRouteStub','EFI_STATUS(CONFIG*, CHAR16*, CHAR16**)','JUMP_STUB_DO_NOT_OVERWRITE_14_BYTES_USE_CONFIGACCESS_POINTER_CAS','native_bridge04.c:ws04_setup_route'),
 ('Setup',0x3398,'ConfigAccessRouteImplementation','EFI_STATUS(CONFIG*, CHAR16*, CHAR16**)','STRICT_PARSE_PRECHECK_COMPILED_NO_DISPATCH','native_bridge04.c:ws04_check_route'),
 ('AMITSE',0x331a4,'NativeHiiRoute','EFI_STATUS(descriptor*,data*,offset,size)','GLOBAL_HII_ROUTING_HAS_FOREIGN_DRIVER_SIDE_EFFECTS_NO_ALLOWLIST',None),
 ('AMITSE',0x3f414,'FormOpen','EFI_STATUS(native page/control list*, action context*) [partial ABI]','CALLS_FORM_OPEN_CALLBACKS; ABI_AND_EFFECT_GRAPH_UNCLOSED',None),
 ('AMITSE',0x3fed4,'HiiPendingProducer','queue normalizer [partial ABI]','NOT_A_VARIABLE_WRITE_QUEUE; MUST_INVALIDATE_NATIVE_HII_EPOCH',None),
 ('AMITSE',0x40094,'HiiPendingDispatch','queue rebuild dispatch [partial ABI]','NOT_A_VARIABLE_WRITE_SINK; REBUILDS_PAGES_AND_CACHE',None),
 ('AMITSE',0x44250,'EvaluateFirstBootDefaults','complex defaults evaluator [partial ABI]','SETVARIABLE_AND_CALLBACK_GRAPH_UNCLOSED',None),
 ('AMITSE',0x1cde4,'NativeCacheEdit','cache update helper [partial ABI]','CACHE_MUTATION_NEEDS_SOURCE_ACTION_CLOSURE',None),
 ('AMITSE',0xfd6c,'GenericCallbackDispatcher','generic dispatch [partial ABI]','NOT_A_DEDICATED_DEFAULTS_ENTRY; DO_NOT_BLANKET_PATCH',None),
]
modules={};dis=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64);dis.detail=True
for name in ['AMITSE','Setup']:
 p=H.parent/'navigation/modules'/f'{name}.efi';pe=pefile.PE(str(p));modules[name]=(p,pe.get_memory_mapped_image(),hashlib.sha256(p.read_bytes()).hexdigest())
rows=[]
for name,rva,label,abi,status,bridge in specs:
 p,blob,sha=modules[name];ins=[];n=0
 for i in dis.disasm(blob[rva:rva+64],rva):
  ins.append(dict(rva=i.address,bytes=i.bytes.hex(),mnemonic=i.mnemonic,operands=i.op_str,rip_relative=any(o.type==capstone.x86.X86_OP_MEM and o.mem.base==capstone.x86.X86_REG_RIP for o in i.operands),relative_control=i.group(capstone.CS_GRP_JUMP)or i.group(capstone.CS_GRP_CALL)))
  n+=i.size
  if n>=14:break
 rows.append(dict(module=name,source_sha256=sha,rva=rva,label=label,abi=abi,status=status,bridge=bridge,original_window_bytes=n,original_hex=blob[rva:rva+n].hex(),instructions=ins,can_copy_without_relocation=not any(x['rip_relative']or x['relative_control']for x in ins),installed=False))
result={'board':'ASUS Pro WS W890E-SAGE SE','bios':'0603','windows':rows,'constraints':['Inventory is evidence, not an executable patch plan.','No new detour installed and no root installer site automatically added.','Setup2248 is an 8-byte stub slot, not a 14-byte overwrite window.','Native indices94/99 are OCMR/SocketMemoryConfig. IFR35/40 are not these native indices.','The deny-only bridges cannot preserve ordinary native Save yet; do not install them on hardware.']}
(H/'hook_inventory.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps({'windows':len(rows),'relocation_required':[x['label']for x in rows if not x['can_copy_without_relocation']]}))
