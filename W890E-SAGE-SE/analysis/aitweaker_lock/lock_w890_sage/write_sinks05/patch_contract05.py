from pathlib import Path
import json,hashlib,sys,struct
H=Path(__file__).resolve().parent;R=H.parents[3];sys.path.insert(0,str(R/'tools/pydeps'))
import pefile,capstone
p=H.parent/'navigation/modules/AMITSE.efi';b=p.read_bytes();e=pefile.PE(data=b);m=e.get_memory_mapped_image()
assert hashlib.sha256(b).hexdigest()=='43f80bf738e0b1101431b7319a8a9c0060655e708f22f5b6379620aee862e6fe'
rows=[(0x1fd58,19,'ws05_save_mid_thunk','ws05_original_save',0x1fd6b),
      (0xfd6c,16,'ws05_native_dispatch','ws05_original_dispatch',0xfd7c),
      (0x1f4ac,14,'ws05_native_defaults','ws05_original_defaults',0x1f4ba),
      (0x851a4,15,'ws05_native_load_defaults_save','ws05_original_load_defaults_save',0x851b3)]
md=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64);out=[]
for a,n,d,t,c in rows:
 code=m[a:a+n];ins=list(md.disasm(code,a));assert sum(x.size for x in ins)==n
 out.append({'module':'AMITSE','rva':hex(a),'length':n,'original':code.hex(),'destination':d,'trampoline':t,'continuation':hex(c),
  'instructions':[{'rva':hex(x.address),'bytes':x.bytes.hex(),'mnemonic':x.mnemonic,'operands':x.op_str}for x in ins],
  'pc_relative_targets':([{'rva':'0x1fd58','target':'0x93458','kind':'rip'},{'rva':'0x1fd5f','target':'0x10704','kind':'call'},{'rva':'0x1fd64','target':'0xafdc8','kind':'rip'}]if a==0x1fd58 else [])})
setup=H.parent/'navigation/modules/Setup.efi';s=pefile.PE(str(setup)).get_memory_mapped_image()
table=[]
for a in [0x2ca40,0x2ca50,0x2ca60,0x2ca70]:
 raw=s[a:a+16];table.append({'rva':hex(a),'original':raw.hex(),'qid':hex(struct.unpack_from('<H',raw,4)[0]),'handler_rva':hex(struct.unpack_from('<Q',raw,8)[0])})
report={'status':'STATIC_ADAPTER_CONTRACT_NOT_A_FLASH_IMAGE','amitsesha256':hashlib.sha256(b).hexdigest(),'setupsha256':hashlib.sha256(setup.read_bytes()).hexdigest(),'patches':out,
 'save_cancel_rva':'0x202f4','save_cancel_semantics':'original AL=0 cleanup in same active native1FCB4 frame; no reset or new frame',
 'setup_static_patches':[],'profile_callback':{'destination':'ws05_profile_callback_gate','signature':'int EFIAPI(CONFIG*,UINTN Action,UINT16 Qid,UINT8 Type,void*Value,UINTN*ActionRequest,void*nativeCaller)',
  'bound_bridge_return':'WS05_BINDING.profile_bridge_return; actual return and 32-byte compiled window are pinned, supplied arguments alone cannot authorize',
  'native_callback_return_rva':'0x3e4f0','original_config_callback_rva':'0x2250','bindings':table,
  'predicate':'QID2BFB/2BFD/2BFE only: Type0C=>Action0, otherTypes=>Action1; QID2BFF=>all actions because original dynamic48180 flag; all other calls delegate unchanged',
  'denial':'return0; integrating ConfigAccess bridge returns EFI_ACCESS_DENIED without calling2250 or altering Value/ActionRequest'},
 'production_sources':['save_guard05.c','save_thunk05.S','catalog05.inc'],'production_dependencies':['genuine no_* authority from observer','w890_policy.c + policy_data.h','password_crypto.c','Runtime02 libc support'],
 'excluded':['fixture05.c','MODEL.dll','standalone test_support.c when Runtime02 supplies libc'],
 'claims':['All windows start/end at actual original instruction boundaries.','Only Save window has PC-relative operands.','Profile handlers remain original in Setup; gate is before existing controlled ConfigAccess bridge delegates2250.','Original vendor I/O status behavior remains; this is authorization gating, not cross-device transactional I/O.'],
 'remaining_integration':['Root static PE aggregation must bind exact observer overlays, all no_scope/request consumer call windows, provider/bootstrap lifetime and reviewed trampoline spans.','No native-owner evidence follows from the model test product.']}
(H/'patch_contract05.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({'patches':len(out),'setup_patches':0,'sha256':hashlib.sha256((H/'patch_contract05.json').read_bytes()).hexdigest()}))
