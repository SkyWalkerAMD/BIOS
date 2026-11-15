from pathlib import Path
import json,hashlib,subprocess,os,sys,re
H=Path(__file__).resolve().parent;B=H.parent;ROOT=H.parents[3];P=B/'password';R=B/'password_runtime02';O=H/'aggregate_build';O.mkdir(exist_ok=True)
sys.path.insert(0,str(ROOT/'tools/pydeps'));import pefile,capstone
zig=ROOT/'tools/zig-x86_64-windows-0.14.1/zig.exe'
env=os.environ.copy();env.update(ZIG_LOCAL_CACHE_DIR=str(O/'zig-local'),ZIG_GLOBAL_CACHE_DIR=str(O/'zig-global'))
(O/'tmp').mkdir(exist_ok=True);env['TEMP']=env['TMP']=str(O/'tmp')
sources=[H/x for x in ['bootstrap05.c','observer_static05.c','identity_static05.c','package_static05.c','publisher_static05.c','bridge_static05.c','static_calls.S']]
sources += [B/'native_observer04/provider_calls.S',B/'installer04/source/memory.c',B/'packaging05/layout.c',B/'packaging05/layout_slot.c']
sources += [R/'source'/(n+'.c')for n in ['services','ui','cpu_entropy','recovery']]
sources += [P/x for x in ['provider/provider.c','w890_policy.c','w890_management.c','core/password_core.c','core/password_crypto.c']]
sources += [B/'navigation05'/x for x in ['navigation.c','bridges.c','free_stubs.S','first_bridge.S']]
sources += [B/'write_sinks05'/x for x in ['save_guard05.c','save_thunk05.S']]
exports='''i05_entry i05_preparse i05_loop i05_send i05_dispatch i05_services i05_failure i05_image_range i05_management_state
 i05_layout_get i05_layout_live i05_layout_symbol i05_static_layout
 mp_bind mp_publish mp_native_publish mp_callback mp_call_provider_return i05_profile_gate_return
 no_initialize no_prepare no_identity no_host no_observe no_scope_enter no_scope_validate no_scope_leave
 no_native_loop no_native_send_form no_publication_validate no_publication_finished
 no_management_enter no_management_valid no_management_leave
 w890_runtime_bind w890_provider w890_provider_begin w890_provider_end w890_provider_query w890_provider_request
 w890_provider_manage w890_config_callback w890_password_core w890_management_config w890_system_table w890_runtime_ended
 n05_bind n05_bridges_bind n05_history_allocate n05_history_reallocate n05_menu_free_stub n05_loop_free_stub
 n05_menu n05_native_render n05_native_page_input n05_native_frame_input n05_native_control_input n05_native_app_input
 n05_native_extra_input n05_native_alt_input n05_native_form_open n05_native_pending n05_native_first n05_first_dispatch n05_check n05_first no_describe_form_callback
 ws05_prepare ws05_before_save ws05_before_protected_action ws05_profile_callback_gate ws05_native_dispatch
 ws05_native_defaults ws05_native_load_defaults_save ws05_save_mid_thunk'''.split()
cmds=[];objs=[]
for i,s in enumerate(sources):
 obj=O/(str(i)+'_'+s.stem+'.obj');cmd=[str(zig),'clang','-target','x86_64-unknown-windows-msvc','-nostdinc','-isystem',str(zig.parent/'lib/include'),'-I',str(B/'management_live04/lab'),'-std=c11','-O2','-Wall','-Wextra','-Werror','-ffreestanding','-fno-builtin','-fno-stack-protector','-fno-unwind-tables','-fno-asynchronous-unwind-tables','-mno-red-zone','-mno-stack-arg-probe','-fshort-wchar','-c',str(s),'-o',str(obj)]
 cmds.append(cmd);r=subprocess.run(cmd,env=env,capture_output=True,creationflags=subprocess.CREATE_NO_WINDOW)
 if r.returncode:print((r.stdout+r.stderr).decode('utf8','replace'));r.check_returncode()
 objs.append(obj)
dll=O/'W890StaticAggregate05.UNBOUND.TESTONLY.dll';cmd=[str(zig),'lld-link','/dll','/noentry','/nodefaultlib','/machine:x64','/dynamicbase','/fixed:no','/base:0x180000000','/nxcompat','/timestamp:0','/opt:noref','/map:'+str(dll.with_suffix('.map')),'/out:'+str(dll),*['/export:'+x for x in exports],*[str(p)for p in objs]]
cmds.append(cmd);r=subprocess.run(cmd,env=env,capture_output=True,creationflags=subprocess.CREATE_NO_WINDOW)
if r.returncode:print((r.stdout+r.stderr).decode('utf8','replace'));r.check_returncode()
p=pefile.PE(str(dll));p.OPTIONAL_HEADER.CheckSum=p.generate_checksum();data=p.write();p.close();dll.write_bytes(data);p=pefile.PE(data=data)
assert not p.OPTIONAL_HEADER.DATA_DIRECTORY[1].Size and not p.OPTIONAL_HEADER.DATA_DIRECTORY[3].Size and not p.OPTIONAL_HEADER.DATA_DIRECTORY[9].Size
symbols={x.name.decode():x.address for x in p.DIRECTORY_ENTRY_EXPORT.symbols};sym={}
for line in dll.with_suffix('.map').read_text().splitlines():
 m=re.match(r'\s+[0-9A-Fa-f]{4}:[0-9A-Fa-f]+\s+(\S+)\s+([0-9A-Fa-f]{16})\s',line)
 if m:sym[m[1]]=int(m[2],16)-p.OPTIONAL_HEADER.ImageBase
md=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64);md.detail=True;image=bytes(p.get_memory_mapped_image());internal=[];effect=0;request=0
for sec in p.sections:
 if not sec.Characteristics&0x20000000:continue
 for ins in md.disasm(image[sec.VirtualAddress:sec.VirtualAddress+sec.Misc_VirtualSize],sec.VirtualAddress):
  if ins.mnemonic!='call':continue
  kind=0;target_export=None;offset=0
  if ins.bytes[0]==0xe8 and ins.size==5 and ins.operands[0].type==capstone.x86.X86_OP_IMM and ins.operands[0].imm==symbols['no_scope_enter']:kind=1;target_export='no_scope_enter';name='i05_effect_'+str(effect);effect+=1
  if ins.size==6 and ins.bytes[:2]==b'\xff\x15' and ins.operands[0].type==capstone.x86.X86_OP_MEM and ins.operands[0].mem.base==capstone.x86.X86_REG_RIP and ins.address+ins.size+ins.operands[0].mem.disp==symbols['w890_provider']+40:kind=3;target_export='w890_provider';offset=40;name='i05_request_'+str(request);request+=1
  if kind:internal.append({'name':name,'rva':ins.address+ins.size,'window_hex':image[ins.address+ins.size-16:ins.address+ins.size+16].hex(),'kind':kind,'instruction_rva':ins.address,'instruction_hex':bytes(ins.bytes).hex(),'target_export':target_export,'target_offset':offset})
(O/'internal_symbols.json').write_text(json.dumps(internal,indent=2)+'\n')
report={'status':'LINKED_STATIC_AGGREGATE_UNBOUND_NOT_FIRMWARE','sha256':hashlib.sha256(data).hexdigest(),'bytes':len(data),'image_size':p.OPTIONAL_HEADER.SizeOfImage,'sections':len(p.sections),'exports':symbols,'map_symbols':sym,'sources':{str(x.relative_to(ROOT)):hashlib.sha256(x.read_bytes()).hexdigest()for x in sources},'internal_symbols':internal,'commands':cmds}
(O/'build.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({k:report[k]for k in ['status','sha256','bytes','image_size','sections','internal_symbols']}))
