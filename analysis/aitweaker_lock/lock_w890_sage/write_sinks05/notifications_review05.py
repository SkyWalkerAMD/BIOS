"""Bind the exact offline notification closure, without any firmware I/O."""
from pathlib import Path
import json,hashlib,sys,uuid
H=Path(__file__).resolve().parent;R=H.parents[3];sys.path.insert(0,str(R/'tools/pydeps'))
import pefile,capstone
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
evidence=[]
for p in sorted(H.glob('rea*/response-*.json')):
 r=json.loads(p.read_text());s=r.get('structuredContent',{})
 if r.get('isError') or s.get('operation')!='analyze_function':continue
 evidence.append({'path':str(p.relative_to(R)),'sha256':sha(p),'evidence_id':s['evidence_id'],'subject':s['subject']['digest']['sha256'],'procedure':s['parameters']['procedure']})
catalog=json.loads((H.parent/'write_sinks04/native_variable_catalog.json').read_text())['items']
protected=[{'index':i,'name':catalog[i]['name'],'guid':catalog[i]['guid']}for i in [94,99,95]]
server=[]
for row in json.loads((H/'server_save_targets.json').read_text()):
 p=Path(row['path']);b=p.read_bytes();assert sha(p)==row['sha256'];e=pefile.PE(data=b);mi=e.get_memory_mapped_image()
 forbidden=[{'name':v['name'],'name_hits':b.count(v['name'].encode('utf-16le')),'guid_hits':b.count(uuid.UUID(v['guid']).bytes_le)}for v in protected]
 cache_guid_hits=b.count(uuid.UUID('451175cf-377b-4bbc-b0c3-f592c4920871').bytes_le)
 rt=0x2090 if row['name']=='Ip4BmcLanConfig'else 0x3090
 d=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64);d.detail=True;d.skipdata=True;refs=[]
 for sec in e.sections:
  if not sec.Characteristics&0x20000000:continue
  ins=list(d.disasm(mi[sec.VirtualAddress:sec.VirtualAddress+sec.Misc_VirtualSize],sec.VirtualAddress))
  for i,x in enumerate(ins):
   if not x.id:continue
   if any(o.type==capstone.CS_OP_MEM and o.mem.base==capstone.x86.X86_REG_RIP and x.address+x.size+o.mem.disp==rt for o in x.operands):
    refs.append({'rva':hex(x.address),'context':[f'{z.address:x}: {z.mnemonic} {z.op_str}'for z in ins[max(0,i-5):i+8]]})
 assert all(v['name_hits']==v['guid_hits']==0 for v in forbidden)and cache_guid_hits==0
 server.append({**row,'protected_literal_scan':forbidden,'native_cache_protocol_literal_hits':cache_guid_hits,'runtime_table_global_rva':hex(rt),'runtime_table_references':refs,
  'interpretation':'REA entry body uses GetVariable/SetVariable only for exact ServerSetup name/GUID and 0x401 bytes; subsidiary calls parse addresses and invoke BMC transport. No original AMITSE cache protocol is located or passed. Literal absence is corroboration, not standalone proof.'})
report={'status':'BOUNDED_ORIGINAL_SAVE_NOTIFICATION_OC_REVIEW','scope':'Exact ASUS W890E-SAGE SE0603 original PE artifacts; cooperative original firmware UI authentication, not hostile DXE/SMM containment or cross-device atomicity.',
 'protected_native_items':protected,
 'cache_binding':{'guid':'451175cf-377b-4bbc-b0c3-f592c4920871','installed_protocol_table_rva':'0xa7cd0','method_20_rva':'0x89244','descriptor_global':'0xbaaf8','pairs_global':'0xafcd8','identity':'Original method resolves full native name+GUID and returns corresponding16-byte pointer/size pair; the gate snapshots the same exact cache. Native indices are not IFRvarstore IDs.','actual_byte_tests':'build/native_save_tests.json'},
 'pre_save':{'guid':'f7ae935c-e0cf-42c6-a634-e92d73aeb107','publisher':'AMITSE1FD58→10704','consumers':[
  {'module':'2172B83D-EB47-4550-B2B9-BD9FE04C5745','callbacks':['0x1354','0x15e8'],'behavior':'Reads SetupLedData actual NV/cache; passes12-byte LED data to board LED protocol. No protected OC object/name/GUID is supplied; existing LED effects are preserved, not transformed into compensatable writes.'},
  {'module':'52E56827-7120-4ECE-AD00-13993B5F6DCB','callbacks':['0x1250'],'behavior':'Return only.'},
  {'module':'C818AAE4-6F82-4AF6-B698-E55073CFB7D3','callbacks':['0x1270'],'behavior':'Closes its notification event if supplied; reads Setup cache and actual NV; no SetVariable or OC mutation.'},
  {'module':'B131B6FD-87E2-42C1-AF5B-BEF2F382AFFE','callbacks':['0x1aa0'],'behavior':'Compares PchSetup byte; conditionally publishes reset-needed8731bf4a.'},
  {'module':'3785F3B4-6856-46B2-BBA4-2F0AE11BEA90','callbacks':['0x1394'],'behavior':'Compares SocketIioConfig; conditionally publishes reset-needed8731bf4a.'},
  {'module':'AsusFtmDxe','callbacks':['0x160c'],'behavior':'Creates FTMActiveFlag if absent; no OC variable/cache write.'},
  {'module':'AsusSmartHsioDxe','callbacks':['0x1578','0x1b58'],'behavior':'Static one-entry loop invokes1B58 return0. Other reset helpers are not reached by this one-entry preSave list.'},
  {'module':'Setup','callbacks':['0x788c','0x74cc'],'behavior':'Reads the exact OCMR pending pair and actual NV; may publish reset-needed8731bf4a. No OCMR mutation. Platform flag may cause publication even when OCMR is unchanged; actual byte test covers this.'},
  {'module':'Setup','callbacks':['0x1660c','0x164e0'],'behavior':'Reads exact OCMR pair and NV, compares training ranges, emits CMOS70/71 training flag only on diff. Actual equal/changed paths run in emulation with cache/NV unchanged.'}]},
 'downstream_reset':{'guid':'8731bf4a-654d-4af8-b9a2-2115c8070cf9','behavior':'Exact-module scan finds known publishers and AMITSE19A14 LocateProtocol; consumer chooses ResetSystem(0). No additional original notification consumer was found for this GUID.'},
 'save_callback_group':{'selector':'0xffff000d','callbacks':{'0x69ec':'Return only.','0x576e4':'Increment AmiHardwareSignatureSetupUpdateCount, attributes3,size4.','0x528ec':'Read ServerSetup and, when its network-config flags request, LoadImage/StartImage exact Ip4/Ip6 BMC network modules via52718. These retain original non-OC behavior.'},'server_modules':server},
 'post_save':{'guid':'d84beff0-159a-4b60-9ab9-ac5c474bd3b1','consumer':'FirmwareConfigDrv2B60','behavior':'Cleanup configuration allocations viaFEC0/15918/6148; optional AmiEmaIndications OR1; cleanup native cached string list via protocol72054231 method18.',
  'protocol':'72054231-4e1e-474d-8900-68cd2c0bdbf8','provider':'AMITSE tableA7E10 method18→8EEFC','native_cleanup':'8EEFC frees owned string/node list atB8C28 and clears head, tested using actual bytes; no OC/NV update.'},
 'profile_import':{'entry':'Controlled original Setup ConfigAccess callback2250','qids':['0x2bfb','0x2bfd','0x2bfe','0x2bff'],'load_chain':'1457C→13DD8→122A0(masked original native cache application)','save_chain':'1457C→13A54','gate':'ws05_profile_callback_gate before delegate2250, actual compiled helper/nativecaller/config identity and private NO_EFFECT/provider required. No Setup code/data overlay is required.',
  'form':'2BFC contains original8-slot ASUS User Profile; no separately advertised USB/file import control found in this exact form. This is not a claim about every external firmware API.'},
 'preserved_vendor_semantics':['Individual original SetVariable errors may be ignored by nativeSave; authentication gate does not repair or hide that behavior.','Boot/Driver configuration, network and LED actions retain original order on permitted Save.','Restoring defaults requires authentication before original dispatcher group or outer851A4 effects; cancellation does not partially run those bodies.'],
 'integration_conditions':['Static patches must have safe pre-prepare behavior: normal FD6C selectors continue original initialization; Save cancellation target must never beNULL.','Root/navigation owns original40094 pending HII/reconnect and all page/control gates; Save notification findings do not substitute for that separate native queue ownership.','External APIs outside the private BIOS session have no minted write ticket and protected wrappers reject; no generic owner=true exception.','Arbitrary third-party callbacks/hostile firmware are outside this GUI-password threat model.'],
 'rea_evidence':evidence,'bindings':[]}
inputs=['save_notification_modules.json','notification_xrefs.json','oc_downstream_notifications.json','downstream_xrefs.json','native_cache_protocol_refs.json','final_notify_refs.json','final_notify_protocol_modules.json','final_notify_protocol_refs.json','profile_callback_bindings.json','profile_direct_callers.json','server_save_targets.json','build/native_save_tests.json','save_guard05.c','save_guard05.h','save_thunk05.S','patch_contract05.json','notifications_review05.py']
for name in inputs:
 p=H/name;report['bindings'].append({'path':str(p.relative_to(R)),'sha256':sha(p)})
(H/'notification_closure05.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({'status':report['status'],'REA_functions':len(evidence),'server_modules':len(server),'sha256':sha(H/'notification_closure05.json')}))
