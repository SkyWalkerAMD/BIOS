"""Recover the exact type/vtable registry traversed by original FrameAddControl.

The traversal and layout come from actual REA analysis at RVA 22178. Exporting
the original input target is not approval to call it with an unowned object.
"""
from map_w890 import *
import struct

def main():
 b=image(NEW/'AMITSE.efi');items=[]
 for i in range(64):
  rva=0x943f0+i*40;raw=b[rva:rva+40];kind,table,hascb,callback,cookie=struct.unpack('<5Q',raw)
  if not kind:
   assert i==15 and raw==bytes(40);break
  assert kind<=0xffff and hascb in [0,1] and table%8==0
  methods=struct.unpack_from('<6Q',b,table)
  assert all(0x1000<=v<0x92dda for v in methods)
  items.append({'type':kind,'descriptor_rva':rva,'descriptor_bytes':raw.hex(),'vtable_rva':table,'create_rva':methods[0],'destroy_rva':methods[1],'initialize_rva':methods[2],'render_rva':methods[3],'input_rva':methods[4],'register_callback_rva':methods[5],'callback_enabled':bool(hascb),'callback_rva':callback,'callback_cookie_rva':cookie,'input_slot_rva':table+0x20,'input_slot_bytes':b[table+0x20:table+0x28].hex()})
 else:raise AssertionError('unterminated original type registry')
 out={'status':'STATIC_SOURCE_BOUND_TYPE_REGISTRY','original_amitse_sha256':sha((NEW/'AMITSE.efi').read_bytes()),'source_sha256':sha(Path(__file__).read_bytes()),'count':len(items),'registry_rva':0x943f0,'stride':40,'terminator_rva':0x94648,'items':items,'evidence':{'factory':'rea/W890-frameaddcontrol22178.json','factory_rva':0x22178,'base_question_initialize':'rea/W890-questioncontrolinit32470.json','initialize_copy':'Original32470 copies descriptor64 bytes into control+20 only after required descriptor fields pass. Descriptor+28 becomes control+48 and is consumed as IFR opcode by31DD8.','control_type_u16':0x34,'candidate_question_ifr_pointer':0x48,'candidate_question_hii_handle':0x20,'candidate_fields_require_live_HII_binding':True},'special_cases':['Type14 at95680 is the menu; bind callback slot94408 plus existing object callback provenance before relying on its navigation gate.','Types6 and10 intentionally share vtable93F90. Match type AND table; do not infer type solely from virtual target.','Page extras use275D0 at93EC0 and a different hotkey structure; they are not these question objects.','Event kind2 broadcasts Input to every control. A prompt-before-every-virtual-call adapter needs hit-testing/consumption semantics; selected-control-only inspection is incomplete.','A vtable-target allowlist does not prove object extent, HII owner, original IFR bytes, native session, or mutation-free prompt return.'],'installed':False,'hardware_accepted':False}
 (HERE/'control_registry_0603.json').write_text(json.dumps(out,indent=2)+'\n',encoding='utf8');print(json.dumps({'status':out['status'],'count':len(items),'sha256':sha((HERE/'control_registry_0603.json').read_bytes())}))

if __name__=='__main__':main()
