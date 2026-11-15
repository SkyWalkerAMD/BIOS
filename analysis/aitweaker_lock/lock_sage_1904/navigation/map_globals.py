from map_native import *
import struct
def main():
 a=image(OLD/'AMITSE.efi');b=image(NEW/'AMITSE.efi');cs.skipdata=True
 wanted=[0x82748,0x92270,0x92b08,0x82628,0x6af78,0x6af80,0x6ae90,0x7cb30,0x82998,0x824c8]
 out={hex(x):[] for x in wanted}
 for ins in cs.disasm(a[0x2c0:0x6a18f],0x2c0):
  if not ins.id:continue
  for op in ins.operands:
   if op.type!=C.CS_OP_MEM or op.mem.base!=X86_REG_RIP:continue
   target=ins.address+ins.size+op.mem.disp
   if target not in wanted or len(out[hex(target)])>=6:continue
   pat,_=pattern(a,ins.address,12);found=[m.start() for m in re.finditer(pat,b,re.S)]
   if len(found)!=1:continue
   new=next(cs.disasm(b[found[0]:found[0]+16],found[0]));no=new.operands[-1]
   rip=[o for o in new.operands if o.type==C.CS_OP_MEM and o.mem.base==X86_REG_RIP]
   if len(rip)!=1:continue
   out[hex(target)].append({'old_instruction':hex(ins.address),'new_instruction':hex(new.address),'new_target':hex(new.address+new.size+rip[0].mem.disp),'old_text':ins.mnemonic+' '+ins.op_str,'new_text':new.mnemonic+' '+new.op_str})
 pointers={}
 for old,new in [(0x16ae0,0x16a90),(0x16c70,0x16c20),(0x121b8,0x12168),(0x1200c,0x11fbc)]:
  pointers[hex(old)]={'old_refs':[hex(m.start()) for m in re.finditer(re.escape(struct.pack('<Q',old)),a)],'new':hex(new),'new_refs':[hex(m.start()) for m in re.finditer(re.escape(struct.pack('<Q',new)),b)]}
 (HERE/'global_mapping.json').write_text(json.dumps({'rip_targets':out,'data_pointer_values':pointers},indent=2),encoding='utf8')
 print(json.dumps({'globals':{k:sorted(set(x['new_target'] for x in v)) for k,v in out.items()},'pointers':pointers},indent=2))
if __name__=='__main__':main()
