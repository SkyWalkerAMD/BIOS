from parser_lab import *
import zipfile,time

def descriptors(v):
 table=v.rq(TSE+0xbaaf0);blob=v.rq(TSE+0xbabc0);cb=v.rq(TSE+0xbab08);out=[]
 for i in range(v.rd(table)):
  p=blob+v.rd(table+4+4*i);controls=[]
  for j in range(v.rd(p+28)):
   c=cb+v.rd(p+32+4*j);op=v.rq(c+40)
   # Unbound static pages for other absent HII packages contain offsets rather
   # than published IFR pointers; do not claim those objects are usable.
   code=bytes(v.u.mem_read(op,bytes(v.u.mem_read(op+1,1))[0]&127)) if op and v.rq(c)==v.hii else b''
   controls.append({'descriptor':c,'type':v.rw(c+20),'hii':v.rq(c),'opcode_address':op,'opcode':code.hex(),'question':v.rw(op+6) if len(code)>=13 else None})
  out.append({'index':i,'descriptor':p,'hii':v.rq(p),'form':v.rw(p+10),'controls':controls})
 return out

def make_buttons(v,pages):
 found=[]
 for p in pages:
  if p['hii']!=v.hii or p['form']!=0x271d:continue
  for c in p['controls']:
   if c['question'] not in [0xffd0,0xffd1,0xffd2] or not c['opcode'].startswith('0c0f'):continue
   assert c['type']==27
   out=v.put(bytes(8));assert v.call(0x68ae8,[out])==0;obj=v.rq(out)
   assert v.call(0x68b38,[obj,c['descriptor']])==0
   assert v.rq(obj)==TSE+0x95620 and v.rw(obj+0x34)==27 and v.rq(obj+0x20)==v.hii and v.rq(obj+0x48)==c['opcode_address']
   found.append({**c,'object':obj,'page_index':p['index'],'form':p['form']})
 assert len(found)==3
 return found

def export_snapshot(v,pages,buttons,out):
 state={'format':'W8900603-original-parser-v1','tse_base':TSE,'hii':v.hii,'pool_base':POOL,'pool_bytes':v.next-POOL,'static':v.static,'original_module_sha256':v.original_sha,'setupdata_sha256':v.static_sha,'services':'Modeled UEFI; no native parser/constructor replacement; absent variables return EFI_NOT_FOUND; three exact volatile DynamicPage writes only; freed pools poisoned 0xDD; monotonic allocator without reuse','pages':pages,'buttons':buttons,'live_allocations':v.live,'events':v.events,'calls':dict(v.calls),'writes':v.writes}
 with zipfile.ZipFile(out,'w',zipfile.ZIP_DEFLATED,compresslevel=6)as z:
  z.writestr('tse-mapped.bin',bytes(v.u.mem_read(TSE,0xde000)))
  z.writestr('pool.bin',bytes(v.u.mem_read(POOL,v.next-POOL)))
  z.writestr('forms.pack',v.forms)
  z.writestr('state.json',json.dumps(state,separators=(',',':')))
 return {'path':str(out.relative_to(HERE)),'sha256':hashlib.sha256(out.read_bytes()).hexdigest(),'bytes':out.stat().st_size}

def main():
 started=time.monotonic();checks=[]
 original=VM(False,hii=0x900013);assert original.run()==0;op=descriptors(original);checks.append('Full original forms parse returns EFI_SUCCESS')
 v=VM(True,hii=0x900013);assert v.run()==0;ps=descriptors(v);checks.append('Full original forms plus exactly 45 management bytes parse returns EFI_SUCCESS')
 assert len(op)==len(ps);checks.append('Page count unchanged by management controls')
 for a,b in zip(op,ps):
  assert (a['index'],a['hii'],a['form'])==(b['index'],b['hii'],b['form'])
  if a['hii']!=v.hii:continue
  aa=[(c['type'],c['hii'],c['opcode'])for c in a['controls']]
  bb=[(c['type'],c['hii'],c['opcode'])for c in b['controls'] if not(c['question']in [0xffd0,0xffd1,0xffd2]and c['opcode'].startswith('0c0f'))]
  assert aa==bb,(a['index'],a['form'])
 checks.append('Every original bound Setup page/control opcode/type/HII unchanged after removing three new management actions; unbound static records are excluded')
 buttons=make_buttons(v,ps);checks.append('All three actual native 68AE8 constructors and 68B38 initializers succeed with original parser descriptors')
 checks.append('Three native type27 / 95620 vtables retain exact parsed ACTION opcodes and Setup HII ownership')
 for c in buttons:
  assert any(p<=c['descriptor'] and c['descriptor']+0x40<=p+n for p,n in v.live.items())
  assert any(p<=c['opcode_address'] and c['opcode_address']+15<=p+n for p,n in v.live.items())
  assert any(p<=c['object'] and c['object']+0x88<=p+n for p,n in v.live.items())
 checks.append('All management raw descriptors, source opcodes and objects reside in still-live actual allocation results')
 assert all(x['attributes']==2 for x in v.writes)and len(v.writes)==3;checks.append('No modeled nonvolatile variable writes; only three exact native volatile DynamicPage initializations')
 artifact=export_snapshot(v,ps,buttons,HERE/'parser-snapshot.zip')
 report={'status':'PASS','checks':checks,'check_count':len(checks),'page_count':len(ps),'setup_hii_count':1,'not_full_hardware_inventory':True,'buttons':buttons,'snapshot':artifact,'original_module_sha256':v.original_sha,'setupdata_sha256':v.static_sha,'sources':{x:hashlib.sha256((HERE/x).read_bytes()).hexdigest()for x in ['parser_lab.py','verify_parser.py']},'elapsed_seconds':round(time.monotonic()-started,3)}
 (HERE/'parser_tests.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
if __name__=='__main__':main()
