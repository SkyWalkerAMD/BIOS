"""Bind original Setup IFR, bounded native descriptors and prior REA evidence.

Type numbers are derived from original AMITSE3E700; this is a candidate input
inventory, not authorization of callbacks or a physical page inventory.
"""
from pathlib import Path
import sys,json,hashlib,struct,zipfile,collections
H=Path(__file__).resolve().parent;B=H.parent;R=H.parents[3]
sys.path.insert(0,str(R/'tools/pydeps'))
import pefile
sha=lambda b:hashlib.sha256(b).hexdigest()
setup_path=B/'navigation/modules/Setup.efi';setup=setup_path.read_bytes()
assert sha(setup)=='c1cf9d755c2ea043d44f19fdf4009cf8b12b03f85e8939034de19ee18251b72e'
pe=pefile.PE(data=setup);mapped=pe.get_memory_mapped_image()
table=json.loads((B/'navigation06_actions/setup_handler_table.json').read_text())
for e in table['entries']:
 kind,qid,fn=struct.unpack_from('<IH2xQ',mapped,e['rva'])
 assert (kind,qid,fn)==(e['type'],e['qid'],int(e['handler'],16))
assert int.from_bytes(mapped[table['terminator_rva']+8:table['terminator_rva']+16],'little')==0
dec_path=B/'foreign_hii05/decoded/Setup_0.json';dec=json.loads(dec_path.read_text())
forms=(R/dec['forms_blob']['path']).read_bytes();assert sha(forms)==dec['forms_blob']['sha256']
questions=[q for q in dec['records']if q.get('callback')and'question_id'in q]
records_by_key=collections.defaultdict(list)
for q in questions:
 assert forms[q['package_offset']:q['package_offset']+q['size']].hex()==q['hex']
 records_by_key[(q['form_id'],q['question_id'],q['hex'])].append(q)
zip_path=B/'integration05/parser-snapshot.zip'
with zipfile.ZipFile(zip_path)as z:s=json.loads(z.read('state.json'));pool=z.read('pool.bin')
def pool_read(a,n):
 assert s['pool_base']<=a and a+n<=s['pool_base']+len(pool)
 return pool[a-s['pool_base']:a-s['pool_base']+n]
native=collections.defaultdict(list)
for page in s['pages']:
 if not page['hii']:continue
 for c in page['controls']:
  raw=pool_read(c['descriptor'],64);flags=int.from_bytes(raw[28:32],'little')
  if not flags&32:continue
  qid=int.from_bytes(raw[12:14],'little');key=(page['form'],qid,c['opcode'])
  if key not in records_by_key:continue
  native[key].append({'page_index':page['index'],'form':page['form'],
    'snapshot_hii':page['hii'],'descriptor_address':c['descriptor'],'descriptor_hex':raw.hex(),
    'native_kind':int.from_bytes(raw[20:22],'little'),'native_flags':flags,'opcode_address':c['opcode_address']})
def types_close(q):
 b=bytes.fromhex(q['hex']);op=q['op']
 if op in (5,7):return [b[13]&3]
 return {6:[4],8:[7],0x0c:[10],0x0f:[9,12],0x1a:[6],0x1b:[5],0x1c:[7],0x23:[8,11]}.get(op,[])
byqid=collections.defaultdict(list)
for e in table['entries']:byqid[e['qid']].append(e)
static_qid_count=len(byqid)
rows=[]
for q in questions:
 key=(q['form_id'],q['question_id'],q['hex'])
 rows.append({'form':q['form_id'],'qid':q['question_id'],'opcode':q['op'],'ifr_type':q['type'],
  'ifr_package_offset':q['package_offset'],'ifr_hex':q['hex'],'ifr_flags':q['flags'],
  'action3_candidate_types':[9],'action4_candidate_types':types_close(q),
  'type_revision_condition':'REF: Type9 if accepted legacy revision<0x2001e;Type12 otherwise'if q['op']==15 else None,
  'original_static_handlers':[e['handler']for e in byqid[q['question_id']]],
  'bounded_native_descriptor_bindings':native[key],
  'excluded_password_management':q['op']==8 or any(e['handler']=='0xd604'for e in byqid[q['question_id']]),
  'runtime_authorized':False})
qidinputs=[]
for qid in sorted({r['qid']for r in rows}):
 qr=[r for r in rows if r['qid']==qid]
 qidinputs.append({'qid':qid,'types':sorted({t for r in qr for t in r['action3_candidate_types']+r['action4_candidate_types']}),
  'action3_types':sorted({t for r in qr for t in r['action3_candidate_types']}),
  'action4_types':sorted({t for r in qr for t in r['action4_candidate_types']}),
  'forms':sorted({r['form']for r in qr}),
  'handlers':[e['handler']for e in byqid[qid]],
  'excluded_password_management':any(r['excluded_password_management']for r in qr)})
binding_paths=[setup_path,dec_path,R/dec['forms_blob']['path'],zip_path,
 B/'navigation06_actions/setup_handler_table.json',B/'navigation06_actions/setup_callback_action_tests.json',
 B/'navigation06_actions/rea_index.json',B/'navigation06_actions/decoded/AMITSE_3e700.json',
 B/'navigation06_actions/decoded/AMITSE_3e700.c.txt',B/'navigation06_actions/decoded/Setup_2250.json']
out={'status':'CANDIDATE_EXACT_ORIGINAL_IFR_AND_BOUNDED_NATIVE_INPUTS_ONLY',
 'source_sha256':sha(Path(__file__).read_bytes()),'original_setup_sha256':sha(setup),
 'original_forms_sha256':sha(forms),'static_entries':len(table['entries']),
 'static_qids':static_qid_count,'original_callback_questions':len(rows),'unique_callback_qids':len(qidinputs),
 'callback_qids_without_static_handler':sum(not q['handlers']for q in qidinputs),
 'callback_type_numbers':sorted({t for q in qidinputs for t in q['types']}),
 'descriptor_bound_questions':sum(bool(r['bounded_native_descriptor_bindings'])for r in rows),
 'inputs':[{'path':p.relative_to(R).as_posix(),'sha256':sha(p.read_bytes())}for p in binding_paths],
 'questions':rows,'qid_inputs':qidinputs,
 'limitations':['Native descriptors are from a previously bounded parser snapshot, not proof of complete current hardware parser state.',
 'Original Setup forms hash is separately physically matched by HII06, but exact runtime dynamic handler list and values remain unobserved.',
 'Types derive from original3E700 paths; no services or value extraction in3E700 are authorized by this inventory.',
 'Known password-management callback QIDs are excluded from new execution.'],
 'runtime_authorized':False}
(H/'inputs.json').write_text(json.dumps(out,indent=2)+'\n')
print(json.dumps({k:v for k,v in out.items()if k not in ['questions','qid_inputs','inputs','limitations']}))
