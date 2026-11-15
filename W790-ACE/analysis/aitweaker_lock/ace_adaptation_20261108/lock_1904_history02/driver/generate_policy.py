from pathlib import Path
import json,hashlib
HERE=Path(__file__).resolve().parent
ROOT=next(p for p in HERE.parents if (p/'tools/zig-x86_64-windows-0.14.1/zig.exe').is_file())
CASE=ROOT/'analysis/aitweaker_lock/hardware_20261102_W790_ACE_E9B906DF'
r=[r for p in json.loads((CASE/'modules/Setup_IFR.json').read_text(encoding='utf8')) for r in p['records']]
forms=json.loads((CASE/'forms_1904.json').read_text(encoding='utf8'))
protected={x['form_id'] for x in forms['reachable_forms_by_local_ifr_ref']}
protected.update([0x2712,0x272c])
# The original Exit form contains legacy storage descriptors under a literal
# DISABLE_IF TRUE. They cannot be interacted with and must not password-gate Exit.
# Verify this exact 1904 construct and unique question IDs before excluding it.
exit_index=next(i for i,x in enumerate(r) if x.get('form_id')==0x271b)
disabled_index=exit_index+1
assert r[disabled_index]['hex']=='1e82' and r[disabled_index+1]['hex']=='4602'
assert r[disabled_index+2]['type']=='NUMERIC'
assert r[disabled_index]['end']==r[exit_index]['end']-2
inert=[x for x in r if x.get('form')==0x271b and x.get('varstore_id')==29]
assert len(inert)==7 and {x['question_id'] for x in inert}==set(range(1832,1839))
for x in inert:
 assert disabled_index in x['parents'] and x['size']==17 and x['type']=='NUMERIC'
 assert not x['flags'] and not x['prompt_id'] and not x['help_id']
 assert sum(y.get('question_id')==x['question_id'] for y in r)==1
inert_offsets={x['offset'] for x in inert}
active=[x for x in r if x['offset'] not in inert_offsets]
protected.update(x['form'] for x in active if x.get('form') is not None and x.get('varstore_id')==29)
assert 0x271b not in protected
questions={x['question_id'] for x in active if 'question_id' in x and (x.get('form') in protected or x.get('varstore_id')==29 or (x.get('varstore_id')==33 and x.get('var_offset') in [0x10,0xbd,0xbe]))}
questions.update([3,0x272d,0x272f])
assert not {0xffe0,0xffe1}&{x.get('question_id') for x in r}
def arr(name,values):
 v=sorted(values)
 return 'static const uint16_t '+name+'[]={\n'+''.join(' '+','.join(hex(x) for x in v[i:i+16])+',\n' for i in range(0,len(v),16))+'};\n'
inert_bytes='static const uint8_t inert_exit_questions[][17]={\n'+''.join(' {'+','.join(hex(b) for b in bytes.fromhex(x['hex']))+'},\n' for x in inert)+'};\n'
(HERE/'policy_data.h').write_text('/* Generated from verified official 1904 IFR; not a dynamic path coverage claim. */\n'+arr('protected_forms',protected)+arr('protected_questions',questions)+inert_bytes,encoding='utf8')
report={'source_ifr_sha256':hashlib.sha256((CASE/'modules/Setup_IFR.json').read_bytes()).hexdigest(),'form_count':len(protected),'question_count':len(questions),'forms':[{'id':hex(i),'title':next((x['title'] for x in r if x.get('form_id')==i),'')} for i in sorted(protected)],'socket_memory_byte_offsets':['0x10','0xbd','0xbe'],'limits':'Dynamic controls additionally scanned at runtime. Non-HII search/EZ and raw hardware writes are not proven by this static map.'}
report['permanently_disabled_exit_descriptors']=[{'question_id':hex(x['question_id']),'ifr_hex':x['hex'],'disable_if_offset':r[disabled_index]['offset'],'predicate':'literal TRUE','dynamic_exception':'exact 17-byte descriptor match only; variable writes remain guarded'} for x in inert]
(HERE/'policy.json').write_text(json.dumps(report,indent=2,ensure_ascii=False),encoding='utf8')
print(json.dumps({'forms':len(protected),'questions':len(questions)}))
