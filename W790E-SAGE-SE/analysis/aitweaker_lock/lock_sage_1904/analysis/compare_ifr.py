from pathlib import Path
import collections, hashlib, json, sys
HERE=Path(__file__).resolve().parent
BASE=HERE.parents[1]
sys.path.insert(0,str(BASE))
from inspect_forms import QUESTIONS

def save(name,v):(HERE/name).write_text(json.dumps(v,ensure_ascii=False,indent=2)+'\n',encoding='utf8')
def read(path):return json.loads(path.read_text(encoding='utf8'))
def compact(r):return {k:r[k] for k in ('offset','type','form','form_id','title','prompt','question_id','varstore_id','var_offset','target_form','flags','hex') if k in r}
def policy(case):
    rs=[r for p in read(case/'modules/Setup_IFR.json') for r in p['records']]
    f=read(case/'forms_1904.json')
    inert=[r for r in rs if r.get('form')==0x271b and r.get('varstore_id')==29]
    ei=next(i for i,r in enumerate(rs) if r.get('form_id')==0x271b); di=ei+1
    assert rs[di]['hex']=='1e82' and rs[di+1]['hex']=='4602' and rs[di]['end']==rs[ei]['end']-2
    assert all(di in r['parents'] and r['size']==17 and r['type']=='NUMERIC' and not r['flags'] and not r['prompt_id'] and not r['help_id'] for r in inert)
    assert all(sum(x.get('question_id')==r['question_id'] for x in rs)==1 for r in inert)
    inert_offsets={r['offset'] for r in inert}
    active=[r for r in rs if r['offset'] not in inert_offsets]
    protected={r['form_id'] for r in f['reachable_forms_by_local_ifr_ref']}|{0x2712,0x272c}
    protected.update(r['form'] for r in active if r.get('form') is not None and r.get('varstore_id')==29)
    qs=[r for r in active if 'question_id' in r and (r.get('form') in protected or r.get('varstore_id')==29 or (r.get('varstore_id')==33 and r.get('var_offset') in (0x10,0xbd,0xbe)))]
    ids={r['question_id'] for r in qs}|{3,0x272d,0x272f}
    title={r['form_id']:r['title'] for r in rs if r['op']==1}
    stores=[r for r in rs if r['op'] in (36,37,38)]
    return rs,protected,qs,{'forms':[{'id':hex(x),'title':title[x]} for x in sorted(protected)],'form_count':len(protected),'question_count':len(ids),'permanently_disabled_exit_descriptors':[compact(r) for r in inert],'socket_memory_questions':[compact(r) for r in qs if r.get('varstore_id')==33],'protected_varstores':[compact(r)|{k:r[k] for k in ('name','guid','varstore_size') if k in r} for r in stores if r.get('varstore_id') in (29,33)],'question_varstores':dict(collections.Counter(r['varstore_id'] for r in qs))}

def main():
    sr,sp,sq,ss=policy(HERE)
    ar,ap,aq,ass=policy(BASE/'hardware_20261102_W790_ACE_E9B906DF')
    st={r['form_id']:r['title'] for r in sr if r['op']==1}; at={r['form_id']:r['title'] for r in ar if r['op']==1}
    def key(r,t):return (r['op'],t.get(r.get('form')),r.get('prompt'),r.get('varstore_id'),r.get('var_offset'),t.get(r.get('target_form')),r.get('flags'))
    sg=collections.defaultdict(list);ag=collections.defaultdict(list)
    for r in sq:sg[key(r,st)].append(r)
    for r in aq:ag[key(r,at)].append(r)
    added=[compact(r) for k,items in sg.items() for r in items[len(ag[k]):]]
    removed=[compact(r) for k,items in ag.items() for r in items[len(sg[k]):]]
    paired=[{'sage':compact(s),'ace':compact(a)} for k,items in sg.items() for s,a in zip(items,ag[k]) if s['question_id']!=a['question_id']]
    protected_stores={r['varstore_id'] for r in sq}
    result={'source_ifr_sha256':hashlib.sha256((HERE/'modules/Setup_IFR.json').read_bytes()).hexdigest(),'sage_policy':ss,'ace_policy':ass,'protected_forms_equal':sp==ap,'sage_only_forms':sorted(sp-ap),'ace_only_forms':sorted(ap-sp),'question_identity_key':['op','form_title','prompt','varstore_id','var_offset','target_form_title','flags'],'sage_only_questions':added,'ace_only_questions':removed,'matched_questions_with_changed_id':paired,'non_ocmr_protected_questions':[compact(r) for r in sq if r.get('varstore_id') not in (0,29,33)],'all_protected_varstore_ids':sorted(protected_stores),'credential_action_question_ids_available':not {0xffe0,0xffe1}&{r.get('question_id') for r in sr},'scope':'Static IFR only; no runtime graph coverage, firmware execution or device tests. Matching uses page titles and question properties; duplicate-key instances paired in IFR order, not asserted original source equivalence.'}
    save('policy_comparison.json',result)
    print(json.dumps({'sage_form_count':ss['form_count'],'sage_question_count':ss['question_count'],'question_id_changed_count':len(paired),'sage_only_questions':added,'ace_only_questions':removed,'protected_form_titles_sage_only':sorted({st[x] for x in sp}-{at[x] for x in ap}),'protected_form_titles_ace_only':sorted({at[x] for x in ap}-{st[x] for x in sp})},ensure_ascii=False,indent=2))
if __name__=='__main__':main()
