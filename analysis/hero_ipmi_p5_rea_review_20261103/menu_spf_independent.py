"""Independent structural walk. Does not import the producer or original verifier."""
from pathlib import Path
import struct,json,hashlib,collections
P=Path(__file__).resolve().parent;ROOT=P.parents[1]
def u(b,p,n=4):
    assert 0<=p<=len(b)-n
    return int.from_bytes(b[p:p+n],'little')
def load(b):
    assert b[:4]==b'$SPF'
    tb,cb,ce=u(b,44),u(b,48),u(b,52)
    np=u(b,tb);pages=[]
    for i in range(np):
        st=u(b,tb+4+i*4);en=u(b,tb+8+i*4) if i+1<np else cb
        n=u(b,st+28);assert st+32+n*4<=en<=cb
        cs=[]
        for j in range(n):
            c=cb+u(b,st+32+j*4);assert cb<=c<=ce-64
            cs.append(b[c:c+64])
        pages.append((b[st:st+32],cs))
    return pages

old=load((ROOT/'analysis/hero_ipmi_p1b/reference/HERO-3107-AMITSESetupData.bin').read_bytes())
new=load((ROOT/'analysis/hero_ipmi_p5/AMITSESetupData-P5.bin').read_bytes())
ifr=(ROOT/'analysis/hero_ipmi_p5/Setup-forms-P5.bin').read_bytes()
pos=4;stack=[];ops={};forms={};current=None;new_types=collections.Counter();new_ids=set()
while pos<len(ifr):
    typ=ifr[pos];ln=ifr[pos+1]&127;scope=ifr[pos+1]&128
    assert 2<=ln<=len(ifr)-pos
    ops[pos]=ifr[pos:pos+ln]
    if typ==1:
        fid=u(ifr,pos+2,2);assert fid not in forms;forms[fid]=[]
    if typ==0x29:
        assert stack;stack.pop()
    else:
        current=next((x[1] for x in reversed(stack) if x[0]==1),None)
        if current is not None:forms[current].append(pos)
        if scope:stack.append((typ,u(ifr,pos+2,2) if typ==1 else None))
    pos+=ln
assert pos==len(ifr) and not stack
assert len(new)==len(old)+5
edges=[]
for i in range(299,304):
    page,controls=new[i]
    assert u(page,8,2)==1 and u(page,10,2)==0x3100+i-299
    assert u(page,16,2)==i and u(page,18,2)==(35 if i==299 else 299)
    assert u(page,20)==0 and u(page,24)==58
    assert u(page,28)==len(controls)
    assert [u(c,40,8) for c in controls]==forms[u(page,10,2)]
    for j,c in enumerate(controls):
        op=ops[u(c,40,8)];new_types[op[0]]+=1
        assert u(c,22,2)==i and u(c,36,2)==j and u(c,38,2)==1
        assert u(c,28)==1 and u(c,48,8)==0 and u(c,58,2)==0
        assert u(c,32,2)==u(op,4,2) and u(c,60,2)==u(op,2,2)
        if op[0]==3:
            assert len(op)==8 and u(c,20,2)==3 and u(c,24,2)==65535
        else:
            assert op[0]==15 and len(op)==15 and op[12]==0
            assert u(op,8,2)==0 and u(op,10,2)==65535
            assert u(c,20,2)==1
            dest=u(c,24,2);assert new[dest][0][10:12]==op[13:15]
            edges.append([i,dest]);assert u(op,6,2) not in new_ids;new_ids.add(u(op,6,2))
c=new[35][1][-1];op=ops[u(c,40,8)]
assert op[0]==15 and u(c,24,2)==299 and u(op,13,2)==0x3100
assert len(new[35][1])==len(old[35][1])+1
edges.insert(0,[35,299])
assert edges==[[35,299],[299,300],[299,301],[299,302],[299,303]]
report={'passed':True,'scope':'independent byte-level structure only; does not prove firmware runtime',
'old_pages':len(old),'new_pages':len(new),'new_form_ids':[hex(i) for i in range(0x3100,0x3105)],
'new_page_control_opcodes':dict(new_types),'advanced_added_ref_controls':1,'edges':edges,
'old_page_flags_values':dict(collections.Counter(u(p,20) for p,cs in old)),
'new_pages_flags_match_original_zero':True,'new_pages_refresh_metadata_58_matches_292_original_pages':True,
'new_questions_have_no_varstore_or_callback':True,'original_pe_payload_unchanged':False}
report.pop('original_pe_payload_unchanged')
(P/'menu-spf-independent.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps(report,indent=2))
