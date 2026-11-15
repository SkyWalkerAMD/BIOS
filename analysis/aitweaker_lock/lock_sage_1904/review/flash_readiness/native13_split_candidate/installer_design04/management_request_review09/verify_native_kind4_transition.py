"""Original171D4 source update on real-constructed kind4, controlled arguments."""
from pathlib import Path
import hashlib,json,sys
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent;C07=HERE.parent/'static_chrome_candidate07'
source=(C07/'verify_chrome.py').read_text(encoding='utf8').split('\nchecks=[];observations=[]',1)[0]
ns={'__file__':str(C07/'verify_chrome.py')};exec(compile(source,str(C07/'verify_chrome.py')+' [prefix only]','exec'),ns)
V,S,q,d,TSE,HEAP=[ns[x]for x in ['ChromeVM','S','q','d','TSE','HEAP']]
rows=[]
for label,hii,token,expected in [('nonzero page title token with foreign source',0x99998888,0x1234,0),
                               ('zero token does not update source',0x99998888,0,-1),
                               ('AMITSE fallback source remains own string package',0x99887766,0x1234,-1)]:
 v=V(4);v.u.mem_write(v.page+0x20,q(0x99998888))
 before=bytes(v.u.mem_read(v.control,0x88));ifr=bytes(v.u.mem_read(v.ifr,16))
 page=HEAP+0x26d000;array=page+0x100
 v.u.mem_write(page+0x4c,d(6)+q(array));v.u.mem_write(array,q(v.frame)*6)
 v.call(TSE+0x171d4,page,4,hii,token)
 after=bytes(v.u.mem_read(v.control,0x88));actual=v.call(S['AMITSE']['frame_protected'],v.frame)
 signed=-1 if actual in [0xffffffff,0xffffffffffffffff]else actual
 assert signed==expected,label
 assert before[:0x20]==after[:0x20] and before[0x28:]==after[0x28:]
 assert bytes(v.u.mem_read(v.ifr,16))==ifr
 assert v.getq(v.control+0x20)==(hii if token else v.amih)
 rows.append({'case':label,'requested_hii':hex(hii),'token':token,'actual_source_hii':hex(v.getq(v.control+0x20)),
              'actual_frame_class':signed,'only_control_source_may_change':True,'ifr_unchanged':True,
              'callback_rva':hex(v.getq(v.control+8)-TSE),'callback_cookie_rva':hex(v.getq(v.control+24)-TSE)})
report={'status':'PASS_ORIGINAL_KIND4_SOURCE_UPDATE_SEMANTICS_NOT_FULL_RENDER',
 'cases':len(rows),'rows':rows,'source_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
 'meaning':'Native16A90 does call171D4 for kind4, choosing page HII/nonzero token or AMITSE fallback.171D4 changes the first control source before testing type8; kind4 type14 receives source update but no IFR token write. The source-owner classification can therefore depend on render timing and token/fallback.',
 'limits':['171D4 is called directly with controlled arguments and a synthetic six-entry array all pointing to the constructed frame; this is not native full page/render execution.',
 'Kind4 still has its live15C44 callback; a source update does not make it inert. No policy changes or hardware state captured.']}
(HERE/'kind4_source_transition.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps({'status':report['status'],'cases':len(rows)}))
